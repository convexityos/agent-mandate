import { createServer, type Server } from 'node:http';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Merchant } from '../src/http/merchant.js';
import {
  localMint,
  mandatedFetch,
  refusalCode,
  remoteMint,
  rfc9421Presenter,
} from '../src/http/mandated-fetch.js';
import { serve } from '../src/http/serve.js';
import { LedgerService } from '../src/http/service.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { toScaled } from '../src/money.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { MemoryReplayCache } from '../src/spend.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §2.2 — the drop-in.
 *
 * Driven against a real merchant over a real socket, because the thing being
 * claimed is that it *is* `fetch`: same call shape, same Response, bodies and
 * status codes intact. A test that stubbed the transport would prove the loop
 * and not the claim.
 */

const LEDGER_URL = 'https://ledger.example.com';
const PRICE = usd('0.02');

let principal: AgentKey;
let agent: AgentKey;
let ledgerKey: AgentKey;
let ledger: Ledger;
let merchant: Merchant;
let clock: number;
let chain: string[];
let quoteN: number;
let served: number;

let server: Server;
let origin: string;
let host: string;

beforeEach(async () => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
  quoteN = 0;
  served = 0;

  ledger = new Ledger({
    url: LEDGER_URL,
    key: ledgerKey,
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
  });

  // Bound first so the merchant's `host` matches what the client will send;
  // §14 checks the token audience against it, and a mismatch is a rejection
  // that looks like a signing bug.
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      void (async () => {
        const signable = {
          method: req.method ?? 'GET',
          url: `http://${host}${req.url ?? '/'}`,
          headers: req.headers,
        };
        const decision = merchant.handle(signable);

        if (decision.kind === 'challenge' || decision.kind === 'reject') {
          res.writeHead(decision.status, decision.headers as Record<string, string>);
          res.end(JSON.stringify((decision as { body?: unknown }).body ?? {}));
          return;
        }

        if (decision.kind === 'free') {
          // Unpriced: served without a token and without a settle. Handling this
          // branch matters — falling through would reach for `claims` that a
          // free decision does not have.
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ free: true }));
          return;
        }

        served++;
        const body = Buffer.concat(chunks).toString('utf8');
        const settled = await ledger.settle(decision.claims.jti, {
          respHash: 'sha256:deadbeef',
          respBytes: 128,
        });
        if (!settled.ok) {
          res.writeHead(500);
          res.end('{}');
          return;
        }
        res.writeHead(200, {
          ...merchant.receiptHeader(settled.receipt.claims.jti),
          'content-type': 'application/json',
        });
        res.end(JSON.stringify({ tempF: 68, echo: body }));
      })();
    });
  });

  server.listen(0, '127.0.0.1');
  if (!server.listening) await new Promise((r) => server.once('listening', r));
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
  host = `127.0.0.1:${port}`;
  origin = `http://${host}`;

  merchant = new Merchant({
    host,
    ledgerUrl: LEDGER_URL,
    ledgerJwk: ledgerKey.jwk,
    replay: new MemoryReplayCache(() => clock),
    clock: () => clock,
    quoteIdFactory: () => `qt_${++quoteN}`,
    // Two priced prefixes; the mandate below covers only /v3/. That is how a
    // request can reach a real 402 and still be refused by the principal.
    price: (_req, uri) =>
      uri.startsWith(`${origin}/v3/`) || uri.startsWith(`${origin}/v9/`)
        ? { amount: PRICE }
        : null,
  });

  chain = buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: usd('1.00'),
        max_per_txn: usd('0.50'),
        aud: [host],
        resources: [`${origin}/v3/*`],
      },
    },
  ]);
});

afterEach(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

const client = (over: Record<string, unknown> = {}) =>
  mandatedFetch({
    tokens: chain,
    key: agent,
    mint: localMint(ledger),
    clock: () => clock,
    ...over,
  });

// The ledger materializes a node on first debit, so a mandate never spent
// against has no row and `remaining` answers null rather than the declared
// budget. For these assertions "never debited" and "full budget left" are the
// same claim — which matters, because the refusal tests expect exactly that.
const remaining = async () => {
  const left = await ledger.remaining('mnd_root');
  return left === null ? toScaled(usd('1.00')) : toScaled(left);
};

describe('it behaves like fetch', () => {
  it('pays a 402 and returns the merchant response with its body intact', async () => {
    const res = await client()(`${origin}/v3/forecast/94110`);

    expect(res.status).toBe(200);
    expect(res.ok).toBe(true);
    expect(await res.json()).toMatchObject({ tempF: 68 });
    expect(served).toBe(1);
    expect(await remaining()).toBe(toScaled(usd('0.98')));

    // The merchant's receipt header survives the round trip.
    expect(res.headers.get('payment-receipt')).toBeTruthy();
  });

  it('leaves a free resource alone', async () => {
    // Priced null by the merchant, so no 402, no mint, no debit.
    const res = await client()(`${origin}/free/ping`);
    expect(res.status).toBe(200);
    expect(await remaining()).toBe(toScaled(usd('1.00')));
  });

  it('replays the request body on the paid retry', async () => {
    // The 402 is answered by re-sending. A drop-in that lost the body here
    // would work for GETs and silently corrupt every POST.
    const res = await client()(`${origin}/v3/forecast/94110`, {
      method: 'POST',
      body: JSON.stringify({ hello: 'world' }),
      headers: { 'content-type': 'application/json' },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ echo: '{"hello":"world"}' });
  });

  it('accepts a Request object as well as a URL', async () => {
    const res = await client()(new Request(`${origin}/v3/forecast/94110`));
    expect(res.status).toBe(200);
  });
});

describe('a refusal is a Response, not an exception', () => {
  it('returns problem details rather than throwing when the budget is gone', async () => {
    const fetch = client();
    // 1.00 budget at 0.02 each: drain it, then ask once more.
    for (let i = 0; i < 50; i++) {
      const r = await fetch(`${origin}/v3/forecast/${94110 + i}`);
      expect(r.status).toBe(200);
    }
    expect(await remaining()).toBe(0n);

    const refused = await fetch(`${origin}/v3/forecast/99999`);
    expect(refused.ok).toBe(false);
    expect(refused.status).toBe(402);
    expect(refusalCode(refused)).toBe('budget_exhausted');
    expect((await refused.json()) as { code: string }).toMatchObject({
      code: 'budget_exhausted',
      type: 'https://agentmandate.org/errors/budget_exhausted',
    });
    // The merchant was never asked to serve it.
    expect(served).toBe(50);
  });

  it('refuses a resource outside the grant without paying for it', async () => {
    // The merchant prices /v9/ and issues a real 402. The mandate covers only
    // /v3/, so the refusal comes from the principal rather than the merchant —
    // and it happens before any money moves.
    const res = await client()(`${origin}/v9/admin/keys`);
    expect(res.ok).toBe(false);
    expect(refusalCode(res)).toBe('resource_not_covered');
    expect(served).toBe(0);
    expect(await remaining()).toBe(toScaled(usd('1.00')));
  });

  it('marks its own refusals so they are not mistaken for the merchant s', async () => {
    const small = buildChain(principal, [
      {
        holder: agent,
        exp: NOW + 86400,
        jti: 'mnd_root',
        cav: {
          max_total: usd('1.00'),
          max_per_txn: usd('0.001'), // below the price
          aud: [host],
          resources: [`${origin}/v3/*`],
        },
      },
    ]);
    const res = await client({ tokens: small })(`${origin}/v3/forecast/94110`);
    expect(refusalCode(res)).toBe('amount_exceeds_cap');
    // A merchant response carries no such header, which is how a caller tells
    // "your principal said no" from "the merchant said no".
    const ok = await client()(`${origin}/v3/forecast/94110`);
    expect(refusalCode(ok)).toBeNull();
  });

  it('surfaces a step-up handle so the caller can go and get approval', async () => {
    const gated = buildChain(principal, [
      {
        holder: agent,
        exp: NOW + 86400,
        jti: 'mnd_root',
        cav: {
          max_total: usd('1.00'),
          max_per_txn: usd('0.50'),
          aud: [host],
          resources: [`${origin}/v3/*`],
          step_up: { over: usd('0.01') },
        },
      },
    ]);
    const res = await client({ tokens: gated })(`${origin}/v3/forecast/94110`);
    expect(refusalCode(res)).toBe('step_up_required');
    const body = (await res.json()) as { stepUpHandle?: string };
    expect(body.stepUpHandle).toMatch(/^stp_/);
  });
});

describe('idempotency is scoped to the quote', () => {
  /**
   * The mint is idempotent per quote, which is the failure that matters: a mint
   * request that is retried or duplicated must not debit twice.
   */
  it('replays a mint for the same quote instead of debiting again', async () => {
    const mint = localMint(ledger);
    const req = {
      tokens: chain,
      resource: `${origin}/v3/forecast/94110`,
      amount: PRICE,
      quote: { quoteId: 'qt_fixed' },
      presenterJkt: agent.jkt,
      idempotencyKey: 'quote:x:qt_fixed',
    };

    const first = await mint.mint(req);
    const after = await remaining();
    const second = await mint.mint(req);

    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) expect(second.spendId).toBe(first.spendId);
    expect(await remaining()).toBe(after);
  });

  /**
   * And a whole-call retry is *not* idempotent, which is correct rather than a
   * gap. A caller that gives up and calls again gets a fresh 402 carrying a
   * fresh quoteId — a different purchase against a different quote. Replaying
   * the earlier mint would return a token bound to a quote the merchant has
   * moved on from. The abandoned reservation is cleaned up by expiry, not by
   * replay.
   */
  it('treats a second call as a second purchase, because the quote changed', async () => {
    const fetch = client();
    const url = `${origin}/v3/forecast/94110`;

    await fetch(url);
    const after = await remaining();
    await fetch(url);

    expect(await remaining()).toBe(after - toScaled(PRICE));
    expect(served).toBe(2);
  });
});

describe('against a remote ledger service', () => {
  let ledgerServer: Server;
  let ledgerOrigin: string;

  beforeEach(async () => {
    ledgerServer = serve({
      port: 0,
      handlers: [
        new LedgerService({
          ledger,
          basePath: '/ledger',
          // The pairing that makes §7 step 9 work over the wire.
          resolvePresenter: rfc9421Presenter({ clock: () => clock }),
        }),
      ],
    });
    if (!ledgerServer.listening) await new Promise((r) => ledgerServer.once('listening', r));
    const addr = ledgerServer.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    ledgerOrigin = `http://127.0.0.1:${port}/ledger`;
  });

  afterEach(async () => {
    await new Promise<void>((r) => ledgerServer.close(() => r()));
  });

  it('mints over HTTP, proving possession with an RFC 9421 signature', async () => {
    const fetch = mandatedFetch({
      tokens: chain,
      key: agent,
      mint: remoteMint({ url: ledgerOrigin, key: agent, clock: () => clock }),
      clock: () => clock,
    });

    const res = await fetch(`${origin}/v3/forecast/94110`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ tempF: 68 });
    expect(await remaining()).toBe(toScaled(usd('0.98')));
  });

  it('is refused by the ledger when the signing key is not the leaf holder', async () => {
    const impostor = generateAgentKey();
    const fetch = mandatedFetch({
      tokens: chain,
      key: agent,
      // Signs the mint with a key that holds nothing.
      mint: remoteMint({ url: ledgerOrigin, key: impostor, clock: () => clock }),
      clock: () => clock,
    });

    const res = await fetch(`${origin}/v3/forecast/94110`);
    expect(res.ok).toBe(false);
    expect(refusalCode(res)).toBe('pop_failed');
    expect(served).toBe(0);
  });

  it('relays a ledger refusal as a refusal, not as a transport error', async () => {
    const fetch = mandatedFetch({
      tokens: chain,
      key: agent,
      mint: remoteMint({ url: ledgerOrigin, key: agent, clock: () => clock }),
      clock: () => clock,
    });
    for (let i = 0; i < 50; i++) await fetch(`${origin}/v3/forecast/${94110 + i}`);

    const refused = await fetch(`${origin}/v3/forecast/99999`);
    expect(refusalCode(refused)).toBe('budget_exhausted');
  });
});
