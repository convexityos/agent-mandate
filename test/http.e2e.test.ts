import { beforeEach, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { MemoryReplayCache } from '../src/spend.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { Merchant } from '../src/http/merchant.js';
import { attachPayment, challengeFrom, payAndRetry, receiptFrom } from '../src/http/client.js';
import { PAYMENT } from '../src/http/headers.js';
import type { SignableRequest } from '../src/http/signature.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * The whole loop: 402 → reserve → signed retry → serve → settle → receipt.
 */

const HOST = 'api.weatherco.com';
const FORECAST = `https://${HOST}/v3/forecast/94110`;
const PREMIUM = `https://${HOST}/v3/premium/deep`;
const LEDGER_URL = 'https://ledger.example.com';
const PRICE = usd('0.02');

let principal: AgentKey;
let agent: AgentKey;
let ledgerKey: AgentKey;
let ledger: Ledger;
let merchant: Merchant;
let clock: number;
let chain: string[];
let quoteN = 0;

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
  quoteN = 0;

  ledger = new Ledger({
    url: LEDGER_URL,
    key: ledgerKey,
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off' },
  });

  merchant = new Merchant({
    host: HOST,
    ledgerUrl: LEDGER_URL,
    ledgerJwk: ledgerKey.jwk,
    replay: new MemoryReplayCache(() => clock),
    clock: () => clock,
    quoteIdFactory: () => `qt_${++quoteN}`,
    price: (_req, uri) => (uri.startsWith(`https://${HOST}/v3/`) ? { amount: PRICE } : null),
  });

  chain = buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: usd('50.00'),
        max_per_txn: usd('1.00'),
        aud: [HOST],
        resources: [`https://${HOST}/v3/*`],
      },
    },
  ]);
});

const get = (url = FORECAST): SignableRequest => ({ method: 'GET', url, headers: {} });

async function reserveFor(url: string) {
  const r = await ledger.reserve({
    tokens: chain,
    request: { resource: url, amount: PRICE },
  });
  if (!r.ok) throw new Error(`reserve failed: ${r.code} ${r.detail}`);
  return r;
}

/** A merchant served over a function, so payAndRetry can drive the real thing. */
function transport(served: { count: number }) {
  return async (req: SignableRequest) => {
    const d = merchant.handle(req);
    if (d.kind === 'challenge') return { status: d.status, headers: d.headers };
    if (d.kind === 'reject') return { status: d.status, headers: d.headers, body: d.body };
    served.count++;
    const settled = await ledger.settle(
      (d as { kind: 'allow'; claims: { jti: string } }).claims.jti,
      { respHash: 'sha256:deadbeef', respBytes: 128 },
    );
    if (!settled.ok) throw new Error('settle failed');
    return {
      status: 200,
      headers: merchant.receiptHeader(settled.receipt.claims.jti),
      body: { tempF: 68 },
    };
  };
}

describe('the full loop', () => {
  it('challenges, pays, serves, and returns a receipt', async () => {
    const served = { count: 0 };
    const result = await payAndRetry(get(), transport(served), {
      key: agent,
      clock: () => clock,
      reserve: async (challenge) => {
        expect(challenge.ledger).toBe(LEDGER_URL);
        expect(challenge.amount).toEqual(PRICE);
        expect(challenge.settle).toEqual(['immediate']);
        const r = await ledger.reserve({
          tokens: chain,
          request: { resource: FORECAST, amount: challenge.amount },
          quote: { quoteId: challenge.quoteId },
        });
        return r.ok ? { ok: true, token: r.token } : { ok: false, detail: r.detail };
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.paid).toBe(true);
    expect(result.response.status).toBe(200);
    expect(result.receipt?.ledger).toBe(LEDGER_URL);
    expect(result.receipt?.id).toMatch(/^rcp_/);
    expect(served.count).toBe(1);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('49.98');
  });

  it('passes free resources straight through', async () => {
    expect(merchant.handle(get(`https://${HOST}/about`)).kind).toBe('free');
  });

  it('emits a well-formed 402 the client can parse', () => {
    const d = merchant.handle(get());
    expect(d.kind).toBe('challenge');
    if (d.kind !== 'challenge') return;
    const c = challengeFrom({ status: 402, headers: d.headers })!;
    expect(c.quoteId).toBe('qt_1');
    expect(c.exp).toBe(clock + 120);
    expect(receiptFrom({ status: 402, headers: d.headers })).toBeNull();
  });
});

describe('merchant rejects', () => {
  async function paidRequest(url = FORECAST, tokenUrl = url) {
    const r = await reserveFor(tokenUrl);
    const req = get(url);
    return { ...req, headers: attachPayment(req, { spendToken: r.token, key: agent, created: clock }) };
  }

  it('rejects an unsigned payment', async () => {
    const r = await reserveFor(FORECAST);
    const d = merchant.handle({ ...get(), headers: { [PAYMENT]: `scheme=agent-mandate, v=1, token="${r.token}"` } });
    expect(d.kind).toBe('reject');
    if (d.kind === 'reject') expect(d.body.code).toBe('pop_failed');
  });

  it('does not let an unsigned request burn the token', async () => {
    // The replay cache is only reached after signature and audience verification
    // (§9.2). Otherwise anyone who observes a jti can spend it into the cache and
    // the legitimate holder's own request bounces as a replay.
    const r = await reserveFor(FORECAST);
    const unsignedHeaders = { [PAYMENT]: `scheme=agent-mandate, v=1, token="${r.token}"` };
    expect(merchant.handle({ ...get(), headers: unsignedHeaders }).kind).toBe('reject');

    const req = get();
    const good = { ...req, headers: attachPayment(req, { spendToken: r.token, key: agent, created: clock }) };
    expect(merchant.handle(good).kind).toBe('allow');
  });

  it('rejects a token minted for another resource', async () => {
    const d = merchant.handle(await paidRequest(PREMIUM, FORECAST));
    expect(d.kind).toBe('reject');
    if (d.kind === 'reject') expect(d.body.code).toBe('resource_not_covered');
  });

  it('rejects a replayed token', async () => {
    const req = await paidRequest();
    expect(merchant.handle(req).kind).toBe('allow');
    const second = merchant.handle(req);
    expect(second.kind).toBe('reject');
    if (second.kind === 'reject') expect(second.body.code).toBe('token_replayed');
  });

  it('rejects a token from a ledger it does not trust', async () => {
    const rogue = new Ledger({
      url: LEDGER_URL,
      key: generateAgentKey(),
      store: new MemoryLedgerStore(() => clock),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
    });
    const r = await rogue.reserve({ tokens: chain, request: { resource: FORECAST, amount: PRICE } });
    if (!r.ok) throw new Error('reserve failed');
    const req = get();
    const d = merchant.handle({
      ...req,
      headers: attachPayment(req, { spendToken: r.token, key: agent, created: clock }),
    });
    expect(d.kind).toBe('reject');
    if (d.kind === 'reject') expect(d.body.code).toBe('chain_invalid');
  });

  it('rejects an expired token even when the signature is fresh', async () => {
    const r = await reserveFor(FORECAST);
    clock += 61 + 60;
    // Re-signed at the new time, so only the spend token is stale. Without this
    // the RFC 9421 max-age fires first and the failure reads as pop_failed —
    // both checks use a 60s window, so in practice they expire together.
    const req = get();
    const d = merchant.handle({
      ...req,
      headers: attachPayment(req, { spendToken: r.token, key: agent, created: clock }),
    });
    expect(d.kind).toBe('reject');
    if (d.kind === 'reject') expect(d.body.code).toBe('token_expired');
  });

  it('rejects a stale request signature before looking at the token', async () => {
    const req = await paidRequest();
    clock += 121;
    const d = merchant.handle(req);
    expect(d.kind).toBe('reject');
    if (d.kind === 'reject') expect(d.body.code).toBe('pop_failed');
  });

  it('rejects a token whose amount does not match the current price', async () => {
    const r = await ledger.reserve({
      tokens: chain,
      request: { resource: FORECAST, amount: usd('0.01') },
    });
    if (!r.ok) throw new Error('reserve failed');
    const req = get();
    const d = merchant.handle({
      ...req,
      headers: attachPayment(req, { spendToken: r.token, key: agent, created: clock }),
    });
    expect(d.kind).toBe('reject');
    if (d.kind === 'reject') expect(d.body.code).toBe('amount_exceeds_cap');
  });

  it('surfaces a ledger refusal as machine-readable problem details', async () => {
    const drained = await ledger.reserve({
      tokens: chain,
      request: { resource: FORECAST, amount: usd('1.00') },
    });
    expect(drained.ok).toBe(true);

    const tooBig = await ledger.reserve({
      tokens: chain,
      request: { resource: FORECAST, amount: usd('2.00') },
    });
    expect(tooBig.ok).toBe(false);
    if (!tooBig.ok) expect(tooBig.code).toBe('amount_exceeds_cap');
  });
});

describe('payAndRetry', () => {
  it('gives up rather than looping when a payment does not satisfy the merchant', async () => {
    let calls = 0;
    const result = await payAndRetry(
      get(),
      async () => {
        calls++;
        const d = merchant.handle(get()); // always unpaid → always 402
        return { status: 402, headers: d.kind === 'challenge' ? d.headers : {} };
      },
      {
        key: agent,
        clock: () => clock,
        reserve: async () => {
          const r = await reserveFor(FORECAST);
          return { ok: true, token: r.token };
        },
      },
    );
    expect(result.ok).toBe(false);
    expect(calls).toBe(2); // one attempt, one retry, then stop
  });

  it('reports a reserve failure without retrying', async () => {
    const result = await payAndRetry(get(), transport({ count: 0 }), {
      key: agent,
      clock: () => clock,
      reserve: async () => ({ ok: false, detail: 'budget_exhausted' }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.detail).toBe('budget_exhausted');
  });
});
