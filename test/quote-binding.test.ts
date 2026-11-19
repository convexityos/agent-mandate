import { createServer, type Server } from 'node:http';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  ACCEPT_PAYMENT,
  Ledger,
  MemoryLedgerStore,
  MemoryQuoteStore,
  MemoryReplayCache,
  Merchant,
  PAYMENT_REQUIRED_HEADER,
  X402NonCustodialRail,
  X402Rail,
  attachPayment,
  challengeHashFrom,
  generateAgentKey,
  localMint,
  mandatedFetch,
  payAndRetry,
  quoteHashForHttpChallenge,
  quoteHashForX402Challenge,
  quoteHashFromX402Response,
  quotesMatch,
  isQuoteHash,
  type AgentKey,
  type Quote,
  type SignableRequest,
  type X402Intent,
} from '../src/index.js';
import { SqliteStore } from '../src/ledger/sql/sqlite.js';
import {
  BASE_CAIP2,
  FUNDING_SPREADS,
  FixtureSigner,
  NFT_OWNER,
  USDC_BASE,
  captureFor,
  fixtureTransport,
  urlFor,
} from './fixtures/x402.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

const HOST = 'api.weatherco.com';
const FORECAST = `https://${HOST}/v3/forecast/94110`;
const PREMIUM = `https://${HOST}/v3/premium/deep`;
const LEDGER_URL = 'https://ledger.example.com';

describe('quote binding digests', () => {
  it('domain-separates HTTP and x402 digests and binds canonical URI', () => {
    const raw = 'scheme=agent-mandate, v=1, quote="qt_1"';
    const httpA = quoteHashForHttpChallenge(FORECAST, raw);
    const httpB = quoteHashForHttpChallenge(PREMIUM, raw);
    const x402A = quoteHashForX402Challenge(FORECAST, raw);

    expect(isQuoteHash(httpA)).toBe(true);
    expect(isQuoteHash('sha256:not-a-hex-digest')).toBe(false);
    expect(quotesMatch(httpA, httpA)).toBe(true);
    expect(quotesMatch(httpA, httpB)).toBe(false);
    expect(quotesMatch(httpA, x402A)).toBe(false);
  });

  it('hashes byte-exact PAYMENT-REQUIRED header from x402-live.json', () => {
    const cap = captureFor(FUNDING_SPREADS);
    const uri = urlFor(FUNDING_SPREADS);
    const fromResponse = quoteHashFromX402Response(uri, {
      status: 402,
      headers: { [PAYMENT_REQUIRED_HEADER]: cap.paymentRequiredHeader },
      body: {},
    });
    const direct = quoteHashForX402Challenge(uri, cap.paymentRequiredHeader);
    expect(fromResponse).toBe(direct);
    expect(isQuoteHash(fromResponse)).toBe(true);
  });
});

describe('HTTP §14 merchant quote binding', () => {
  let principal: AgentKey;
  let agent: AgentKey;
  let ledgerKey: AgentKey;
  let ledger: Ledger;
  let merchant: Merchant;
  let clock: number;
  let chain: string[];
  let currentQuote: Quote;
  let quoteN: number;

  beforeEach(() => {
    principal = generateAgentKey();
    agent = generateAgentKey();
    ledgerKey = generateAgentKey();
    clock = NOW + 10;
    quoteN = 0;
    currentQuote = { amount: usd('0.02') };

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
      quoteTtlSeconds: 60,
      quoteIdFactory: () => `qt_${++quoteN}`,
      quotes: new MemoryQuoteStore(() => clock),
      price: (_req, uri) => (uri.startsWith(`https://${HOST}/v3/`) ? currentQuote : null),
    });

    chain = buildChain(principal, [
      {
        holder: agent,
        exp: NOW + 86400,
        jti: 'mnd_root',
        cav: {
          max_total: usd('50.00'),
          max_per_txn: usd('5.00'),
          aud: [HOST],
          resources: [`https://${HOST}/v3/*`],
        },
      },
    ]);
  });

  const get = (url = FORECAST): SignableRequest => ({ method: 'GET', url, headers: {} });

  function getChallenge(url = FORECAST) {
    const d = merchant.handle(get(url));
    if (d.kind !== 'challenge') throw new Error(`expected challenge, got ${d.kind}`);
    return d;
  }

  async function mintFor(
    url: string,
    amount = currentQuote.amount,
    quote?: { quoteId?: string; quoteHash?: string; schema?: string },
  ) {
    const r = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      request: { resource: url, amount },
      ...(quote !== undefined ? { quote } : {}),
    });
    if (!r.ok) throw new Error(`reserve failed: ${r.code} ${r.detail}`);
    return r;
  }

  function signedRetry(url: string, token: string): SignableRequest {
    const req = get(url);
    return {
      ...req,
      headers: attachPayment(req, { spendToken: token, key: agent, created: clock }),
    };
  }

  it('binds quote_id and quote_hash across 402, spend token, and settled receipt', async () => {
    const served: string[] = [];
    const result = await payAndRetry(
      get(),
      async (req) => {
        const d = merchant.handle(req);
        if (d.kind === 'challenge') return { status: d.status, headers: d.headers };
        if (d.kind === 'reject') return { status: d.status, headers: d.headers, body: d.body };
        if (d.kind === 'free') return { status: 200, headers: {} };
        served.push(d.claims.jti);
        const settled = await ledger.settle(d.claims.jti, {
          respHash: 'sha256:abcd',
          respBytes: 42,
        });
        if (!settled.ok) throw new Error('settle failed');
        expect(settled.receipt.claims.quote_id).toBe('qt_1');
        expect(settled.receipt.claims.quote_hash).toBe(d.claims.quote_hash);
        return {
          status: 200,
          headers: merchant.receiptHeader(settled.receipt.claims.jti),
          body: { ok: true },
        };
      },
      {
        key: agent,
        clock: () => clock,
        reserve: async (challenge, meta) => {
          expect(meta?.quoteHash).toBeDefined();
          const r = await ledger.reserve({
            tokens: chain,
            presenterJkt: agent.jkt,
            request: { resource: FORECAST, amount: challenge.amount },
            quote: {
              quoteId: challenge.quoteId,
              ...(meta?.quoteHash !== undefined ? { quoteHash: meta.quoteHash } : {}),
            },
          });
          return r.ok ? { ok: true, token: r.token } : { ok: false, detail: r.detail };
        },
      },
    );

    expect(result.ok).toBe(true);
    expect(served).toHaveLength(1);
  });

  it('rejects a stale cheap quote after the merchant reprices the resource', async () => {
    const ch = getChallenge();
    const res = await mintFor(FORECAST, usd('0.02'), {
      quoteId: ch.quoteId,
      quoteHash: ch.quoteHash,
    });

    // Merchant reprices before the agent retries with the stale quote.
    currentQuote = { amount: usd('0.05') };

    const decision = merchant.handle(signedRetry(FORECAST, res.token));
    expect(decision.kind).toBe('reject');
    if (decision.kind === 'reject') {
      expect(decision.status).toBe(409);
      expect(decision.body.code).toBe('quote_mismatch');
      expect(decision.body.detail).toMatch(/repriced/i);
    }
  });

  it('rejects an expired quote even when the spend token and signature are fresh', async () => {
    const ch = getChallenge();

    // Advance past the 60s quote TTL, THEN mint a fresh spend token.
    clock += 65;
    const res = await mintFor(FORECAST, usd('0.02'), {
      quoteId: ch.quoteId,
      quoteHash: ch.quoteHash,
    });

    const decision = merchant.handle(signedRetry(FORECAST, res.token));
    expect(decision.kind).toBe('reject');
    if (decision.kind === 'reject') {
      expect(decision.status).toBe(409);
      expect(decision.body.code).toBe('quote_expired');
    }
  });

  it('rejects a quote when the response schema changes between 402 and retry', async () => {
    currentQuote = { amount: usd('0.02'), settle: ['immediate'], schema: 'sha256:v1' };
    const ch = getChallenge();
    const res = await mintFor(FORECAST, usd('0.02'), {
      quoteId: ch.quoteId,
      quoteHash: ch.quoteHash,
      schema: 'sha256:v1',
    });

    currentQuote = { amount: usd('0.02'), settle: ['immediate'], schema: 'sha256:v2' };

    const decision = merchant.handle(signedRetry(FORECAST, res.token));
    expect(decision.kind).toBe('reject');
    if (decision.kind === 'reject') {
      expect(decision.body.code).toBe('quote_mismatch');
      expect(decision.body.detail).toMatch(/schema changed/i);
    }
  });

  it('rejects a token carrying a tampered quote_hash or missing quote binding', async () => {
    const ch = getChallenge();

    const unbound = await mintFor(FORECAST, usd('0.02'));
    const d1 = merchant.handle(signedRetry(FORECAST, unbound.token));
    expect(d1.kind).toBe('reject');
    if (d1.kind === 'reject') expect(d1.body.code).toBe('quote_mismatch');

    const tampered = await mintFor(FORECAST, usd('0.02'), {
      quoteId: ch.quoteId,
      quoteHash: 'sha256:' + '0'.repeat(64),
    });
    const d2 = merchant.handle(signedRetry(FORECAST, tampered.token));
    expect(d2.kind).toBe('reject');
    if (d2.kind === 'reject') expect(d2.body.code).toBe('quote_mismatch');
  });

  it('rejects lifting a quote issued for one resource onto another resource', async () => {
    const ch = getChallenge(FORECAST);
    const res = await mintFor(PREMIUM, usd('0.02'), {
      quoteId: ch.quoteId,
      quoteHash: ch.quoteHash,
    });
    const decision = merchant.handle(signedRetry(PREMIUM, res.token));
    expect(decision.kind).toBe('reject');
    if (decision.kind === 'reject') expect(decision.body.code).toBe('quote_mismatch');
  });

  it('consumes a quote on first use so a second spend token cannot reuse it', async () => {
    const ch = getChallenge();
    const first = await mintFor(FORECAST, usd('0.02'), {
      quoteId: ch.quoteId,
      quoteHash: ch.quoteHash,
    });
    const second = await mintFor(FORECAST, usd('0.02'), {
      quoteId: ch.quoteId,
      quoteHash: ch.quoteHash,
    });

    expect(merchant.handle(signedRetry(FORECAST, first.token)).kind).toBe('allow');
    const replay = merchant.handle(signedRetry(FORECAST, second.token));
    expect(replay.kind).toBe('reject');
    if (replay.kind === 'reject') {
      expect(replay.body.code).toBe('quote_mismatch');
      expect(replay.body.detail).toMatch(/already consumed/i);
    }
  });

  it('refuses a malformed quoteHash at Ledger.reserve before debiting', async () => {
    const r = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      request: { resource: FORECAST, amount: usd('0.02') },
      quote: { quoteId: 'qt_bad', quoteHash: 'not-a-digest' },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('chain_invalid');
    expect(await ledger.remaining('mnd_root')).toBeNull();
  });

  it('refuses Idempotency-Key reuse when quoteHash differs', async () => {
    const h1 = quoteHashForHttpChallenge(FORECAST, 'challenge-1');
    const h2 = quoteHashForHttpChallenge(FORECAST, 'challenge-2');

    const r1 = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      idempotencyKey: 'idem-quote-1',
      request: { resource: FORECAST, amount: usd('0.02') },
      quote: { quoteId: 'qt_1', quoteHash: h1 },
    });
    expect(r1.ok).toBe(true);

    const r2 = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      idempotencyKey: 'idem-quote-1',
      request: { resource: FORECAST, amount: usd('0.02') },
      quote: { quoteId: 'qt_1', quoteHash: h2 },
    });
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.code).toBe('chain_invalid');
  });

  it('computes the same quoteHash on client challengeHashFrom and merchant challenge', () => {
    const ch = getChallenge();
    const fromClient = challengeHashFrom(FORECAST, {
      status: 402,
      headers: { [ACCEPT_PAYMENT]: ch.headers[ACCEPT_PAYMENT] },
    });
    expect(fromClient).toBe(ch.quoteHash);
  });
});

describe('mandatedFetch automatic quote binding over real HTTP', () => {
  let server: Server;

  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
  });

  it('automatically binds 402 challenge hashes against a requireQuoteBinding merchant', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const ledgerKey = generateAgentKey();
    const clock = NOW + 10;

    const ledger = new Ledger({
      url: LEDGER_URL,
      key: ledgerKey,
      store: new SqliteStore({ location: ':memory:', clock: () => clock }),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
      breakers: { novelMerchant: 'off' },
    });

    let merchant!: Merchant;
    let boundQuoteHash: string | undefined;

    server = createServer((req, res) => {
      const signable = {
        method: req.method ?? 'GET',
        url: `http://${host}${req.url ?? '/'}`,
        headers: req.headers,
      };
      const decision = merchant.handle(signable);
      if (decision.kind === 'challenge' || decision.kind === 'reject') {
        res.writeHead(decision.status, decision.headers);
        res.end(JSON.stringify(decision.body));
        return;
      }
      if (decision.kind === 'free') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{}');
        return;
      }
      void (async () => {
        boundQuoteHash = decision.claims.quote_hash;
        const settled = await ledger.settle(decision.claims.jti, {
          respHash: 'sha256:beef',
          respBytes: 16,
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
        res.end(JSON.stringify({ ok: true }));
      })();
    });

    server.listen(0, '127.0.0.1');
    if (!server.listening) await new Promise((r) => server.once('listening', r));
    const addr = server.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    const host = `127.0.0.1:${port}`;
    const origin = `http://${host}`;

    merchant = new Merchant({
      host,
      ledgerUrl: LEDGER_URL,
      ledgerJwk: ledgerKey.jwk,
      replay: new MemoryReplayCache(() => clock),
      clock: () => clock,
      requireQuoteBinding: true,
      price: (_req, uri) => (uri.startsWith(`${origin}/v3/`) ? { amount: usd('0.03') } : null),
    });

    const chain = buildChain(principal, [
      {
        holder: agent,
        exp: NOW + 86400,
        jti: 'mnd_root',
        cav: {
          max_total: usd('10.00'),
          max_per_txn: usd('1.00'),
          aud: [host],
          resources: [`${origin}/v3/*`],
        },
      },
    ]);

    const fetchWithMandate = mandatedFetch({
      tokens: chain,
      key: agent,
      mint: localMint(ledger),
      clock: () => clock,
    });

    const res = await fetchWithMandate(`${origin}/v3/forecast`);
    expect(res.status).toBe(200);
    expect(isQuoteHash(boundQuoteHash)).toBe(true);
  });
});

describe('x402 quote binding against x402-live.json captures', () => {
  const URL = urlFor(FUNDING_SPREADS);
  const CAPTURE = captureFor(FUNDING_SPREADS);
  /** 1000 atomic units = 0.001 USDC, the storefront's captured price. */
  const PRICE = usd('0.001');

  function makeCustodialLedger(transport: ReturnType<typeof fixtureTransport>, signer: FixtureSigner) {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const ledgerKey = generateAgentKey();
    const clock = NOW + 10;

    const rail = new X402Rail({
      transport: transport.transport,
      signer,
      network: BASE_CAIP2,
      asset: USDC_BASE,
      assetDecimals: 6,
      clock: () => clock,
    });

    const ledger = new Ledger({
      url: LEDGER_URL,
      key: ledgerKey,
      store: new SqliteStore({ location: ':memory:', clock: () => clock }),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
      rail,
      breakers: { novelMerchant: 'off' },
    });

    const chain = buildChain(principal, [
      {
        holder: agent,
        exp: NOW + 86400,
        jti: 'mnd_root',
        cav: {
          max_total: usd('5.00'),
          max_per_txn: usd('1.00'),
          aud: ['x402.fablerlabs.com'],
        },
      },
    ]);

    return { ledger, chain, agent };
  }

  it('settles custodial x402 when live PAYMENT-REQUIRED bytes match quoteHash and records it on receipt', async () => {
    const ft = fixtureTransport({ path: FUNDING_SPREADS });
    const signer = new FixtureSigner();
    const { ledger, chain, agent } = makeCustodialLedger(ft, signer);

    const quoteHash = quoteHashForX402Challenge(URL, CAPTURE.paymentRequiredHeader);
    const res = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      request: { resource: URL, amount: PRICE },
      quote: { quoteId: 'x402_qt_1', quoteHash },
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const settled = await ledger.settle(res.spendId);
    expect(settled.ok).toBe(true);
    if (!settled.ok) return;
    expect(settled.status).toBe('settled');
    expect(settled.receipt.claims.quote_hash).toBe(quoteHash);
    expect(settled.receipt.claims.quote_id).toBe('x402_qt_1');
    expect(signer.signed).toHaveLength(1);
  });

  it('refuses custodial x402 settlement and refunds when live PAYMENT-REQUIRED mutates payTo or amount', async () => {
    // Mutate payTo inside a copy of the live capture while keeping the price identical.
    const decoded = JSON.parse(
      Buffer.from(CAPTURE.paymentRequiredHeader, 'base64').toString('utf8'),
    ) as { accepts: Array<Record<string, unknown>> };
    decoded.accepts[0]!['payTo'] = '0x9999999999999999999999999999999999999999';
    const mutatedHeader = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64');

    const ft = fixtureTransport({ path: FUNDING_SPREADS, challengeHeader: mutatedHeader });
    const signer = new FixtureSigner();
    const { ledger, chain, agent } = makeCustodialLedger(ft, signer);

    // Agent reserved against the genuine captured challenge header.
    const originalHash = quoteHashForX402Challenge(URL, CAPTURE.paymentRequiredHeader);
    const res = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      request: { resource: URL, amount: PRICE },
      quote: { quoteHash: originalHash },
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const settled = await ledger.settle(res.spendId);
    expect(settled.ok).toBe(true);
    if (settled.ok) expect(settled.status).toBe('refunded');
    // Zero EIP-3009 signatures signed, and full budget refunded.
    expect(signer.signed).toHaveLength(0);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('5');
  });

  it('binds verbatim PAYMENT-REQUIRED header in non-custodial X402NonCustodialRail directive', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const ledgerKey = generateAgentKey();
    const clock = NOW + 10;

    const nc = new X402NonCustodialRail({
      payer: '0x1111111111111111111111111111111111111111',
      verifier: { recover: () => null },
      chain: { authorizationState: async () => false },
      network: BASE_CAIP2,
      asset: USDC_BASE,
      assetDecimals: 6,
      clock: () => clock,
    });

    const ledger = new Ledger({
      url: LEDGER_URL,
      key: ledgerKey,
      store: new MemoryLedgerStore(() => clock),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
      nonCustodialRail: nc,
      breakers: { novelMerchant: 'off' },
    });

    const chain = buildChain(principal, [
      {
        holder: agent,
        exp: NOW + 86400,
        jti: 'mnd_root',
        cav: {
          max_total: usd('5.00'),
          max_per_txn: usd('1.00'),
          aud: ['x402.fablerlabs.com'],
        },
      },
    ]);

    const goodHash = quoteHashForX402Challenge(URL, CAPTURE.paymentRequiredHeader);
    const okRes = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      request: { resource: URL, amount: PRICE },
      quote: {
        quoteHash: goodHash,
        rail: CAPTURE.paymentRequiredHeader,
      },
    });
    expect(okRes.ok).toBe(true);
    if (okRes.ok) {
      const intent = okRes.directive?.intent as X402Intent | undefined;
      expect(intent?.quoteHash).toBe(goodHash);
    }

    // Forwarding a different endpoint's PAYMENT-REQUIRED header against goodHash fails before debit.
    const otherHeader = captureFor(NFT_OWNER).paymentRequiredHeader;
    const badRes = await ledger.reserve({
      tokens: chain,
      presenterJkt: agent.jkt,
      request: { resource: URL, amount: PRICE },
      quote: {
        quoteHash: goodHash,
        rail: otherHeader,
      },
    });
    expect(badRes.ok).toBe(false);
    if (!badRes.ok) {
      expect(badRes.detail).toMatch(/digest mismatch/i);
    }
  });
});
