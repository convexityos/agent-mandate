import { beforeEach, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { verifyReceiptSignature, canonicalJson } from '../src/receipt.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { MemoryReplayCache, verifySpendToken } from '../src/spend.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

let principal: AgentKey;
let agentA: AgentKey;
let ledgerKey: AgentKey;
let ledger: Ledger;
let clock: number;

const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;

beforeEach(() => {
  principal = generateAgentKey();
  agentA = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
  ledger = new Ledger({
    url: 'https://ledger.example.com',
    key: ledgerKey,
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
  });
});

async function mint(amount = '0.02') {
  const tokens = buildChain(principal, [
    {
      holder: agentA,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: { max_total: usd('50.00'), max_per_txn: usd('2.00'), aud: [HOST] },
    },
  ]);
  const r = await ledger.reserve({
    tokens,
    request: { resource: RESOURCE, amount: usd(amount) },
  });
  if (!r.ok) throw new Error(`reserve failed: ${r.code} ${r.detail}`);
  return r;
}

const merchantOpts = () => ({
  ledgerJwk: ledgerKey.jwk,
  host: HOST,
  now: clock,
  replay: new MemoryReplayCache(() => clock),
});

describe('§9.2 — merchant-side verification', () => {
  it('accepts a freshly minted token', async () => {
    const { token } = await mint();
    const v = verifySpendToken(token, merchantOpts());
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.claims.aud).toBe(HOST);
      expect(v.claims.amt).toEqual(usd('0.02'));
      expect(v.claims.res).toBe(RESOURCE);
      expect(v.claims.cnf.jkt).toBe(agentA.jkt);
    }
  });

  it('rejects a token addressed to another merchant', async () => {
    const { token } = await mint();
    const v = verifySpendToken(token, { ...merchantOpts(), host: 'evil.test' });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.code).toBe('audience_mismatch');
  });

  it('rejects a token signed by the wrong key', async () => {
    const { token } = await mint();
    const v = verifySpendToken(token, { ...merchantOpts(), ledgerJwk: agentA.jwk });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.code).toBe('chain_invalid');
  });

  it('rejects a replayed jti', async () => {
    const { token } = await mint();
    const opts = merchantOpts();
    expect(verifySpendToken(token, opts).ok).toBe(true);
    const second = verifySpendToken(token, opts);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe('token_replayed');
  });

  it('does not let an unsigned or misaddressed token burn a legitimate jti', async () => {
    const { token } = await mint();
    const opts = merchantOpts();

    // A forgery for the same jti, and a token meant for someone else, must both
    // be rejected without consuming the replay slot.
    const [h, p] = token.split('.') as [string, string];
    const forged = `${h}.${p}.${'A'.repeat(86)}`;
    expect(verifySpendToken(forged, opts).ok).toBe(false);
    expect(verifySpendToken(token, { ...opts, host: 'evil.test' }).ok).toBe(false);

    expect(verifySpendToken(token, opts).ok).toBe(true);
  });

  it('rejects an expired token outside the skew tolerance', async () => {
    const { token, expiresAt } = await mint();
    expect(verifySpendToken(token, { ...merchantOpts(), now: expiresAt + 59 }).ok).toBe(true);
    const late = verifySpendToken(token, { ...merchantOpts(), now: expiresAt + 61 });
    expect(late.ok).toBe(false);
    if (!late.ok) expect(late.code).toBe('token_expired');
  });

  it('binds proof of possession to the leaf holder', async () => {
    const { token } = await mint();
    const stranger = generateAgentKey();
    const bad = verifySpendToken(token, { ...merchantOpts(), presenterJkt: stranger.jkt });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.code).toBe('pop_failed');

    expect(verifySpendToken(token, { ...merchantOpts(), presenterJkt: agentA.jkt }).ok).toBe(true);
  });

  it('never shows the merchant the mandate chain', async () => {
    const { token } = await mint();
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    expect(payload['chain_hash']).toMatch(/^sha256:/);
    expect(JSON.stringify(payload)).not.toContain('max_total');
    expect(JSON.stringify(payload)).not.toContain('mnd_root');
  });
});

describe('§11 — receipts', () => {
  it('is signed by the ledger over canonical bytes', async () => {
    const r = await mint();
    const s = await ledger.settle(r.spendId, { respHash: 'sha256:aaa', respBytes: 10 });
    expect(s.ok).toBe(true);
    if (!s.ok) return;

    expect(verifyReceiptSignature(s.receipt.claims, s.receipt.sigs.ledger, ledgerKey.jwk)).toBe(
      true,
    );
    // Any edit invalidates it.
    const tampered = { ...s.receipt.claims, amt: usd('999.00') };
    expect(verifyReceiptSignature(tampered, s.receipt.sigs.ledger, ledgerKey.jwk)).toBe(false);
  });

  it('canonicalizes independent of key order', () => {
    expect(canonicalJson({ b: 1, a: [3, { d: 4, c: 5 }] })).toBe(
      canonicalJson({ a: [3, { c: 5, d: 4 }], b: 1 }),
    );
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});
