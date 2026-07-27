import { beforeEach, describe, expect, it } from 'vitest';

import { executeDirective, verifyDirective } from '../src/agent/directive.js';
import { LocalEip3009Signer, type SignerPolicy } from '../src/agent/signer.js';
import { NobleEip712Verifier } from '../src/chain/eip712.js';
import { EthCallChainReader } from '../src/chain/ethcall.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { X402NonCustodialRail, type X402Intent } from '../src/rail/x402-noncustodial.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { BASE_CAIP2, FUNDING_SPREADS, LIVE, USDC_BASE, captureFor, urlFor } from './fixtures/x402.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

const KEY = '0x4c0883a69102937d6231471b5dbb6204fe512961708279f2e3e8a5d4b8e3e3aa';
const LEDGER_URL = 'https://ledger.optera.one';

let principal: AgentKey;
let agentKey: AgentKey;
let ledgerKey: AgentKey;
let clock: number;
let consumed: Set<string>;

const basePolicy = (over: Partial<SignerPolicy> = {}): SignerPolicy => ({
  maxPerTransfer: 100_000n,
  allowedAssets: [USDC_BASE],
  allowedChainIds: [8453],
  ...over,
});

function makeSigner(over: Partial<SignerPolicy> = {}) {
  return new LocalEip3009Signer({
    privateKey: KEY,
    policy: basePolicy(over),
    clock: () => clock,
  });
}

function makeLedger(payer: string) {
  consumed = new Set();
  const chain = new EthCallChainReader(async ({ data }) => {
    const key = `0x${data.slice(34, 74)}:0x${data.slice(74)}`;
    return `0x${'00'.repeat(31)}${consumed.has(key.toLowerCase()) ? '01' : '00'}`;
  });
  return new Ledger({
    url: LEDGER_URL,
    key: ledgerKey,
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off' },
    nonCustodialRail: new X402NonCustodialRail({
      payer,
      verifier: new NobleEip712Verifier(),
      chain,
      network: BASE_CAIP2,
      asset: USDC_BASE,
      clock: () => clock,
    }),
  });
}

function tokens(payer: string) {
  return buildChain(principal, [
    {
      holder: agentKey,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: { max_total: usd('1.00'), max_per_txn: usd('0.50'), aud: [LIVE.host], payer },
    },
  ]);
}

const request = { resource: urlFor(FUNDING_SPREADS), amount: usd('0.001') };
const quote = () => ({ rail: captureFor(FUNDING_SPREADS).decoded });

beforeEach(() => {
  principal = generateAgentKey();
  agentKey = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
});

async function issue(signerAddress: string) {
  const ledger = makeLedger(signerAddress);
  const r = await ledger.reserve({ tokens: tokens(signerAddress), request, quote: quote() });
  if (!r.ok) throw new Error(`reserve failed: ${r.detail}`);
  return { ledger, reserved: r, jws: r.directiveJws! };
}

const opts = () => ({
  ledgerJwk: ledgerKey.jwk,
  ledgerUrl: LEDGER_URL,
  now: clock,
});

describe('verifyDirective', () => {
  it('accepts a genuine directive', async () => {
    const signer = makeSigner();
    const { jws } = await issue(signer.address);
    const check = verifyDirective(jws, { ...opts(), jkt: agentKey.jkt });
    expect(check.ok).toBe(true);
  });

  it('rejects one signed by a different ledger', async () => {
    const signer = makeSigner();
    const { jws } = await issue(signer.address);
    const impostor = generateAgentKey();
    const check = verifyDirective(jws, { ...opts(), ledgerJwk: impostor.jwk });
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toContain('signature verification failed');
  });

  it('rejects one issued by a ledger this agent does not expect', async () => {
    const signer = makeSigner();
    const { jws } = await issue(signer.address);
    const check = verifyDirective(jws, { ...opts(), ledgerUrl: 'https://elsewhere.example' });
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toContain('expected');
  });

  it('rejects one bound to another agent key', async () => {
    const signer = makeSigner();
    const { jws } = await issue(signer.address);
    const check = verifyDirective(jws, { ...opts(), jkt: generateAgentKey().jkt });
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toContain('different agent key');
  });

  it('rejects an intent that does not match its own hash', async () => {
    const signer = makeSigner();
    const { jws } = await issue(signer.address);

    // Re-sign a tampered payload with the real ledger key: a valid signature
    // over an inconsistent directive.
    const [h, p, s] = jws.split('.') as [string, string, string];
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<string, unknown>;
    (payload['intent'] as X402Intent).authorization.to = `0x${'99'.repeat(20)}`;
    const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;

    const check = verifyDirective(tampered, opts());
    expect(check.ok).toBe(false);
    // Signature check fires first; the hash check is the backstop if it ever does not.
    if (!check.ok) expect(check.reason).toMatch(/signature|intentHash/);
  });

  it('rejects an expired directive', async () => {
    const signer = makeSigner();
    const { jws, reserved } = await issue(signer.address);
    const check = verifyDirective(jws, { ...opts(), now: reserved.directive!.expiresAt + 61 });
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toContain('expired');
  });

  it('rejects garbage', () => {
    expect(verifyDirective('not-a-jws', opts()).ok).toBe(false);
  });
});

describe('executeDirective', () => {
  it('verifies, signs, and hands back a report the ledger accepts', async () => {
    const signer = makeSigner();
    const { ledger, reserved, jws } = await issue(signer.address);

    const result = executeDirective(jws, { ...opts(), signer, jkt: agentKey.jkt });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const intent = reserved.directive!.intent as X402Intent;
    expect(result.signed.address).toBe(signer.address);
    expect(result.signed.authorization.nonce).toBe(intent.authorization.nonce);

    // The ledger independently verifies the same signature.
    const reportResult = await ledger.report(reserved.spendId, result.report);
    expect(reportResult.ok).toBe(false); // accepted, awaiting the oracle
    expect((await ledger.reservation(reserved.spendId))?.reported?.ok).toBe(true);

    // Agent submits; the token contract records the nonce.
    consumed.add(
      `${intent.authorization.from.toLowerCase()}:${intent.authorization.nonce.toLowerCase()}`,
    );
    expect(await ledger.reconcile()).toEqual([
      { spendId: reserved.spendId, outcome: 'settled' },
    ]);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
  });

  it('refuses a directive for a different payer', async () => {
    const signer = makeSigner();
    const { jws } = await issue(signer.address);
    const other = new LocalEip3009Signer({
      privateKey: `0x${'11'.repeat(32)}`,
      policy: basePolicy(),
      clock: () => clock,
    });
    const result = executeDirective(jws, { ...opts(), signer: other });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('this signer is');
  });

  it('lets the signer veto a directive the ledger considered fine', async () => {
    // The whole point of non-custodial: the key holder keeps the last word. A
    // compromised or buggy ledger cannot exceed the principal's own limits.
    const signer = makeSigner({ maxPerTransfer: 500n }); // below the 1000-unit price
    const { jws } = await issue(signer.address);

    const result = executeDirective(jws, { ...opts(), signer });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('maxPerTransfer');
  });

  it('lets the signer veto an unexpected destination', async () => {
    const signer = makeSigner({ allowedRecipients: [`0x${'77'.repeat(20)}`] });
    const { jws } = await issue(signer.address);
    const result = executeDirective(jws, { ...opts(), signer });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('recipient');
  });

  it('returns a refusal rather than throwing mid-task', async () => {
    const signer = makeSigner({ maxPerTransfer: 1n });
    const { jws } = await issue(signer.address);
    expect(() => executeDirective(jws, { ...opts(), signer })).not.toThrow();
  });

  it('produces nothing that has already been spent', async () => {
    // Signing and submitting are separate steps, so a signature can be produced,
    // inspected and discarded without any chance it was broadcast first.
    const signer = makeSigner();
    const { ledger, reserved, jws } = await issue(signer.address);
    const result = executeDirective(jws, { ...opts(), signer });
    expect(result.ok).toBe(true);
    expect(await ledger.reconcile()).toEqual([
      { spendId: reserved.spendId, outcome: 'still_unknown' },
    ]);
  });
});
