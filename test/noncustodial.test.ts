import { beforeEach, describe, expect, it } from 'vitest';

import { secp256k1 } from '@noble/curves/secp256k1';
import {
  NobleEip712Verifier,
  bytesToHex,
  hexToBytes,
  keccak256,
  toChecksumAddress,
  transferWithAuthorizationDigest,
} from '../src/chain/eip712.js';
import { EthCallChainReader } from '../src/chain/ethcall.js';
import { narrows } from '../src/caveats.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import type { Directive } from '../src/rail/noncustodial.js';
import { intentHash } from '../src/rail/noncustodial.js';
import {
  type ChainReader,
  type Eip712Verifier,
  X402NonCustodialRail,
  type X402Intent,
} from '../src/rail/x402-noncustodial.js';
import {
  type ConfirmationSource,
  DelegatedTransferRail,
  type InstructionAuthenticator,
  type TransferConfirmation,
} from '../src/rail/delegated-transfer.js';
import { nonceFor } from '../src/rail/x402.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';
import { BASE_CAIP2, FUNDING_SPREADS, LIVE, USDC_BASE, captureFor, urlFor } from './fixtures/x402.js';

const PAYER = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';
const RESOURCE = urlFor(FUNDING_SPREADS);

let principal: AgentKey;
let agent: AgentKey;
let ledgerKey: AgentKey;
let clock: number;
let ids: number;

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
  ids = 0;
});

/** Recovers whoever the fake signature names. Real wiring uses viem/ethers. */
class FakeVerifier implements Eip712Verifier {
  recover(_d: unknown, auth: { nonce: string }, signature: string): string | null {
    const m = /^signed-by:(0x[0-9a-fA-F]{40}):(.+)$/.exec(signature);
    if (m === null) return null;
    // A signature is only over the tuple it was made for.
    return m[2] === auth.nonce ? m[1]! : null;
  }
}

const sigBy = (addr: string, nonce: string) => ({ signature: `signed-by:${addr}:${nonce}` });

class FakeChain implements ChainReader {
  private readonly used = new Set<string>();
  calls = 0;
  fail = false;
  consume(from: string, nonce: string) {
    this.used.add(`${from.toLowerCase()}:${nonce}`);
  }
  async authorizationState(_t: string, from: string, nonce: string): Promise<boolean> {
    this.calls++;
    if (this.fail) throw new Error('RPC unavailable');
    return this.used.has(`${from.toLowerCase()}:${nonce}`);
  }
}

function x402Rail(chain = new FakeChain(), payer = PAYER) {
  return {
    chain,
    rail: new X402NonCustodialRail({
      payer,
      verifier: new FakeVerifier(),
      chain,
      network: BASE_CAIP2,
      asset: USDC_BASE,
      clock: () => clock,
    }),
  };
}

function makeLedger(nonCustodialRail: ConstructorParameters<typeof Ledger>[0]['nonCustodialRail']) {
  return new Ledger({
    url: 'https://ledger.optera.one',
    key: ledgerKey,
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    idFactory: (p) => `${p}_${String(++ids).padStart(6, '0')}`,
    breakers: { novelMerchant: 'off' },
    nonCustodialRail,
  });
}

function chainTokens(over: Record<string, unknown> = {}) {
  return buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: usd('1.00'),
        max_per_txn: usd('0.50'),
        aud: [LIVE.host],
        ...over,
      },
    },
  ]);
}

const request = { resource: RESOURCE, amount: usd('0.001') };
const quote = () => ({ rail: captureFor(FUNDING_SPREADS).decoded });

describe('the payer caveat', () => {
  it('narrows like any other discrete caveat', () => {
    expect(narrows({ payer: PAYER }, {}).ok).toBe(true);
    expect(narrows({ payer: PAYER }, { payer: PAYER }).ok).toBe(true);
    expect(narrows({ payer: OTHER }, { payer: PAYER }).ok).toBe(false);
  });

  it('binds a mandate to one funding account', async () => {
    const { rail } = x402Rail();
    const ledger = makeLedger(rail);

    const wrong = await ledger.reserve({
      tokens: chainTokens({ payer: OTHER }),
      request,
      quote: quote(),
    });
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.code).toBe('attenuation_violation');

    const right = await ledger.reserve({
      tokens: chainTokens({ payer: PAYER }),
      request,
      quote: quote(),
    });
    expect(right.ok).toBe(true);
  });
});

describe('directive issuance', () => {
  it('pins every field of the transfer', async () => {
    const { rail } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    expect(r.ok).toBe(true);
    if (!r.ok) return;

    const d = r.directive!;
    const intent = d.intent as X402Intent;

    expect(d.typ).toBe('directive');
    expect(d.rail).toBe('x402-noncustodial');
    expect(d.payer).toBe(PAYER);
    // Destination, amount, validity and domain all fixed by the ledger.
    expect(intent.authorization.to).toBe('0x65E3E64935eA709bDf1119E1fC991299c04c0154');
    expect(intent.authorization.value).toBe('1000');
    expect(intent.authorization.from).toBe(PAYER);
    expect(intent.domain).toEqual({
      name: 'USD Coin',
      version: '2',
      chainId: 8453,
      verifyingContract: USDC_BASE,
    });
    // The LEDGER chose the nonce. That is what makes confirmation possible.
    expect(intent.authorization.nonce).toBe(nonceFor(r.spendId));
    expect(d.intentHash).toBe(intentHash(intent));
    expect(r.directiveJws).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it('still mints a spend token — the two artifacts are orthogonal', async () => {
    const { rail } = x402Rail();
    const r = await makeLedger(rail).reserve({ tokens: chainTokens(), request, quote: quote() });
    expect(r.ok && r.token).toBeTruthy();
  });

  it('rejects a quote whose price does not match the reservation', async () => {
    const { rail } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({
      tokens: chainTokens(),
      request: { ...request, amount: usd('0.002') },
      quote: quote(),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toContain('price moved');
  });

  it('refuses to be both custodial and not', () => {
    expect(
      () =>
        new Ledger({
          url: 'x',
          key: ledgerKey,
          store: new MemoryLedgerStore(() => clock),
          isTrustedRootIssuer: () => true,
          rail: { name: 'n', pay: async () => ({ ok: true, ref: 'r' }), status: async () => ({ state: 'not_paid' }) },
          nonCustodialRail: x402Rail().rail,
        }),
    ).toThrow(/not both/);
  });
});

describe('report verification (§12.4.6)', () => {
  it('accepts a proof that matches the directive, and still does not settle', async () => {
    const { rail } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    if (!r.ok) throw new Error('reserve failed');

    const nonce = (r.directive!.intent as X402Intent).authorization.nonce;
    const rep = await ledger.report(r.spendId, sigBy(PAYER, nonce));

    // A report is never proof of payment.
    expect(rep.ok).toBe(false);
    if (!rep.ok) expect(rep.detail).toContain('awaiting oracle');
    const stored = await ledger.reservation(r.spendId);
    expect(stored?.status).toBe('settling');
    expect(stored?.reported?.ok).toBe(true);
  });

  it('refunds immediately when the proof was signed by someone else', async () => {
    const { rail } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    if (!r.ok) throw new Error('reserve failed');

    const nonce = (r.directive!.intent as X402Intent).authorization.nonce;
    const rep = await ledger.report(r.spendId, sigBy(OTHER, nonce));
    expect(rep.ok && rep.status).toBe('refunded');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('1');
    expect((await ledger.reservation(r.spendId))?.reported?.ok).toBe(false);
  });

  it('refunds when the signature is over a different authorization', async () => {
    const { rail } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    if (!r.ok) throw new Error('reserve failed');

    // Right signer, wrong tuple — this is the redirect attack.
    const rep = await ledger.report(r.spendId, sigBy(PAYER, nonceFor('spn_999999')));
    expect(rep.ok && rep.status).toBe('refunded');
  });
});

describe('confirmation against a trustless oracle', () => {
  it('settles only once the authorization is actually consumed', async () => {
    const { rail, chain } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    if (!r.ok) throw new Error('reserve failed');
    const nonce = (r.directive!.intent as X402Intent).authorization.nonce;
    await ledger.report(r.spendId, sigBy(PAYER, nonce));

    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'still_unknown' }]);

    chain.consume(PAYER, nonce);
    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'settled' }]);
    expect((await ledger.reservation(r.spendId))?.railRef).toMatch(/^eip3009:/);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
  });

  it('settles a directive the agent executed but never reported', async () => {
    // Silence is not evidence of inaction. This is why sweepExpired refuses to
    // touch anything carrying a directive.
    const { rail, chain } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    if (!r.ok) throw new Error('reserve failed');

    chain.consume(PAYER, (r.directive!.intent as X402Intent).authorization.nonce);
    clock += 10_000;

    expect(await ledger.sweepExpired()).toEqual([]);
    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'settled' }]);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
  });

  it('refunds once the authorization is permanently unusable', async () => {
    const { rail } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    if (!r.ok) throw new Error('reserve failed');

    // Still live: unconfirmed does not mean unpaid.
    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'still_unknown' }]);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');

    clock = r.directive!.decidableAt + 1;
    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'refunded' }]);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('1');
  });

  it('escalates rather than guessing when the oracle itself is unreachable', async () => {
    const { rail, chain } = x402Rail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chainTokens(), request, quote: quote() });
    if (!r.ok) throw new Error('reserve failed');

    chain.fail = true;
    clock = r.directive!.decidableAt + 1;
    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'escalated' }]);
    expect((await ledger.reservation(r.spendId))?.escalated?.reason).toContain('undecided');
    // Budget stays debited — the conservative side.
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
  });
});

describe('a rail with neither guarantee', () => {
  class Source implements ConfirmationSource {
    result: TransferConfirmation = { state: 'not_settled' };
    async lookup(): Promise<TransferConfirmation> {
      return this.result;
    }
  }
  const auth: InstructionAuthenticator = {
    verify: (d: Directive, p: unknown) =>
      (p as { instruction?: string })?.instruction === d.intentHash
        ? { ok: true }
        : { ok: false, detail: 'instruction does not match the directive' },
  };

  function setup() {
    const source = new Source();
    const rail = new DelegatedTransferRail({
      payer: 'acct_9912',
      currency: 'USD',
      decimals: 2,
      source,
      authenticator: auth,
      clock: () => clock,
      latestSettlementSeconds: 86400 * 3,
    });
    return { source, rail, ledger: makeLedger(rail) };
  }

  const cardQuote = { rail: { payee: 'acct_merchant', currency: 'USD' } };
  const cardReq = { resource: RESOURCE, amount: usd('0.50') };

  it('declares its weaker capabilities honestly', () => {
    const { rail } = setup();
    expect(rail.capabilities).toEqual({
      trustlessOracle: false,
      hardExpiry: false,
      decimals: 2,
      reversible: true,
    });
  });

  it('separates the expiry deadline from the decidability deadline', async () => {
    const { ledger } = setup();
    const r = await ledger.reserve({ tokens: chainTokens(), request: cardReq, quote: cardQuote });
    if (!r.ok) throw new Error('reserve failed');
    // Three days of possible late settlement after the instruction expires.
    expect(r.directive!.decidableAt - r.directive!.expiresAt).toBe(86400 * 3);
  });

  it('ESCALATES instead of refunding, because a late settlement is still possible', async () => {
    const { ledger } = setup();
    const r = await ledger.reserve({ tokens: chainTokens(), request: cardReq, quote: cardQuote });
    if (!r.ok) throw new Error('reserve failed');
    await ledger.report(r.spendId, { instruction: r.directive!.intentHash });

    clock = r.directive!.decidableAt + 1;
    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'escalated' }]);

    // Crucially NOT refunded — this rail cannot promise the money stayed put.
    expect((await ledger.reservation(r.spendId))?.status).toBe('settling');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.5');
    expect((await ledger.reservation(r.spendId))?.escalated?.reason).toContain('later');
  });

  it('settles normally when the institution confirms', async () => {
    const { ledger, source } = setup();
    const r = await ledger.reserve({ tokens: chainTokens(), request: cardReq, quote: cardQuote });
    if (!r.ok) throw new Error('reserve failed');
    await ledger.report(r.spendId, { instruction: r.directive!.intentHash });

    source.result = { state: 'settled', ref: 'txn_abc' };
    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'settled' }]);
    expect((await ledger.reservation(r.spendId))?.railRef).toBe('txn_abc');
  });

  it('rejects an instruction that does not match its directive', async () => {
    const { ledger } = setup();
    const r = await ledger.reserve({ tokens: chainTokens(), request: cardReq, quote: cardQuote });
    if (!r.ok) throw new Error('reserve failed');
    const rep = await ledger.report(r.spendId, { instruction: 'sha256:something-else' });
    expect(rep.ok && rep.status).toBe('refunded');
  });

  it('refuses a currency the payer account cannot pay in', async () => {
    const { ledger } = setup();
    const r = await ledger.reserve({
      tokens: chainTokens({ max_per_txn: usd('5.00'), currency: 'USD' }),
      request: { ...cardReq, amount: { cur: 'USD', amt: '0.005' } },
      quote: cardQuote,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toContain('precision');
  });
});

describe('with the real verifier and chain reader', () => {
  it('drives the whole non-custodial flow on genuine secp256k1', async () => {
    const priv = hexToBytes('0x4c0883a69102937d6231471b5dbb6204fe512961708279f2e3e8a5d4b8e3e3aa')!;
    const pub = secp256k1.getPublicKey(priv, false).slice(1);
    const payer = toChecksumAddress(bytesToHex(keccak256(pub).slice(12)));

    // eth_call is served from an in-memory contract state; no network, no chain.
    const consumed = new Set<string>();
    const reader = new EthCallChainReader(async ({ data }) => {
      const from = `0x${data.slice(34, 74)}`;
      const nonce = `0x${data.slice(74)}`;
      return `0x${'00'.repeat(31)}${consumed.has(`${from}:${nonce}`) ? '01' : '00'}`;
    });

    const rail = new X402NonCustodialRail({
      payer,
      verifier: new NobleEip712Verifier(),
      chain: reader,
      network: BASE_CAIP2,
      asset: USDC_BASE,
      clock: () => clock,
    });
    const ledger = makeLedger(rail);

    const r = await ledger.reserve({
      tokens: chainTokens({ payer }),
      request,
      quote: quote(),
    });
    if (!r.ok) throw new Error(`reserve failed: ${r.detail}`);

    const intent = r.directive!.intent as X402Intent;
    const digest = transferWithAuthorizationDigest(intent.domain, intent.authorization);

    // A signature from the wrong key is refunded on the spot.
    const wrongKey = hexToBytes('0x' + '11'.repeat(32))!;
    const bad = secp256k1.sign(digest, wrongKey);
    const badSig = `${bytesToHex(bad.toCompactRawBytes())}${(bad.recovery + 27).toString(16).padStart(2, '0')}`;
    const rejected = await ledger.report(r.spendId, { signature: badSig });
    expect(rejected.ok && rejected.status).toBe('refunded');

    // Same flow, correct key, on a fresh reservation.
    const r2 = await ledger.reserve({ tokens: chainTokens({ payer }), request, quote: quote() });
    if (!r2.ok) throw new Error('reserve failed');
    const i2 = r2.directive!.intent as X402Intent;
    const d2 = transferWithAuthorizationDigest(i2.domain, i2.authorization);
    const good = secp256k1.sign(d2, priv);
    const goodSig = `${bytesToHex(good.toCompactRawBytes())}${(good.recovery + 27).toString(16).padStart(2, '0')}`;

    expect((await ledger.report(r2.spendId, { signature: goodSig })).ok).toBe(false);
    expect((await ledger.reservation(r2.spendId))?.reported?.ok).toBe(true);

    // Unexecuted: the oracle says nothing happened yet.
    expect(await ledger.reconcile()).toEqual([{ spendId: r2.spendId, outcome: 'still_unknown' }]);

    // The agent submits; the contract records the nonce as used.
    consumed.add(`${i2.authorization.from.toLowerCase()}:${i2.authorization.nonce}`);
    expect(await ledger.reconcile()).toEqual([{ spendId: r2.spendId, outcome: 'settled' }]);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
  });
});
