import { describe, expect, it, vi } from 'vitest';

import {
  NobleEip712Verifier,
  bytesToHex,
  hexToBytes,
  transferWithAuthorizationDigest,
} from '../src/chain/eip712.js';
import {
  LocalEip3009Signer,
  PolicyViolation,
  type SignerPolicy,
  signerFromEnv,
} from '../src/agent/signer.js';
import type { Eip3009Authorization, Eip712Domain } from '../src/rail/x402.js';
import { USDC_BASE } from './fixtures/x402.js';

const KEY = '0x4c0883a69102937d6231471b5dbb6204fe512961708279f2e3e8a5d4b8e3e3aa';
const NOW = 1770001240;
const MERCHANT = '0x65E3E64935eA709bDf1119E1fC991299c04c0154';

const DOMAIN: Eip712Domain = {
  name: 'USD Coin',
  version: '2',
  chainId: 8453,
  verifyingContract: USDC_BASE,
};

const policy = (over: Partial<SignerPolicy> = {}): SignerPolicy => ({
  maxPerTransfer: 100_000n, // 0.10 USDC
  allowedAssets: [USDC_BASE],
  allowedChainIds: [8453],
  ...over,
});

function makeSigner(over: Partial<SignerPolicy> = {}, opts = {}) {
  return new LocalEip3009Signer({
    privateKey: KEY,
    policy: policy(over),
    clock: () => NOW,
    ...opts,
  });
}

function auth(from: string, over: Partial<Eip3009Authorization> = {}): Eip3009Authorization {
  return {
    from,
    to: MERCHANT,
    value: '1000',
    validAfter: String(NOW - 60),
    validBefore: String(NOW + 300),
    nonce: `0x${'ab'.repeat(32)}`,
    ...over,
  };
}

describe('construction', () => {
  it('derives its own address from the key', () => {
    expect(makeSigner().address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it('refuses malformed or invalid keys', () => {
    for (const k of ['0xdead', `0x${'00'.repeat(32)}`, `0x${'ff'.repeat(32)}`]) {
      expect(() => new LocalEip3009Signer({ privateKey: k, policy: policy() })).toThrow();
    }
  });

  it('refuses to be constructed without limits', () => {
    // A signer with no policy is a hot wallet with extra steps, so there is no
    // default-open construction to fall into.
    expect(() =>
      new LocalEip3009Signer({ privateKey: KEY, policy: policy({ maxPerTransfer: 0n }) }),
    ).toThrow(/maxPerTransfer/);
    expect(() =>
      new LocalEip3009Signer({ privateKey: KEY, policy: policy({ allowedAssets: [] }) }),
    ).toThrow(/allowlist/);
    expect(() =>
      new LocalEip3009Signer({ privateKey: KEY, policy: policy({ allowedChainIds: [] }) }),
    ).toThrow(/allowlist/);
  });
});

describe('key material never escapes', () => {
  it('is redacted in JSON and inspect output', () => {
    const s = makeSigner();
    const serialized = JSON.stringify(s);
    expect(serialized).not.toContain(KEY.slice(2));
    expect(serialized).toContain('[redacted]');
    const key = Symbol.for('nodejs.util.inspect.custom');
    const custom = (s as unknown as Record<symbol, unknown>)[key] as (
      this: unknown,
    ) => string;
    expect(custom.call(s)).toBe(`LocalEip3009Signer<${s.address}>`);
    // And it must not blow up when called detached, which is how it tends to be
    // reached from inside an error path.
    expect(custom.call(undefined)).toContain('detached');
  });

  it('is not reachable as a property', () => {
    const s = makeSigner();
    expect(Object.keys(s)).not.toContain('key');
    expect(JSON.stringify(Object.getOwnPropertyNames(s))).not.toContain('key');
  });

  it('does not leak the key through a policy refusal', () => {
    const s = makeSigner();
    try {
      s.sign(DOMAIN, auth(s.address, { value: '999999999' }));
      throw new Error('should have refused');
    } catch (e) {
      expect(String((e as Error).message)).not.toContain(KEY.slice(2));
      expect(JSON.stringify(e)).not.toContain(KEY.slice(2));
    }
  });
});

describe('signing produces a recoverable, canonical signature', () => {
  it('round-trips through the production verifier', () => {
    const s = makeSigner();
    const a = auth(s.address);
    const signed = s.sign(DOMAIN, a);

    expect(new NobleEip712Verifier().recover(DOMAIN, a, signed.signature)).toBe(s.address);
    expect(signed.digest).toBe(bytesToHex(transferWithAuthorizationDigest(DOMAIN, a)));
    expect(hexToBytes(signed.signature)!.length).toBe(65);
  });

  it('computes the digest itself rather than accepting one', () => {
    // The interface takes structured fields, never a hash. A signer that accepts
    // a pre-computed digest can be handed the hash of a completely different
    // transaction and will authorize it.
    const s = makeSigner();
    const surface = Object.getOwnPropertyNames(Object.getPrototypeOf(s));
    expect(surface).toContain('sign');
    expect(surface.join(',')).not.toMatch(/digest|hash|raw/i);
  });

  it('reports cumulative spend against a total cap', () => {
    const s = makeSigner({ maxTotal: 5000n });
    expect(s.remaining).toBe(5000n);
    s.sign(DOMAIN, auth(s.address));
    expect(s.remaining).toBe(4000n);
  });
});

describe('policy enforcement', () => {
  const cases: Array<[string, Partial<Eip3009Authorization>, Partial<SignerPolicy>, RegExp]> = [
    ['over the per-transfer ceiling', { value: '100001' }, {}, /maxPerTransfer/],
    ['zero value', { value: '0' }, {}, /zero-value/],
    ['non-numeric value', { value: '1e3' }, {}, /not a uint/],
    ['already expired', { validBefore: String(NOW - 1) }, {}, /already expired/],
    ['not yet valid', { validAfter: String(NOW + 60) }, {}, /not yet valid/],
    ['malformed nonce', { nonce: '0xdead' }, {}, /bytes32/],
    [
      'destination outside the allowlist',
      {},
      { allowedRecipients: ['0x' + '99'.repeat(20)] },
      /recipient/,
    ],
    [
      'validity window longer than policy allows',
      { validAfter: String(NOW - 60), validBefore: String(NOW + 100_000) },
      { maxValidityWindowSeconds: 600 },
      /window/,
    ],
  ];

  for (const [label, authOver, policyOver, message] of cases) {
    it(`refuses: ${label}`, () => {
      const s = makeSigner(policyOver);
      expect(() => s.sign(DOMAIN, auth(s.address, authOver))).toThrow(message);
    });
  }

  it('refuses a chain or asset it was not configured for', () => {
    const s = makeSigner();
    expect(() => s.sign({ ...DOMAIN, chainId: 1 }, auth(s.address))).toThrow(/chain/);
    expect(() =>
      s.sign({ ...DOMAIN, verifyingContract: '0x' + '11'.repeat(20) }, auth(s.address)),
    ).toThrow(/asset/);
  });

  it('refuses to fund an account that is not its own', () => {
    const s = makeSigner();
    expect(() => s.sign(DOMAIN, auth('0x' + '22'.repeat(20)))).toThrow(/this signer is/);
  });

  it('refuses once the cumulative cap is reached', () => {
    const s = makeSigner({ maxTotal: 1500n });
    s.sign(DOMAIN, auth(s.address, { value: '1000' }));
    expect(() =>
      s.sign(DOMAIN, auth(s.address, { value: '1000', nonce: `0x${'cd'.repeat(32)}` })),
    ).toThrow(/maxTotal/);
  });

  it('surfaces refusals through the audit hook', () => {
    const onRefuse = vi.fn();
    const s = makeSigner({}, { onRefuse });
    expect(() => s.sign(DOMAIN, auth(s.address, { value: '999999' }))).toThrow();
    expect(onRefuse).toHaveBeenCalledWith('maxPerTransfer', expect.stringContaining('ceiling'));
  });

  it('calls the audit hook on success without exposing the key', () => {
    const onSign = vi.fn();
    const s = makeSigner({}, { onSign });
    s.sign(DOMAIN, auth(s.address));
    expect(onSign).toHaveBeenCalledOnce();
    expect(JSON.stringify(onSign.mock.calls[0])).not.toContain(KEY.slice(2));
  });
});

describe('nonce binding', () => {
  it('is idempotent for an identical re-request', () => {
    const s = makeSigner();
    const a = auth(s.address);
    expect(s.sign(DOMAIN, a).signature).toBe(s.sign(DOMAIN, a).signature);
  });

  it('refuses to re-use a nonce for a different transfer', () => {
    // The Ledger derives the nonce from the spend id. A Ledger that reissued one
    // with a new destination would otherwise get a second, unintended signature
    // the principal can no longer distinguish from the first.
    const s = makeSigner();
    const nonce = `0x${'11'.repeat(32)}`;
    s.sign(DOMAIN, auth(s.address, { nonce }));
    expect(() =>
      s.sign(DOMAIN, auth(s.address, { nonce, to: '0x' + '66'.repeat(20) })),
    ).toThrow(/already signed for a different transfer/);
    expect(() => s.sign(DOMAIN, auth(s.address, { nonce, value: '2000' }))).toThrow(/different/);
  });
});

describe('inspect', () => {
  it('reports what would happen without signing', () => {
    const s = makeSigner();
    const ok = s.inspect(DOMAIN, auth(s.address));
    expect(ok.ok).toBe(true);

    const bad = s.inspect(DOMAIN, auth(s.address, { value: '999999' }));
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.rule).toBe('maxPerTransfer');

    // Inspecting must not consume the nonce or the budget.
    expect(s.remaining).toBeNull();
    expect(s.sign(DOMAIN, auth(s.address)).signature).toBeTruthy();
  });
});

describe('signerFromEnv', () => {
  it('reads a key from the environment and refuses when absent', () => {
    process.env['TEST_SIGNER_KEY'] = KEY;
    try {
      expect(signerFromEnv('TEST_SIGNER_KEY', policy()).address).toBe(makeSigner().address);
    } finally {
      delete process.env['TEST_SIGNER_KEY'];
    }
    expect(() => signerFromEnv('TEST_SIGNER_KEY', policy())).toThrow(/not set/);
  });
});

describe('PolicyViolation', () => {
  it('carries a machine-readable rule', () => {
    const e = new PolicyViolation('maxPerTransfer', 'too big');
    expect(e.rule).toBe('maxPerTransfer');
    expect(e.name).toBe('PolicyViolation');
  });
});
