import { secp256k1 } from '@noble/curves/secp256k1';
import { describe, expect, it } from 'vitest';

import {
  EIP712_DOMAIN_TYPEHASH,
  NobleEip712Verifier,
  TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
  bytesToHex,
  domainSeparator,
  hexToBytes,
  keccak256,
  recoverAddress,
  toChecksumAddress,
  transferWithAuthorizationDigest,
  utf8,
  word,
} from '../src/chain/eip712.js';
import {
  AUTHORIZATION_STATE_SELECTOR,
  EthCallChainReader,
  type EthCallRequest,
  decodeBool,
  encodeAuthorizationState,
  jsonRpcTransport,
} from '../src/chain/ethcall.js';
import type { Eip3009Authorization, Eip712Domain } from '../src/rail/x402.js';
import { USDC_BASE } from './fixtures/x402.js';

/** Base USDC's real EIP-712 domain. */
const DOMAIN: Eip712Domain = {
  name: 'USD Coin',
  version: '2',
  chainId: 8453,
  verifyingContract: USDC_BASE,
};

const NONCE = '0x9c1f00000000000000000000000000000000000000000000000000000000e401';

function authFor(from: string): Eip3009Authorization {
  return {
    from,
    to: '0x65E3E64935eA709bDf1119E1fC991299c04c0154',
    value: '1000',
    validAfter: '1770001180',
    validBefore: '1770001540',
    nonce: NONCE,
  };
}

/** Deterministic test key. Never used for anything real. */
const PRIV = hexToBytes('0x4c0883a69102937d6231471b5dbb6204fe512961708279f2e3e8a5d4b8e3e3aa')!;

function addressOf(priv: Uint8Array): string {
  const pub = secp256k1.getPublicKey(priv, false).slice(1);
  return toChecksumAddress(bytesToHex(keccak256(pub).slice(12)));
}

function sign(digest: Uint8Array, priv = PRIV): string {
  const sig = secp256k1.sign(digest, priv);
  return `${bytesToHex(sig.toCompactRawBytes())}${(sig.recovery + 27).toString(16).padStart(2, '0')}`;
}

describe('keccak and the published typehashes', () => {
  // External vectors. If any of these drift, the digest is wrong and every
  // signature this module produces a verdict on is meaningless.
  it('matches the canonical keccak256 of the empty string', () => {
    expect(bytesToHex(keccak256(utf8('')))).toBe(
      '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    );
  });

  it('matches the published EIP712Domain typehash', () => {
    expect(bytesToHex(EIP712_DOMAIN_TYPEHASH)).toBe(
      '0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f',
    );
  });

  it('matches the published EIP-3009 TransferWithAuthorization typehash', () => {
    expect(bytesToHex(TRANSFER_WITH_AUTHORIZATION_TYPEHASH)).toBe(
      '0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267',
    );
  });

  it('derives the authorizationState selector rather than hard-coding it', () => {
    expect(bytesToHex(AUTHORIZATION_STATE_SELECTOR)).toBe('0xe94a0102');
  });
});

describe('EIP-55 checksums', () => {
  it('matches the addresses in the EIP itself', () => {
    for (const a of [
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
      '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
      '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
      '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
    ]) {
      expect(toChecksumAddress(a.toLowerCase())).toBe(a);
    }
  });
});

describe('ABI word packing', () => {
  it('left-pads numbers and right-aligns byte strings', () => {
    expect(bytesToHex(word(1n))).toBe(`0x${'00'.repeat(31)}01`);
    expect(bytesToHex(word(hexToBytes('0xdeadbeef')!))).toBe(`0x${'00'.repeat(28)}deadbeef`);
  });

  it('refuses values wider than a word', () => {
    expect(() => word(2n ** 256n)).toThrow();
    expect(() => word(new Uint8Array(33))).toThrow();
    expect(() => word(-1n)).toThrow();
  });
});

describe('digest construction', () => {
  it('is stable and sensitive to every field', () => {
    const base = transferWithAuthorizationDigest(DOMAIN, authFor(addressOf(PRIV)));
    expect(base.length).toBe(32);

    const variants: Array<[string, () => Uint8Array]> = [
      ['to', () => transferWithAuthorizationDigest(DOMAIN, { ...authFor(addressOf(PRIV)), to: '0x' + '11'.repeat(20) })],
      ['value', () => transferWithAuthorizationDigest(DOMAIN, { ...authFor(addressOf(PRIV)), value: '1001' })],
      ['nonce', () => transferWithAuthorizationDigest(DOMAIN, { ...authFor(addressOf(PRIV)), nonce: '0x' + '00'.repeat(32) })],
      ['validBefore', () => transferWithAuthorizationDigest(DOMAIN, { ...authFor(addressOf(PRIV)), validBefore: '1' })],
      // The domain name is the quiet one: "USDC" instead of "USD Coin" yields a
      // perfectly formed signature the token contract will not accept.
      ['domain name', () => transferWithAuthorizationDigest({ ...DOMAIN, name: 'USDC' }, authFor(addressOf(PRIV)))],
      ['chainId', () => transferWithAuthorizationDigest({ ...DOMAIN, chainId: 1 }, authFor(addressOf(PRIV)))],
    ];

    for (const [label, make] of variants) {
      expect(bytesToHex(make()), `${label} did not change the digest`).not.toBe(bytesToHex(base));
    }
  });

  it('separates domains', () => {
    expect(bytesToHex(domainSeparator(DOMAIN))).not.toBe(
      bytesToHex(domainSeparator({ ...DOMAIN, chainId: 1 })),
    );
  });

  it('rejects malformed authorization fields', () => {
    expect(() => transferWithAuthorizationDigest(DOMAIN, { ...authFor(addressOf(PRIV)), from: '0x00' })).toThrow();
    expect(() => transferWithAuthorizationDigest(DOMAIN, { ...authFor(addressOf(PRIV)), nonce: '0xdead' })).toThrow();
    expect(() => transferWithAuthorizationDigest(DOMAIN, { ...authFor(addressOf(PRIV)), value: 'lots' })).toThrow();
  });
});

describe('recoverAddress', () => {
  const signer = addressOf(PRIV);

  it('round-trips a real secp256k1 signature', () => {
    const digest = transferWithAuthorizationDigest(DOMAIN, authFor(signer));
    expect(recoverAddress(digest, sign(digest))).toBe(signer);
  });

  it('returns a different address for a tampered digest', () => {
    const auth = authFor(signer);
    const signature = sign(transferWithAuthorizationDigest(DOMAIN, auth));
    const other = transferWithAuthorizationDigest(DOMAIN, { ...auth, value: '999999' });
    expect(recoverAddress(other, signature)).not.toBe(signer);
  });

  it('rejects high-s signatures the token contract would also reject', () => {
    // OpenZeppelin's ECDSA — which USDC's EIP-3009 verifies through — refuses
    // s > n/2. Accepting one here means settling in our books against a transfer
    // that can never execute.
    const digest = transferWithAuthorizationDigest(DOMAIN, authFor(signer));
    const sig = secp256k1.sign(digest, PRIV);
    const n = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
    const highS = new secp256k1.Signature(sig.r, n - sig.s).addRecoveryBit(sig.recovery ^ 1);
    const malleable = `${bytesToHex(highS.toCompactRawBytes())}${(highS.recovery! + 27)
      .toString(16)
      .padStart(2, '0')}`;

    expect(recoverAddress(digest, malleable)).toBeNull();
    expect(recoverAddress(digest, sign(digest))).toBe(signer); // the canonical one still works
  });

  it('rejects structurally invalid signatures', () => {
    const digest = transferWithAuthorizationDigest(DOMAIN, authFor(signer));
    expect(recoverAddress(digest, '0x')).toBeNull();
    expect(recoverAddress(digest, `0x${'00'.repeat(65)}`)).toBeNull(); // r = s = 0
    expect(recoverAddress(digest, `0x${'11'.repeat(64)}05`)).toBeNull(); // bad recovery bit
    expect(recoverAddress(digest, `0x${'11'.repeat(63)}`)).toBeNull(); // short
  });

  it('accepts both 0/1 and 27/28 recovery encodings', () => {
    const digest = transferWithAuthorizationDigest(DOMAIN, authFor(signer));
    const full = sign(digest);
    const v = parseInt(full.slice(-2), 16);
    const raw = `${full.slice(0, -2)}${(v - 27).toString(16).padStart(2, '0')}`;
    expect(recoverAddress(digest, raw)).toBe(signer);
  });
});

describe('NobleEip712Verifier', () => {
  it('implements the rail seam end to end', () => {
    const v = new NobleEip712Verifier();
    const signer = addressOf(PRIV);
    const auth = authFor(signer);
    const signature = sign(transferWithAuthorizationDigest(DOMAIN, auth));
    expect(v.recover(DOMAIN, auth, signature)).toBe(signer);
  });

  it('returns null rather than throwing on a malformed directive', () => {
    const v = new NobleEip712Verifier();
    expect(v.recover(DOMAIN, { ...authFor(addressOf(PRIV)), from: 'nope' }, '0x00')).toBeNull();
  });
});

describe('eth_call encoding', () => {
  const FROM = '0x1111111111111111111111111111111111111111';

  it('encodes authorizationState(address,bytes32) correctly', () => {
    const data = encodeAuthorizationState(FROM, NONCE);
    expect(data.slice(0, 10)).toBe('0xe94a0102');
    expect(hexToBytes(data)!.length).toBe(68);
    expect(data.slice(10, 74)).toBe(`${'00'.repeat(12)}${FROM.slice(2)}`);
    expect(data.slice(74)).toBe(NONCE.slice(2));
  });

  it('rejects malformed arguments', () => {
    expect(() => encodeAuthorizationState('0xshort', NONCE)).toThrow();
    expect(() => encodeAuthorizationState(FROM, '0xdead')).toThrow();
  });

  it('decodes a bool', () => {
    expect(decodeBool(`0x${'00'.repeat(32)}`)).toBe(false);
    expect(decodeBool(`0x${'00'.repeat(31)}01`)).toBe(true);
  });

  it('throws rather than returning false on empty or malformed return data', () => {
    // `eth_call` against a non-contract returns "0x". Reading that as false
    // would let one misconfigured token address refund every payment ever made.
    expect(() => decodeBool('0x')).toThrow();
    expect(() => decodeBool(`0x${'00'.repeat(31)}02`)).toThrow();
    expect(() => decodeBool(`0x${'ff'.repeat(32)}`)).toThrow();
  });

  it('reads authorization state over a transport', async () => {
    const seen: EthCallRequest[] = [];
    const reader = new EthCallChainReader(async (req) => {
      seen.push(req);
      return `0x${'00'.repeat(31)}01`;
    });
    expect(await reader.authorizationState(USDC_BASE, FROM, NONCE)).toBe(true);
    expect(seen[0]?.to).toBe(USDC_BASE);
    expect(seen[0]?.block).toBe('latest');
  });
});

describe('jsonRpcTransport', () => {
  const req = { to: USDC_BASE, data: '0xe94a0102' };

  it('sends a well-formed eth_call and returns the result', async () => {
    let body: Record<string, unknown> = {};
    const transport = jsonRpcTransport({
      url: 'https://rpc.example',
      fetchImpl: (async (_u: string, init: RequestInit) => {
        body = JSON.parse(String(init.body)) as Record<string, unknown>;
        return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x01' }) };
      }) as unknown as typeof fetch,
    });

    expect(await transport(req)).toBe('0x01');
    expect(body['method']).toBe('eth_call');
    expect((body['params'] as unknown[])[1]).toBe('latest');
  });

  it('surfaces RPC errors instead of swallowing them into a false', async () => {
    const transport = jsonRpcTransport({
      url: 'https://rpc.example',
      fetchImpl: (async () => ({
        ok: true,
        json: async () => ({ error: { code: -32000, message: 'execution reverted' } }),
      })) as unknown as typeof fetch,
    });
    await expect(transport(req)).rejects.toThrow(/execution reverted/);
  });

  it('surfaces HTTP failures', async () => {
    const transport = jsonRpcTransport({
      url: 'https://rpc.example',
      fetchImpl: (async () => ({ ok: false, status: 503 })) as unknown as typeof fetch,
    });
    await expect(transport(req)).rejects.toThrow(/503/);
  });
});
