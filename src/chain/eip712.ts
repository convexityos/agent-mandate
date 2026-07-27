import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

import type { Eip3009Authorization, Eip712Domain } from '../rail/x402.js';
import type { Eip712Verifier } from '../rail/x402-noncustodial.js';

/**
 * EIP-712 / EIP-3009 signature recovery for the non-custodial rail (§12.4.6).
 *
 * The elliptic-curve work is delegated to `@noble/curves`, and keccak to
 * `@noble/hashes`. Both are audited. Hand-rolling secp256k1 recovery is the
 * single worst place in this codebase to write original code — malleability,
 * point-at-infinity, and recovery-bit edge cases are all silent-wrong failures,
 * and "our signature checker has a subtle bug" is indistinguishable from "anyone
 * can spend your budget".
 *
 * Everything else here — struct hashing, ABI word packing, EIP-55 — is
 * deterministic encoding with no secrets in it, so it is implemented directly.
 * All EIP-3009 fields are static 32-byte words, which is why there is no general
 * ABI encoder in this file.
 *
 * Verification only. No private key ever reaches this module.
 */

const EIP712_DOMAIN_TYPE =
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)';

const TRANSFER_WITH_AUTHORIZATION_TYPE =
  'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)';

/** secp256k1 group order, for the low-s malleability check. */
const SECP256K1_N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);
const SECP256K1_HALF_N = SECP256K1_N / 2n;

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function hexToBytes(hex: string): Uint8Array | null {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return `0x${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Left-pad a value to one 32-byte ABI word. */
export function word(value: bigint | Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  if (value instanceof Uint8Array) {
    if (value.length > 32) throw new Error('value wider than one word');
    out.set(value, 32 - value.length);
    return out;
  }
  if (value < 0n) throw new Error('negative values are not ABI-encodable here');
  let v = value;
  for (let i = 31; i >= 0 && v > 0n; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v > 0n) throw new Error('value wider than one word');
  return out;
}

function addressWord(addr: string): Uint8Array {
  const b = hexToBytes(addr);
  if (b === null || b.length !== 20) throw new Error(`not an address: ${addr}`);
  return word(b);
}

function bytes32(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b === null || b.length !== 32) throw new Error(`not a bytes32: ${hex}`);
  return b;
}

function uintWord(decimal: string): Uint8Array {
  if (!/^\d+$/.test(decimal)) throw new Error(`not a uint: ${decimal}`);
  return word(BigInt(decimal));
}

export const EIP712_DOMAIN_TYPEHASH = keccak256(utf8(EIP712_DOMAIN_TYPE));
export const TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
  utf8(TRANSFER_WITH_AUTHORIZATION_TYPE),
);

export function domainSeparator(d: Eip712Domain): Uint8Array {
  return keccak256(
    concat(
      EIP712_DOMAIN_TYPEHASH,
      keccak256(utf8(d.name)),
      keccak256(utf8(d.version)),
      word(BigInt(d.chainId)),
      addressWord(d.verifyingContract),
    ),
  );
}

export function transferWithAuthorizationStructHash(a: Eip3009Authorization): Uint8Array {
  return keccak256(
    concat(
      TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
      addressWord(a.from),
      addressWord(a.to),
      uintWord(a.value),
      uintWord(a.validAfter),
      uintWord(a.validBefore),
      bytes32(a.nonce),
    ),
  );
}

/** EIP-712 §"signature": keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash). */
export function transferWithAuthorizationDigest(
  domain: Eip712Domain,
  authorization: Eip3009Authorization,
): Uint8Array {
  return keccak256(
    concat(
      Uint8Array.from([0x19, 0x01]),
      domainSeparator(domain),
      transferWithAuthorizationStructHash(authorization),
    ),
  );
}

/** EIP-55 mixed-case checksum. */
export function toChecksumAddress(addr: string): string {
  const lower = (addr.startsWith('0x') ? addr.slice(2) : addr).toLowerCase();
  const hash = bytesToHex(keccak256(utf8(lower))).slice(2);
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i]!;
  }
  return out;
}

/**
 * Recover the signing address from a 65-byte `r ‖ s ‖ v` signature.
 *
 * Rejects high-s signatures. USDC's EIP-3009 implementation verifies through
 * OpenZeppelin's ECDSA library, which rejects `s > n/2` — so accepting one here
 * would mean the Ledger considers an authorization valid that the token contract
 * will refuse, and the reservation settles in our books against a transfer that
 * can never execute.
 */
export function recoverAddress(digest: Uint8Array, signature: string): string | null {
  const sig = hexToBytes(signature);
  if (sig === null || sig.length !== 65) return null;

  const r = BigInt(bytesToHex(sig.slice(0, 32)));
  const s = BigInt(bytesToHex(sig.slice(32, 64)));
  if (r === 0n || s === 0n || r >= SECP256K1_N || s >= SECP256K1_N) return null;
  if (s > SECP256K1_HALF_N) return null;

  const vRaw = sig[64]!;
  const recovery = vRaw >= 27 ? vRaw - 27 : vRaw;
  if (recovery !== 0 && recovery !== 1) return null;

  try {
    const point = new secp256k1.Signature(r, s)
      .addRecoveryBit(recovery)
      .recoverPublicKey(digest);
    // Address = last 20 bytes of keccak(uncompressed pubkey without the 0x04 tag).
    const uncompressed = point.toRawBytes(false).slice(1);
    return toChecksumAddress(bytesToHex(keccak256(uncompressed).slice(12)));
  } catch {
    return null;
  }
}

/** Production `Eip712Verifier` for the non-custodial x402 rail. */
export class NobleEip712Verifier implements Eip712Verifier {
  recover(
    domain: Eip712Domain,
    authorization: Eip3009Authorization,
    signature: string,
  ): string | null {
    let digest: Uint8Array;
    try {
      digest = transferWithAuthorizationDigest(domain, authorization);
    } catch {
      // A malformed directive cannot produce a digest; treat as unrecoverable
      // rather than throwing into the report path.
      return null;
    }
    return recoverAddress(digest, signature);
  }
}
