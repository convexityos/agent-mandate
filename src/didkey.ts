import { createHash } from 'node:crypto';

/**
 * did:key for Ed25519, plus RFC 7638 JWK thumbprints.
 *
 * Agents use did:key rather than did:web because chain verification at depth 4
 * must not require four network round-trips on the spend path. did:key is
 * self-certifying: the identifier *is* the public key.
 */

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP = new Map<string, number>([...B58_ALPHABET].map((c, i) => [c, i]));

/** multicodec `ed25519-pub` = 0xed 0x01 (varint) */
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);

export function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);

  let out = '';
  while (n > 0n) {
    const rem = Number(n % 58n);
    out = B58_ALPHABET[rem]! + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out === '' ? '1' : out;
}

export function base58Decode(s: string): Uint8Array | null {
  if (s.length === 0) return null;
  let n = 0n;
  for (const ch of s) {
    const v = B58_MAP.get(ch);
    if (v === undefined) return null;
    n = n * 58n + BigInt(v);
  }

  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of s) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

export function didKeyFromEd25519(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  const multi = new Uint8Array(ED25519_MULTICODEC.length + 32);
  multi.set(ED25519_MULTICODEC, 0);
  multi.set(publicKey, ED25519_MULTICODEC.length);
  return `did:key:z${base58Encode(multi)}`;
}

/** Accepts both `did:key:zX` and the fragment form `did:key:zX#zX`. */
export function ed25519FromDidKey(did: string): Uint8Array | null {
  if (typeof did !== 'string') return null;
  const bare = did.split('#')[0]!;
  if (!bare.startsWith('did:key:z')) return null;

  const decoded = base58Decode(bare.slice('did:key:z'.length));
  if (decoded === null || decoded.length !== 34) return null;
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) return null;

  // A fragment, when present, must name the same key the method-specific id encodes.
  const hash = did.indexOf('#');
  if (hash !== -1 && did.slice(hash + 1) !== bare.slice('did:key:'.length)) return null;

  return decoded.slice(2);
}

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export interface Ed25519Jwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

export function jwkFromDidKey(did: string): Ed25519Jwk | null {
  const raw = ed25519FromDidKey(did);
  if (raw === null) return null;
  return { kty: 'OKP', crv: 'Ed25519', x: base64url(raw) };
}

/**
 * RFC 7638 thumbprint. Members are the required ones only, serialized with
 * lexicographic keys and no whitespace — the canonicalization is the whole
 * point, so it is spelled out rather than delegated to JSON.stringify of a
 * literal whose key order happens to be right.
 */
export function jwkThumbprint(jwk: Ed25519Jwk): string {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

export function thumbprintOfDidKey(did: string): string | null {
  const jwk = jwkFromDidKey(did);
  return jwk === null ? null : jwkThumbprint(jwk);
}
