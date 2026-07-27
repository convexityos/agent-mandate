import { type JsonWebKey, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { Ed25519Jwk } from './didkey.js';

/**
 * Minimal JWS Compact Serialization verification, Ed25519 only.
 *
 * `alg` is checked against a static allowlist and is never used to *select* a
 * key or an algorithm implementation — that indirection is the root of every
 * algorithm-confusion CVE in the JWT family. The key comes from the resolver;
 * `alg` only has to agree with it.
 */

const ALLOWED_ALGS = new Set(['EdDSA']);
export const MANDATE_TYP = 'application/agent-mandate+jwt';

export interface JwsHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

export interface ParsedJws {
  header: JwsHeader;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

const COMPACT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function decodeJsonSegment(seg: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function parseCompactJws(token: string): ParsedJws | null {
  if (typeof token !== 'string' || !COMPACT_RE.test(token)) return null;

  const [h, p, s] = token.split('.') as [string, string, string];
  const header = decodeJsonSegment(h);
  const payload = decodeJsonSegment(p);
  if (header === null || payload === null) return null;

  const alg = header['alg'];
  if (typeof alg !== 'string' || !ALLOWED_ALGS.has(alg)) return null;

  const typ = header['typ'];
  if (typ !== undefined && typeof typ !== 'string') return null;
  const kid = header['kid'];
  if (kid !== undefined && typeof kid !== 'string') return null;

  return {
    header: { alg, ...(typ !== undefined ? { typ } : {}), ...(kid !== undefined ? { kid } : {}) },
    payload,
    signingInput: `${h}.${p}`,
    signature: Buffer.from(s, 'base64url'),
  };
}

export function verifyJwsSignature(jws: ParsedJws, jwk: Ed25519Jwk): boolean {
  if (jws.signature.length !== 64) return false;
  try {
    const key = createPublicKey({ key: jwk as unknown as JsonWebKey, format: 'jwk' });
    return cryptoVerify(null, Buffer.from(jws.signingInput, 'ascii'), key, jws.signature);
  } catch {
    return false;
  }
}

/** Convenience for tests and issuers; signing lives in `sign.ts`. */
export function encodeSegment(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}
