import {
  createHash,
  createHmac,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPublicKey,
  timingSafeEqual,
} from 'node:crypto';

import type { Money } from './money.js';
import type { AgentKey } from './sign.js';
import type { Ed25519Jwk } from './didkey.js';
import type { ReservationStatus } from './ledger/store.js';

/**
 * Spec §11 — receipts.
 *
 * Not an accounting afterthought. When no human approved the individual
 * transaction, the signed receipt trail is the only thing that makes the spend
 * legitimate after the fact, and it is what a finance or compliance function
 * actually asks for. Both parties sign the same canonical bytes so that either
 * side's records can reconstruct the history independently, which is the only
 * reason a compromised ledger is a survivable event rather than a total one.
 */

/**
 * How `path` and `principal` are represented in a receipt (§18 #5):
 *
 * - `plain` (default, omitted on the wire): cleartext mandate jtis. Easiest to
 *   audit; reveals delegation topology and naming to any external reader.
 * - `salted`: keyed HMAC-SHA256 per node (`hmac-sha256:<hex>`). Hides cleartext
 *   mandate ids and preserves O(1) indexed rollup by subtree for any holder of
 *   the salt or a pre-computed subtree tag. Tradeoff: deterministic tags allow
 *   an external observer with many receipts from one principal to cluster
 *   unlabeled co-occurrence graphs.
 * - `blinded`: keyed HMAC-SHA256 per `(spend, node)`. Hides both mandate ids
 *   and cross-receipt linkability across spends under the same subtree or
 *   principal. Tradeoff: rollup requires scanning with the salt (O(N)) rather
 *   than a static index, and `path.length` still reflects delegation depth.
 */
export type ReceiptPathMode = 'plain' | 'salted' | 'blinded';

export type ReceiptPathPrivacyConfig =
  | { mode: 'plain' }
  | { mode: 'salted' | 'blinded'; salt: string | Buffer };

/** Minimum secret salt length (128 bits) for `salted` and `blinded` path modes. */
export const MIN_RECEIPT_SALT_BYTES = 16;

const HMAC_TAG_RE = /^hmac-sha256:[0-9a-f]{64}$/;

export interface ReceiptClaims {
  v: string;
  typ: 'receipt';
  jti: string;
  spend: string;
  chain_hash: string;
  /** Mandate jtis or keyed digests, root first. Makes rollup by principal or subtree queryable. */
  path: string[];
  /** Present when `path` and `principal` are privacy-protected (`salted` or `blinded`). */
  path_mode?: ReceiptPathMode;
  agent: string;
  principal: string;
  task: string | null;
  merchant: string;
  res: string;
  amt: Money;
  resp_hash?: string;
  resp_bytes?: number;
  /** Rail that moved the money, and its own reference (e.g. an on-chain tx hash). */
  rail?: string;
  rail_ref?: string;
  /** Bound quote identity and challenge digest, when supplied at reserve time. */
  quote_id?: string;
  quote_hash?: string;
  status: ReservationStatus;
  ts: number;
}

export interface Receipt {
  claims: ReceiptClaims;
  sigs: { ledger: string; merchant?: string };
}

/** Validates that a receipt privacy salt carries at least 128 bits of key material. */
export function assertReceiptSalt(salt: string | Buffer): Buffer {
  const key = typeof salt === 'string' ? Buffer.from(salt, 'utf8') : salt;
  if (key.byteLength < MIN_RECEIPT_SALT_BYTES) {
    throw new Error(
      `receipt path privacy salt must be at least ${MIN_RECEIPT_SALT_BYTES} bytes, got ${key.byteLength}`,
    );
  }
  return key;
}

function hmacTag(key: Buffer, domain: string, parts: readonly string[]): string {
  const mac = createHmac('sha256', key);
  mac.update(domain, 'utf8');
  for (const part of parts) {
    mac.update('\0', 'utf8');
    mac.update(part, 'utf8');
  }
  return `hmac-sha256:${mac.digest('hex')}`;
}

function equalTag(expected: string, actual: string): boolean {
  if (!HMAC_TAG_RE.test(expected) || !HMAC_TAG_RE.test(actual)) return false;
  return timingSafeEqual(Buffer.from(expected, 'ascii'), Buffer.from(actual, 'ascii'));
}

/** Deterministic subtree rollup tag for `salted` mode. */
export function saltedPathTag(jti: string, salt: string | Buffer): string {
  return hmacTag(assertReceiptSalt(salt), 'am/1:receipt:path', [jti]);
}

/** Per-spend unlinkable node tag for `blinded` mode. */
export function blindedPathTag(spendId: string, jti: string, salt: string | Buffer): string {
  return hmacTag(assertReceiptSalt(salt), 'am/1:receipt:path-blind', [spendId, jti]);
}

/** Per-spend unlinkable principal tag for `blinded` mode. */
export function blindedPrincipalTag(spendId: string, root: string, salt: string | Buffer): string {
  return hmacTag(assertReceiptSalt(salt), 'am/1:receipt:principal-blind', [spendId, root]);
}

/** Encodes `path` and `principal` according to the configured privacy mode. */
export function encodeReceiptPath(
  path: readonly string[],
  root: string,
  spendId: string,
  privacy?: ReceiptPathPrivacyConfig,
): { path: string[]; principal: string; path_mode?: ReceiptPathMode } {
  if (privacy === undefined || privacy.mode === 'plain') {
    return { path: [...path], principal: root };
  }
  const key = assertReceiptSalt(privacy.salt);
  if (privacy.mode === 'salted') {
    return {
      path: path.map((jti) => hmacTag(key, 'am/1:receipt:path', [jti])),
      principal: hmacTag(key, 'am/1:receipt:path', [root]),
      path_mode: 'salted',
    };
  }
  return {
    path: path.map((jti) => hmacTag(key, 'am/1:receipt:path-blind', [spendId, jti])),
    principal: hmacTag(key, 'am/1:receipt:principal-blind', [spendId, root]),
    path_mode: 'blinded',
  };
}

/**
 * Verifies a disclosed cleartext delegation path against a receipt's claims
 * across `plain`, `salted`, and `blinded` modes.
 */
export function verifyReceiptPath(
  claims: ReceiptClaims,
  expectedPath: readonly string[],
  salt?: string | Buffer,
): boolean {
  if (expectedPath.length === 0 || claims.path.length !== expectedPath.length) return false;
  const mode = claims.path_mode ?? 'plain';
  const root = expectedPath[0]!;

  if (mode === 'plain') {
    return (
      claims.principal === root &&
      expectedPath.every((jti, i) => claims.path[i] === jti)
    );
  }
  if (salt === undefined) return false;

  const key = assertReceiptSalt(salt);
  if (mode === 'salted') {
    if (!equalTag(hmacTag(key, 'am/1:receipt:path', [root]), claims.principal)) return false;
    return expectedPath.every((jti, i) =>
      equalTag(hmacTag(key, 'am/1:receipt:path', [jti]), claims.path[i]!),
    );
  }
  if (mode === 'blinded') {
    if (
      !equalTag(hmacTag(key, 'am/1:receipt:principal-blind', [claims.spend, root]), claims.principal)
    ) {
      return false;
    }
    return expectedPath.every((jti, i) =>
      equalTag(hmacTag(key, 'am/1:receipt:path-blind', [claims.spend, jti]), claims.path[i]!),
    );
  }
  return false;
}

/**
 * Answers whether a receipt rolls up under mandate node `jti`, across `plain`,
 * `salted`, and `blinded` receipts.
 */
export function receiptMatchesNode(
  claims: ReceiptClaims,
  jti: string,
  salt?: string | Buffer,
): boolean {
  const mode = claims.path_mode ?? 'plain';
  if (mode === 'plain') return claims.path.includes(jti);
  if (salt === undefined) return false;
  const key = assertReceiptSalt(salt);
  const expected =
    mode === 'salted'
      ? hmacTag(key, 'am/1:receipt:path', [jti])
      : hmacTag(key, 'am/1:receipt:path-blind', [claims.spend, jti]);
  return claims.path.some((entry) => equalTag(expected, entry));
}

/** Filters receipts belonging to mandate subtree `jti` across any receipt path mode. */
export function rollupReceiptsByNode(
  receipts: readonly Receipt[],
  jti: string,
  salt?: string | Buffer,
): Receipt[] {
  return receipts.filter((r) => receiptMatchesNode(r.claims, jti, salt));
}

/**
 * Deterministic serialization for detached signatures. Both parties must sign
 * identical bytes; `JSON.stringify` on a literal only happens to produce stable
 * output while nobody reorders the fields.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

export function receiptSigningInput(claims: ReceiptClaims): Buffer {
  return Buffer.from(canonicalJson(claims), 'utf8');
}

export function signReceipt(claims: ReceiptClaims, key: AgentKey): string {
  return cryptoSign(null, receiptSigningInput(claims), key.privateKey).toString('base64url');
}

export function verifyReceiptSignature(
  claims: ReceiptClaims,
  signature: string,
  jwk: Ed25519Jwk,
): boolean {
  try {
    const key = createPublicKey({ key: jwk as never, format: 'jwk' });
    return cryptoVerify(
      null,
      receiptSigningInput(claims),
      key,
      Buffer.from(signature, 'base64url'),
    );
  } catch {
    return false;
  }
}

export function sha256Hex(data: string | Buffer): string {
  return `sha256:${createHash('sha256').update(data).digest('hex')}`;
}
