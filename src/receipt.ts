import { createHash, sign as cryptoSign, verify as cryptoVerify, createPublicKey } from 'node:crypto';

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
 * side's records can reconstruct the history independently — which is the only
 * reason a compromised ledger is a survivable event rather than a total one.
 */

export interface ReceiptClaims {
  v: string;
  typ: 'receipt';
  jti: string;
  spend: string;
  chain_hash: string;
  /** Mandate jtis, root first. Makes rollup by principal or subtree an indexed query. */
  path: string[];
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
