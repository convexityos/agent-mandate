import { createHash, timingSafeEqual } from 'node:crypto';

import type { Settle } from './caveats.js';
import type { Money } from './money.js';
import { canonicalJson } from './receipt.js';
import { DEFAULT_SKEW_SECONDS } from './types.js';

/**
 * Cryptographic quote binding (spec §14, §18 #3).
 *
 * Without quote binding, `quote_id` is an opaque label that nothing verifies:
 * an agent can mint a spend token against a stale or expired quote after a
 * merchant reprices or changes terms, or a custodial rail can settle against a
 * live x402 challenge whose `payTo` or fields mutated since the agent asked.
 *
 * Binding hashes the exact challenge bytes together with the canonical resource
 * URI under a domain separator. The hash travels from the 402 response into the
 * reservation, spend token, directive, and signed receipt.
 */

const QUOTE_HASH_RE = /^sha256:[0-9a-f]{64}$/;

/** Domain-separated SHA-256 of a §14 HTTP `Accept-Payment` 402 challenge. */
export function quoteHashForHttpChallenge(
  canonicalUri: string,
  acceptPaymentHeader: string,
): string {
  const digest = createHash('sha256')
    .update('am/1:quote:http\0', 'utf8')
    .update(canonicalUri, 'utf8')
    .update('\0', 'utf8')
    .update(acceptPaymentHeader, 'utf8')
    .digest('hex');
  return `sha256:${digest}`;
}

/** Domain-separated SHA-256 of an x402 402 challenge payload (v2 header or v1 body). */
export function quoteHashForX402Challenge(
  canonicalUri: string,
  rawChallenge: string | Buffer,
): string {
  const hash = createHash('sha256')
    .update('am/1:quote:x402\0', 'utf8')
    .update(canonicalUri, 'utf8')
    .update('\0', 'utf8');
  if (typeof rawChallenge === 'string') {
    hash.update(rawChallenge, 'utf8');
  } else {
    hash.update(rawChallenge);
  }
  return `sha256:${hash.digest('hex')}`;
}

export interface X402ChallengeLikeResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

function headerLookup(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const needle = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === needle) {
      return Array.isArray(v) ? v[0] : v;
    }
  }
  return undefined;
}

/**
 * Extracts the exact challenge bytes to bind from an x402 402 response.
 *
 * In x402 v2, the challenge rides verbatim in the `PAYMENT-REQUIRED` header
 * (base64 JSON). In v1, it rides in the JSON body; when only a parsed object is
 * available we canonicalize it deterministically so both sides compute the same
 * digest.
 */
export function rawX402ChallengeBytes(res: X402ChallengeLikeResponse): string | null {
  if (res.status !== 402) return null;
  const header = headerLookup(res.headers, 'payment-required');
  if (header !== undefined && header.length > 0) return header;
  if (typeof res.body === 'string' && res.body.length > 0) return res.body;
  if (typeof res.body === 'object' && res.body !== null) {
    const rec = res.body as Record<string, unknown>;
    if (Array.isArray(rec['accepts']) && rec['accepts'].length > 0) {
      return canonicalJson(rec);
    }
  }
  return null;
}

/** Computes the quote hash directly from a live or captured x402 402 response. */
export function quoteHashFromX402Response(
  canonicalUri: string,
  res: X402ChallengeLikeResponse,
): string | null {
  const raw = rawX402ChallengeBytes(res);
  return raw === null ? null : quoteHashForX402Challenge(canonicalUri, raw);
}

export function isQuoteHash(value: unknown): value is string {
  return typeof value === 'string' && QUOTE_HASH_RE.test(value);
}

export function quotesMatch(expected: string, actual: string): boolean {
  if (!isQuoteHash(expected) || !isQuoteHash(actual)) return false;
  return timingSafeEqual(Buffer.from(expected, 'ascii'), Buffer.from(actual, 'ascii'));
}

// -------------------------------------------------------- merchant quote store

export interface IssuedQuote {
  quoteId: string;
  quoteHash: string;
  canonicalUri: string;
  amount: Money;
  settle: Settle[];
  schema?: string;
  exp: number;
  consumed?: boolean;
}

export interface QuoteStore {
  put(quote: IssuedQuote): void;
  get(quoteId: string): IssuedQuote | undefined;
  /** Marks a quote consumed once paid. Returns false if missing or already consumed. */
  consume(quoteId: string): boolean;
}

/**
 * In-memory store for merchant-issued 402 quotes.
 *
 * Prunes entries once past `exp + retentionSeconds` so expired quotes can still
 * be distinguished from unknown quotes within the retention window while
 * keeping memory bounded.
 */
export class MemoryQuoteStore implements QuoteStore {
  private readonly entries = new Map<string, IssuedQuote>();
  private readonly retentionSeconds: number;

  constructor(
    private readonly clock: () => number,
    options: { retentionSeconds?: number } = {},
  ) {
    this.retentionSeconds = options.retentionSeconds ?? DEFAULT_SKEW_SECONDS * 2;
  }

  put(quote: IssuedQuote): void {
    this.prune();
    this.entries.set(quote.quoteId, { ...quote, consumed: false });
  }

  get(quoteId: string): IssuedQuote | undefined {
    this.prune();
    const entry = this.entries.get(quoteId);
    return entry === undefined ? undefined : { ...entry };
  }

  consume(quoteId: string): boolean {
    this.prune();
    const entry = this.entries.get(quoteId);
    if (entry === undefined || entry.consumed === true) return false;
    entry.consumed = true;
    return true;
  }

  private prune(): void {
    const cutoff = this.clock() - this.retentionSeconds;
    for (const [id, q] of this.entries) {
      if (q.exp < cutoff) this.entries.delete(id);
    }
  }
}
