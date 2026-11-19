import type { AgentKey } from '../sign.js';
import { quoteHashForHttpChallenge } from '../quote.js';
import { canonicalizeUri } from '../uri.js';
import {
  ACCEPT_PAYMENT,
  PAYMENT,
  PAYMENT_RECEIPT,
  type Challenge,
  buildPayment,
  parseChallenge,
  parseReceiptHeader,
} from './headers.js';
import { type SignableRequest, getHeader, signRequest } from './signature.js';

/** Agent side of §14. */

export interface PaidResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export function challengeFrom(res: PaidResponse): Challenge | null {
  if (res.status !== 402) return null;
  return parseChallenge(getHeader(res.headers, ACCEPT_PAYMENT) ?? undefined);
}

/**
 * Computes the cryptographic quote binding digest for a §14 402 response
 * using the canonical request URI and exact `Accept-Payment` header bytes.
 */
export function challengeHashFrom(url: string, res: PaidResponse): string | null {
  if (res.status !== 402) return null;
  const raw = getHeader(res.headers, ACCEPT_PAYMENT);
  if (raw === null) return null;
  const canonicalUri = canonicalizeUri(url);
  if (canonicalUri === null) return null;
  return quoteHashForHttpChallenge(canonicalUri, raw);
}

export function receiptFrom(res: PaidResponse): { id: string; ledger: string } | null {
  return parseReceiptHeader(getHeader(res.headers, PAYMENT_RECEIPT) ?? undefined);
}

export interface AttachPaymentOptions {
  spendToken: string;
  key: AgentKey;
  created: number;
  components?: readonly string[];
  nonce?: string;
}

/**
 * Produces the headers for a paid retry.
 *
 * Order matters: the `Payment` header is added to the request *before* signing,
 * because it is one of the covered components. Signing first and appending the
 * payment afterwards produces a signature that verifies while covering nothing
 * about what is being paid for, which is a token any interceptor can lift onto
 * a different request.
 */
export function attachPayment(
  req: SignableRequest,
  opts: AttachPaymentOptions,
): Record<string, string> {
  const paymentHeader = buildPayment(opts.spendToken);
  const withPayment: SignableRequest = {
    ...req,
    headers: { ...req.headers, [PAYMENT]: paymentHeader },
  };

  const sigs = signRequest(withPayment, {
    key: opts.key,
    created: opts.created,
    ...(opts.components !== undefined ? { components: opts.components } : {}),
    ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
  });

  return { [PAYMENT]: paymentHeader, ...sigs };
}

export type Transport = (req: SignableRequest) => Promise<PaidResponse>;

export interface ChallengeBindingMeta {
  /** SHA-256 binding digest over canonical request URI and exact `Accept-Payment` bytes. */
  quoteHash?: string;
}

export interface PayAndRetryOptions {
  key: AgentKey;
  clock: () => number;
  /** Exchange a challenge for a spend token, normally a call to the ledger. */
  reserve: (
    challenge: Challenge,
    meta?: ChallengeBindingMeta,
  ) => Promise<{ ok: true; token: string } | { ok: false; detail: string }>;
}

export type PayAndRetryResult =
  | { ok: true; response: PaidResponse; paid: boolean; receipt?: { id: string; ledger: string } }
  | { ok: false; detail: string; response?: PaidResponse };

/**
 * Request -> 402 -> reserve -> signed retry. Exactly one retry: a second 402 after
 * paying means the price moved or the token was rejected, and looping on that is
 * how an agent spends a budget on nothing.
 */
export async function payAndRetry(
  req: SignableRequest,
  transport: Transport,
  opts: PayAndRetryOptions,
): Promise<PayAndRetryResult> {
  const first = await transport(req);
  if (first.status !== 402) {
    const r: PayAndRetryResult = { ok: true, response: first, paid: false };
    const receipt = receiptFrom(first);
    return receipt === null ? r : { ...r, receipt };
  }

  const challenge = challengeFrom(first);
  if (challenge === null) {
    return { ok: false, detail: 'unparseable payment challenge', response: first };
  }

  const quoteHash = challengeHashFrom(req.url, first);
  const reserved = await opts.reserve(
    challenge,
    quoteHash !== null ? { quoteHash } : {},
  );
  if (!reserved.ok) return { ok: false, detail: reserved.detail, response: first };

  const headers = attachPayment(req, {
    spendToken: reserved.token,
    key: opts.key,
    created: opts.clock(),
  });
  const second = await transport({ ...req, headers: { ...req.headers, ...headers } });

  if (second.status === 402) {
    return { ok: false, detail: 'still 402 after payment', response: second };
  }
  const result: PayAndRetryResult = { ok: true, response: second, paid: true };
  const receipt = receiptFrom(second);
  return receipt === null ? result : { ...result, receipt };
}
