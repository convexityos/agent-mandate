import { randomUUID } from 'node:crypto';

import type { Settle } from '../caveats.js';
import type { Ed25519Jwk } from '../didkey.js';
import type { ErrorCode } from '../errors.js';
import type { Money } from '../money.js';
import { type ReplayCache, type SpendClaims, verifySpendToken } from '../spend.js';
import { canonicalizeUri } from '../uri.js';
import {
  ACCEPT_PAYMENT,
  PAYMENT,
  PAYMENT_RECEIPT,
  SCHEME,
  buildChallenge,
  buildPayment,
  buildReceiptHeader,
  parsePayment,
} from './headers.js';
import { PROBLEM_CONTENT_TYPE, type ProblemDetails, problem } from './problem.js';
import {
  DEFAULT_COMPONENTS,
  type SignableRequest,
  getHeader,
  verifyRequestSignature,
} from './signature.js';

/**
 * Spec §14 merchant side.
 *
 * Framework-agnostic on purpose: it takes a request shape and returns a
 * decision, so the same logic drops into Express, Hono, a Cloudflare Worker, or
 * an MCP server's tool dispatch without any of them being able to skip a step.
 */

export interface Quote {
  amount: Money;
  settle?: Settle[];
  /** Hash of the response schema, for `escrow_schema`. */
  schema?: string;
}

export interface MerchantConfig {
  host: string;
  ledgerUrl: string;
  ledgerJwk: Ed25519Jwk;
  replay: ReplayCache;
  /** Return null for resources that are free. */
  price: (req: SignableRequest, canonicalUri: string) => Quote | null;
  clock: () => number;
  quoteTtlSeconds?: number;
  quoteIdFactory?: () => string;
  requiredComponents?: readonly string[];
  signatureMaxAgeSeconds?: number;
}

export type MerchantDecision =
  | { kind: 'free'; canonicalUri: string }
  | { kind: 'allow'; claims: SpendClaims; canonicalUri: string; presenterJkt: string }
  | {
      kind: 'challenge';
      status: 402;
      headers: Record<string, string>;
      body: ProblemDetails;
      quoteId: string;
      quote: Quote;
    }
  | { kind: 'reject'; status: number; headers: Record<string, string>; body: ProblemDetails };

export class Merchant {
  constructor(private readonly cfg: MerchantConfig) {}

  handle(req: SignableRequest): MerchantDecision {
    const now = this.cfg.clock();

    const canonicalUri = canonicalizeUri(req.url);
    if (canonicalUri === null) {
      return this.reject('resource_not_covered', 'request URI could not be canonicalized');
    }

    const quote = this.cfg.price(req, canonicalUri);
    if (quote === null) return { kind: 'free', canonicalUri };

    const payment = parsePayment(this.header(req, PAYMENT));
    if (payment === null) return this.challenge(quote, now);

    // The signature is verified BEFORE the spend token, so an unsigned request
    // can never reach the replay cache and burn a legitimate jti (§9.2).
    const sig = verifyRequestSignature(req, {
      now,
      requiredComponents: this.cfg.requiredComponents ?? DEFAULT_COMPONENTS,
      ...(this.cfg.signatureMaxAgeSeconds !== undefined
        ? { maxAgeSeconds: this.cfg.signatureMaxAgeSeconds }
        : {}),
    });
    if (!sig.ok) return this.reject('pop_failed', sig.detail);

    const verified = verifySpendToken(payment.token, {
      ledgerJwk: this.cfg.ledgerJwk,
      host: this.cfg.host,
      now,
      replay: this.cfg.replay,
      presenterJkt: sig.jkt,
    });
    if (!verified.ok) return this.reject(verified.code, verified.detail);

    const claims = verified.claims;
    if (claims.iss !== this.cfg.ledgerUrl) {
      return this.reject('chain_invalid', `token issued by ${claims.iss}, not ${this.cfg.ledgerUrl}`);
    }
    // The token authorizes one resource. Without this a token minted for a cheap
    // endpoint pays for an expensive one inside its 60-second window.
    if (claims.res !== canonicalUri) {
      return this.reject('resource_not_covered', `token is for ${claims.res}`);
    }
    if (claims.amt.amt !== quote.amount.amt || claims.amt.cur !== quote.amount.cur) {
      return this.reject(
        'amount_exceeds_cap',
        `token pays ${claims.amt.amt} ${claims.amt.cur}, price is ${quote.amount.amt} ${quote.amount.cur}`,
      );
    }

    return { kind: 'allow', claims, canonicalUri, presenterJkt: sig.jkt };
  }

  /** Header for a successful response (§14.3). */
  receiptHeader(receiptId: string): Record<string, string> {
    return { [PAYMENT_RECEIPT]: buildReceiptHeader(receiptId, this.cfg.ledgerUrl) };
  }

  private header(req: SignableRequest, name: string): string | undefined {
    return getHeader(req.headers, name) ?? undefined;
  }

  private challenge(quote: Quote, now: number): MerchantDecision {
    const quoteId = (this.cfg.quoteIdFactory ?? (() => `qt_${randomUUID().replace(/-/g, '')}`))();
    const exp = now + (this.cfg.quoteTtlSeconds ?? 120);
    const header = buildChallenge({
      scheme: SCHEME,
      v: 1,
      ledger: this.cfg.ledgerUrl,
      quoteId,
      amount: quote.amount,
      settle: quote.settle ?? ['immediate'],
      ...(quote.schema !== undefined ? { schema: quote.schema } : {}),
      exp,
    });
    return {
      kind: 'challenge',
      status: 402,
      headers: { [ACCEPT_PAYMENT]: header, 'Content-Type': PROBLEM_CONTENT_TYPE },
      body: problem('budget_exhausted', 'payment required', {
        status: 402,
        title: 'Payment Required',
        code: 'budget_exhausted',
        quote: quoteId,
        amount: quote.amount,
      }),
      quoteId,
      quote,
    };
  }

  private reject(code: ErrorCode, detail: string): MerchantDecision {
    const body = problem(code, detail);
    return {
      kind: 'reject',
      status: body.status,
      headers: { 'Content-Type': PROBLEM_CONTENT_TYPE },
      body,
    };
  }
}

export { buildPayment };
