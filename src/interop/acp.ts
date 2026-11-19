import { type Caveats, type Effect, type Settle, validateCaveats } from '../caveats.js';
import { type ErrorCode } from '../errors.js';
import type { Reservation } from '../ledger/store.js';
import { type Money, toScaled } from '../money.js';
import {
  type PayResult,
  type RailStatus,
  type SettlementRail,
  fromAtomicUnits,
  toAtomicUnits,
} from '../rail/rail.js';
import { canonicalJson, sha256Hex } from '../receipt.js';
import { type AgentKey, signMandate } from '../sign.js';
import { MAX_DEPTH, type MandateClaims, PROTOCOL_VERSION } from '../types.js';
import { canonicalizeUri, hostOfUri, parseHostPattern } from '../uri.js';

/**
 * Agentic Commerce Protocol (ACP) interop adapter and SettlementRail (spec §12.5).
 *
 * Bridges ACP in both directions:
 *   1. Inbound: converts an ACP DelegatedPayment allowance into a root `am/1`
 *      mandate pinned to the checkout session, currency, minor-unit cap,
 *      merchant host/resource, and expiry.
 *   2. Outbound (`AcpRail`): settles an `am/1` reservation by completing an ACP
 *      Checkout Session (`POST /checkout_sessions/{id}/complete`) with an
 *      idempotency key derived deterministically from `reservation.id`.
 *
 * Security invariants:
 *   - No floating-point conversion: ACP integer minor units map via exact
 *     `fromAtomicUnits` / `toAtomicUnits`, refusing sub-minor-unit precision
 *     rather than rounding.
 *   - Checkout session total verification (enabled by default in `AcpRail`):
 *     reads `GET /checkout_sessions/{id}` before `complete` and refuses
 *     terminally if the session currency or `total` disagrees with the
 *     authorized `reservation.amount`.
 *   - Three-outcome settlement: `4xx` declines are terminal (refund safe);
 *     `408`/`429`/`5xx` and transport errors after `complete` are indeterminate
 *     (remain `settling` until `status()` / `Ledger.reconcile()` decides).
 */

export const DEFAULT_ACP_CURRENCY_DECIMALS: Readonly<Record<string, number>> = Object.freeze({
  USD: 2,
  EUR: 2,
  GBP: 2,
  CAD: 2,
  AUD: 2,
  CHF: 2,
  JPY: 0,
  KRW: 0,
});

export interface AcpTotal {
  type:
    | 'items_base_amount'
    | 'items_discount'
    | 'subtotal'
    | 'discount'
    | 'fulfillment'
    | 'tax'
    | 'fee'
    | 'total';
  display_text: string;
  /** Integer minor units (e.g. cents for USD). */
  amount: number;
}

export interface AcpLineItem {
  id: string;
  item: { id: string; quantity: number };
  base_amount: number;
  discount?: number;
  subtotal: number;
  tax?: number;
  total: number;
}

export type AcpCheckoutStatus =
  | 'not_ready_for_payment'
  | 'ready_for_payment'
  | 'in_progress'
  | 'completed'
  | 'canceled';

export interface AcpCheckoutSession {
  id: string;
  status: AcpCheckoutStatus;
  currency: string;
  line_items?: AcpLineItem[];
  totals: AcpTotal[];
  order?: {
    id: string;
    checkout_session_id: string;
    permalink_url?: string;
  };
  expires_at?: number | string;
}

export interface AcpDelegatedAllowance {
  reason: 'one_time' | 'recurring';
  /** Maximum amount in integer minor units (e.g. 2500 for $25.00 USD). */
  max_amount: number;
  /** ISO-4217 currency code (case-insensitive, e.g. 'usd' or 'USD'). */
  currency: string;
  checkout_session_id: string;
  merchant_id: string;
  /** Expiry as UNIX epoch seconds. */
  expires_at: number;
}

export interface AcpAllowanceAdapterOptions {
  issuer: string;
  subject: string;
  subjectJkt: string;
  ledger: string;
  now: number;
  /** Canonical HTTPS checkout endpoint URI (recommended) or merchant origin. */
  merchantResource?: string;
  /** Merchant hostname when `merchantResource` is not provided. */
  merchantHost?: string;
  /** Currency minor-unit decimals override (defaults to `DEFAULT_ACP_CURRENCY_DECIMALS`). */
  currencyDecimals?: Readonly<Record<string, number>>;
  jti?: string;
  nbf?: number;
  statusIdx?: number;
  delegable?: boolean;
  maxDepth?: number;
  settle?: Settle;
  purpose?: string[];
  effect?: Effect;
  payer?: string;
}

export type AcpAdapterResult =
  | { ok: true; claims: MandateClaims; provenanceHash: string }
  | { ok: false; code: ErrorCode; detail: string };

export type AcpIssueResult =
  | { ok: true; token: string; claims: MandateClaims; provenanceHash: string }
  | { ok: false; code: ErrorCode; detail: string };

export function acpAllowanceDigest(allowance: AcpDelegatedAllowance): string {
  return sha256Hex(canonicalJson(allowance));
}

function decimalsForCurrency(
  currency: string,
  overrides?: Readonly<Record<string, number>>,
): number | null {
  const upper = currency.trim().toUpperCase();
  if (overrides !== undefined && Object.prototype.hasOwnProperty.call(overrides, upper)) {
    const d = overrides[upper];
    return typeof d === 'number' && Number.isInteger(d) && d >= 0 && d <= 9 ? d : null;
  }
  const def = DEFAULT_ACP_CURRENCY_DECIMALS[upper];
  return def === undefined ? null : def;
}

/**
 * Translate an ACP DelegatedPayment allowance into root `am/1` MandateClaims.
 * Fails closed on non-integer/non-positive minor units, unknown currency
 * precision, expired allowance, missing session id, or invalid merchant URI.
 */
export function mandateClaimsFromAcpAllowance(
  allowance: AcpDelegatedAllowance,
  opts: AcpAllowanceAdapterOptions,
): AcpAdapterResult {
  if (!opts.issuer || !opts.subject || !opts.subjectJkt || !opts.ledger) {
    return { ok: false, code: 'chain_invalid', detail: 'issuer, subject, subjectJkt, and ledger are required' };
  }
  if (!Number.isInteger(opts.now) || opts.now <= 0) {
    return { ok: false, code: 'chain_invalid', detail: 'now must be a positive integer epoch timestamp' };
  }
  if (typeof allowance !== 'object' || allowance === null) {
    return { ok: false, code: 'chain_invalid', detail: 'ACP allowance must be an object' };
  }
  if (allowance.reason !== 'one_time' && allowance.reason !== 'recurring') {
    return { ok: false, code: 'chain_invalid', detail: 'ACP allowance reason must be one_time or recurring' };
  }
  if (typeof allowance.checkout_session_id !== 'string' || allowance.checkout_session_id.trim().length === 0) {
    return { ok: false, code: 'chain_invalid', detail: 'ACP allowance missing checkout_session_id' };
  }
  if (typeof allowance.merchant_id !== 'string' || allowance.merchant_id.trim().length === 0) {
    return { ok: false, code: 'chain_invalid', detail: 'ACP allowance missing merchant_id' };
  }
  if (!Number.isSafeInteger(allowance.max_amount) || allowance.max_amount <= 0) {
    return {
      ok: false,
      code: 'chain_invalid',
      detail: 'ACP allowance max_amount must be a positive safe integer in minor units',
    };
  }
  if (!Number.isInteger(allowance.expires_at) || allowance.expires_at <= opts.now) {
    return { ok: false, code: 'mandate_expired', detail: 'ACP allowance is expired or has invalid expires_at' };
  }
  const nbf = opts.nbf ?? opts.now;
  if (!Number.isInteger(nbf) || nbf <= 0 || nbf >= allowance.expires_at) {
    return { ok: false, code: 'chain_invalid', detail: 'nbf must be positive and precede expires_at' };
  }

  if (typeof allowance.currency !== 'string' || !/^[A-Za-z]{3,8}$/.test(allowance.currency.trim())) {
    return { ok: false, code: 'chain_invalid', detail: 'ACP allowance has invalid currency code' };
  }
  const cur = allowance.currency.trim().toUpperCase();
  const decimals = decimalsForCurrency(cur, opts.currencyDecimals);
  if (decimals === null) {
    return {
      ok: false,
      code: 'currency_mismatch',
      detail: `unknown minor-unit decimals for ACP currency ${cur}; supply currencyDecimals`,
    };
  }

  const cap: Money = fromAtomicUnits(BigInt(allowance.max_amount), decimals, cur);
  if (toScaled(cap) <= 0n) {
    return { ok: false, code: 'chain_invalid', detail: 'ACP allowance cap must be strictly positive' };
  }

  let host: string | undefined;
  let resource: string | undefined;
  if (opts.merchantResource !== undefined) {
    const canon = canonicalizeUri(opts.merchantResource);
    if (canon === null || !canon.startsWith('https://')) {
      return {
        ok: false,
        code: 'chain_invalid',
        detail: `ACP merchantResource must be a valid https URI: ${opts.merchantResource}`,
      };
    }
    const extracted = hostOfUri(canon);
    if (extracted === null) {
      return { ok: false, code: 'chain_invalid', detail: 'cannot extract host from merchantResource' };
    }
    host = extracted;
    resource = canon;
  } else if (opts.merchantHost !== undefined) {
    const hp = parseHostPattern(opts.merchantHost);
    if (hp === null || hp.wildcard) {
      return { ok: false, code: 'chain_invalid', detail: `invalid merchantHost: ${opts.merchantHost}` };
    }
    host = hp.host;
  }

  const maxDepth = opts.maxDepth ?? (allowance.reason === 'one_time' ? 0 : 2);
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > MAX_DEPTH) {
    return {
      ok: false,
      code: 'depth_exceeded',
      detail: `maxDepth must be an integer between 0 and ${MAX_DEPTH}`,
    };
  }

  const provenanceHash = acpAllowanceDigest(allowance);
  const hashSuffix = provenanceHash.slice('sha256:'.length, 'sha256:'.length + 16);

  const cav: Caveats = {
    currency: cur,
    max_total: cap,
    max_per_txn: cap,
    depth: maxDepth,
    delegable: opts.delegable ?? (allowance.reason === 'recurring'),
    task: `acp:${allowance.checkout_session_id}`,
  };
  if (allowance.reason === 'one_time') {
    cav.rate = { n: 1, per: 'PT24H' };
  }
  if (host !== undefined) cav.aud = [host];
  if (resource !== undefined) cav.resources = [resource];
  if (opts.settle !== undefined) cav.settle = opts.settle;
  if (opts.purpose !== undefined) cav.purpose = opts.purpose;
  if (opts.effect !== undefined) cav.effect = opts.effect;
  if (opts.payer !== undefined) cav.payer = opts.payer;

  const cavCheck = validateCaveats(cav);
  if (!cavCheck.ok) return cavCheck;

  const claims: MandateClaims = {
    v: PROTOCOL_VERSION,
    typ: 'mandate',
    jti: opts.jti ?? `mnd_acp_${hashSuffix}`,
    iss: opts.issuer,
    sub: opts.subject,
    par: null,
    iat: opts.now,
    nbf,
    exp: allowance.expires_at,
    cnf: { jkt: opts.subjectJkt },
    ledger: opts.ledger,
    cav,
  };
  if (opts.statusIdx !== undefined) claims.st = opts.statusIdx;

  return { ok: true, claims, provenanceHash };
}

/** Validate and sign a root `am/1` mandate from an ACP DelegatedPayment allowance. */
export function issueMandateFromAcpAllowance(
  allowance: AcpDelegatedAllowance,
  signer: AgentKey,
  opts: Omit<AcpAllowanceAdapterOptions, 'issuer'> & { issuer?: string; kid?: string },
): AcpIssueResult {
  const res = mandateClaimsFromAcpAllowance(allowance, {
    ...opts,
    issuer: opts.issuer ?? signer.did,
  });
  if (!res.ok) return res;
  const token = signMandate(res.claims, signer, opts.kid);
  return { ok: true, token, claims: res.claims, provenanceHash: res.provenanceHash };
}

// ------------------------------------------------------------------ AcpRail

export interface AcpHttpRequest {
  method: 'GET' | 'POST';
  url: string;
  headers: Record<string, string>;
  body?: unknown;
}

export interface AcpHttpResponse {
  status: number;
  headers?: Record<string, string | undefined>;
  body?: unknown;
}

/** Injected HTTP transport so `AcpRail` performs no live network I/O by default. */
export type AcpTransport = (req: AcpHttpRequest) => Promise<AcpHttpResponse>;

export interface AcpBuyer {
  first_name?: string;
  last_name?: string;
  email?: string;
  phone_number?: string;
}

export interface AcpRailConfig {
  /** Base URL of the merchant's ACP API (e.g. `https://merchant.example/acp`). */
  checkoutBaseUrl: string;
  /** Injected HTTP transport. */
  transport: AcpTransport;
  /** Returns the ACP Shared Payment Token (`spt_...`) for the reservation. */
  paymentTokenFor: (reservation: Reservation) => string | Promise<string>;
  /**
   * Resolves the ACP checkout session id from a reservation.
   * Defaults to stripping `acp:` from `reservation.taskId` or parsing
   * `/checkout_sessions/:id` from `reservation.resource`.
   */
  checkoutSessionFor?: (reservation: Reservation) => string | null;
  /** Payment provider name for `payment_data.provider` (default `'stripe'`). */
  paymentProvider?: string;
  /** Optional `API-Version` header value (default `'2026-01-30'`). */
  apiVersion?: string;
  /** Optional static headers (e.g. Authorization supplied by deployment). */
  headers?: Readonly<Record<string, string>>;
  /** Optional buyer info builder for ACP `complete` requests. */
  buyerFor?: (reservation: Reservation) => AcpBuyer | undefined;
  /** Currency minor-unit decimals override. */
  currencyDecimals?: Readonly<Record<string, number>>;
  /**
   * When true (default), `pay()` fetches `GET /checkout_sessions/{id}` before
   * completing and refuses terminally if the session's `total` or `currency`
   * does not exactly match `reservation.amount`.
   */
  verifySessionTotal?: boolean;
}

/** Deterministic idempotency key derived from `reservation.id` (never random). */
export function acpIdempotencyKeyFor(spendId: string): string {
  return `am1-acp-${spendId}`;
}

export function defaultAcpSessionIdFor(reservation: Reservation): string | null {
  if (typeof reservation.taskId === 'string' && reservation.taskId.startsWith('acp:')) {
    const id = reservation.taskId.slice('acp:'.length).trim();
    if (id.length > 0 && !id.includes('/')) return id;
  }
  const m = /\/checkout_sessions\/([^/?#]+)/.exec(reservation.resource);
  if (m !== null && m[1] !== undefined && m[1].length > 0) return m[1];
  return null;
}

function extractSessionTotal(session: unknown): {
  status: AcpCheckoutStatus;
  currency: string;
  totalAmount: number;
  ref: string;
} | null {
  if (typeof session !== 'object' || session === null) return null;
  const s = session as Record<string, unknown>;
  if (typeof s['id'] !== 'string' || typeof s['status'] !== 'string' || typeof s['currency'] !== 'string') {
    return null;
  }
  if (!Array.isArray(s['totals'])) return null;
  const totalEntry = (s['totals'] as unknown[]).find(
    (t): t is AcpTotal =>
      typeof t === 'object' &&
      t !== null &&
      (t as Record<string, unknown>)['type'] === 'total' &&
      typeof (t as Record<string, unknown>)['amount'] === 'number' &&
      Number.isSafeInteger((t as Record<string, unknown>)['amount']),
  );
  if (totalEntry === undefined) return null;
  const order = s['order'] as Record<string, unknown> | undefined;
  const ref = typeof order?.['id'] === 'string' && order['id'].length > 0 ? order['id'] : (s['id'] as string);
  return {
    status: s['status'] as AcpCheckoutStatus,
    currency: (s['currency'] as string).trim().toUpperCase(),
    totalAmount: totalEntry.amount,
    ref,
  };
}

/**
 * Outbound ACP `SettlementRail`: completes an ACP Checkout Session on behalf
 * of an authorized `am/1` reservation, enforcing exact minor-unit amount and
 * currency parity and deterministic `spendId` idempotency.
 */
export class AcpRail implements SettlementRail {
  readonly name = 'acp';
  private readonly baseUrl: string;
  private readonly cfg: AcpRailConfig;

  constructor(cfg: AcpRailConfig) {
    this.baseUrl = cfg.checkoutBaseUrl.replace(/\/+$/, '');
    this.cfg = cfg;
  }

  private buildHeaders(idempotencyKey?: string): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'API-Version': this.cfg.apiVersion ?? '2026-01-30',
      ...(this.cfg.headers ?? {}),
      ...(idempotencyKey !== undefined ? { 'Idempotency-Key': idempotencyKey } : {}),
    };
  }

  private sessionId(reservation: Reservation): string | null {
    return this.cfg.checkoutSessionFor
      ? this.cfg.checkoutSessionFor(reservation)
      : defaultAcpSessionIdFor(reservation);
  }

  async pay(reservation: Reservation): Promise<PayResult> {
    const sid = this.sessionId(reservation);
    if (sid === null) {
      return { ok: false, terminal: true, detail: 'cannot determine ACP checkout_session_id for reservation' };
    }

    const decimals = decimalsForCurrency(reservation.amount.cur, this.cfg.currencyDecimals);
    if (decimals === null) {
      return {
        ok: false,
        terminal: true,
        detail: `unknown minor-unit decimals for currency ${reservation.amount.cur}`,
      };
    }

    const minorUnits = toAtomicUnits(reservation.amount, decimals);
    if (minorUnits === null) {
      return {
        ok: false,
        terminal: true,
        detail: `amount ${reservation.amount.amt} ${reservation.amount.cur} cannot be expressed in ${decimals}-decimal ACP minor units without rounding`,
      };
    }
    const expectedMinor = Number(minorUnits);
    if (!Number.isSafeInteger(expectedMinor) || expectedMinor <= 0) {
      return { ok: false, terminal: true, detail: 'ACP minor-unit amount out of safe positive integer range' };
    }

    const sessionUrl = `${this.baseUrl}/checkout_sessions/${encodeURIComponent(sid)}`;

    // Pre-flight total & currency verification before sending complete.
    // Because GET moves no money, any failure here is safely terminal.
    if (this.cfg.verifySessionTotal !== false) {
      let getResp: AcpHttpResponse;
      try {
        getResp = await this.cfg.transport({
          method: 'GET',
          url: sessionUrl,
          headers: this.buildHeaders(),
        });
      } catch (err) {
        return {
          ok: false,
          terminal: true,
          detail: `ACP pre-flight session fetch failed before completion: ${(err as Error).message}`,
        };
      }
      if (getResp.status < 200 || getResp.status >= 300) {
        return {
          ok: false,
          terminal: true,
          detail: `ACP pre-flight session fetch returned HTTP ${getResp.status}`,
        };
      }
      const parsed = extractSessionTotal(getResp.body);
      if (parsed === null) {
        return { ok: false, terminal: true, detail: 'ACP checkout session response missing valid status or total' };
      }
      if (parsed.currency !== reservation.amount.cur) {
        return {
          ok: false,
          terminal: true,
          detail: `ACP session currency ${parsed.currency} disagrees with reservation ${reservation.amount.cur}`,
        };
      }
      if (parsed.totalAmount !== expectedMinor) {
        return {
          ok: false,
          terminal: true,
          detail: `ACP session total ${parsed.totalAmount} disagrees with authorized ${expectedMinor} minor units`,
        };
      }
      if (parsed.status === 'canceled') {
        return { ok: false, terminal: true, detail: 'ACP checkout session is already canceled' };
      }
      if (parsed.status === 'not_ready_for_payment') {
        return { ok: false, terminal: true, detail: 'ACP checkout session is not_ready_for_payment' };
      }
      if (parsed.status === 'completed') {
        return { ok: true, ref: parsed.ref, detail: 'already completed' };
      }
    }

    let token: string;
    try {
      token = await this.cfg.paymentTokenFor(reservation);
    } catch (err) {
      return {
        ok: false,
        terminal: true,
        detail: `failed to obtain ACP payment token before completion: ${(err as Error).message}`,
      };
    }
    if (typeof token !== 'string' || token.trim().length === 0) {
      return { ok: false, terminal: true, detail: 'ACP payment token is empty' };
    }

    const buyer = this.cfg.buyerFor?.(reservation);
    const body: Record<string, unknown> = {
      payment_data: {
        token,
        provider: this.cfg.paymentProvider ?? 'stripe',
      },
    };
    if (buyer !== undefined) body['buyer'] = buyer;

    // From this point on, `complete` is in flight: transport errors or 5xx/408/429
    // are indeterminate and MUST NOT be auto-refunded.
    let postResp: AcpHttpResponse;
    try {
      postResp = await this.cfg.transport({
        method: 'POST',
        url: `${sessionUrl}/complete`,
        headers: this.buildHeaders(acpIdempotencyKeyFor(reservation.id)),
        body,
      });
    } catch (err) {
      return {
        ok: false,
        terminal: false,
        detail: `ACP complete transport error: ${(err as Error).message}`,
      };
    }

    if (postResp.status >= 200 && postResp.status < 300) {
      const parsed = extractSessionTotal(postResp.body);
      if (parsed !== null && parsed.status === 'completed') {
        return { ok: true, ref: parsed.ref };
      }
      if (parsed !== null && parsed.status === 'canceled') {
        return { ok: false, terminal: true, detail: 'ACP checkout session canceled during completion' };
      }
      return {
        ok: false,
        terminal: false,
        detail: `ACP complete returned HTTP ${postResp.status} with non-completed status`,
      };
    }

    // 408 Request Timeout and 429 Too Many Requests can occur around network edges
    // or retries; treat 5xx/408/429 as indeterminate and other 4xx as terminal decline.
    if (postResp.status === 408 || postResp.status === 429 || postResp.status >= 500) {
      return {
        ok: false,
        terminal: false,
        detail: `ACP complete returned indeterminate HTTP ${postResp.status}`,
      };
    }
    if (postResp.status >= 400 && postResp.status < 500) {
      return {
        ok: false,
        terminal: true,
        detail: `ACP complete declined with HTTP ${postResp.status}`,
      };
    }
    return {
      ok: false,
      terminal: false,
      detail: `ACP complete returned unexpected HTTP ${postResp.status}`,
    };
  }

  async status(reservation: Reservation): Promise<RailStatus> {
    const sid = this.sessionId(reservation);
    if (sid === null) {
      return { state: 'unknown', detail: 'cannot determine ACP checkout_session_id for reservation' };
    }
    const sessionUrl = `${this.baseUrl}/checkout_sessions/${encodeURIComponent(sid)}`;
    let resp: AcpHttpResponse;
    try {
      resp = await this.cfg.transport({
        method: 'GET',
        url: sessionUrl,
        headers: this.buildHeaders(),
      });
    } catch (err) {
      return { state: 'unknown', detail: `ACP status fetch failed: ${(err as Error).message}` };
    }
    if (resp.status === 404) {
      return { state: 'not_paid' };
    }
    if (resp.status < 200 || resp.status >= 300) {
      return { state: 'unknown', detail: `ACP status fetch returned HTTP ${resp.status}` };
    }
    const parsed = extractSessionTotal(resp.body);
    if (parsed === null) {
      return { state: 'unknown', detail: 'ACP status response unparseable' };
    }
    if (parsed.status === 'completed') {
      return { state: 'paid', ref: parsed.ref };
    }
    if (
      parsed.status === 'canceled' ||
      parsed.status === 'ready_for_payment' ||
      parsed.status === 'not_ready_for_payment'
    ) {
      return { state: 'not_paid' };
    }
    return { state: 'unknown', detail: `ACP checkout session still ${parsed.status}` };
  }
}
