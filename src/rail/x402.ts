import { createHash } from 'node:crypto';

import type { Money } from '../money.js';
import type { Reservation } from '../ledger/store.js';
import { type PayResult, type RailStatus, type SettlementRail, toAtomicUnits } from './rail.js';

/**
 * x402 protocol v2 adapter — "mode A": the Ledger pays x402 on the agent's
 * behalf, and the merchant needs to implement nothing.
 *
 * This matters more than the alternative. Asking a merchant to adopt §14 means
 * five checks plus RFC 9421 before a single agent has ever paid them. Here the
 * storefront sees an ordinary x402 client; the delegation, budgets, breakers and
 * receipts all happen upstream, and the agent never holds the wallet — which is
 * the entire point, because a held wallet is unbounded authority.
 *
 * Written against a live capture (test/fixtures/x402-live.json). In v2:
 *
 *   - the 402 body is always `{}` and the challenge rides in a base64
 *     `PAYMENT-REQUIRED` *response header*
 *   - payment replays in a base64 `PAYMENT-SIGNATURE` *request header*
 *   - `accepts[].amount`, not `maxAmountRequired`
 *   - `network` is CAIP-2 (`eip155:8453`), not a bare chain nickname
 *   - `resource` is an object at the top level, not a string inside `accepts`
 *
 * v1 put the challenge in the body under `maxAmountRequired`. Both are accepted
 * on the read path; deployments genuinely differ, and guessing wrong fails at
 * the first parse with no useful diagnostic.
 */

export const PAYMENT_REQUIRED_HEADER = 'PAYMENT-REQUIRED';
export const PAYMENT_SIGNATURE_HEADER = 'PAYMENT-SIGNATURE';

export interface X402Accepts {
  scheme: string;
  /** CAIP-2 in v2 (`eip155:8453`); a bare nickname (`base`) in v1. */
  network: string;
  /** Atomic units of `asset`, decimal string. v2 name. */
  amount?: string;
  /** v1 name for the same thing. */
  maxAmountRequired?: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  /** EIP-712 domain for the asset contract. For Base USDC: {name:"USD Coin", version:"2"}. */
  extra?: { name?: string; version?: string };
}

export interface X402Challenge {
  x402Version: number;
  error?: string;
  resource?: { url: string; description?: string; mimeType?: string } | string;
  accepts: X402Accepts[];
  extensions?: Record<string, unknown>;
}

export interface Eip3009Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  /** 0x-prefixed 32-byte hex. Deterministic in the spendId; see `nonceFor`. */
  nonce: string;
}

export interface Eip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

/**
 * The signing seam. EIP-712 typed-data signing needs keccak256 and secp256k1,
 * neither of which is in Node's crypto — a production wiring supplies viem or
 * ethers here. Injecting it keeps this package dependency-free and, more
 * usefully, keeps the private key outside protocol code entirely.
 */
export interface Eip3009Signer {
  readonly address: string;
  signTransferAuthorization(
    domain: Eip712Domain,
    authorization: Eip3009Authorization,
  ): Promise<string>;
}

export interface X402HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
}

export interface X402HttpResponse {
  status: number;
  headers: Record<string, string | undefined>;
  body?: unknown;
}

/** Injected so nothing here performs live network I/O by default. */
export type X402Transport = (req: X402HttpRequest) => Promise<X402HttpResponse>;

export interface X402RailConfig {
  signer: Eip3009Signer;
  transport: X402Transport;
  /** CAIP-2 network to accept, e.g. "eip155:8453". A bare "base" also matches v1 challenges. */
  network: string;
  asset: string;
  /** Decimals of `asset`. USDC is 6. */
  assetDecimals: number;
  /** EIP-712 chainId. Derived from a CAIP-2 `network` when omitted. */
  chainId?: number;
  clock: () => number;
  authorizationTtlSeconds?: number;
  scheme?: string;
  /** Header carrying the payment. Default `PAYMENT-SIGNATURE` (v2). */
  paymentHeader?: string;
  /**
   * Header carrying the settlement receipt on success, if the merchant emits
   * one. Fabler's storefront declares none, so this is optional — see the note
   * on `refFor` about what stands in.
   */
  settlementHeader?: string;
  x402Version?: number;
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64');

function decodeB64Json(v: string | undefined): Record<string, unknown> | null {
  if (v === undefined || v === '') return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(v, 'base64').toString('utf8'));
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function headerOf(headers: Record<string, string | undefined>, name: string): string | undefined {
  const want = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === want && headers[k] !== undefined) return headers[k];
  }
  return undefined;
}

export function chainIdFromCaip2(network: string): number | null {
  const m = /^eip155:(\d+)$/.exec(network);
  return m === null ? null : Number(m[1]);
}

/**
 * A nonce derived from the spendId, not from randomness.
 *
 * EIP-3009 authorizations are single-use per (from, nonce): the token contract
 * rejects a nonce it has already seen. Deriving it deterministically means the
 * *chain itself* deduplicates a retried settlement, so a crash between "transfer
 * submitted" and "reservation marked settled" cannot produce a second transfer
 * no matter how the ledger's own records ended up. Stronger than any bookkeeping
 * on this side of the wire.
 */
export function nonceFor(spendId: string): string {
  return `0x${createHash('sha256').update(`am/1:x402:${spendId}`, 'utf8').digest('hex')}`;
}

/**
 * Reconciliation reference when the merchant returns no transaction hash.
 *
 * `(from, nonce)` uniquely identifies an EIP-3009 authorization and the token
 * contract exposes `authorizationState(from, nonce)`, so this is independently
 * checkable against chain state — which is the property a receipt actually
 * needs. A transaction hash is nicer to read and no more authoritative.
 */
export function refFor(from: string, spendId: string): string {
  return `eip3009:${from.toLowerCase()}:${nonceFor(spendId)}`;
}

/** Reads the v2 header form first, then the v1 body form. */
export function parseX402Challenge(res: X402HttpResponse): X402Challenge | null {
  const fromHeader = decodeB64Json(headerOf(res.headers, PAYMENT_REQUIRED_HEADER));
  const raw = fromHeader ?? (typeof res.body === 'object' && res.body !== null ? (res.body as Record<string, unknown>) : null);
  if (raw === null) return null;
  if (!Array.isArray(raw['accepts']) || raw['accepts'].length === 0) return null;
  if (typeof raw['x402Version'] !== 'number') return null;
  return raw as unknown as X402Challenge;
}

export function amountOf(a: X402Accepts): string | null {
  return a.amount ?? a.maxAmountRequired ?? null;
}

export class X402Rail implements SettlementRail {
  readonly name = 'x402';

  private readonly attempts = new Map<string, PayResult>();

  constructor(private readonly cfg: X402RailConfig) {}

  async pay(r: Reservation): Promise<PayResult> {
    const cached = this.attempts.get(r.id);
    if (cached !== undefined && (cached.ok || cached.terminal)) return cached;

    const result = await this.attempt(r);
    // Indeterminate results are not cached: reconciliation must be free to ask
    // the rail again rather than be handed back our own uncertainty.
    if (result.ok || result.terminal) this.attempts.set(r.id, result);
    return result;
  }

  private matches(a: X402Accepts): boolean {
    if (a.scheme !== (this.cfg.scheme ?? 'exact')) return false;
    if (a.asset.toLowerCase() !== this.cfg.asset.toLowerCase()) return false;
    return a.network === this.cfg.network;
  }

  private async attempt(r: Reservation): Promise<PayResult> {
    let challengeRes: X402HttpResponse;
    try {
      challengeRes = await this.cfg.transport({ method: 'GET', url: r.resource, headers: {} });
    } catch (e) {
      return { ok: false, terminal: false, detail: `challenge request failed: ${String(e)}` };
    }

    if (challengeRes.status !== 402) {
      return {
        ok: false,
        terminal: true,
        detail: `expected 402 from ${r.resource}, got ${challengeRes.status}`,
      };
    }

    const challenge = parseX402Challenge(challengeRes);
    if (challenge === null) {
      return { ok: false, terminal: true, detail: 'unparseable x402 challenge' };
    }

    const accepts = challenge.accepts.find((a) => this.matches(a));
    if (accepts === undefined) {
      return {
        ok: false,
        terminal: true,
        detail: `no ${this.cfg.network} / ${this.cfg.asset} option in the challenge`,
      };
    }

    const requiredRaw = amountOf(accepts);
    if (requiredRaw === null) {
      return { ok: false, terminal: true, detail: 'challenge states no amount' };
    }
    let required: bigint;
    try {
      required = BigInt(requiredRaw);
    } catch {
      return { ok: false, terminal: true, detail: `malformed amount "${requiredRaw}"` };
    }

    const value = toAtomicUnits(r.amount, this.cfg.assetDecimals);
    if (value === null) {
      return {
        ok: false,
        terminal: true,
        detail: `${r.amount.amt} ${r.amount.cur} needs more precision than ${this.cfg.assetDecimals} decimals`,
      };
    }
    if (value <= 0n) {
      return { ok: false, terminal: true, detail: 'amount rounds to zero atomic units' };
    }
    if (value !== required) {
      return {
        ok: false,
        terminal: true,
        detail: `reserved ${value} atomic units, merchant requires ${required} — price moved`,
      };
    }

    const chainId = this.cfg.chainId ?? chainIdFromCaip2(accepts.network);
    if (chainId === null) {
      return {
        ok: false,
        terminal: true,
        detail: `cannot derive an EIP-712 chainId from network "${accepts.network}"`,
      };
    }

    const now = this.cfg.clock();
    const authorization: Eip3009Authorization = {
      from: this.cfg.signer.address,
      to: accepts.payTo,
      value: value.toString(),
      validAfter: String(now - 60),
      validBefore: String(
        now + (this.cfg.authorizationTtlSeconds ?? accepts.maxTimeoutSeconds ?? 600),
      ),
      nonce: nonceFor(r.id),
    };

    let signature: string;
    try {
      signature = await this.cfg.signer.signTransferAuthorization(
        {
          // Must be the asset contract's real EIP-712 domain. Base USDC is
          // "USD Coin"/"2"; "USDC" produces a valid-looking, unusable signature.
          name: accepts.extra?.name ?? 'USD Coin',
          version: accepts.extra?.version ?? '2',
          chainId,
          verifyingContract: accepts.asset,
        },
        authorization,
      );
    } catch (e) {
      return { ok: false, terminal: true, detail: `signing failed: ${String(e)}` };
    }

    const header = b64({
      x402Version: challenge.x402Version ?? this.cfg.x402Version ?? 2,
      scheme: accepts.scheme,
      network: accepts.network,
      payload: { signature, authorization },
    });

    let paidRes: X402HttpResponse;
    try {
      paidRes = await this.cfg.transport({
        method: 'GET',
        url: r.resource,
        headers: { [this.cfg.paymentHeader ?? PAYMENT_SIGNATURE_HEADER]: header },
      });
    } catch (e) {
      // The authorization is signed and may already be on-chain. Never terminal.
      return { ok: false, terminal: false, detail: `payment request failed: ${String(e)}` };
    }

    if (paidRes.status === 402) {
      return { ok: false, terminal: true, detail: 'merchant rejected the payment' };
    }
    if (paidRes.status >= 500) {
      return { ok: false, terminal: false, detail: `merchant returned ${paidRes.status}` };
    }
    if (paidRes.status >= 400) {
      return { ok: false, terminal: true, detail: `merchant returned ${paidRes.status}` };
    }

    // A merchant that advertises a settlement header must produce one; a
    // merchant that advertises none (as this storefront does) is taken at its
    // word, and the EIP-3009 authorization identifier stands in as the
    // on-chain-checkable reference.
    if (this.cfg.settlementHeader !== undefined) {
      const info = decodeB64Json(headerOf(paidRes.headers, this.cfg.settlementHeader));
      if (info === null) {
        return {
          ok: false,
          terminal: false,
          detail: `2xx without the declared ${this.cfg.settlementHeader} header`,
        };
      }
      if (info['success'] === false) {
        return { ok: false, terminal: true, detail: 'facilitator reported settlement failure' };
      }
      const tx = info['transaction'];
      if (typeof tx === 'string' && tx !== '') return { ok: true, ref: tx };
    }

    return { ok: true, ref: refFor(this.cfg.signer.address, r.id) };
  }

  /**
   * Re-attempts the payment to resolve an indeterminate outcome. Safe precisely
   * because of the deterministic nonce: if the first authorization landed, the
   * token contract rejects this one as a used nonce and the merchant answers
   * 402 or 4xx, which reports as `not_paid` for THIS attempt while the original
   * transfer stands.
   *
   * That asymmetry is the weak point of reconciling over HTTP alone — a rail
   * with chain access should instead read `authorizationState(from, nonce)`,
   * which answers the question directly. `refFor` returns exactly the pair
   * needed for that call.
   */
  async status(r: Reservation): Promise<RailStatus> {
    const cached = this.attempts.get(r.id);
    if (cached?.ok === true) return { state: 'paid', ref: cached.ref };

    try {
      const probe = await this.cfg.transport({ method: 'GET', url: r.resource, headers: {} });
      if (probe.status !== 402) {
        return { state: 'unknown', detail: `resource answered ${probe.status}` };
      }
    } catch (e) {
      return { state: 'unknown', detail: `probe failed: ${String(e)}` };
    }

    const retry = await this.attempt(r);
    if (retry.ok) {
      this.attempts.set(r.id, retry);
      return { state: 'paid', ref: retry.ref };
    }
    if (retry.terminal) return { state: 'not_paid' };
    return { state: 'unknown', detail: retry.detail };
  }
}

/**
 * Book-entry rail for development and tests: records intent, moves nothing.
 * Named honestly so nobody ships it by accident.
 */
export class NullRail implements SettlementRail {
  readonly name = 'null';
  readonly paid: Array<{ id: string; amount: Money }> = [];

  async pay(r: Reservation): Promise<PayResult> {
    this.paid.push({ id: r.id, amount: r.amount });
    return { ok: true, ref: `null:${r.id}` };
  }

  async status(r: Reservation): Promise<RailStatus> {
    const hit = this.paid.find((p) => p.id === r.id);
    return hit === undefined ? { state: 'not_paid' } : { state: 'paid', ref: `null:${r.id}` };
  }
}
