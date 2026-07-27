import type { Money } from '../money.js';
import type { Reservation } from '../ledger/store.js';

/**
 * The settlement seam.
 *
 * Everything above this line is authority and accounting: who may spend, how
 * much is left, what happened. Nothing above this line moves money. A rail is
 * what actually does, and the protocol is deliberately agnostic about which one
 * — x402/USDC, Lightning, a Stripe transfer, an internal book entry between two
 * accounts on the same ledger.
 *
 * The hard part of this interface is not `pay`. It is the distinction between
 * "definitely did not pay" and "don't know", because those require opposite
 * responses and conflating them either double-spends or strands funds.
 */

export interface RailQuote {
  /** What the rail says this costs, in the rail's own terms. */
  amount: Money;
  /** Rail-specific opaque data to carry into `pay` (e.g. an x402 `accepts` entry). */
  requirements: unknown;
  expiresAt?: number;
}

export type PayResult =
  | { ok: true; ref: string; detail?: string }
  /**
   * The payment definitively did not happen: a rejected quote, an amount the
   * rail cannot express, a merchant 4xx. Safe — and required — to credit the
   * budget back.
   */
  | { ok: false; terminal: true; detail: string }
  /**
   * Indeterminate: timeout, connection reset, an unparseable response. The
   * transfer may or may not have landed. MUST NOT be refunded on the strength
   * of this alone; leave the reservation `settling` for reconciliation.
   */
  | { ok: false; terminal: false; detail: string };

export type RailStatus =
  | { state: 'paid'; ref: string }
  | { state: 'not_paid' }
  | { state: 'unknown'; detail: string };

export interface SettlementRail {
  readonly name: string;

  /**
   * Pay for a reservation. MUST be idempotent on `reservation.id`: the ledger
   * retries after crashes, and a rail that transfers twice for one spendId is
   * worse than one that fails outright.
   */
  pay(reservation: Reservation): Promise<PayResult>;

  /** Resolve an indeterminate `pay`. Called by `Ledger.reconcile()`. */
  status(reservation: Reservation): Promise<RailStatus>;

  /** Best-effort reversal. Most rails cannot; returning false is normal and expected. */
  refund?(reservation: Reservation, ref: string): Promise<boolean>;
}

/**
 * Converts a protocol amount to a rail's atomic units.
 *
 * Returns null rather than rounding. Our amounts carry 9 decimal places (§4.3);
 * USDC carries 6. A price of 0.0000005 is perfectly expressible in a mandate and
 * not expressible on Base — and silently truncating it to zero atomic units
 * means the merchant serves the request for free, forever, and nothing in the
 * system reports a problem.
 */
export function toAtomicUnits(amount: Money, decimals: number): bigint | null {
  const [whole, frac = ''] = amount.amt.split('.') as [string, string?];
  if (frac.length > decimals) {
    // Trailing zeros beyond the rail's precision are harmless.
    if (!/^0*$/.test(frac.slice(decimals))) return null;
  }
  const padded = frac.slice(0, decimals).padEnd(decimals, '0');
  return BigInt(whole) * 10n ** BigInt(decimals) + BigInt(padded === '' ? '0' : padded);
}

export function fromAtomicUnits(units: bigint, decimals: number, cur: string): Money {
  if (decimals === 0) return { cur, amt: units.toString() };
  const d = 10n ** BigInt(decimals);
  const frac = (units % d).toString().padStart(decimals, '0').replace(/0+$/, '');
  return { cur, amt: frac === '' ? `${units / d}` : `${units / d}.${frac}` };
}
