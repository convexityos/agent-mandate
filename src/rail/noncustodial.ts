import { createHash } from 'node:crypto';

import { canonicalJson } from '../receipt.js';
import type { Reservation } from '../ledger/store.js';
import type { RailStatus } from './rail.js';

/**
 * Spec §12.4 — non-custodial settlement.
 *
 * The Ledger never holds funds. It issues a **Directive** naming exactly one
 * payment the agent is permitted to execute with its own key, records the
 * commitment, and later confirms the outcome against an oracle rather than
 * against the agent's word.
 *
 * The honest limit, restated here because it belongs next to the code:
 * a non-custodial mandate cannot *prevent* a spend. An agent holding its own
 * key can always bypass the Ledger. What this buys is detective control —
 * every authorized transfer bound to a directive, and every unmatched outflow
 * detectable (§12.4.7).
 *
 * Nothing in this module is chain-specific. EIP-3009 supplies an unusually good
 * oracle (`authorizationState`) and an unusually clean deadline (`validBefore`),
 * but neither is assumed: rails declare what they can actually guarantee via
 * `RailCapabilities`, and the Ledger adapts its resolution policy to match.
 */

export interface RailCapabilities {
  /**
   * Confirmation requires trusting no party — a chain read, a payment preimage,
   * a signed receipt from the payer's own institution that the Ledger can
   * verify. When false, `confirm` is an assertion by a third party and the
   * Ledger treats a negative answer as provisional.
   */
  trustlessOracle: boolean;
  /**
   * An unexecuted authorization becomes permanently void at `expiresAt`.
   *
   * This is the property that makes auto-refund sound. Without it a payment can
   * still land after the deadline, so "unconfirmed and past the deadline" is not
   * the same as "will never happen" and refunding on it double-spends.
   */
  hardExpiry: boolean;
  /** Atomic-unit precision of the rail's asset. */
  decimals: number;
  /** Whether a completed payment can be reversed by the rail. Usually false. */
  reversible: boolean;
}

/** Everything the agent is permitted to do, with nothing left to its discretion. */
export interface DirectiveIntent {
  /**
   * Fully-pinned, rail-specific payment description. Every field the executing
   * party could otherwise choose MUST appear here — a directive that leaves the
   * destination or the amount free is a suggestion, not a constraint.
   */
  intent: Record<string, unknown>;
  /** Account the funds leave. Matched against the `payer` caveat. */
  payer: string;
  /** Hard deadline after which the authorization cannot execute. */
  expiresAt: number;
  /** When a negative oracle answer becomes final. Never earlier than `expiresAt`. */
  decidableAt: number;
}

export interface Directive extends DirectiveIntent {
  v: string;
  typ: 'directive';
  /** Same id as the reservation, so one identifier threads the whole flow. */
  jti: string;
  iss: string;
  sub: string;
  chainHash: string;
  rail: string;
  /** Canonical hash of `intent`; what the agent's proof is checked against. */
  intentHash: string;
  iat: number;
  cnf: { jkt: string };
}

export type PrepareResult =
  | { ok: true; prepared: DirectiveIntent }
  | { ok: false; terminal: boolean; detail: string };

export type ProofVerdict = { ok: true; ref?: string } | { ok: false; detail: string };

export interface NonCustodialRail {
  readonly name: string;
  readonly capabilities: RailCapabilities;
  /** The account this rail's agent will pay from. */
  readonly payer: string;

  /**
   * Pin a quote into an executable intent. Offline by contract: the quote comes
   * from the agent, which already received it in the merchant's challenge, so
   * the Ledger never has to reach the merchant. That keeps the Ledger off the
   * merchant-facing path entirely and removes a network call from the critical
   * section.
   *
   * A dishonest quote is self-limiting: an inflated amount spends the agent's
   * own funds, a redirected destination means the merchant never serves, and an
   * unsigned directive simply expires and refunds. The budget debit always
   * equals the amount the directive pins, so the books stay consistent whatever
   * the agent claims.
   */
  prepare(reservation: Reservation, quote: unknown): PrepareResult | Promise<PrepareResult>;

  /** Check the agent's execution artifact against the directive it was issued. */
  verifyProof(directive: Directive, proof: unknown): ProofVerdict | Promise<ProofVerdict>;

  /** Independent confirmation. Never consults the agent. */
  confirm(directive: Directive): Promise<RailStatus>;
}

export function intentHash(intent: Record<string, unknown>): string {
  return `sha256:${createHash('sha256').update(canonicalJson(intent), 'utf8').digest('hex')}`;
}

export function isNonCustodial(r: unknown): r is NonCustodialRail {
  return (
    typeof r === 'object' &&
    r !== null &&
    'capabilities' in r &&
    typeof (r as NonCustodialRail).prepare === 'function'
  );
}
