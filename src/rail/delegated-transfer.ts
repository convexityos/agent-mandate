import { createHash } from 'node:crypto';

import type { Reservation } from '../ledger/store.js';
import { toAtomicUnits } from './rail.js';
import type { RailStatus } from './rail.js';
import type {
  Directive,
  NonCustodialRail,
  PrepareResult,
  ProofVerdict,
  RailCapabilities,
} from './noncustodial.js';

/**
 * A non-custodial rail with **neither** strong property, included precisely
 * because most of the world's payment rails are shaped like this.
 *
 * Card authorizations, ACH debits, bank transfers and PSP-mediated payments all
 * share the awkward shape: the only party who can say whether the money moved is
 * the institution holding it, and an authorization that looks abandoned can
 * still settle days later. So:
 *
 *   - `trustlessOracle: false` — confirmation is a third party's assertion
 *   - `hardExpiry: false` — "unconfirmed past the deadline" is NOT "never"
 *
 * The Ledger reads those flags and refuses to auto-refund on this rail,
 * escalating instead (§12.4.5). If the abstraction only worked for rails with
 * chain-grade guarantees it would not be an abstraction, it would be EIP-3009
 * with extra steps.
 */

export interface TransferConfirmation {
  state: 'settled' | 'not_settled' | 'pending';
  ref?: string;
  detail?: string;
}

/** Whatever the payer's institution offers: a webhook store, a status API, a file drop. */
export interface ConfirmationSource {
  lookup(idempotencyKey: string): Promise<TransferConfirmation>;
}

/** Verifies that an execution artifact really came from the payer's institution. */
export interface InstructionAuthenticator {
  verify(directive: Directive, proof: unknown): ProofVerdict | Promise<ProofVerdict>;
}

export interface DelegatedTransferConfig {
  name?: string;
  payer: string;
  /** Currency the payer account is denominated in. */
  currency: string;
  decimals: number;
  source: ConfirmationSource;
  authenticator: InstructionAuthenticator;
  clock: () => number;
  /** How long the payer's institution accepts the instruction. */
  instructionTtlSeconds?: number;
  /**
   * How long after expiry a late settlement can still appear. This is the
   * number that makes auto-refund unsound, so it is required rather than
   * defaulted to zero.
   */
  latestSettlementSeconds: number;
}

export interface DelegatedTransferIntent extends Record<string, unknown> {
  rail: 'delegated-transfer';
  from: string;
  to: string;
  amount: string;
  currency: string;
  /** Derived from the reservation id, so a retried instruction cannot double-pay. */
  idempotencyKey: string;
  notValidAfter: number;
}

export class DelegatedTransferRail implements NonCustodialRail {
  readonly name: string;
  readonly capabilities: RailCapabilities;

  constructor(private readonly cfg: DelegatedTransferConfig) {
    this.name = cfg.name ?? 'delegated-transfer';
    this.capabilities = {
      trustlessOracle: false,
      hardExpiry: false,
      decimals: cfg.decimals,
      reversible: true,
    };
  }

  get payer(): string {
    return this.cfg.payer;
  }

  prepare(r: Reservation, quote: unknown): PrepareResult {
    const q = quote as { payee?: unknown; currency?: unknown } | undefined;
    if (q === undefined || typeof q.payee !== 'string' || q.payee === '') {
      return { ok: false, terminal: true, detail: 'quote names no payee' };
    }
    if (typeof q.currency === 'string' && q.currency !== this.cfg.currency) {
      return {
        ok: false,
        terminal: true,
        detail: `quote is in ${q.currency}, payer account is ${this.cfg.currency}`,
      };
    }
    if (r.amount.cur !== this.cfg.currency) {
      return {
        ok: false,
        terminal: true,
        detail: `reservation is in ${r.amount.cur}, payer account is ${this.cfg.currency}`,
      };
    }
    const units = toAtomicUnits(r.amount, this.cfg.decimals);
    if (units === null) {
      return {
        ok: false,
        terminal: true,
        detail: `${r.amount.amt} needs more precision than ${this.cfg.decimals} decimals`,
      };
    }

    const now = this.cfg.clock();
    const notValidAfter = now + (this.cfg.instructionTtlSeconds ?? 900);

    const intent: DelegatedTransferIntent = {
      rail: 'delegated-transfer',
      from: this.cfg.payer,
      to: q.payee,
      amount: units.toString(),
      currency: this.cfg.currency,
      idempotencyKey: idempotencyKeyFor(r.id),
      notValidAfter,
    };

    return {
      ok: true,
      prepared: {
        intent,
        payer: this.cfg.payer,
        expiresAt: notValidAfter,
        // The whole point of this rail: decidability lags expiry, sometimes by
        // days. Reporting them as equal is how a reconciler refunds a payment
        // that has not finished happening yet.
        decidableAt: notValidAfter + this.cfg.latestSettlementSeconds,
      },
    };
  }

  async verifyProof(directive: Directive, proof: unknown): Promise<ProofVerdict> {
    return this.cfg.authenticator.verify(directive, proof);
  }

  async confirm(directive: Directive): Promise<RailStatus> {
    const intent = directive.intent as DelegatedTransferIntent;
    let result: TransferConfirmation;
    try {
      result = await this.cfg.source.lookup(intent.idempotencyKey);
    } catch (e) {
      return { state: 'unknown', detail: `confirmation source failed: ${String(e)}` };
    }

    if (result.state === 'settled') {
      return { state: 'paid', ref: result.ref ?? intent.idempotencyKey };
    }
    if (result.state === 'pending') {
      return { state: 'unknown', detail: result.detail ?? 'instruction still pending' };
    }
    // `not_settled` before the settlement horizon is provisional, not final —
    // this rail settles late often enough that the distinction has teeth.
    if (this.cfg.clock() < directive.decidableAt) {
      return { state: 'unknown', detail: 'within the late-settlement window' };
    }
    return { state: 'not_paid' };
  }
}

export function idempotencyKeyFor(spendId: string): string {
  return createHash('sha256').update(`am/1:transfer:${spendId}`, 'utf8').digest('hex').slice(0, 32);
}
