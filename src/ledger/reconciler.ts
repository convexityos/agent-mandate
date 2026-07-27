import type { Money } from '../money.js';
import type { Ledger } from './ledger.js';
import type { Reservation } from './store.js';

/**
 * Spec §12.2.1 and open question 8 — the pass that resolves `settling`.
 *
 * `settling` exists because paying is an external call and external calls have a
 * third outcome. Inventing that state was only worth it if something eventually
 * asks the rail what happened; §12.2.1 says an implementation **MUST** provide
 * that pass, and until this file there was a `reconcile()` method that nothing
 * called on a timer.
 *
 * Open question 8 asks how long a reservation may sit in `settling` before a
 * human hears about it, and answers only that *silence is the wrong default*.
 * This is where a deployment writes down its answer.
 *
 * ## What escalation does not do
 *
 * It does not refund, and it does not settle. A reservation reaches this state
 * precisely because nobody knows whether the money moved, and §12.2.1 is
 * emphatic that guessing costs either a double-spend or a stranded balance. The
 * budget stays debited — the conservative side — and a human is told.
 *
 * A deployment that wants an escalation to halt spending has `setGlobalKill` and
 * can call it from `onEscalation`. That is deliberately not the default: one
 * slow rail should not be able to stop a principal's every agent.
 */

export interface Escalation {
  spendId: string;
  reason: string;
  /** How long it had been in `settling`. */
  ageSeconds: number;
  amount: Money;
  merchant: string;
  resource: string;
  root: string;
  agent: string;
  taskId: string | null;
  railName?: string;
}

export interface ReconcilerPass {
  at: number;
  /** Resolved by asking the rail. */
  settled: string[];
  refunded: string[];
  /** Asked, still no answer. */
  stillUnknown: string[];
  /** Newly handed to a human this pass. Already-escalated ones are not repeated. */
  escalated: Escalation[];
  /** Swept by `sweepExpired`: tokens nobody redeemed. */
  expired: string[];
  /**
   * Reservations in `settling` when the pass finished.
   *
   * This is the number to page on. A deployment where it trends upward is
   * accumulating money that is neither spent nor available, which is the exact
   * failure `settling` was introduced to make visible rather than to hide.
   */
  outstanding: number;
  /** Age of the oldest outstanding settlement, or null if there are none. */
  oldestOutstandingSeconds: number | null;
  /** Anything that threw. A failing rail degrades the pass; it must not end it. */
  errors: string[];
}

export interface ReconcilerConfig {
  ledger: Ledger;
  /**
   * A reservation in `settling` longer than this needs a human. There is no
   * defensible universal value — it depends on the rail's own settlement
   * window — so it is required rather than defaulted.
   */
  stuckAfterSeconds: number;
  /** How often `start()` runs a pass. */
  intervalMs?: number;
  /**
   * Cap on reservations expired per pass. A sweep runs inside one transaction,
   * so an unbounded backlog would hold row locks on every stale reservation at
   * once and stall live spending while it ran.
   */
  sweepLimit?: number;
  onEscalation?: (e: Escalation) => void | Promise<void>;
  onPass?: (pass: ReconcilerPass) => void | Promise<void>;
  clock?: () => number;
}

const describe = (err: unknown): string => (err instanceof Error ? err.message : String(err));

export class Reconciler {
  private readonly clock: () => number;
  private timer: ReturnType<typeof setInterval> | null = null;
  /** Held while a pass runs, so `start()` cannot overlap two of them. */
  private inFlight: Promise<ReconcilerPass> | null = null;

  constructor(private readonly cfg: ReconcilerConfig) {
    this.clock = cfg.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  private toEscalation(r: Reservation, reason: string, now: number): Escalation {
    return {
      spendId: r.id,
      reason,
      ageSeconds: now - (r.settlingSince ?? r.createdAt),
      amount: r.amount,
      merchant: r.merchant,
      resource: r.resource,
      root: r.root,
      agent: r.agent,
      taskId: r.taskId,
      ...(r.railName !== undefined ? { railName: r.railName } : {}),
    };
  }

  /**
   * One pass: ask the rail, escalate what has waited too long, sweep what
   * expired unredeemed, then report.
   *
   * The order matters. Asking first means a reservation the rail can resolve
   * this second is never escalated, so a human is only ever woken for something
   * genuinely undecidable. Sweeping last means the expiry sweep sees the state
   * reconciliation just wrote.
   */
  async pass(): Promise<ReconcilerPass> {
    const now = this.clock();
    const result: ReconcilerPass = {
      at: now,
      settled: [],
      refunded: [],
      stillUnknown: [],
      escalated: [],
      expired: [],
      outstanding: 0,
      oldestOutstandingSeconds: null,
      errors: [],
    };

    // 1. Ask the rail about everything in flight.
    //
    // `escalated` comes back from the non-custodial path, which decides on the
    // rail's own capabilities (§12.4.5) rather than on a clock: without
    // `hardExpiry` a late settlement is still possible, so "unconfirmed" can
    // never become "never happened" and a human has to look. Those are collected
    // here rather than in step 2, because that step only sees `settling` and a
    // non-custodial escalation can land on a reservation still at `reserved`.
    const fromRail: string[] = [];
    try {
      for (const { spendId, outcome } of await this.cfg.ledger.reconcile()) {
        if (outcome === 'settled') result.settled.push(spendId);
        else if (outcome === 'refunded') result.refunded.push(spendId);
        else if (outcome === 'still_unknown') result.stillUnknown.push(spendId);
        else fromRail.push(spendId);
      }
    } catch (err) {
      result.errors.push(`reconcile: ${describe(err)}`);
    }

    for (const spendId of fromRail) {
      try {
        const r = await this.cfg.ledger.reservation(spendId);
        if (r?.escalated === undefined) continue;
        result.escalated.push(this.toEscalation(r, r.escalated.reason, now));
      } catch (err) {
        result.errors.push(`escalation detail (${spendId}): ${describe(err)}`);
      }
    }

    // 2. Escalate what the rail could not resolve and has waited too long.
    //
    // Custodial settlement is the gap this closes: `reconcile()` answers
    // `still_unknown` forever and nothing was ever told. The non-custodial path
    // escalates on its own terms, and `escalate` is a one-shot, so a reservation
    // it already flagged is not flagged twice here.
    try {
      for (const r of await this.cfg.ledger.stuckSettlements(this.cfg.stuckAfterSeconds)) {
        const age = now - (r.settlingSince ?? r.createdAt);
        const reason = `in settling for ${age}s with no answer from ${r.railName ?? 'the rail'}`;
        if (await this.cfg.ledger.escalate(r.id, reason)) {
          result.escalated.push(this.toEscalation(r, reason, now));
        }
      }
    } catch (err) {
      result.errors.push(`escalate: ${describe(err)}`);
    }

    // 3. Sweep tokens nobody redeemed.
    //
    // `sweepExpired` refuses anything carrying a directive, and that rule is the
    // whole reason this is safe: an agent can execute a directive and never
    // report, so silence is not evidence of inaction and a blind refund would
    // hand back money that has already left the payer.
    try {
      result.expired = await this.cfg.ledger.sweepExpired(this.cfg.sweepLimit);
    } catch (err) {
      result.errors.push(`sweep: ${describe(err)}`);
    }

    // 4. Report what is still outstanding.
    try {
      const outstanding = await this.cfg.ledger.stuckSettlements();
      result.outstanding = outstanding.length;
      result.oldestOutstandingSeconds = outstanding.reduce<number | null>((oldest, r) => {
        const age = now - (r.settlingSince ?? r.createdAt);
        return oldest === null || age > oldest ? age : oldest;
      }, null);
    } catch (err) {
      result.errors.push(`outstanding: ${describe(err)}`);
    }

    for (const e of result.escalated) {
      try {
        await this.cfg.onEscalation?.(e);
      } catch (err) {
        // A dead pager must not lose the escalation. It is recorded on the
        // reservation either way, so this degrades to somebody having to look.
        result.errors.push(`onEscalation(${e.spendId}): ${describe(err)}`);
      }
    }
    try {
      await this.cfg.onPass?.(result);
    } catch (err) {
      result.errors.push(`onPass: ${describe(err)}`);
    }

    return result;
  }

  /**
   * Run passes on a timer.
   *
   * A pass already running blocks the next tick rather than queueing behind it:
   * two concurrent passes would both ask the rail about the same reservations,
   * and on a rail that bills per query that is a bill, not just noise. If passes
   * consistently outrun the interval the deployment wants a longer interval, not
   * a deeper queue.
   *
   * The timer is unref'd, so a reconciler does not by itself keep a process
   * alive — a CLI that finishes its work should exit.
   */
  start(): void {
    if (this.timer !== null) return;
    const interval = this.cfg.intervalMs ?? 60_000;
    this.timer = setInterval(() => void this.tick(), interval);
    this.timer.unref?.();
  }

  private tick(): Promise<ReconcilerPass> | null {
    if (this.inFlight !== null) return null;
    const run = this.pass();
    this.inFlight = run;
    void run.catch(() => undefined).finally(() => {
      this.inFlight = null;
    });
    return run;
  }

  stop(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
  }

  /** Resolves once any in-flight pass has finished; for orderly shutdown and tests. */
  async drain(): Promise<void> {
    await this.inFlight?.catch(() => undefined);
  }
}
