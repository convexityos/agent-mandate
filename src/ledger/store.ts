import type { Rate, Settle } from '../caveats.js';
import type { Money } from '../money.js';

/**
 * Ledger persistence, spec §10.
 *
 * The critical section is the whole point of this interface. `transact` MUST
 * serialize: a check-then-debit that interleaves with another check-then-debit
 * overdraws, and overdraw is the one failure this component exists to prevent.
 *
 * A SQL implementation maps `transact` onto a single transaction and takes its
 * row locks through `lockPath`, which exists so the ordering rule lives in the
 * store rather than in the order a caller happens to write a `for` loop.
 *
 * Every method is async because a durable store answers over a socket. In the
 * in-memory store nothing actually suspends, but the signatures have to admit
 * the round trip or no SQL implementation can satisfy them.
 */

export interface MandateNode {
  jti: string;
  parent: string | null;
  root: string;
  /**
   * `iss` of the link that introduced this node.
   *
   * On the root that is the principal who granted the whole subtree, and it is
   * what a control action is checked against: `isTrustedRootIssuer` says a DID
   * is *a* principal this deployment trusts, not that it is *this* subtree's
   * principal. Without this field, one trusted principal could revoke or halt
   * another's mandates.
   */
  issuer: string;
  /** SHA-256 of the exact JWS. Binds a jti to its content; see §10.1 note on substitution. */
  tokenHash: string;
  /** Declared `max_total`, scaled. null = this link declares no budget of its own. */
  budgetScaled: bigint | null;
  currency: string | null;
  spentScaled: bigint;
  rate: Rate | null;
  /** Timestamps of spends counted against this node's own rate caveat. */
  rateEvents: number[];
  revoked: boolean;
  exp: number;
}

/**
 * `settling` exists because paying is an external call and external calls have a
 * third outcome. A reservation whose transfer timed out is neither settled nor
 * safe to refund; it sits here until `Ledger.reconcile()` asks the rail what
 * actually happened. Collapsing this state into either neighbour double-spends
 * or strands funds, depending on which way you guess.
 */
export type ReservationStatus =
  | 'reserved'
  | 'settling'
  | 'settled'
  | 'refunded'
  | 'expired';

export interface Reservation {
  id: string;
  path: string[];
  root: string;
  agent: string;
  taskId: string | null;
  merchant: string;
  resource: string;
  amount: Money;
  amountScaled: bigint;
  settle: Settle;
  schema: string | null;
  chainHash: string;
  status: ReservationStatus;
  createdAt: number;
  expiresAt: number;
  respHash?: string;
  respBytes?: number;
  merchantSig?: string;
  refundReason?: string;
  /** Rail-side reference once paid, e.g. an on-chain transaction hash. */
  railRef?: string;
  railName?: string;
  /** When the reservation entered `settling`, for stuck-payment alerting. */
  settlingSince?: number;
  /** §12.4 — the issued directive, when a non-custodial rail is in use. */
  directive?: import('../rail/noncustodial.js').Directive;
  /** Whether the agent has reported execution, and whether the proof checked out. */
  reported?: { at: number; ok: boolean; detail?: string; ref?: string };
  /**
   * Set when reconciliation cannot decide and the rail gives no guarantee that
   * it ever will (§12.4.5). Auto-refund is unsound here; a human must look.
   */
  escalated?: { at: number; reason: string };
}

export interface SpendEvent {
  ts: number;
  amountScaled: bigint;
}

/**
 * §10.5 — where a step-up request stands.
 *
 * `pending` is the state that was missing. Without it a handle is minted already
 * valid, and since the Ledger hands the handle to the agent in the
 * `step_up_required` response, the agent approves its own spend by presenting
 * back what it was just given. The state machine is what makes "a human approved
 * this" a fact the ledger records rather than an assumption it makes.
 */
export type StepUpState = 'pending' | 'approved' | 'denied';

export interface StepUpDecisionRecord {
  at: number;
  /** The principal DID that signed it. */
  by: string;
  /** The decision JWS, kept whole so the approval can be re-verified later. */
  jws: string;
  reason?: string;
}

export interface StepUpApproval {
  handle: string;
  root: string;
  resource: string;
  maxAmountScaled: bigint;
  currency: string;
  expiresAt: number;
  used: boolean;
  state: StepUpState;
  requestedAt: number;
  /** Who was asking, and for what — the context a human needs to decide. */
  agent: string;
  taskId: string | null;
  decision?: StepUpDecisionRecord;
}

/** Selects step-ups for an approval queue. */
export interface StepUpQuery {
  state?: StepUpState[];
  root?: string;
  /** Exclude ones already spent. */
  unused?: boolean;
  /** `expiresAt` at or after this instant. */
  notExpiredAt?: number;
  limit?: number;
}

/**
 * The sweeper and the reconciler select reservations by shape.
 *
 * This is a structured query rather than a predicate because a predicate is a
 * closure, a closure cannot become a `WHERE` clause, and the only way to honour
 * one over SQL is to load every reservation ever written and filter in process.
 * Each field below exists because one of the three call sites needs it.
 */
export interface ReservationQuery {
  /** Match any of these. Omitted matches every status. */
  status?: ReservationStatus[];
  /** Whether the reservation carries a §12.4 directive. */
  hasDirective?: boolean;
  /** Whether a human has already been asked to look at it. */
  escalated?: boolean;
  /** `expiresAt` strictly before this instant. */
  expiresBefore?: number;
  /**
   * Cap on the result set, oldest first. A sweep runs inside the critical
   * section, so an uncapped backlog is a transaction that locks every stale
   * reservation at once and blocks live spending while it does.
   */
  limit?: number;
}

export interface LedgerTx {
  getNode(jti: string): Promise<MandateNode | undefined>;
  /**
   * Read every node on a path, taking the store's locks as it goes.
   *
   * `path` MUST be root-to-leaf, as `verifyChain` produces it and as
   * `Reservation.path` stores it. The ordering is load-bearing rather than
   * cosmetic: every spend under a principal touches the same root row, so paths
   * overlap constantly, and two spends that lock overlapping rows in different
   * orders deadlock under ordinary traffic rather than adversarial traffic.
   *
   * Root-to-leaf is deadlock-free for a structural reason: every path runs from
   * the root, so any two paths intersect in a common prefix and therefore lock
   * their shared rows in the same relative order. Any consistent global order
   * would do; this one is also the order the caller reads in.
   *
   * Returns one entry per input element, aligned by index, `undefined` where the
   * node has not been recorded yet.
   */
  lockPath(path: string[]): Promise<Array<MandateNode | undefined>>;
  putNode(node: MandateNode): Promise<void>;
  /**
   * Every node under a root, for rendering a budget tree. Read-only by intent —
   * this is a reporting query, not part of any critical section.
   */
  findNodes(root: string): Promise<MandateNode[]>;

  /**
   * Record a one-time-use nonce; `false` if it was already recorded.
   *
   * Needed because a control decision (§10.6) names no handle, unlike a step-up
   * decision which is bound to a one-shot request. Replaying a signed `release`
   * would restart spending a principal had deliberately halted, so the guard has
   * to be durable — an in-memory cache would forget it across the restart that a
   * halted principal is quite likely to involve.
   */
  consumeNonce(nonce: string, expiresAt: number): Promise<boolean>;

  getReservation(id: string): Promise<Reservation | undefined>;
  putReservation(r: Reservation): Promise<void>;
  /** Oldest first, by `createdAt` then `id`, so `limit` clears a backlog from the front. */
  findReservations(q: ReservationQuery): Promise<Reservation[]>;

  /** Rolling spend history per root, for circuit breakers. */
  appendHistory(root: string, e: SpendEvent): Promise<void>;
  historySince(root: string, since: number): Promise<SpendEvent[]>;

  taskTotal(taskId: string): Promise<bigint>;
  addTaskTotal(taskId: string, amountScaled: bigint): Promise<void>;

  merchantSeen(root: string, host: string): Promise<boolean>;
  markMerchant(root: string, host: string): Promise<void>;

  getStepUp(handle: string): Promise<StepUpApproval | undefined>;
  putStepUp(a: StepUpApproval): Promise<void>;
  /** Oldest request first, so an approval queue drains in the order it filled. */
  findStepUps(q: StepUpQuery): Promise<StepUpApproval[]>;

  killed(root: string): Promise<boolean>;
  setKilled(root: string, on: boolean): Promise<void>;
}

export interface LedgerStore {
  /**
   * Run `fn` in a serialized critical section.
   *
   * Commit is on **return**, rollback on **throw** — a returned value carries no
   * verdict. `reserve` depends on exactly this: the `step_up_required` path
   * writes a fresh approval handle and then returns `ok: false`, and a store
   * that rolled back on a failure-shaped result would hand the caller a handle
   * that does not exist.
   *
   * `fn` may be retried after a serialization failure, so it must be replayable:
   * derive nothing from state read in a previous attempt.
   */
  transact<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T>;
  /**
   * Read-only convenience for dashboards and tests. Explicitly *not* the
   * critical section: it takes no locks and a durable store is free to serve it
   * from a snapshot, so nothing that decides whether to move money may be
   * decided here.
   */
  read<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T>;
}

/** How long spend history is retained for breaker baselines. */
export const HISTORY_RETENTION_SECONDS = 14 * 86400;

/**
 * Shared by every implementation so `findReservations` cannot quietly mean
 * different things in memory and in SQL. The SQL stores push the same
 * conditions into a `WHERE` clause; this is what they are checked against.
 */
export function matchesQuery(r: Reservation, q: ReservationQuery): boolean {
  if (q.status !== undefined && !q.status.includes(r.status)) return false;
  if (q.hasDirective !== undefined && (r.directive !== undefined) !== q.hasDirective) return false;
  if (q.escalated !== undefined && (r.escalated !== undefined) !== q.escalated) return false;
  if (q.expiresBefore !== undefined && !(r.expiresAt < q.expiresBefore)) return false;
  return true;
}

/** The ordering `findReservations` promises: oldest first, `id` breaking ties. */
export function compareReservations(a: Reservation, b: Reservation): number {
  if (a.createdAt !== b.createdAt) return a.createdAt - b.createdAt;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/** As `matchesQuery`, for step-ups. Shared so SQL and memory cannot drift. */
export function matchesStepUpQuery(a: StepUpApproval, q: StepUpQuery): boolean {
  if (q.state !== undefined && !q.state.includes(a.state)) return false;
  if (q.root !== undefined && a.root !== q.root) return false;
  if (q.unused !== undefined && a.used === q.unused) return false;
  if (q.notExpiredAt !== undefined && a.expiresAt < q.notExpiredAt) return false;
  return true;
}

export function compareStepUps(a: StepUpApproval, b: StepUpApproval): number {
  if (a.requestedAt !== b.requestedAt) return a.requestedAt - b.requestedAt;
  return a.handle < b.handle ? -1 : a.handle > b.handle ? 1 : 0;
}

export class MemoryLedgerStore implements LedgerStore {
  private readonly nodes = new Map<string, MandateNode>();
  private readonly reservations = new Map<string, Reservation>();
  private readonly history = new Map<string, SpendEvent[]>();
  private readonly taskTotals = new Map<string, bigint>();
  private readonly merchants = new Map<string, Set<string>>();
  private readonly stepUps = new Map<string, StepUpApproval>();
  private readonly kills = new Set<string>();
  private readonly nonces = new Map<string, number>();

  /**
   * Serialization via a promise chain. Node is single-threaded, but `reserve`
   * awaits chain verification before debiting, and anything after an `await` can
   * interleave — so "JavaScript is single-threaded" is not on its own a defence
   * against a double-spend here.
   *
   * The chain covers the whole closure, including any `await` inside it, because
   * the next transaction waits on the promise this one returns.
   */
  private queue: Promise<unknown> = Promise.resolve();

  /**
   * Undo log for the current transaction, so a closure that throws leaves no
   * trace — the rollback half of the `transact` contract.
   *
   * Journaling rather than snapshotting: an undo entry per write is proportional
   * to the writes, and copying seven maps at every `BEGIN` would be proportional
   * to the whole ledger. Only `transact` populates it, and `transact` is
   * serialized, so one log per store is enough.
   *
   * Every mutator below is copy-on-write for this reason: an undo entry that
   * restores a reference is only a rollback if nothing mutated the referent.
   */
  private journal: Array<() => void> = [];

  constructor(private readonly clock: () => number = () => Math.floor(Date.now() / 1000)) {}

  private undo<K, V>(map: Map<K, V>, key: K): void {
    const had = map.has(key);
    const prev = map.get(key);
    this.journal.push(() => {
      if (had) map.set(key, prev as V);
      else map.delete(key);
    });
  }

  private readonly tx: LedgerTx = {
    getNode: async (jti) => this.nodes.get(jti),
    lockPath: async (path) => path.map((jti) => this.nodes.get(jti)),
    putNode: async (node) => {
      this.undo(this.nodes, node.jti);
      this.nodes.set(node.jti, node);
    },
    findNodes: async (root) =>
      [...this.nodes.values()]
        .filter((n) => n.root === root)
        .sort((a, b) => (a.jti < b.jti ? -1 : a.jti > b.jti ? 1 : 0)),

    consumeNonce: async (nonce, expiresAt) => {
      const now = this.clock();
      for (const [k, until] of this.nonces) if (until < now) this.nonces.delete(k);
      if (this.nonces.has(nonce)) return false;
      this.undo(this.nonces, nonce);
      this.nonces.set(nonce, expiresAt);
      return true;
    },

    getReservation: async (id) => this.reservations.get(id),
    putReservation: async (r) => {
      this.undo(this.reservations, r.id);
      this.reservations.set(r.id, r);
    },
    findReservations: async (q) => {
      const out = [...this.reservations.values()]
        .filter((r) => matchesQuery(r, q))
        .sort(compareReservations);
      return q.limit === undefined ? out : out.slice(0, q.limit);
    },

    appendHistory: async (root, e) => {
      this.undo(this.history, root);
      const cutoff = this.clock() - HISTORY_RETENTION_SECONDS;
      this.history.set(
        root,
        [...(this.history.get(root) ?? []), e].filter((x) => x.ts >= cutoff),
      );
    },
    historySince: async (root, since) =>
      (this.history.get(root) ?? []).filter((e) => e.ts >= since),

    taskTotal: async (taskId) => this.taskTotals.get(taskId) ?? 0n,
    addTaskTotal: async (taskId, amt) => {
      this.undo(this.taskTotals, taskId);
      this.taskTotals.set(taskId, (this.taskTotals.get(taskId) ?? 0n) + amt);
    },

    merchantSeen: async (root, host) => this.merchants.get(root)?.has(host) ?? false,
    markMerchant: async (root, host) => {
      this.undo(this.merchants, root);
      this.merchants.set(root, new Set([...(this.merchants.get(root) ?? []), host]));
    },

    getStepUp: async (handle) => this.stepUps.get(handle),
    putStepUp: async (a) => {
      this.undo(this.stepUps, a.handle);
      this.stepUps.set(a.handle, a);
    },
    findStepUps: async (q) => {
      const out = [...this.stepUps.values()]
        .filter((a) => matchesStepUpQuery(a, q))
        .sort(compareStepUps);
      return q.limit === undefined ? out : out.slice(0, q.limit);
    },

    killed: async (root) => this.kills.has(root),
    setKilled: async (root, on) => {
      const had = this.kills.has(root);
      this.journal.push(() => void (had ? this.kills.add(root) : this.kills.delete(root)));
      if (on) this.kills.add(root);
      else this.kills.delete(root);
    },
  };

  async transact<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T> {
    const run = this.queue.then(async () => {
      this.journal = [];
      try {
        return await fn(this.tx);
      } catch (err) {
        for (let i = this.journal.length - 1; i >= 0; i--) this.journal[i]!();
        throw err;
      } finally {
        this.journal = [];
      }
    });
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async read<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T> {
    return fn(this.tx);
  }
}
