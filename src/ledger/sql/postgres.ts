import { createHash } from 'node:crypto';

import {
  HISTORY_RETENTION_SECONDS,
  type LedgerStore,
  type LedgerTx,
  type MandateNode,
  type Reservation,
  type ReservationQuery,
  type SpendEvent,
  type StepUpApproval,
  type StepUpQuery,
} from '../store.js';
import {
  type Row,
  big,
  nodeToRow,
  reservationToRow,
  reservationWhere,
  rowToNode,
  rowToReservation,
  rowToSpendEvent,
  rowToStepUp,
  stepUpToRow,
  stepUpWhere,
} from './codec.js';

/**
 * Durable ledger state on Postgres — the real one.
 *
 * ## Lock order
 *
 * Every transaction that takes more than one lock takes them in this order, and
 * a new one must:
 *
 *   1. `reservation` — `settle`, `refund` and `sweepExpired` start here
 *   2. mandate nodes — **root-to-leaf**, always via `lockPath` or `getNode`,
 *      as transaction-scoped advisory locks rather than row locks
 *   3. `step_up`
 *   4. `task_total`
 *
 * `reserve` enters at (2) and only ever *inserts* its reservation, under an id
 * minted for that attempt. That is what keeps (1) and (2) from forming a cycle:
 * a cycle needs `reserve` to wait on a reservation row while holding a node, and
 * an insert of a fresh primary key waits for nobody.
 *
 * Root-to-leaf within (2) is the ordering `store.ts` calls load-bearing. Paths
 * are root-anchored, so any two overlap in a common prefix and lock the shared
 * keys in the same relative order. Mixed order deadlocks on ordinary traffic,
 * not adversarial traffic: every spend under a principal touches the root.
 *
 * Nodes are locked by *key* and not by row because the row is not there yet on a
 * mandate's first spend, and `FOR UPDATE` cannot lock an absent row. See
 * `lockNode`.
 *
 * ## Isolation
 *
 * `READ COMMITTED`, with an explicit lock taken before every read whose row this
 * transaction may later write — `FOR UPDATE` where the row is guaranteed to
 * exist, an advisory lock on the key where it is not.
 *
 * `READ COMMITTED` is what makes lock-then-read correct: each statement takes a
 * fresh snapshot, so the read issued after the lock is granted sees the winner's
 * committed `spent_scaled` rather than a snapshot from before the wait.
 * `REPEATABLE READ` would pin the snapshot to the start of the transaction, so
 * the read after the lock would return the *stale* row and the debit would be
 * computed against it — trading a lock wait for a serialization failure on every
 * contended spend, and needing the retry loop to be correct rather than merely
 * resilient. The lock is what serializes here, not the snapshot.
 */

export interface PgQueryResult {
  rows: Row[];
}

/** Structurally satisfied by `pg`'s `PoolClient`; `pg` is not imported here. */
export interface PgClient {
  query(text: string, params?: unknown[]): Promise<PgQueryResult>;
  release?(): void;
}

/** Structurally satisfied by `pg`'s `Pool`. */
export interface PgPool {
  connect(): Promise<PgClient>;
}

export interface PostgresStoreOptions {
  pool: PgPool;
  clock?: () => number;
  /** Attempts after a deadlock or serialization failure before giving up. */
  maxRetries?: number;
}

/** 40001 serialization_failure, 40P01 deadlock_detected. */
const RETRYABLE = new Set(['40001', '40P01']);

function isRetryable(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    typeof (err as { code?: unknown }).code === 'string' &&
    RETRYABLE.has((err as { code: string }).code)
  );
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const TWO_63 = 1n << 63n;
const TWO_64 = 1n << 64n;

/**
 * Transaction-scoped advisory lock key for a `jti`.
 *
 * Derived in JS rather than with `hashtext()` so the key does not depend on an
 * undocumented internal function, and so the same jti maps to the same lock from
 * any client. Returned as a decimal string and cast in SQL: `pg_advisory_*`
 * takes `bigint`, and node-postgres has no first-class `BigInt` parameter.
 *
 * Distinct jtis can collide onto one key. That costs two unrelated paths a
 * needless serialization and costs correctness nothing, which is the right side
 * of that trade to be on.
 */
export function advisoryKey(jti: string): string {
  const unsigned = BigInt(`0x${createHash('sha256').update(jti, 'utf8').digest('hex').slice(0, 16)}`);
  return (unsigned >= TWO_63 ? unsigned - TWO_64 : unsigned).toString();
}

export const SCHEMA = `
CREATE TABLE IF NOT EXISTS mandate_node (
  jti           TEXT PRIMARY KEY,
  parent        TEXT,
  root          TEXT NOT NULL,
  issuer        TEXT NOT NULL DEFAULT '',
  token_hash    TEXT NOT NULL,
  budget_scaled NUMERIC,
  currency      TEXT,
  spent_scaled  NUMERIC NOT NULL,
  rate          TEXT,
  rate_events   TEXT NOT NULL,
  revoked       BOOLEAN NOT NULL,
  exp           BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS mandate_node_root ON mandate_node (root);

CREATE TABLE IF NOT EXISTS reservation (
  id            TEXT PRIMARY KEY,
  root          TEXT NOT NULL,
  status        TEXT NOT NULL,
  created_at    BIGINT NOT NULL,
  expires_at    BIGINT NOT NULL,
  has_directive BOOLEAN NOT NULL,
  escalated     BOOLEAN NOT NULL,
  doc           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reservation_sweep
  ON reservation (status, has_directive, expires_at);
CREATE INDEX IF NOT EXISTS reservation_order ON reservation (created_at, id);

CREATE TABLE IF NOT EXISTS spend_history (
  root          TEXT NOT NULL,
  ts            BIGINT NOT NULL,
  amount_scaled NUMERIC NOT NULL
);
CREATE INDEX IF NOT EXISTS spend_history_root_ts ON spend_history (root, ts);

CREATE TABLE IF NOT EXISTS task_total (
  task_id      TEXT PRIMARY KEY,
  total_scaled NUMERIC NOT NULL
);

CREATE TABLE IF NOT EXISTS merchant_seen (
  root TEXT NOT NULL,
  host TEXT NOT NULL,
  PRIMARY KEY (root, host)
);

CREATE TABLE IF NOT EXISTS step_up (
  handle            TEXT PRIMARY KEY,
  root              TEXT NOT NULL,
  resource          TEXT NOT NULL,
  max_amount_scaled NUMERIC NOT NULL,
  currency          TEXT NOT NULL,
  expires_at        BIGINT NOT NULL,
  used              BOOLEAN NOT NULL,
  state             TEXT NOT NULL,
  requested_at      BIGINT NOT NULL,
  agent             TEXT NOT NULL,
  task_id           TEXT,
  decision          TEXT
);

CREATE TABLE IF NOT EXISTS kill_switch (
  root TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS nonce (
  nonce      TEXT PRIMARY KEY,
  expires_at BIGINT NOT NULL
);

-- CREATE TABLE IF NOT EXISTS is not a migration: it silently does nothing to a
-- table that already exists, so a deployment created before the §10.5 columns
-- landed would fail on the first step-up write with "column state does not
-- exist". These are idempotent and run every time.
--
-- Note the default: an existing row becomes pending, not approved. Under the old
-- semantics any handle was spendable, so carrying those rows forward as approved
-- would carry the self-approval hole forward with them. Old handles stop
-- working, and a human can still approve one.
ALTER TABLE mandate_node ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS state        TEXT   NOT NULL DEFAULT 'pending';
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS requested_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS agent        TEXT   NOT NULL DEFAULT '';
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS task_id      TEXT;
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS decision     TEXT;

-- After the ALTERs, not before: an index over columns a pre-existing table does
-- not have yet fails, and takes the whole DDL with it.
CREATE INDEX IF NOT EXISTS step_up_queue ON step_up (state, requested_at);
`;

export const TABLES = [
  'mandate_node',
  'reservation',
  'spend_history',
  'task_total',
  'merchant_seen',
  'step_up',
  'kill_switch',
  'nonce',
] as const;

export class PostgresStore implements LedgerStore {
  private readonly pool: PgPool;
  private readonly clock: () => number;
  private readonly maxRetries: number;

  constructor(opts: PostgresStoreOptions) {
    this.pool = opts.pool;
    this.clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
    this.maxRetries = opts.maxRetries ?? 5;
  }

  /** Idempotent DDL. Separate from the constructor because it awaits. */
  async init(): Promise<void> {
    const c = await this.pool.connect();
    try {
      await c.query(SCHEMA);
    } finally {
      c.release?.();
    }
  }

  /**
   * `locking` is the difference between the two `LedgerTx` flavours, and it is
   * not an optimization.
   *
   * Inside `transact`, a read whose row this transaction may later write must
   * lock it, or two transactions read the same row, both decide, and the second
   * write silently overwrites the first. Two places in `ledger.ts` depend on
   * this and neither could say so against a `Map`:
   *
   *   - `settle` claims a reservation by moving it off `reserved`, and its own
   *     comment says a concurrent settle is stopped by finding a status that has
   *     already changed. Without the lock both callers read `reserved` and both
   *     pay.
   *   - `sweepExpired` selects stale reservations and then refunds them. Without
   *     the lock it can credit a path for a reservation another transaction is
   *     concurrently settling.
   *
   * `read` takes no locks by construction, which is why the interface forbids
   * deciding anything there.
   */
  private makeTx(c: PgClient, locking: boolean): LedgerTx {
    const forUpdate = locking ? ' FOR UPDATE' : '';

    /**
     * `FOR UPDATE` is not usable for mandate nodes, and the reason is the case
     * that matters most: **a mandate's first spend has no row yet.**
     *
     * `SELECT ... FOR UPDATE` on a row that does not exist matches nothing and
     * therefore locks nothing. Two concurrent first spends on the same fresh
     * mandate would both read no node, both compute `spent = 0`, both find the
     * budget untouched, and both `INSERT ... ON CONFLICT DO UPDATE` — the second
     * overwriting the first's debit instead of adding to it. Two spends, one
     * debited. That is the exact overdraw this component exists to prevent, and
     * it would appear on the *first* two concurrent calls against any new
     * mandate rather than in some rare interleaving.
     *
     * An advisory lock is keyed by value rather than by row, so it exists before
     * the row does. It is transaction-scoped, so it releases on COMMIT or
     * ROLLBACK like a row lock, and it is taken in the same root-to-leaf order.
     *
     * This is also what serializes step-up consumption: a handle is bound to a
     * root, and every reserve that could consume it locks that root first.
     */
    const lockNode = async (jti: string): Promise<void> => {
      if (locking) await c.query('SELECT pg_advisory_xact_lock($1::bigint)', [advisoryKey(jti)]);
    };

    return {
      getNode: async (jti) => {
        // `revoke` reads a node and writes it back, so it takes the same lock a
        // path walk would: without it, a revoke and a concurrent debit each
        // write a whole row derived from a stale read, and one of the two edits
        // disappears.
        await lockNode(jti);
        const { rows } = await c.query('SELECT * FROM mandate_node WHERE jti = $1', [jti]);
        return rows[0] === undefined ? undefined : rowToNode(rows[0]);
      },

      /**
       * Lock then read, one node at a time, in the caller's order.
       *
       * A batched `WHERE jti = ANY($1) ORDER BY array_position(...)` would be
       * one round trip, but it makes the lock order a consequence of where the
       * planner puts its locking node relative to the sort — true today, not a
       * documented guarantee, and the failure if it ever changes is intermittent
       * production deadlocks masked by the retry loop. Paths are two or three
       * links deep; the round trips are worth the ordering being stated rather
       * than inferred.
       */
      lockPath: async (path) => {
        const out: Array<MandateNode | undefined> = [];
        for (const jti of path) {
          await lockNode(jti);
          const { rows } = await c.query('SELECT * FROM mandate_node WHERE jti = $1', [jti]);
          out.push(rows[0] === undefined ? undefined : rowToNode(rows[0]));
        }
        return out;
      },

      putNode: async (node: MandateNode) => {
        const r = nodeToRow(node);
        await c.query(
          `INSERT INTO mandate_node
             (jti, parent, root, issuer, token_hash, budget_scaled, currency,
              spent_scaled, rate, rate_events, revoked, exp)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           ON CONFLICT (jti) DO UPDATE SET
             parent = EXCLUDED.parent,
             root = EXCLUDED.root,
             issuer = EXCLUDED.issuer,
             token_hash = EXCLUDED.token_hash,
             budget_scaled = EXCLUDED.budget_scaled,
             currency = EXCLUDED.currency,
             spent_scaled = EXCLUDED.spent_scaled,
             rate = EXCLUDED.rate,
             rate_events = EXCLUDED.rate_events,
             revoked = EXCLUDED.revoked,
             exp = EXCLUDED.exp`,
          [
            r['jti'],
            r['parent'],
            r['root'],
            r['issuer'],
            r['token_hash'],
            r['budget_scaled'],
            r['currency'],
            r['spent_scaled'],
            r['rate'],
            r['rate_events'],
            r['revoked'],
            r['exp'],
          ],
        );
      },

      findNodes: async (root) => {
        const { rows } = await c.query(
          'SELECT * FROM mandate_node WHERE root = $1 ORDER BY jti',
          [root],
        );
        return rows.map(rowToNode);
      },

      consumeNonce: async (nonce, expiresAt) => {
        await c.query('DELETE FROM nonce WHERE expires_at < $1', [this.clock()]);
        const { rows } = await c.query(
          `INSERT INTO nonce (nonce, expires_at) VALUES ($1, $2)
           ON CONFLICT (nonce) DO NOTHING
           RETURNING nonce`,
          [nonce, expiresAt],
        );
        return rows.length > 0;
      },

      getReservation: async (id) => {
        const { rows } = await c.query(
          `SELECT doc FROM reservation WHERE id = $1${forUpdate}`,
          [id],
        );
        return rows[0] === undefined ? undefined : rowToReservation(rows[0]);
      },

      putReservation: async (res: Reservation) => {
        const r = reservationToRow(res);
        await c.query(
          `INSERT INTO reservation
             (id, root, status, created_at, expires_at, has_directive, escalated, doc)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (id) DO UPDATE SET
             root = EXCLUDED.root,
             status = EXCLUDED.status,
             created_at = EXCLUDED.created_at,
             expires_at = EXCLUDED.expires_at,
             has_directive = EXCLUDED.has_directive,
             escalated = EXCLUDED.escalated,
             doc = EXCLUDED.doc`,
          [
            r['id'],
            r['root'],
            r['status'],
            r['created_at'],
            r['expires_at'],
            r['has_directive'],
            r['escalated'],
            r['doc'],
          ],
        );
      },

      findReservations: async (q: ReservationQuery) => {
        const { sql, params } = reservationWhere(q, (i) => `$${i}`);
        const limit = q.limit === undefined ? '' : ` LIMIT ${Math.max(0, Math.floor(q.limit))}`;
        const { rows } = await c.query(
          `SELECT doc FROM reservation WHERE ${sql} ORDER BY created_at, id${limit}${forUpdate}`,
          params,
        );
        return rows.map(rowToReservation);
      },

      appendHistory: async (root, e: SpendEvent) => {
        await c.query('INSERT INTO spend_history (root, ts, amount_scaled) VALUES ($1, $2, $3)', [
          root,
          e.ts,
          e.amountScaled.toString(),
        ]);
        await c.query('DELETE FROM spend_history WHERE root = $1 AND ts < $2', [
          root,
          this.clock() - HISTORY_RETENTION_SECONDS,
        ]);
      },

      historySince: async (root, since) => {
        const { rows } = await c.query(
          'SELECT ts, amount_scaled FROM spend_history WHERE root = $1 AND ts >= $2',
          [root, since],
        );
        return rows.map(rowToSpendEvent);
      },

      /**
       * Materialize before locking: `FOR UPDATE` on a row that does not exist
       * locks nothing, so two transactions would both find no total, both pass
       * the ceiling check and both insert. The empty insert is what gives the
       * lock something to hold.
       */
      taskTotal: async (taskId) => {
        if (locking) {
          await c.query(
            `INSERT INTO task_total (task_id, total_scaled) VALUES ($1, 0)
             ON CONFLICT (task_id) DO NOTHING`,
            [taskId],
          );
        }
        const { rows } = await c.query(
          `SELECT total_scaled FROM task_total WHERE task_id = $1${forUpdate}`,
          [taskId],
        );
        return rows[0] === undefined ? 0n : big(rows[0]['total_scaled']);
      },

      /**
       * The one place a scaled amount is added in SQL rather than in `BigInt`.
       * `NUMERIC` is arbitrary-precision decimal, so the sum is exact, and doing
       * it in one statement makes it atomic without a preceding read — which
       * matters because `addTaskTotal` is reached from `creditPath` on paths
       * that never called `taskTotal` and so hold no lock on this row.
       */
      addTaskTotal: async (taskId, amt) => {
        await c.query(
          `INSERT INTO task_total (task_id, total_scaled) VALUES ($1, $2::numeric)
           ON CONFLICT (task_id) DO UPDATE
             SET total_scaled = task_total.total_scaled + EXCLUDED.total_scaled`,
          [taskId, amt.toString()],
        );
      },

      merchantSeen: async (root, host) => {
        const { rows } = await c.query(
          'SELECT 1 FROM merchant_seen WHERE root = $1 AND host = $2',
          [root, host],
        );
        return rows.length > 0;
      },

      markMerchant: async (root, host) => {
        await c.query(
          'INSERT INTO merchant_seen (root, host) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [root, host],
        );
      },

      getStepUp: async (handle) => {
        const { rows } = await c.query(
          `SELECT * FROM step_up WHERE handle = $1${forUpdate}`,
          [handle],
        );
        return rows[0] === undefined ? undefined : rowToStepUp(rows[0]);
      },

      putStepUp: async (a: StepUpApproval) => {
        const r = stepUpToRow(a);
        await c.query(
          `INSERT INTO step_up
             (handle, root, resource, max_amount_scaled, currency, expires_at, used,
              state, requested_at, agent, task_id, decision)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           ON CONFLICT (handle) DO UPDATE SET
             root = EXCLUDED.root,
             resource = EXCLUDED.resource,
             max_amount_scaled = EXCLUDED.max_amount_scaled,
             currency = EXCLUDED.currency,
             expires_at = EXCLUDED.expires_at,
             used = EXCLUDED.used,
             state = EXCLUDED.state,
             requested_at = EXCLUDED.requested_at,
             agent = EXCLUDED.agent,
             task_id = EXCLUDED.task_id,
             decision = EXCLUDED.decision`,
          [
            r['handle'],
            r['root'],
            r['resource'],
            r['max_amount_scaled'],
            r['currency'],
            r['expires_at'],
            r['used'],
            r['state'],
            r['requested_at'],
            r['agent'],
            r['task_id'],
            r['decision'],
          ],
        );
      },

      findStepUps: async (q: StepUpQuery) => {
        const { sql, params } = stepUpWhere(q, (i) => `$${i}`);
        const limit = q.limit === undefined ? '' : ` LIMIT ${Math.max(0, Math.floor(q.limit))}`;
        const { rows } = await c.query(
          `SELECT * FROM step_up WHERE ${sql} ORDER BY requested_at, handle${limit}${forUpdate}`,
          params,
        );
        return rows.map(rowToStepUp);
      },

      killed: async (root) => {
        const { rows } = await c.query('SELECT 1 FROM kill_switch WHERE root = $1', [root]);
        return rows.length > 0;
      },

      setKilled: async (root, on) => {
        if (on) {
          await c.query('INSERT INTO kill_switch (root) VALUES ($1) ON CONFLICT DO NOTHING', [
            root,
          ]);
        } else {
          await c.query('DELETE FROM kill_switch WHERE root = $1', [root]);
        }
      },
    };
  }

  /**
   * One connection per transaction, so concurrent callers are concurrent in the
   * database rather than queued in the process. That is the whole difference
   * between this store and the other two, and the reason the concurrency
   * properties mean something different when pointed here.
   *
   * The retry covers deadlock and serialization failure. It is sound only
   * because `fn` is replayable — every attempt re-reads through `tx` and derives
   * nothing from a previous one — which is a contract on `transact`, stated in
   * `store.ts`, not an accident of the current callers.
   */
  async transact<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const c = await this.pool.connect();
      try {
        await c.query('BEGIN');
        const out = await fn(this.makeTx(c, true));
        await c.query('COMMIT');
        return out;
      } catch (err) {
        try {
          await c.query('ROLLBACK');
        } catch {
          // The connection may already be unusable; the original error is the
          // one worth reporting.
        }
        if (attempt >= this.maxRetries || !isRetryable(err)) throw err;
        await sleep(Math.min(200, 5 * 2 ** attempt) * (0.5 + Math.random()));
      } finally {
        c.release?.();
      }
    }
  }

  async read<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      return await fn(this.makeTx(c, false));
    } finally {
      c.release?.();
    }
  }
}
