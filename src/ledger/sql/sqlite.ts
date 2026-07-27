import { createRequire } from 'node:module';

import type { DatabaseSync as DatabaseSyncType, SQLInputValue } from 'node:sqlite';

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
  idempotentToRow,
  rowToIdempotent,
  rowToStepUp,
  stepUpToRow,
  stepUpWhere,
} from './codec.js';

/**
 * Durable ledger state on SQLite — the local-dev and CLI store.
 *
 * SQLite is the easy case for the reason the roadmap says: one writer. A
 * `BEGIN IMMEDIATE` takes the database write lock for the whole transaction, so
 * `transact` is serialized by the engine and the root-to-leaf lock ordering that
 * Postgres depends on is vacuous here — there is never a second writer to
 * deadlock against. `lockPath` is therefore just a read, and that is not a
 * shortcut: it is what "single-writer, trivial serialization" means.
 *
 * This is also why SQLite is not the answer for the real thing. Serializing
 * every spend in the deployment behind one write lock is correct and does not
 * scale, which is the trade the two stores exist to let a deployment make.
 *
 * Imported directly rather than through the package barrel: `node:sqlite` is
 * still flagged experimental and prints a warning on load, which nobody who is
 * not using this store should have to see.
 */

/**
 * Loaded through `createRequire` rather than imported.
 *
 * `node:sqlite` is a *prefix-only* builtin: Node lists it in `builtinModules` as
 * `"node:sqlite"`, not `"sqlite"`. Bundlers that test membership by stripping
 * the prefix and looking up the bare name therefore decide it is not a builtin
 * and go looking for an npm package called `sqlite`. A runtime require is opaque
 * to that analysis, so this store works under any bundler instead of requiring
 * each consumer to patch their resolver.
 */
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: typeof DatabaseSyncType;
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS mandate_node (
  jti           TEXT PRIMARY KEY,
  parent        TEXT,
  root          TEXT NOT NULL,
  issuer        TEXT NOT NULL DEFAULT '',
  token_hash    TEXT NOT NULL,
  budget_scaled TEXT,
  currency      TEXT,
  spent_scaled  TEXT NOT NULL,
  rate          TEXT,
  rate_events   TEXT NOT NULL,
  revoked       INTEGER NOT NULL,
  status_idx    INTEGER,
  exp           INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS mandate_node_root ON mandate_node (root);

CREATE TABLE IF NOT EXISTS revocation (
  root TEXT NOT NULL,
  jti  TEXT NOT NULL,
  at   INTEGER NOT NULL,
  PRIMARY KEY (root, jti)
) STRICT;

CREATE TABLE IF NOT EXISTS reservation (
  id            TEXT PRIMARY KEY,
  root          TEXT NOT NULL,
  status        TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  has_directive INTEGER NOT NULL,
  escalated     INTEGER NOT NULL,
  doc           TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS reservation_sweep
  ON reservation (status, has_directive, expires_at);
CREATE INDEX IF NOT EXISTS reservation_order ON reservation (created_at, id);

CREATE TABLE IF NOT EXISTS spend_history (
  root          TEXT NOT NULL,
  ts            INTEGER NOT NULL,
  amount_scaled TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS spend_history_root_ts ON spend_history (root, ts);

CREATE TABLE IF NOT EXISTS task_total (
  task_id      TEXT PRIMARY KEY,
  total_scaled TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS merchant_seen (
  root TEXT NOT NULL,
  host TEXT NOT NULL,
  PRIMARY KEY (root, host)
) STRICT;

CREATE TABLE IF NOT EXISTS step_up (
  handle            TEXT PRIMARY KEY,
  root              TEXT NOT NULL,
  resource          TEXT NOT NULL,
  max_amount_scaled TEXT NOT NULL,
  currency          TEXT NOT NULL,
  expires_at        INTEGER NOT NULL,
  used              INTEGER NOT NULL,
  state             TEXT NOT NULL,
  requested_at      INTEGER NOT NULL,
  agent             TEXT NOT NULL,
  task_id           TEXT,
  decision          TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS kill_switch (
  root TEXT PRIMARY KEY
) STRICT;

CREATE TABLE IF NOT EXISTS nonce (
  nonce      TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS idempotency (
  key          TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  response     TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
) STRICT;
`;

/** STRICT tables reject a bound boolean, and SQLite has no boolean type anyway. */
function bind(v: unknown): SQLInputValue {
  if (typeof v === 'boolean') return v ? 1 : 0;
  return v as SQLInputValue;
}

export interface SqliteStoreOptions {
  /** File path, or `:memory:`. */
  location?: string;
  clock?: () => number;
}

export class SqliteStore implements LedgerStore {
  private readonly db: DatabaseSyncType;
  private readonly clock: () => number;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: SqliteStoreOptions = {}) {
    this.db = new DatabaseSync(opts.location ?? ':memory:');
    this.clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA busy_timeout = 5000');
    this.db.exec(SCHEMA);
    this.addMissingColumns('mandate_node', [
      ['issuer', "TEXT NOT NULL DEFAULT ''"],
      ['status_idx', 'INTEGER'],
    ]);
    this.addMissingColumns('step_up', [
      ['state', "TEXT NOT NULL DEFAULT 'pending'"],
      ['requested_at', 'INTEGER NOT NULL DEFAULT 0'],
      ['agent', "TEXT NOT NULL DEFAULT ''"],
      ['task_id', 'TEXT'],
      ['decision', 'TEXT'],
    ]);
    // After the column check, not inside SCHEMA: an index over columns a
    // pre-existing table does not have yet fails, and takes the DDL with it.
    this.db.exec('CREATE INDEX IF NOT EXISTS step_up_queue ON step_up (state, requested_at)');
  }

  /**
   * `CREATE TABLE IF NOT EXISTS` is not a migration — it does nothing at all to
   * a table that already exists, so a database created before a column was added
   * fails on the first write that mentions it.
   *
   * SQLite has no `ADD COLUMN IF NOT EXISTS`, so existence is checked against
   * `pragma_table_info` first. This is a stopgap for additive columns and not a
   * migration framework: there is no version table and nothing here can rename,
   * drop, or backfill.
   *
   * The default for `state` is `pending` rather than `approved` on purpose. Under
   * the old semantics any handle was spendable; carrying those rows forward as
   * approved would carry the self-approval hole forward with them.
   */
  private addMissingColumns(table: string, columns: Array<[string, string]>): void {
    const present = new Set(
      this.all('SELECT name FROM pragma_table_info(?)', [table]).map((r) => r['name'] as string),
    );
    for (const [name, declaration] of columns) {
      if (!present.has(name)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${declaration}`);
    }
  }

  close(): void {
    this.db.close();
  }

  private all(sql: string, params: unknown[] = []): Row[] {
    return this.db.prepare(sql).all(...params.map(bind)) as Row[];
  }

  private one(sql: string, params: unknown[] = []): Row | undefined {
    return this.db.prepare(sql).get(...params.map(bind)) as Row | undefined;
  }

  private run(sql: string, params: unknown[] = []): void {
    this.db.prepare(sql).run(...params.map(bind));
  }

  private readonly tx: LedgerTx = {
    getNode: async (jti) => {
      const r = this.one('SELECT * FROM mandate_node WHERE jti = ?', [jti]);
      return r === undefined ? undefined : rowToNode(r);
    },

    // No ordering concern: `BEGIN IMMEDIATE` already holds the only write lock.
    lockPath: async (path) => {
      const out: Array<MandateNode | undefined> = [];
      for (const jti of path) {
        const r = this.one('SELECT * FROM mandate_node WHERE jti = ?', [jti]);
        out.push(r === undefined ? undefined : rowToNode(r));
      }
      return out;
    },

    putNode: async (node: MandateNode) => {
      const r = nodeToRow(node);
      this.run(
        `INSERT INTO mandate_node
           (jti, parent, root, issuer, token_hash, budget_scaled, currency,
            spent_scaled, rate, rate_events, revoked, status_idx, exp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(jti) DO UPDATE SET
           parent = excluded.parent,
           root = excluded.root,
           issuer = excluded.issuer,
           token_hash = excluded.token_hash,
           budget_scaled = excluded.budget_scaled,
           currency = excluded.currency,
           spent_scaled = excluded.spent_scaled,
           rate = excluded.rate,
           rate_events = excluded.rate_events,
           revoked = excluded.revoked,
           status_idx = excluded.status_idx,
           exp = excluded.exp`,
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
          r['status_idx'],
          r['exp'],
        ],
      );
    },

    findNodes: async (root) =>
      this.all('SELECT * FROM mandate_node WHERE root = ? ORDER BY jti', [root]).map(rowToNode),

    consumeNonce: async (nonce, expiresAt) => {
      this.run('DELETE FROM nonce WHERE expires_at < ?', [this.clock()]);
      if (this.one('SELECT 1 AS hit FROM nonce WHERE nonce = ?', [nonce]) !== undefined) {
        return false;
      }
      this.run('INSERT INTO nonce (nonce, expires_at) VALUES (?, ?)', [nonce, expiresAt]);
      return true;
    },

    putRevocation: async (root, jti, at) => {
      this.run(
        'INSERT INTO revocation (root, jti, at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING',
        [root, jti, at],
      );
    },

    isRevoked: async (root, jti) =>
      this.one('SELECT 1 AS hit FROM revocation WHERE root = ? AND jti = ?', [root, jti]) !==
      undefined,

    getIdempotent: async (key) => {
      const r = this.one(
        'SELECT * FROM idempotency WHERE key = ? AND expires_at >= ?',
        [key, this.clock()],
      );
      return r === undefined ? undefined : rowToIdempotent(r);
    },

    putIdempotent: async (record) => {
      this.run('DELETE FROM idempotency WHERE expires_at < ?', [this.clock()]);
      const r = idempotentToRow(record);
      this.run(
        `INSERT INTO idempotency (key, request_hash, response, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
           request_hash = excluded.request_hash,
           response = excluded.response,
           created_at = excluded.created_at,
           expires_at = excluded.expires_at`,
        [r['key'], r['request_hash'], r['response'], r['created_at'], r['expires_at']],
      );
    },

    getReservation: async (id) => {
      const r = this.one('SELECT doc FROM reservation WHERE id = ?', [id]);
      return r === undefined ? undefined : rowToReservation(r);
    },

    putReservation: async (res: Reservation) => {
      const r = reservationToRow(res);
      this.run(
        `INSERT INTO reservation
           (id, root, status, created_at, expires_at, has_directive, escalated, doc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           root = excluded.root,
           status = excluded.status,
           created_at = excluded.created_at,
           expires_at = excluded.expires_at,
           has_directive = excluded.has_directive,
           escalated = excluded.escalated,
           doc = excluded.doc`,
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
      const { sql, params } = reservationWhere(q, () => '?');
      const limit = q.limit === undefined ? '' : ` LIMIT ${Math.max(0, Math.floor(q.limit))}`;
      return this.all(
        `SELECT doc FROM reservation WHERE ${sql} ORDER BY created_at, id${limit}`,
        params,
      ).map(rowToReservation);
    },

    appendHistory: async (root, e: SpendEvent) => {
      this.run('INSERT INTO spend_history (root, ts, amount_scaled) VALUES (?, ?, ?)', [
        root,
        e.ts,
        e.amountScaled.toString(),
      ]);
      this.run('DELETE FROM spend_history WHERE root = ? AND ts < ?', [
        root,
        this.clock() - HISTORY_RETENTION_SECONDS,
      ]);
    },

    historySince: async (root, since) =>
      this.all('SELECT ts, amount_scaled FROM spend_history WHERE root = ? AND ts >= ?', [
        root,
        since,
      ]).map(rowToSpendEvent),

    taskTotal: async (taskId) => {
      const r = this.one('SELECT total_scaled FROM task_total WHERE task_id = ?', [taskId]);
      return r === undefined ? 0n : big(r['total_scaled']);
    },

    // Read-modify-write is safe here only because there is one writer. Postgres
    // increments in SQL instead; see the note in `postgres.ts`.
    addTaskTotal: async (taskId, amt) => {
      const r = this.one('SELECT total_scaled FROM task_total WHERE task_id = ?', [taskId]);
      const next = (r === undefined ? 0n : big(r['total_scaled'])) + amt;
      this.run(
        `INSERT INTO task_total (task_id, total_scaled) VALUES (?, ?)
         ON CONFLICT(task_id) DO UPDATE SET total_scaled = excluded.total_scaled`,
        [taskId, next.toString()],
      );
    },

    merchantSeen: async (root, host) =>
      this.one('SELECT 1 AS hit FROM merchant_seen WHERE root = ? AND host = ?', [root, host]) !==
      undefined,

    markMerchant: async (root, host) => {
      this.run(
        'INSERT INTO merchant_seen (root, host) VALUES (?, ?) ON CONFLICT DO NOTHING',
        [root, host],
      );
    },

    getStepUp: async (handle) => {
      const r = this.one('SELECT * FROM step_up WHERE handle = ?', [handle]);
      return r === undefined ? undefined : rowToStepUp(r);
    },

    putStepUp: async (a: StepUpApproval) => {
      const r = stepUpToRow(a);
      this.run(
        `INSERT INTO step_up
           (handle, root, resource, max_amount_scaled, currency, expires_at, used,
            state, requested_at, agent, task_id, decision)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(handle) DO UPDATE SET
           root = excluded.root,
           resource = excluded.resource,
           max_amount_scaled = excluded.max_amount_scaled,
           currency = excluded.currency,
           expires_at = excluded.expires_at,
           used = excluded.used,
           state = excluded.state,
           requested_at = excluded.requested_at,
           agent = excluded.agent,
           task_id = excluded.task_id,
           decision = excluded.decision`,
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
      const { sql, params } = stepUpWhere(q, () => '?');
      const limit = q.limit === undefined ? '' : ` LIMIT ${Math.max(0, Math.floor(q.limit))}`;
      return this.all(
        `SELECT * FROM step_up WHERE ${sql} ORDER BY requested_at, handle${limit}`,
        params,
      ).map(rowToStepUp);
    },

    killed: async (root) =>
      this.one('SELECT 1 AS hit FROM kill_switch WHERE root = ?', [root]) !== undefined,

    setKilled: async (root, on) => {
      if (on) {
        this.run('INSERT INTO kill_switch (root) VALUES (?) ON CONFLICT DO NOTHING', [root]);
      } else {
        this.run('DELETE FROM kill_switch WHERE root = ?', [root]);
      }
    },
  };

  /**
   * One connection, one transaction at a time. The promise queue is not
   * belt-and-braces over `BEGIN IMMEDIATE` — SQLite has no nested transactions,
   * so a second `BEGIN` on this connection while the first is open is an error,
   * and `reserve` holds its transaction open across `await`s by construction.
   */
  async transact<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T> {
    const run = this.queue.then(async () => {
      this.db.exec('BEGIN IMMEDIATE');
      try {
        const out = await fn(this.tx);
        this.db.exec('COMMIT');
        return out;
      } catch (err) {
        try {
          this.db.exec('ROLLBACK');
        } catch {
          // A failed COMMIT has already ended the transaction, so ROLLBACK then
          // raises "no transaction is active" — a second error that would mask
          // the first. The connection is left usable either way, which is what
          // the next `BEGIN IMMEDIATE` needs.
        }
        throw err;
      }
    });
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * Unserialized, as the interface specifies. On one connection that means a
   * `read` overlapping an open `transact` sees that transaction's uncommitted
   * writes. Both callers of `read` on a decision path — the two reconcilers —
   * re-read and re-check status inside `transact` before acting, which is the
   * only reason this is safe.
   */
  async read<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T> {
    return fn(this.tx);
  }
}
