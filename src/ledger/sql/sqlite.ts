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

import {
  type AppliedMigration,
  LEDGER_MIGRATIONS,
  MIGRATIONS_TABLE,
  inspectSqliteMigrations,
  runSqliteMigrations,
} from './migrations.js';

/**
 * Durable ledger state on SQLite - the local-dev and CLI store.
 *
 * SQLite is the easy case for the reason the roadmap says: one writer. A
 * `BEGIN IMMEDIATE` takes the database write lock for the whole transaction, so
 * `transact` is serialized by the engine and the root-to-leaf lock ordering that
 * Postgres depends on is vacuous here: there is never a second writer to
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

/** STRICT tables reject a bound boolean, and SQLite has no boolean type anyway. */
function bind(v: unknown): SQLInputValue {
  if (typeof v === 'boolean') return v ? 1 : 0;
  return v as SQLInputValue;
}

/**
 * Every ledger table and column this store reads, derived by applying
 * `LEDGER_MIGRATIONS` to an empty in-memory database (excluding the internal
 * `schema_migrations` ledger). Not a second list: any column added by a new
 * migration is required of a read-only open automatically.
 */
function declaredColumns(): Map<string, Set<string>> {
  const mem = new DatabaseSync(':memory:');
  try {
    runSqliteMigrations(mem, LEDGER_MIGRATIONS);
    const tables = mem
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name != ?")
      .all(MIGRATIONS_TABLE) as Row[];
    return columnsOf(
      mem,
      tables.map((r) => r['name'] as string),
    );
  } finally {
    mem.close();
  }
}

function columnsOf(db: DatabaseSyncType, tables: string[]): Map<string, Set<string>> {
  const stmt = db.prepare('SELECT name FROM pragma_table_info(?)');
  return new Map(
    tables.map((t) => [t, new Set((stmt.all(t) as Row[]).map((r) => r['name'] as string))]),
  );
}

function missingLedgerColumns(db: DatabaseSyncType): string[] {
  const declared = declaredColumns();
  const present = columnsOf(db, [...declared.keys()]);
  const missing: string[] = [];
  for (const [table, columns] of declared) {
    const have = present.get(table)!;
    if (have.size === 0) {
      missing.push(table);
      continue;
    }
    for (const c of columns) if (!have.has(c)) missing.push(`${table}.${c}`);
  }
  return missing;
}

/** See `SqliteStoreOptions.readOnly`. */
function openReadOnly(location: string | undefined): DatabaseSyncType {
  if (location === undefined || location === '' || location === ':memory:') {
    throw new Error(
      'a read-only SqliteStore needs the path of an existing ledger file: an in-memory or temporary database opened read-only is empty and stays empty',
    );
  }
  // Fails, and creates nothing, when the file does not exist.
  const db = new DatabaseSync(location, { readOnly: true });
  try {
    // A second refusal under the flag, for a runtime that ever opens this
    // without honouring it. It refuses every statement this store can issue;
    // it would not refuse a journal-mode change, and nothing here issues one.
    db.exec('PRAGMA query_only = ON');
    db.exec('PRAGMA busy_timeout = 5000');

    // Refuse databases migrated by a newer binary or with altered migration checksums.
    inspectSqliteMigrations(db, LEDGER_MIGRATIONS);

    const missing = missingLedgerColumns(db);
    if (missing.length > 0) {
      throw new Error(
        `ledger file ${location} predates this store, missing ${missing.join(', ')}. ` +
          'A read-only store cannot add them; a writable SqliteStore adds them on open, which the process that owns the file does on start.',
      );
    }
    return db;
  } catch (err) {
    db.close();
    throw err;
  }
}

export interface SqliteStoreOptions {
  /** File path, or `:memory:`. */
  location?: string;
  clock?: () => number;
  /**
   * Open an existing ledger file without changing it, for a reader beside the
   * process that owns it: a status command, a console, an audit export.
   *
   * A writable open is not that, even when nothing is spent through it. The
   * constructor sets the journal mode and runs pending schema migrations, so
   * opening a file to look at it can migrate it out from under the gateway
   * that owns it. Read-only skips all of that, opens the file with SQLite's
   * own read-only flag so the engine refuses every write, and refuses
   * `transact` outright.
   *
   * It needs a file that exists and already has every table and column this
   * store reads. A file that predates one is refused by name rather than read
   * with fields missing, and the remedy is the writable open the owner already
   * does on start.
   *
   * The database file is not touched. Its WAL sidecars can be: SQLite creates
   * `-wal` and `-shm` to read a WAL database that nobody else has open, and a
   * read-only connection cannot checkpoint them away on close. The log is left
   * empty, and the owner's next close removes both.
   */
  readOnly?: boolean;
}

export class SqliteStore implements LedgerStore {
  private readonly db: DatabaseSyncType;
  private readonly clock: () => number;
  private readonly readOnly: boolean;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: SqliteStoreOptions = {}) {
    this.clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
    this.readOnly = opts.readOnly === true;
    if (this.readOnly) {
      this.db = openReadOnly(opts.location);
      return;
    }
    this.db = new DatabaseSync(opts.location ?? ':memory:');
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA busy_timeout = 5000');
    runSqliteMigrations(this.db, LEDGER_MIGRATIONS, { clock: this.clock });

    // If an external tool dropped a baseline table or column after migrations
    // were recorded, heal idempotently using the baseline v1..v3 definitions
    // rather than failing on the first read or write.
    if (missingLedgerColumns(this.db).length > 0) {
      this.repairBaselineSchema();
    }
  }

  private repairBaselineSchema(): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const ctx = {
        exec: (sql: string) => this.db.exec(sql),
        query: (sql: string, params: unknown[] = []) => this.all(sql, params),
        hasColumn: (table: string, column: string) =>
          this.all('SELECT name FROM pragma_table_info(?)', [table]).some(
            (r) => r['name'] === column,
          ),
        addColumnIfMissing: (table: string, column: string, declaration: string) => {
          const present = this.all('SELECT name FROM pragma_table_info(?)', [table]).some(
            (r) => r['name'] === column,
          );
          if (!present) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${declaration}`);
        },
      };
      for (const m of LEDGER_MIGRATIONS.slice(0, 3)) {
        if (typeof m.sqlite === 'string') {
          this.db.exec(m.sqlite);
        } else {
          m.sqlite(ctx);
        }
      }
      this.db.exec('COMMIT');
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Ignore rollback failure.
      }
      throw err;
    }
  }

  /** Highest migration version recorded in `schema_migrations` (0 if uninitialized). */
  schemaVersion(): number {
    return inspectSqliteMigrations(this.db, LEDGER_MIGRATIONS).currentVersion;
  }

  /** Ordered list of migrations applied to this database. */
  appliedMigrations(): AppliedMigration[] {
    return inspectSqliteMigrations(this.db, LEDGER_MIGRATIONS).applied;
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
    // Refused before `BEGIN`, not left to the engine: SQLite grants
    // `BEGIN IMMEDIATE` on a read-only connection, so a closure that only reads
    // would commit cleanly and a caller would take the critical section for
    // granted where none can exist.
    if (this.readOnly) {
      throw new Error(
        'this SqliteStore was opened read-only: transact is refused, and every Ledger method that changes state goes through it',
      );
    }
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
   *
   * A read-only store is a second connection, so it has the opposite property:
   * it sees what the owner has committed and never a transaction still open,
   * and in WAL mode it does not wait on the owner's write lock to see it. Each
   * statement is its own snapshot, so a method that reads twice, as
   * `budgetTree` does, can straddle a commit between the two.
   */
  async read<T>(fn: (tx: LedgerTx) => Promise<T>): Promise<T> {
    return fn(this.tx);
  }
}
