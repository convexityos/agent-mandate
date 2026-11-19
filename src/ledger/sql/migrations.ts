import { createHash } from 'node:crypto';
import type { DatabaseSync as DatabaseSyncType, SQLInputValue } from 'node:sqlite';

import type { Row } from './codec.js';

/**
 * Versioned, transactional, checksum-verified SQL migrations for both
 * `SqliteStore` and `PostgresStore`.
 *
 * Replaces the ad-hoc `CREATE TABLE IF NOT EXISTS` + column-patching stopgap
 * with an explicit `schema_migrations` version ledger so both additive and
 * non-additive schema evolutions (renames, table rebuilds, backfills) run
 * exactly once, atomically, and fail closed on drift or binary downgrade.
 *
 * Design invariants:
 *   1. Every migration runs inside a single database transaction (`BEGIN IMMEDIATE`
 *      on SQLite; `BEGIN` + transaction-scoped `pg_advisory_xact_lock` on Postgres).
 *      A failing migration rolls back completely and never leaves a partial version.
 *   2. Applied versions are recorded with a SHA-256 checksum. Editing an already
 *      shipped migration triggers `MigrationChecksumError` on startup rather than
 *      silently drifting across environments.
 *   3. A database whose max recorded version exceeds this binary's highest known
 *      migration triggers `MigrationFutureVersionError`, refusing to let an older
 *      binary corrupt a newer schema (both on writable and read-only opens).
 *   4. Baseline migrations (v1..v3) are idempotent so pre-existing databases
 *      created before `schema_migrations` existed upgrade cleanly in place and
 *      carry existing `step_up` rows forward as `pending` (never `approved`).
 */

export type SqlDialect = 'sqlite' | 'postgres';

export const MIGRATIONS_TABLE = 'schema_migrations';

const TWO_63 = 1n << 63n;
const TWO_64 = 1n << 64n;

/**
 * Deterministic signed 64-bit advisory lock key for serializing concurrent
 * Postgres startups running migrations against the same database.
 */
export const POSTGRES_MIGRATION_LOCK_KEY: string = (() => {
  const unsigned = BigInt(
    `0x${createHash('sha256').update('__am1_schema_migrations__', 'utf8').digest('hex').slice(0, 16)}`,
  );
  return (unsigned >= TWO_63 ? unsigned - TWO_64 : unsigned).toString();
})();

export interface MigrationPgClient {
  query(text: string, params?: unknown[]): Promise<{ rows: Row[] }>;
}

export interface SqliteMigrationContext {
  exec(sql: string): void;
  query(sql: string, params?: unknown[]): Row[];
  hasColumn(table: string, column: string): boolean;
  addColumnIfMissing(table: string, column: string, declaration: string): void;
}

export interface PostgresMigrationContext {
  query(sql: string, params?: unknown[]): Promise<{ rows: Row[] }>;
}

export interface SqlMigration {
  /** Strictly ascending positive integer version (1, 2, 3, ...). */
  readonly version: number;
  /** Short, unique, human-readable migration identifier. */
  readonly name: string;
  /** SQLite SQL text or transactional imperative step. */
  readonly sqlite: string | ((ctx: SqliteMigrationContext) => void);
  /** Postgres SQL text or transactional imperative step. */
  readonly postgres: string | ((ctx: PostgresMigrationContext) => Promise<void>);
  /**
   * Canonical text hashed into `schema_migrations.checksum`. Required whenever
   * `sqlite` or `postgres` is a function so checksums remain stable across
   * transpilers, bundlers, and runtimes.
   */
  readonly checksumSource?: string;
}

export interface AppliedMigration {
  version: number;
  name: string;
  checksum: string;
  appliedAt: number;
}

export interface MigrationRunResult {
  dialect: SqlDialect;
  currentVersion: number;
  applied: AppliedMigration[];
  alreadyApplied: number;
}

export interface MigrationInspection {
  dialect: SqlDialect;
  hasTable: boolean;
  currentVersion: number;
  applied: AppliedMigration[];
  pending: number[];
}

export interface MigrationRunOptions {
  clock?: () => number;
  /** Optional upper version bound (inclusive), useful for staged rollouts and testing. */
  targetVersion?: number;
}

export class MigrationOrderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MigrationOrderError';
  }
}

export class MigrationChecksumError extends Error {
  readonly version: number;
  readonly expected: string;
  readonly actual: string;

  constructor(version: number, name: string, expected: string, actual: string) {
    super(
      `migration v${version} (${name}) checksum mismatch: database recorded ${actual}, binary expects ${expected}`,
    );
    this.name = 'MigrationChecksumError';
    this.version = version;
    this.expected = expected;
    this.actual = actual;
  }
}

export class MigrationFutureVersionError extends Error {
  readonly dbVersion: number;
  readonly maxSupportedVersion: number;

  constructor(dbVersion: number, maxSupportedVersion: number) {
    super(
      `database schema version v${dbVersion} is newer than this binary supports (max v${maxSupportedVersion}); upgrade the binary before opening this ledger`,
    );
    this.name = 'MigrationFutureVersionError';
    this.dbVersion = dbVersion;
    this.maxSupportedVersion = maxSupportedVersion;
  }
}

function bindSqlite(v: unknown): SQLInputValue {
  if (typeof v === 'boolean') return v ? 1 : 0;
  return v as SQLInputValue;
}

/** Validate migration sequence invariants before touching any database. */
export function validateMigrations(migrations: readonly SqlMigration[]): void {
  if (migrations.length === 0) {
    throw new MigrationOrderError('migration list must not be empty');
  }
  let prev = 0;
  const names = new Set<string>();
  for (const m of migrations) {
    if (!Number.isInteger(m.version) || m.version <= 0) {
      throw new MigrationOrderError(`migration version must be a positive integer, got ${m.version}`);
    }
    if (m.version <= prev) {
      throw new MigrationOrderError(
        `migrations must have strictly ascending versions: v${m.version} follows v${prev}`,
      );
    }
    if (typeof m.name !== 'string' || m.name.trim().length === 0) {
      throw new MigrationOrderError(`migration v${m.version} must have a non-empty name`);
    }
    if (names.has(m.name)) {
      throw new MigrationOrderError(`duplicate migration name "${m.name}" at v${m.version}`);
    }
    if (
      (typeof m.sqlite === 'function' || typeof m.postgres === 'function') &&
      (typeof m.checksumSource !== 'string' || m.checksumSource.trim().length === 0)
    ) {
      throw new MigrationOrderError(
        `imperative migration v${m.version} (${m.name}) must specify a non-empty checksumSource`,
      );
    }
    names.add(m.name);
    prev = m.version;
  }
}

/** Deterministic SHA-256 checksum for a migration and dialect. */
export function migrationChecksum(m: SqlMigration, dialect: SqlDialect): string {
  const step = dialect === 'sqlite' ? m.sqlite : m.postgres;
  const body =
    m.checksumSource !== undefined
      ? m.checksumSource
      : typeof step === 'string'
        ? step
        : step.toString();
  const payload = `v:${m.version}\nname:${m.name}\ndialect:${dialect}\nbody:${body}`;
  return `sha256:${createHash('sha256').update(payload, 'utf8').digest('hex')}`;
}

function verifyAppliedAgainstCatalog(
  applied: readonly AppliedMigration[],
  migrations: readonly SqlMigration[],
  dialect: SqlDialect,
): void {
  const maxSupported = migrations[migrations.length - 1]!.version;
  const byVersion = new Map(migrations.map((m) => [m.version, m]));

  for (const row of applied) {
    if (row.version > maxSupported) {
      throw new MigrationFutureVersionError(row.version, maxSupported);
    }
    const def = byVersion.get(row.version);
    if (def === undefined) {
      throw new MigrationOrderError(
        `database records applied migration v${row.version} (${row.name}) which is missing from migration catalog`,
      );
    }
    const expected = migrationChecksum(def, dialect);
    if (row.checksum !== expected) {
      throw new MigrationChecksumError(row.version, row.name, expected, row.checksum);
    }
  }
}

// ------------------------------------------------------------ canonical ledger migrations

const V1_SQLITE = `
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

const V1_POSTGRES = `
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
  status_idx    BIGINT,
  exp           BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS mandate_node_root ON mandate_node (root);

CREATE TABLE IF NOT EXISTS revocation (
  root TEXT NOT NULL,
  jti  TEXT NOT NULL,
  at   BIGINT NOT NULL,
  PRIMARY KEY (root, jti)
);

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

CREATE TABLE IF NOT EXISTS idempotency (
  key          TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  response     TEXT NOT NULL,
  created_at   BIGINT NOT NULL,
  expires_at   BIGINT NOT NULL
);
`;

const V2_POSTGRES = `
ALTER TABLE mandate_node ADD COLUMN IF NOT EXISTS issuer     TEXT NOT NULL DEFAULT '';
ALTER TABLE mandate_node ADD COLUMN IF NOT EXISTS status_idx BIGINT;
`;

const V3_POSTGRES = `
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS state        TEXT   NOT NULL DEFAULT 'pending';
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS requested_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS agent        TEXT   NOT NULL DEFAULT '';
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS task_id      TEXT;
ALTER TABLE step_up ADD COLUMN IF NOT EXISTS decision     TEXT;
CREATE INDEX IF NOT EXISTS step_up_queue ON step_up (state, requested_at);
`;

/**
 * Canonical ordered ledger migrations.
 *
 * Rules for future changes:
 *   - NEVER edit an existing migration once shipped (its checksum is recorded in
 *     live `schema_migrations` tables and editing it triggers `MigrationChecksumError`).
 *   - Append a new entry with `version = LATEST_SCHEMA_VERSION + 1`.
 */
export const LEDGER_MIGRATIONS: readonly SqlMigration[] = Object.freeze([
  {
    version: 1,
    name: '001_initial_ledger_schema',
    sqlite: V1_SQLITE,
    postgres: V1_POSTGRES,
  },
  {
    version: 2,
    name: '002_mandate_node_issuer_and_status_idx',
    sqlite: (ctx) => {
      ctx.addColumnIfMissing('mandate_node', 'issuer', "TEXT NOT NULL DEFAULT ''");
      ctx.addColumnIfMissing('mandate_node', 'status_idx', 'INTEGER');
    },
    postgres: V2_POSTGRES,
    checksumSource:
      "mandate_node:+issuer TEXT NOT NULL DEFAULT '';mandate_node:+status_idx INTEGER/BIGINT",
  },
  {
    version: 3,
    name: '003_step_up_approval_queue',
    sqlite: (ctx) => {
      // Existing handles default to `pending` rather than `approved` so legacy
      // rows cannot bypass explicit principal approval.
      ctx.addColumnIfMissing('step_up', 'state', "TEXT NOT NULL DEFAULT 'pending'");
      ctx.addColumnIfMissing('step_up', 'requested_at', 'INTEGER NOT NULL DEFAULT 0');
      ctx.addColumnIfMissing('step_up', 'agent', "TEXT NOT NULL DEFAULT ''");
      ctx.addColumnIfMissing('step_up', 'task_id', 'TEXT');
      ctx.addColumnIfMissing('step_up', 'decision', 'TEXT');
      ctx.exec('CREATE INDEX IF NOT EXISTS step_up_queue ON step_up (state, requested_at)');
    },
    postgres: V3_POSTGRES,
    checksumSource:
      "step_up:+state pending,+requested_at 0,+agent '',+task_id,+decision;idx:step_up_queue(state,requested_at)",
  },
]);

export const LATEST_SCHEMA_VERSION: number =
  LEDGER_MIGRATIONS[LEDGER_MIGRATIONS.length - 1]!.version;

// ------------------------------------------------------------ SQLite runner

const CREATE_SQLITE_MIGRATIONS_TABLE = `
CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE} (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  checksum   TEXT NOT NULL,
  applied_at INTEGER NOT NULL
) STRICT;
`;

function createSqliteContext(db: DatabaseSyncType): SqliteMigrationContext {
  return {
    exec: (sql) => {
      db.exec(sql);
    },
    query: (sql, params = []) => db.prepare(sql).all(...params.map(bindSqlite)) as Row[],
    hasColumn: (table, column) => {
      const rows = db.prepare('SELECT name FROM pragma_table_info(?)').all(table) as Row[];
      return rows.some((r) => r['name'] === column);
    },
    addColumnIfMissing: (table, column, declaration) => {
      const rows = db.prepare('SELECT name FROM pragma_table_info(?)').all(table) as Row[];
      if (!rows.some((r) => r['name'] === column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${declaration}`);
      }
    },
  };
}

function readSqliteApplied(db: DatabaseSyncType): AppliedMigration[] {
  const rows = db
    .prepare(
      `SELECT version, name, checksum, applied_at FROM ${MIGRATIONS_TABLE} ORDER BY version ASC`,
    )
    .all() as Row[];
  return rows.map((r) => ({
    version: Number(r['version']),
    name: String(r['name']),
    checksum: String(r['checksum']),
    appliedAt: Number(r['applied_at']),
  }));
}

/**
 * Inspect SQLite migration state without issuing any write statements.
 * Safe on read-only connections (`PRAGMA query_only = ON`).
 */
export function inspectSqliteMigrations(
  db: DatabaseSyncType,
  migrations: readonly SqlMigration[] = LEDGER_MIGRATIONS,
): MigrationInspection {
  validateMigrations(migrations);
  const exists = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(MIGRATIONS_TABLE) as Row | undefined;

  if (exists === undefined) {
    return {
      dialect: 'sqlite',
      hasTable: false,
      currentVersion: 0,
      applied: [],
      pending: migrations.map((m) => m.version),
    };
  }

  const applied = readSqliteApplied(db);
  verifyAppliedAgainstCatalog(applied, migrations, 'sqlite');
  const appliedSet = new Set(applied.map((a) => a.version));
  const currentVersion = applied.length > 0 ? applied[applied.length - 1]!.version : 0;

  return {
    dialect: 'sqlite',
    hasTable: true,
    currentVersion,
    applied,
    pending: migrations.filter((m) => !appliedSet.has(m.version)).map((m) => m.version),
  };
}

/**
 * Run all pending SQLite migrations atomically inside a single `BEGIN IMMEDIATE`
 * transaction. Verifies checksums and refuses databases migrated by a newer binary.
 */
export function runSqliteMigrations(
  db: DatabaseSyncType,
  migrations: readonly SqlMigration[] = LEDGER_MIGRATIONS,
  opts: MigrationRunOptions = {},
): MigrationRunResult {
  validateMigrations(migrations);
  const clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
  const target = opts.targetVersion ?? migrations[migrations.length - 1]!.version;

  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec(CREATE_SQLITE_MIGRATIONS_TABLE);
    const existing = readSqliteApplied(db);
    verifyAppliedAgainstCatalog(existing, migrations, 'sqlite');

    const appliedSet = new Set(existing.map((a) => a.version));
    const ctx = createSqliteContext(db);
    const newlyApplied: AppliedMigration[] = [];
    const insertStmt = db.prepare(
      `INSERT INTO ${MIGRATIONS_TABLE} (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
    );

    for (const m of migrations) {
      if (m.version > target || appliedSet.has(m.version)) continue;
      if (typeof m.sqlite === 'string') {
        db.exec(m.sqlite);
      } else {
        m.sqlite(ctx);
      }
      const checksum = migrationChecksum(m, 'sqlite');
      const appliedAt = clock();
      insertStmt.run(m.version, m.name, checksum, appliedAt);
      newlyApplied.push({ version: m.version, name: m.name, checksum, appliedAt });
    }

    db.exec('COMMIT');

    const all = [...existing, ...newlyApplied];
    const currentVersion = all.length > 0 ? all[all.length - 1]!.version : 0;
    return {
      dialect: 'sqlite',
      currentVersion,
      applied: newlyApplied,
      alreadyApplied: existing.length,
    };
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Rollback failed because transaction was never active or already aborted.
    }
    throw err;
  }
}

// ------------------------------------------------------------ Postgres runner

const CREATE_POSTGRES_MIGRATIONS_TABLE = `
CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE} (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  checksum   TEXT NOT NULL,
  applied_at BIGINT NOT NULL
);
`;

async function readPostgresApplied(client: MigrationPgClient): Promise<AppliedMigration[]> {
  const { rows } = await client.query(
    `SELECT version, name, checksum, applied_at FROM ${MIGRATIONS_TABLE} ORDER BY version ASC`,
  );
  return rows.map((r) => ({
    version: Number(r['version']),
    name: String(r['name']),
    checksum: String(r['checksum']),
    appliedAt: Number(r['applied_at']),
  }));
}

/**
 * Inspect Postgres migration state without taking write locks or altering DDL.
 */
export async function inspectPostgresMigrations(
  client: MigrationPgClient,
  migrations: readonly SqlMigration[] = LEDGER_MIGRATIONS,
): Promise<MigrationInspection> {
  validateMigrations(migrations);
  const { rows } = await client.query(
    "SELECT to_regclass($1) AS tbl",
    [MIGRATIONS_TABLE],
  );
  const exists = rows[0]?.['tbl'] !== null && rows[0]?.['tbl'] !== undefined;
  if (!exists) {
    return {
      dialect: 'postgres',
      hasTable: false,
      currentVersion: 0,
      applied: [],
      pending: migrations.map((m) => m.version),
    };
  }

  const applied = await readPostgresApplied(client);
  verifyAppliedAgainstCatalog(applied, migrations, 'postgres');
  const appliedSet = new Set(applied.map((a) => a.version));
  const currentVersion = applied.length > 0 ? applied[applied.length - 1]!.version : 0;

  return {
    dialect: 'postgres',
    hasTable: true,
    currentVersion,
    applied,
    pending: migrations.filter((m) => !appliedSet.has(m.version)).map((m) => m.version),
  };
}

/**
 * Run all pending Postgres migrations inside a single transaction guarded by
 * `pg_advisory_xact_lock`, preventing concurrent startup races across replicas.
 */
export async function runPostgresMigrations(
  client: MigrationPgClient,
  migrations: readonly SqlMigration[] = LEDGER_MIGRATIONS,
  opts: MigrationRunOptions = {},
): Promise<MigrationRunResult> {
  validateMigrations(migrations);
  const clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
  const target = opts.targetVersion ?? migrations[migrations.length - 1]!.version;

  await client.query('BEGIN');
  try {
    await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [POSTGRES_MIGRATION_LOCK_KEY]);
    await client.query(CREATE_POSTGRES_MIGRATIONS_TABLE);

    const existing = await readPostgresApplied(client);
    verifyAppliedAgainstCatalog(existing, migrations, 'postgres');

    const appliedSet = new Set(existing.map((a) => a.version));
    const newlyApplied: AppliedMigration[] = [];
    const ctx: PostgresMigrationContext = {
      query: (sql, params) => client.query(sql, params),
    };

    for (const m of migrations) {
      if (m.version > target || appliedSet.has(m.version)) continue;
      if (typeof m.postgres === 'string') {
        await client.query(m.postgres);
      } else {
        await m.postgres(ctx);
      }
      const checksum = migrationChecksum(m, 'postgres');
      const appliedAt = clock();
      await client.query(
        `INSERT INTO ${MIGRATIONS_TABLE} (version, name, checksum, applied_at) VALUES ($1, $2, $3, $4)`,
        [m.version, m.name, checksum, appliedAt],
      );
      newlyApplied.push({ version: m.version, name: m.name, checksum, appliedAt });
    }

    await client.query('COMMIT');

    const all = [...existing, ...newlyApplied];
    const currentVersion = all.length > 0 ? all[all.length - 1]!.version : 0;
    return {
      dialect: 'postgres',
      currentVersion,
      applied: newlyApplied,
      alreadyApplied: existing.length,
    };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Ignore secondary rollback error and rethrow the original failure.
    }
    throw err;
  }
}
