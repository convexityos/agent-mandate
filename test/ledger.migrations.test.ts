import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  LATEST_SCHEMA_VERSION,
  LEDGER_MIGRATIONS,
  MIGRATIONS_TABLE,
  MigrationChecksumError,
  MigrationFutureVersionError,
  MigrationOrderError,
  POSTGRES_MIGRATION_LOCK_KEY,
  type MigrationPgClient,
  type SqlMigration,
  inspectPostgresMigrations,
  inspectSqliteMigrations,
  migrationChecksum,
  runPostgresMigrations,
  runSqliteMigrations,
  validateMigrations,
} from '../src/ledger/sql/migrations.js';
import { type PgClient, type PgPool, PostgresStore } from '../src/ledger/sql/postgres.js';
import { SqliteStore } from '../src/ledger/sql/sqlite.js';

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: typeof DatabaseSyncType;
};

describe('migration catalog validation', () => {
  it('accepts LEDGER_MIGRATIONS and rejects malformed catalogs', () => {
    expect(() => validateMigrations(LEDGER_MIGRATIONS)).not.toThrow();
    expect(() => validateMigrations([])).toThrow(MigrationOrderError);

    expect(() =>
      validateMigrations([
        { version: 0, name: 'zero', sqlite: 'SELECT 1;', postgres: 'SELECT 1;' },
      ]),
    ).toThrow(MigrationOrderError);

    expect(() =>
      validateMigrations([
        { version: 2, name: 'two', sqlite: 'SELECT 1;', postgres: 'SELECT 1;' },
        { version: 1, name: 'one', sqlite: 'SELECT 1;', postgres: 'SELECT 1;' },
      ]),
    ).toThrow(MigrationOrderError);

    expect(() =>
      validateMigrations([
        { version: 1, name: 'dup', sqlite: 'SELECT 1;', postgres: 'SELECT 1;' },
        { version: 2, name: 'dup', sqlite: 'SELECT 1;', postgres: 'SELECT 1;' },
      ]),
    ).toThrow(MigrationOrderError);

    // Imperative migrations must supply checksumSource for stable hashes.
    expect(() =>
      validateMigrations([
        {
          version: 1,
          name: 'imperative_without_source',
          sqlite: () => undefined,
          postgres: 'SELECT 1;',
        },
      ]),
    ).toThrow(MigrationOrderError);
  });
});

describe('SQLite versioned migrations', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'am-migrations-'));
    file = join(dir, 'ledger.db');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('initializes a fresh SqliteStore to LATEST_SCHEMA_VERSION and is idempotent on reopen', () => {
    const t0 = 1_780_000_100;
    const s1 = new SqliteStore({ location: file, clock: () => t0 });
    expect(s1.schemaVersion()).toBe(LATEST_SCHEMA_VERSION);
    const applied = s1.appliedMigrations();
    expect(applied.map((a) => a.version)).toEqual(LEDGER_MIGRATIONS.map((m) => m.version));
    expect(applied.every((a) => a.checksum.startsWith('sha256:'))).toBe(true);
    expect(applied.every((a) => a.appliedAt === t0)).toBe(true);
    s1.close();

    // Reopening applies 0 new migrations.
    const raw = new DatabaseSync(file);
    try {
      const res = runSqliteMigrations(raw, LEDGER_MIGRATIONS, { clock: () => t0 + 999 });
      expect(res.applied).toHaveLength(0);
      expect(res.alreadyApplied).toBe(LEDGER_MIGRATIONS.length);
      expect(res.currentVersion).toBe(LATEST_SCHEMA_VERSION);
    } finally {
      raw.close();
    }
  });

  it('upgrades a legacy pre-migration SQLite database in place and keeps legacy step_up rows pending', () => {
    // Build a legacy database that predates schema_migrations, mandate_node.issuer/status_idx,
    // and the §10.5 step_up approval queue columns.
    const legacy = new DatabaseSync(file);
    legacy.exec(`
      CREATE TABLE mandate_node (
        jti           TEXT PRIMARY KEY,
        parent        TEXT,
        root          TEXT NOT NULL,
        token_hash    TEXT NOT NULL,
        budget_scaled TEXT,
        currency      TEXT,
        spent_scaled  TEXT NOT NULL,
        rate          TEXT,
        rate_events   TEXT NOT NULL,
        revoked       INTEGER NOT NULL,
        exp           INTEGER NOT NULL
      ) STRICT;
      INSERT INTO mandate_node
        (jti, parent, root, token_hash, budget_scaled, currency, spent_scaled, rate, rate_events, revoked, exp)
        VALUES ('mnd_legacy', NULL, 'mnd_legacy', 'sha256:abc', '10000000000', 'USD', '0', NULL, '[]', 0, 1900000000);

      CREATE TABLE step_up (
        handle            TEXT PRIMARY KEY,
        root              TEXT NOT NULL,
        resource          TEXT NOT NULL,
        max_amount_scaled TEXT NOT NULL,
        currency          TEXT NOT NULL,
        expires_at        INTEGER NOT NULL,
        used              INTEGER NOT NULL
      ) STRICT;
      INSERT INTO step_up
        (handle, root, resource, max_amount_scaled, currency, expires_at, used)
        VALUES ('su_legacy', 'mnd_legacy', 'https://api.example/x', '5000000000', 'USD', 1900000000, 0);
    `);
    legacy.close();

    // Writable SqliteStore upgrades legacy DB cleanly to LATEST_SCHEMA_VERSION.
    const store = new SqliteStore({ location: file, clock: () => 1_780_000_200 });
    expect(store.schemaVersion()).toBe(LATEST_SCHEMA_VERSION);
    store.close();

    // Existing rows are preserved and legacy step_up row defaults to pending (never approved).
    const verify = new DatabaseSync(file, { readOnly: true });
    try {
      const node = verify
        .prepare('SELECT jti, issuer, status_idx FROM mandate_node WHERE jti = ?')
        .get('mnd_legacy') as Record<string, unknown>;
      expect(node).toEqual({ jti: 'mnd_legacy', issuer: '', status_idx: null });

      const stepUp = verify
        .prepare('SELECT handle, state, requested_at, agent, decision FROM step_up WHERE handle = ?')
        .get('su_legacy') as Record<string, unknown>;
      expect(stepUp).toEqual({
        handle: 'su_legacy',
        state: 'pending',
        requested_at: 0,
        agent: '',
        decision: null,
      });
    } finally {
      verify.close();
    }

    // Read-only SqliteStore opens the upgraded file without error.
    const ro = new SqliteStore({ location: file, readOnly: true });
    expect(ro.schemaVersion()).toBe(LATEST_SCHEMA_VERSION);
    ro.close();
  });

  it('supports non-additive backfill migrations and staged targetVersion execution', () => {
    const db = new DatabaseSync(':memory:');
    try {
      const catalog: SqlMigration[] = [
        {
          version: 1,
          name: '001_create_items',
          sqlite: 'CREATE TABLE items (id TEXT PRIMARY KEY, label TEXT NOT NULL) STRICT;',
          postgres: 'CREATE TABLE items (id TEXT PRIMARY KEY, label TEXT NOT NULL);',
        },
        {
          version: 2,
          name: '002_backfill_uppercase_slug',
          sqlite: (ctx) => {
            ctx.exec("ALTER TABLE items ADD COLUMN slug TEXT NOT NULL DEFAULT ''");
            const rows = ctx.query('SELECT id, label FROM items');
            for (const r of rows) {
              ctx.exec(
                `UPDATE items SET slug = '${String(r['label']).toUpperCase()}' WHERE id = '${String(r['id'])}'`,
              );
            }
          },
          postgres: 'ALTER TABLE items ADD COLUMN slug TEXT NOT NULL DEFAULT \'\';',
          checksumSource: 'items:+slug + backfill upper(label)',
        },
      ];

      const r1 = runSqliteMigrations(db, catalog, { targetVersion: 1, clock: () => 100 });
      expect(r1.currentVersion).toBe(1);
      expect(r1.applied.map((a) => a.version)).toEqual([1]);

      db.prepare('INSERT INTO items (id, label) VALUES (?, ?)').run('i1', 'alpha');

      const r2 = runSqliteMigrations(db, catalog, { clock: () => 200 });
      expect(r2.currentVersion).toBe(2);
      expect(r2.alreadyApplied).toBe(1);
      expect(r2.applied.map((a) => a.version)).toEqual([2]);

      const row = db.prepare('SELECT id, label, slug FROM items WHERE id = ?').get('i1') as Record<
        string,
        unknown
      >;
      expect(row).toEqual({ id: 'i1', label: 'alpha', slug: 'ALPHA' });
    } finally {
      db.close();
    }
  });

  it('rolls back completely when a migration fails mid-transaction', () => {
    const db = new DatabaseSync(':memory:');
    try {
      runSqliteMigrations(db, LEDGER_MIGRATIONS, { clock: () => 100 });

      const failingCatalog: SqlMigration[] = [
        ...LEDGER_MIGRATIONS,
        {
          version: LATEST_SCHEMA_VERSION + 1,
          name: '004_broken_migration',
          sqlite: `
            CREATE TABLE should_not_exist (id TEXT PRIMARY KEY) STRICT;
            INSERT INTO nonexistent_table VALUES (1);
          `,
          postgres: 'SELECT 1;',
        },
      ];

      expect(() => runSqliteMigrations(db, failingCatalog, { clock: () => 200 })).toThrow();

      // Neither the table nor version 4 should exist after rollback.
      const table = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'should_not_exist'")
        .get();
      expect(table).toBeUndefined();

      const inspection = inspectSqliteMigrations(db, LEDGER_MIGRATIONS);
      expect(inspection.currentVersion).toBe(LATEST_SCHEMA_VERSION);
      expect(inspection.applied).toHaveLength(LEDGER_MIGRATIONS.length);
    } finally {
      db.close();
    }
  });

  it('fails closed with MigrationChecksumError when an applied migration checksum drifts', () => {
    const store = new SqliteStore({ location: file, clock: () => 100 });
    store.close();

    // Tamper with recorded checksum for v2.
    const raw = new DatabaseSync(file);
    raw.prepare(`UPDATE ${MIGRATIONS_TABLE} SET checksum = ? WHERE version = 2`).run('sha256:tampered');
    raw.close();

    expect(() => new SqliteStore({ location: file })).toThrow(MigrationChecksumError);
    expect(() => new SqliteStore({ location: file, readOnly: true })).toThrow(MigrationChecksumError);
  });

  it('fails closed with MigrationFutureVersionError on both writable and read-only opens when DB is newer', () => {
    const store = new SqliteStore({ location: file, clock: () => 100 });
    store.close();

    const raw = new DatabaseSync(file);
    raw
      .prepare(
        `INSERT INTO ${MIGRATIONS_TABLE} (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
      )
      .run(LATEST_SCHEMA_VERSION + 1, '999_future_schema', 'sha256:future', 200);
    raw.close();

    expect(() => new SqliteStore({ location: file })).toThrow(MigrationFutureVersionError);
    expect(() => new SqliteStore({ location: file, readOnly: true })).toThrow(
      MigrationFutureVersionError,
    );
  });
});

/**
 * In-memory mock Postgres client implementing transaction state, advisory lock
 * recording, and the `schema_migrations` table so Postgres migration logic is
 * verified in every default test run without requiring a live PG server.
 */
function makeMockPgPool(opts?: { failOnSqlMatch?: RegExp }) {
  let tableCreated = false;
  let committedRows: Array<{ version: number; name: string; checksum: string; applied_at: number }> = [];
  let txRows: Array<{ version: number; name: string; checksum: string; applied_at: number }> | null = null;
  let txTableCreated = false;
  const queries: Array<{ text: string; params?: unknown[] }> = [];

  const client: PgClient & MigrationPgClient = {
    async query(text: string, params?: unknown[]) {
      queries.push({ text, params });
      const trimmed = text.trim();

      if (trimmed === 'BEGIN') {
        txRows = committedRows.map((r) => ({ ...r }));
        txTableCreated = tableCreated;
        return { rows: [] };
      }
      if (trimmed === 'COMMIT') {
        if (txRows !== null) {
          committedRows = txRows;
          tableCreated = txTableCreated;
          txRows = null;
        }
        return { rows: [] };
      }
      if (trimmed === 'ROLLBACK') {
        txRows = null;
        return { rows: [] };
      }
      if (trimmed.startsWith('SELECT pg_advisory_xact_lock')) {
        return { rows: [{ pg_advisory_xact_lock: '' }] };
      }
      if (trimmed.startsWith('SELECT to_regclass')) {
        const activeTable = txRows !== null ? txTableCreated : tableCreated;
        return { rows: [{ tbl: activeTable ? MIGRATIONS_TABLE : null }] };
      }
      if (trimmed.includes(`CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE}`)) {
        if (txRows !== null) txTableCreated = true;
        else tableCreated = true;
        return { rows: [] };
      }
      if (trimmed.startsWith(`SELECT version, name, checksum, applied_at FROM ${MIGRATIONS_TABLE}`)) {
        const rows = (txRows ?? committedRows).slice().sort((a, b) => a.version - b.version);
        return { rows };
      }
      if (trimmed.startsWith(`INSERT INTO ${MIGRATIONS_TABLE}`)) {
        const [version, name, checksum, applied_at] = params as [number, string, string, number];
        const target = txRows ?? committedRows;
        target.push({ version, name, checksum, applied_at });
        return { rows: [] };
      }
      if (opts?.failOnSqlMatch !== undefined && opts.failOnSqlMatch.test(trimmed)) {
        throw new Error('simulated postgres DDL failure');
      }
      return { rows: [] };
    },
    release() {},
  };

  const pool: PgPool = {
    async connect() {
      return client;
    },
  };

  return {
    pool,
    client,
    queries,
    getRows: () => committedRows,
    setRows: (rows: typeof committedRows) => {
      tableCreated = true;
      committedRows = rows;
    },
  };
}

describe('Postgres versioned migrations', () => {
  it('acquires transaction-scoped advisory lock, applies v1..v3 atomically, and is idempotent', async () => {
    const mock = makeMockPgPool();
    const store = new PostgresStore({ pool: mock.pool, clock: () => 1_780_000_500 });

    expect(await store.schemaVersion()).toBe(0);

    const first = await store.init();
    expect(first.dialect).toBe('postgres');
    expect(first.currentVersion).toBe(LATEST_SCHEMA_VERSION);
    expect(first.alreadyApplied).toBe(0);
    expect(first.applied.map((a) => a.version)).toEqual(LEDGER_MIGRATIONS.map((m) => m.version));

    // Verify advisory lock was acquired inside the transaction.
    const lockQuery = mock.queries.find((q) => q.text.includes('pg_advisory_xact_lock'));
    expect(lockQuery).toBeDefined();
    expect(lockQuery?.params).toEqual([POSTGRES_MIGRATION_LOCK_KEY]);

    // Second init applies 0 migrations.
    const second = await store.init();
    expect(second.applied).toHaveLength(0);
    expect(second.alreadyApplied).toBe(LEDGER_MIGRATIONS.length);
    expect(await store.schemaVersion()).toBe(LATEST_SCHEMA_VERSION);
    expect((await store.appliedMigrations()).map((a) => a.version)).toEqual(
      LEDGER_MIGRATIONS.map((m) => m.version),
    );
  });

  it('rolls back Postgres migration transaction when a DDL step fails', async () => {
    const mock = makeMockPgPool({ failOnSqlMatch: /step_up_queue/ });
    await expect(runPostgresMigrations(mock.client, LEDGER_MIGRATIONS)).rejects.toThrow(
      /simulated postgres DDL failure/,
    );
    expect(mock.queries.some((q) => q.text.trim() === 'ROLLBACK')).toBe(true);
    expect(mock.getRows()).toHaveLength(0);
  });

  it('fails closed on Postgres checksum mismatch and future schema versions', async () => {
    const mock = makeMockPgPool();
    mock.setRows([
      {
        version: 1,
        name: LEDGER_MIGRATIONS[0]!.name,
        checksum: 'sha256:wrong',
        applied_at: 100,
      },
    ]);
    await expect(runPostgresMigrations(mock.client, LEDGER_MIGRATIONS)).rejects.toThrow(
      MigrationChecksumError,
    );
    await expect(inspectPostgresMigrations(mock.client, LEDGER_MIGRATIONS)).rejects.toThrow(
      MigrationChecksumError,
    );

    mock.setRows([
      ...LEDGER_MIGRATIONS.map((m) => ({
        version: m.version,
        name: m.name,
        checksum: migrationChecksum(m, 'postgres'),
        applied_at: 100,
      })),
      {
        version: LATEST_SCHEMA_VERSION + 1,
        name: '999_future',
        checksum: 'sha256:future',
        applied_at: 200,
      },
    ]);
    await expect(runPostgresMigrations(mock.client, LEDGER_MIGRATIONS)).rejects.toThrow(
      MigrationFutureVersionError,
    );
  });
});
