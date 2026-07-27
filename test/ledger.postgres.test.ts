import { afterAll, describe, it } from 'vitest';

import { PostgresStore, TABLES } from '../src/ledger/sql/postgres.js';
import { runStoreSuite } from './store-suite.js';

/**
 * The concurrency properties against real row locks.
 *
 * Opt-in via `PG_URL`, the same shape as `LIVE_RPC=1`, so the default test run
 * needs no database. This is the only configuration in which the properties mean
 * what §1.1 of the roadmap wants them to mean: every caller gets its own
 * connection, so the interleaving is the database's rather than a promise
 * queue's, and an ordering mistake in `lockPath` shows up as a deadlock instead
 * of passing quietly.
 *
 *   docker run --rm -d --name am-ledger-pg -p 15432:5432 \
 *     -e POSTGRES_PASSWORD=am postgres:16-alpine
 *   PG_URL=postgres://postgres:am@localhost:15432/postgres npx vitest run
 *
 * Port 15432 rather than something near 5432: Windows reserves several ranges in
 * the 55xxx band for Hyper-V, and a bind there fails with a permissions error
 * that reads nothing like "this port is reserved".
 */

const PG_URL = process.env['PG_URL'];

if (PG_URL === undefined) {
  describe.skip('postgres store (set PG_URL to run)', () => {
    it('needs a database', () => {});
  });
} else {
  const { Pool } = await import('pg');

  // Wider than any single transaction needs and narrower than the property's
  // fan-out, so callers genuinely contend. No transaction ever takes a second
  // connection, so the pool cannot deadlock against itself.
  const pool = new Pool({ connectionString: PG_URL, max: 16 });
  await new PostgresStore({ pool }).init();

  afterAll(async () => {
    await pool.end();
  });

  runStoreSuite({
    name: 'postgres',
    make: async (clock) => {
      await pool.query(`TRUNCATE ${TABLES.join(', ')}`);
      return new PostgresStore({ pool, clock });
    },
    // Every operation is a round trip and every property run is a TRUNCATE plus
    // a few dozen transactions. Stated rather than defaulted so nobody reads
    // this as the same coverage the in-memory store gets.
    runs: 20,
    // Generous, because tripping this one poisons the tests after it: an
    // abandoned property leaves transactions open and the next `TRUNCATE`
    // deadlocks against them.
    timeoutMs: 180_000,
  });
}
