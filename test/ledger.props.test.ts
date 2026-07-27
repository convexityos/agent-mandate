import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { SqliteStore } from '../src/ledger/sql/sqlite.js';
import { toScaled } from '../src/money.js';
import { NOW, buildChain, generateAgentKey, trustOnly, usd } from './helpers.js';
import { runStoreSuite } from './store-suite.js';

/**
 * The ledger's single invariant: no interleaving of concurrent operations may
 * overdraw any node on any path.
 *
 * The suite is in `store-suite.ts` and runs once per store. Against the `Map` it
 * proves the promise-chain critical section holds; against SQLite it proves the
 * transaction boundary does. Postgres — where the interleaving is across
 * connections rather than inside one event loop — is in
 * `ledger.postgres.test.ts`, gated on `PG_URL`.
 */

runStoreSuite({
  name: 'memory',
  make: async (clock) => new MemoryLedgerStore(clock),
  runs: 150,
  timeoutMs: 30_000,
});

runStoreSuite({
  name: 'sqlite',
  make: async (clock) => new SqliteStore({ clock }),
  dispose: async (store) => (store as SqliteStore).close(),
  // A third of memory's: every operation is a real statement against a real
  // database, and the same generators cover the same shapes more slowly.
  runs: 50,
  timeoutMs: 60_000,
});

describe('sqlite survives a restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'am-ledger-'));
  const file = join(dir, 'ledger.db');
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('reads back a debited budget from a reopened file', async () => {
    const clock = NOW + 10;
    const principal = generateAgentKey();
    const agentA = generateAgentKey();
    const ledgerKey = generateAgentKey();
    const tokens = buildChain(principal, [
      {
        holder: agentA,
        exp: NOW + 86400,
        jti: 'mnd_root',
        cav: {
          max_total: usd('10.00'),
          max_per_txn: usd('10.00'),
          aud: ['api.weatherco.com'],
        },
      },
    ]);
    const cfg = (store: SqliteStore) => ({
      url: 'https://ledger.example.com',
      key: ledgerKey,
      store,
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
      breakers: { novelMerchant: 'off' as const, velocityMinSamples: 1e9 },
    });
    const request = {
      resource: 'https://api.weatherco.com/v3/forecast/94110',
      amount: usd('6.00'),
    };

    const before = new SqliteStore({ location: file, clock: () => clock });
    const spend = await new Ledger(cfg(before)).reserve({ tokens, request });
    expect(spend.ok).toBe(true);
    before.close();

    // New process, as far as the database is concerned.
    const after = new SqliteStore({ location: file, clock: () => clock });
    try {
      const ledger = new Ledger(cfg(after));
      expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(toScaled(usd('4.00')));

      // And the reservation is still there to be settled.
      const reservation = await ledger.reservation(spend.ok ? spend.spendId : '');
      expect(reservation?.status).toBe('reserved');
      expect(reservation?.amountScaled).toBe(toScaled(usd('6.00')));

      const over = await ledger.reserve({ tokens, request: { ...request, amount: usd('5.00') } });
      expect(over.ok).toBe(false);
      if (!over.ok) expect(over.code).toBe('budget_exhausted');
    } finally {
      after.close();
    }
  });
});
