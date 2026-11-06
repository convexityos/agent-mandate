import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { SqliteStore } from '../src/ledger/sql/sqlite.js';
import { toScaled } from '../src/money.js';
import { LEDGER, NOW, buildChain, generateAgentKey, trustOnly, usd } from './helpers.js';

// Same reason as the store: `node:sqlite` is prefix-only and a bundler can
// mistake it for an npm package.
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: typeof DatabaseSyncType;
};

/**
 * A reader beside the process that owns a ledger file: a status command or a
 * console opening the gateway's database to show what it holds.
 *
 * The oracle throughout is the owner's own `Ledger`. Whatever it reads, the
 * read-only one must read identically, and the file must come out of a
 * read-only session byte for byte as it went in.
 */
describe('a read-only SqliteStore', () => {
  const RESOURCE = 'https://api.weatherco.com/v3/forecast/94110';
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
        step_up: { over: usd('5.00') },
      },
    },
  ]);
  const cfg = (store: SqliteStore) => ({
    url: LEDGER,
    key: ledgerKey,
    store,
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off' as const, velocityMinSamples: 1e9 },
  });
  const ask = (amt: string) => ({ resource: RESOURCE, amount: usd(amt) });

  let dir: string;
  let file: string;
  let owner: SqliteStore;
  let ownerLedger: Ledger;
  let spendId: string;
  let handle: string;
  const open: SqliteStore[] = [];
  const reader = () => {
    const store = new SqliteStore({ location: file, readOnly: true, clock: () => clock });
    open.push(store);
    return store;
  };

  /** Every file in the directory and a hash of its bytes. */
  const snapshot = (): Record<string, string> =>
    Object.fromEntries(
      readdirSync(dir)
        .sort()
        .map((f) => [f, createHash('sha256').update(readFileSync(join(dir, f))).digest('hex')]),
    );

  /**
   * The database file's bytes are what they were, and the only files added are
   * the WAL sidecars, with nothing in the log.
   *
   * SQLite creates `-wal` and `-shm` to read a WAL database nobody else has open
   * (since 3.22), and a read-only connection cannot checkpoint them away on
   * close. They are coordination files, not data: the log is empty, and the
   * owner's next close removes both.
   */
  const expectUnchanged = (before: Record<string, string>) => {
    const after = snapshot();
    expect(after['ledger.db']).toBe(before['ledger.db']);
    expect(Object.keys(after).filter((f) => !(f in before))).toEqual(
      ['ledger.db-shm', 'ledger.db-wal'].filter((f) => f in after),
    );
    for (const f of Object.keys(before)) expect(after[f]).toBe(before[f]);
    if ('ledger.db-wal' in after) expect(statSync(join(dir, 'ledger.db-wal')).size).toBe(0);
  };

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'am-ledger-ro-'));
    file = join(dir, 'ledger.db');
    owner = new SqliteStore({ location: file, clock: () => clock });
    open.push(owner);
    ownerLedger = new Ledger(cfg(owner));

    const spend = await ownerLedger.reserve({ tokens, request: ask('3.00') });
    if (!spend.ok) throw new Error(`setup spend refused: ${spend.code}`);
    spendId = spend.spendId;

    const blocked = await ownerLedger.reserve({ tokens, request: ask('6.00') });
    if (blocked.ok || blocked.stepUpHandle === undefined) {
      throw new Error('setup step-up was not required');
    }
    handle = blocked.stepUpHandle;
  });

  afterEach(() => {
    for (const store of open.splice(0)) {
      try {
        store.close();
      } catch {
        // Already closed by the test.
      }
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it('reads everything the owner reads, while the owner holds the file open', async () => {
    const readLedger = new Ledger(cfg(reader()));

    const tree = await readLedger.budgetTree('mnd_root');
    expect(tree).toEqual(await ownerLedger.budgetTree('mnd_root'));
    // Not two empty answers agreeing: the spend and the waiting step-up are there.
    expect(toScaled(tree[0]!.spent)).toBe(toScaled(usd('3.00')));
    expect(await readLedger.pendingStepUps()).toEqual(await ownerLedger.pendingStepUps());
    expect(await readLedger.pendingStepUps('mnd_root')).toHaveLength(1);
    expect(await readLedger.stepUp(handle)).toEqual(await ownerLedger.stepUp(handle));
    expect(await readLedger.reservation(spendId)).toEqual(await ownerLedger.reservation(spendId));
    expect((await readLedger.reservation(spendId))?.status).toBe('reserved');
    expect(await readLedger.spendFeed('mnd_root')).toEqual(await ownerLedger.spendFeed('mnd_root'));
    expect(await readLedger.remaining('mnd_root')).toEqual(await ownerLedger.remaining('mnd_root'));
  });

  it("sees each commit as it lands, and never the owner's transaction in flight", async () => {
    const readLedger = new Ledger(cfg(reader()));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const inFlight = owner.transact(async (tx) => {
      await tx.setKilled('mnd_root', true);
      await gate;
    });
    // Let the transaction begin and make its write.
    await new Promise((r) => setImmediate(r));

    // The owner's own connection sees its uncommitted write (see `read`); a
    // second connection does not, and is not held up by the write lock.
    expect((await ownerLedger.budgetTree('mnd_root'))[0]!.killed).toBe(true);
    expect((await readLedger.budgetTree('mnd_root'))[0]!.killed).toBe(false);

    release();
    await inFlight;
    expect((await readLedger.budgetTree('mnd_root'))[0]!.killed).toBe(true);
  });

  it('refuses transact before it begins, even for a closure that only reads', async () => {
    const store = reader();
    await expect(store.transact(async (tx) => tx.getNode('mnd_root'))).rejects.toThrow(
      /opened read-only/,
    );
    // So every Ledger method that changes state is refused too.
    await expect(new Ledger(cfg(store)).reserve({ tokens, request: ask('1.00') })).rejects.toThrow(
      /opened read-only/,
    );
    expect(toScaled((await ownerLedger.remaining('mnd_root'))!)).toBe(toScaled(usd('7.00')));
  });

  it('refuses a write made through read, at the engine', async () => {
    await expect(reader().read((tx) => tx.setKilled('mnd_root', true))).rejects.toThrow(
      /readonly/,
    );
    expect((await ownerLedger.budgetTree('mnd_root'))[0]!.killed).toBe(false);
  });

  it('leaves the database byte for byte as it found it', async () => {
    owner.close();
    const before = snapshot();
    expect(Object.keys(before)).toEqual(['ledger.db']);

    const store = reader();
    const readLedger = new Ledger(cfg(store));
    await readLedger.budgetTree('mnd_root');
    await readLedger.pendingStepUps();
    await readLedger.stepUp(handle);
    await readLedger.reservation(spendId);
    await readLedger.spendFeed('mnd_root');
    await readLedger.remaining('mnd_root');
    await expect(store.transact(async () => undefined)).rejects.toThrow(/opened read-only/);
    await expect(store.read((tx) => tx.setKilled('mnd_root', true))).rejects.toThrow(/readonly/);
    store.close();

    expectUnchanged(before);
    // And the owner's next open and close leaves the directory as it was.
    new SqliteStore({ location: file }).close();
    expect(snapshot()).toEqual(before);
  });

  describe('will not open what it would have to create or change', () => {
    it('refuses a file that does not exist, and creates nothing', () => {
      const absent = join(dir, 'absent.db');
      expect(() => new SqliteStore({ location: absent, readOnly: true })).toThrow();
      expect(existsSync(absent)).toBe(false);
    });

    it('refuses a database that is not a file', () => {
      expect(() => new SqliteStore({ readOnly: true })).toThrow(/existing ledger file/);
      for (const location of ['', ':memory:']) {
        expect(() => new SqliteStore({ location, readOnly: true })).toThrow(/existing ledger file/);
      }
    });

    it('refuses a file that predates a table or column, names each, and leaves it unchanged', async () => {
      owner.close();
      const old = new DatabaseSync(file);
      old.exec('ALTER TABLE step_up DROP COLUMN decision');
      old.exec('DROP TABLE kill_switch');
      old.close();
      const before = snapshot();

      let message = '';
      try {
        reader();
      } catch (err) {
        message = (err as Error).message;
      }
      expect(message).toMatch(/predates this store/);
      expect(message).toContain('step_up.decision');
      expect(message).toContain('kill_switch');
      expect(message).not.toContain('mandate_node');
      expectUnchanged(before);

      // The remedy it names: the owner's writable open brings the file up to date.
      new SqliteStore({ location: file }).close();
      const readLedger = new Ledger(cfg(reader()));
      expect(toScaled((await readLedger.remaining('mnd_root'))!)).toBe(toScaled(usd('7.00')));
    });

    it('refuses a database that is not a ledger', () => {
      const other = join(dir, 'other.db');
      const db = new DatabaseSync(other);
      db.exec('CREATE TABLE notes (body TEXT)');
      db.close();
      expect(() => new SqliteStore({ location: other, readOnly: true })).toThrow(
        /missing mandate_node, revocation/,
      );
    });
  });
});
