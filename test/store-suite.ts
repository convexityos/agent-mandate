import fc from 'fast-check';
import { describe, expect, it as baseIt } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import {
  HISTORY_RETENTION_SECONDS,
  type LedgerStore,
  type MandateNode,
  type Reservation,
  type ReservationQuery,
  type StepUpApproval,
  type StepUpQuery,
  compareReservations,
  compareStepUps,
  matchesQuery,
  matchesStepUpQuery,
} from '../src/ledger/store.js';
import { toScaled } from '../src/money.js';
import { signStepUpDecision } from '../src/stepup.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * One suite, every store.
 *
 * The concurrency properties below used to run against a `Map` and proved that a
 * `Map` cannot be overdrawn. Run against SQLite they prove a transaction
 * boundary holds; run against Postgres, where each caller gets its own
 * connection and the interleaving is real rather than a promise queue, they
 * prove the row locks and their ordering hold. Same assertions, three very
 * different claims — which is the point of running them from one place.
 *
 * The conformance block above them is the other half: it pins the behaviour the
 * ledger silently depends on, so a store that passes here is substitutable
 * rather than merely plausible.
 */

export interface StoreHarness {
  name: string;
  /** A fresh, empty store bound to `clock`. */
  make(clock: () => number): Promise<LedgerStore>;
  dispose?(store: LedgerStore): Promise<void>;
  /**
   * Property runs for this store. Stated per harness rather than defaulted,
   * because the SQL stores pay a round trip per operation and quietly running
   * a tenth of the cases would read as equal coverage.
   */
  runs: number;
  /**
   * Per-test timeout. Needed because the default 5s is shorter than a Postgres
   * property run once the rest of the suite is competing for the CPU, and the
   * consequence of tripping it is worse than a slow test: vitest abandons the
   * test while its transactions are still open, so the next test's `TRUNCATE`
   * deadlocks against the leaked work and every test after it fails for a reason
   * that has nothing to do with what it was checking.
   */
  timeoutMs: number;
}

const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;

function fixtureNode(over: Partial<MandateNode> = {}): MandateNode {
  return {
    jti: 'mnd_root',
    parent: null,
    root: 'mnd_root',
    issuer: 'did:key:zPrincipal',
    tokenHash: 'sha256:0000',
    budgetScaled: toScaled(usd('10.00')),
    currency: 'USD',
    spentScaled: 0n,
    rate: null,
    rateEvents: [],
    revoked: false,
    statusIdx: null,
    exp: NOW + 3600,
    ...over,
  };
}

function fixtureReservation(over: Partial<Reservation> = {}): Reservation {
  return {
    id: 'spn_1',
    path: ['mnd_root'],
    root: 'mnd_root',
    agent: 'did:key:zAgent',
    taskId: null,
    merchant: HOST,
    resource: RESOURCE,
    amount: usd('1.50'),
    amountScaled: toScaled(usd('1.50')),
    settle: 'immediate',
    schema: null,
    chainHash: 'sha256:1111',
    status: 'reserved',
    createdAt: NOW,
    expiresAt: NOW + 300,
    ...over,
  };
}

function fixtureStepUp(over: Partial<StepUpApproval> = {}): StepUpApproval {
  return {
    handle: 'stp_1',
    root: 'mnd_root',
    resource: RESOURCE,
    maxAmountScaled: toScaled(usd('5.00')),
    currency: 'USD',
    expiresAt: NOW + 3600,
    used: false,
    state: 'pending',
    requestedAt: NOW,
    agent: 'did:key:zAgent',
    taskId: null,
    ...over,
  };
}

/**
 * A directive whose rail-specific `intent` carries a `BigInt`. `DirectiveIntent`
 * declares `intent` as open `Record<string, unknown>` precisely so rails can put
 * what they need in it, and an on-chain rail puts atomic-unit amounts there —
 * which `JSON.stringify` refuses to serialize.
 */
const FIXTURE_DIRECTIVE: Reservation['directive'] = {
  v: 'am/1',
  typ: 'directive',
  jti: 'spn_1',
  iss: 'https://ledger.example.com',
  sub: 'did:key:zAgent',
  chainHash: 'sha256:1111',
  rail: 'x402-noncustodial',
  intentHash: 'sha256:2222',
  iat: NOW,
  cnf: { jkt: 'jkt-fixture' },
  intent: { value: 1_500_000n, to: '0xabc', nested: { fee: 7n } },
  payer: '0xpayer',
  expiresAt: NOW + 600,
  decidableAt: NOW + 700,
};

export function runStoreSuite(h: StoreHarness): void {
  /** Every test in this suite carries the harness's timeout. */
  const it = (name: string, fn: () => Promise<void>) => baseIt(name, fn, h.timeoutMs);

  const withStore = async <T>(
    clock: () => number,
    fn: (store: LedgerStore) => Promise<T>,
  ): Promise<T> => {
    const store = await h.make(clock);
    try {
      return await fn(store);
    } finally {
      await h.dispose?.(store);
    }
  };

  // ---------------------------------------------------------------- conformance

  describe(`store conformance [${h.name}]`, () => {
    const at = () => NOW;

    it('round-trips a node through every field it has', async () => {
      await withStore(at, async (store) => {
        const cases: MandateNode[] = [
          fixtureNode(),
          // No budget of its own — the null that means "declares nothing", not zero.
          fixtureNode({ jti: 'mnd_a', budgetScaled: null, currency: null }),
          fixtureNode({
            jti: 'mnd_b',
            rate: { n: 5, per: 'PT1H' },
            rateEvents: [NOW - 10, NOW - 5, NOW],
          }),
          fixtureNode({ jti: 'mnd_c', revoked: true, parent: 'mnd_root', statusIdx: 0 }),
          // Large enough to prove the column is not a 32-bit int somewhere.
          fixtureNode({ jti: 'mnd_f', statusIdx: 131_071 }),
          // Credits can drive a node negative if a refund outruns its debit.
          fixtureNode({ jti: 'mnd_d', spentScaled: -42n }),
          // Beyond int64 at scale 9 — the reason amount columns are not BIGINT.
          fixtureNode({ jti: 'mnd_e', budgetScaled: 10n ** 30n, spentScaled: 10n ** 29n }),
        ];

        for (const n of cases) await store.transact(async (tx) => tx.putNode(n));
        for (const n of cases) {
          expect(await store.read(async (tx) => tx.getNode(n.jti))).toEqual(n);
        }
      });
    });

    it('round-trips a reservation carrying a BigInt inside a rail-specific directive', async () => {
      await withStore(at, async (store) => {
        const full = fixtureReservation({
          taskId: 'task-1',
          schema: 'https://schema.example/v1',
          status: 'settling',
          respHash: 'sha256:3333',
          respBytes: 2048,
          merchantSig: 'sig',
          refundReason: 'none',
          railRef: '0xdeadbeef',
          railName: 'x402',
          settlingSince: NOW + 1,
          directive: FIXTURE_DIRECTIVE,
          reported: { at: NOW + 2, ok: true, ref: '0xfeed' },
          escalated: { at: NOW + 3, reason: 'oracle undecided' },
        });

        await store.transact(async (tx) => tx.putReservation(full));
        const got = await store.read(async (tx) => tx.getReservation(full.id));

        expect(got).toEqual(full);
        expect(typeof got!.amountScaled).toBe('bigint');
        expect((got!.directive!.intent as { value: bigint }).value).toBe(1_500_000n);
        expect((got!.directive!.intent as { nested: { fee: bigint } }).nested.fee).toBe(7n);
      });
    });

    it('leaves absent optional fields absent rather than null', async () => {
      await withStore(at, async (store) => {
        const bare = fixtureReservation();
        await store.transact(async (tx) => tx.putReservation(bare));
        const got = await store.read(async (tx) => tx.getReservation(bare.id));
        expect(got).toEqual(bare);
        expect('directive' in got!).toBe(false);
        expect('railRef' in got!).toBe(false);
      });
    });

    it('aligns lockPath with its input and reports unknown nodes as undefined', async () => {
      await withStore(at, async (store) => {
        const a = fixtureNode({ jti: 'mnd_a' });
        const c = fixtureNode({ jti: 'mnd_c', parent: 'mnd_a' });
        await store.transact(async (tx) => {
          await tx.putNode(a);
          await tx.putNode(c);
        });

        const got = await store.transact(async (tx) => tx.lockPath(['mnd_a', 'mnd_b', 'mnd_c']));
        expect(got).toHaveLength(3);
        expect(got[0]).toEqual(a);
        expect(got[1]).toBeUndefined();
        expect(got[2]).toEqual(c);
      });
    });

    /**
     * The one that keeps the two implementations of the same question honest:
     * `matchesQuery` in `store.ts` and the `WHERE` clause in `codec.ts` must
     * select the same rows, or a sweeper behaves differently depending on which
     * store is configured.
     */
    it('answers findReservations exactly as matchesQuery does', async () => {
      await withStore(at, async (store) => {
        const corpus: Reservation[] = [];
        let i = 0;
        for (const status of ['reserved', 'settling', 'settled', 'refunded', 'expired'] as const) {
          for (const hasDirective of [false, true]) {
            for (const escalated of [false, true]) {
              for (const expiresAt of [NOW - 100, NOW + 100]) {
                corpus.push(
                  fixtureReservation({
                    id: `spn_${String(++i).padStart(3, '0')}`,
                    status,
                    expiresAt,
                    createdAt: NOW - (i % 7),
                    ...(hasDirective ? { directive: FIXTURE_DIRECTIVE } : {}),
                    ...(escalated ? { escalated: { at: NOW, reason: 'r' } } : {}),
                  }),
                );
              }
            }
          }
        }
        await store.transact(async (tx) => {
          for (const r of corpus) await tx.putReservation(r);
        });

        const queries: ReservationQuery[] = [
          {},
          { status: [] },
          { status: ['settling'] },
          { status: ['settling', 'reserved'] },
          { hasDirective: true },
          { hasDirective: false },
          { escalated: true },
          { escalated: false },
          { expiresBefore: NOW },
          { status: ['reserved'], hasDirective: false, expiresBefore: NOW },
          { status: ['settling', 'reserved'], hasDirective: true, escalated: false },
          { status: ['reserved'], limit: 3 },
          { limit: 5 },
        ];

        for (const q of queries) {
          const expected = corpus
            .filter((r) => matchesQuery(r, q))
            .sort(compareReservations)
            .slice(0, q.limit ?? corpus.length);
          const actual = await store.read(async (tx) => tx.findReservations(q));
          expect(actual.map((r) => r.id), `query ${JSON.stringify(q)}`).toEqual(
            expected.map((r) => r.id),
          );
        }
      });
    });

    it('commits on return and rolls back on throw', async () => {
      await withStore(at, async (store) => {
        // A closure that returns a failure-shaped value still commits: `reserve`
        // writes a step-up handle and then returns `ok: false`, and the caller
        // is handed that handle.
        const verdict = await store.transact(async (tx) => {
          await tx.putStepUp(fixtureStepUp({ handle: 'stp_kept' }));
          return { ok: false as const };
        });
        expect(verdict.ok).toBe(false);
        expect(await store.read(async (tx) => tx.getStepUp('stp_kept'))).toBeDefined();

        await expect(
          store.transact(async (tx) => {
            await tx.putNode(fixtureNode({ jti: 'mnd_rolled_back' }));
            throw new Error('abort');
          }),
        ).rejects.toThrow('abort');
        expect(await store.read(async (tx) => tx.getNode('mnd_rolled_back'))).toBeUndefined();

        // The store is still usable after a rollback.
        await store.transact(async (tx) => tx.putNode(fixtureNode({ jti: 'mnd_after' })));
        expect(await store.read(async (tx) => tx.getNode('mnd_after'))).toBeDefined();
      });
    });

    it('records a revocation for a jti with no node, scoped to its root', async () => {
      await withStore(at, async (store) => {
        // The case the record exists for: nothing has ever been spent under
        // this mandate, so there is no node to carry a `revoked` flag.
        expect(await store.read(async (tx) => tx.isRevoked('mnd_root', 'mnd_unseen'))).toBe(false);
        await store.transact(async (tx) => tx.putRevocation('mnd_root', 'mnd_unseen', NOW));
        expect(await store.read(async (tx) => tx.isRevoked('mnd_root', 'mnd_unseen'))).toBe(true);

        // Scoped by root: the same jti under someone else's root is untouched,
        // which is the check that cannot be made against a node that does not
        // exist yet.
        expect(await store.read(async (tx) => tx.isRevoked('mnd_other', 'mnd_unseen'))).toBe(false);

        // Idempotent — a principal re-sending a revocation is not an error.
        await store.transact(async (tx) => tx.putRevocation('mnd_root', 'mnd_unseen', NOW + 5));
        expect(await store.read(async (tx) => tx.isRevoked('mnd_root', 'mnd_unseen'))).toBe(true);

        await expect(
          store.transact(async (tx) => {
            await tx.putRevocation('mnd_root', 'mnd_rolled_back', NOW);
            throw new Error('abort');
          }),
        ).rejects.toThrow('abort');
        expect(await store.read(async (tx) => tx.isRevoked('mnd_root', 'mnd_rolled_back'))).toBe(
          false,
        );
      });
    });

    it('accumulates task totals in both directions', async () => {
      await withStore(at, async (store) => {
        expect(await store.read(async (tx) => tx.taskTotal('t-unknown'))).toBe(0n);
        await store.transact(async (tx) => {
          await tx.addTaskTotal('t1', toScaled(usd('3.00')));
          await tx.addTaskTotal('t1', toScaled(usd('1.50')));
          await tx.addTaskTotal('t1', -toScaled(usd('4.00')));
        });
        expect(await store.read(async (tx) => tx.taskTotal('t1'))).toBe(toScaled(usd('0.50')));
      });
    });

    it('round-trips step-ups, merchant sightings and the kill switch', async () => {
      await withStore(at, async (store) => {
        const approval = fixtureStepUp({
          handle: 'stp_1',
          maxAmountScaled: toScaled(usd('7.25')),
          taskId: 'tsk_1',
          // A decided request keeps the signed decision whole, so it can be
          // re-verified from storage years later.
          state: 'approved',
          decision: { at: NOW + 5, by: 'did:key:zPrincipal', jws: 'ey.J.sig', reason: 'ok' },
        });
        await store.transact(async (tx) => {
          await tx.putStepUp(approval);
          await tx.markMerchant('mnd_root', HOST);
          await tx.setKilled('mnd_root', true);
        });
        expect(await store.read(async (tx) => tx.getStepUp('stp_1'))).toEqual(approval);
        expect(await store.read(async (tx) => tx.getStepUp('stp_missing'))).toBeUndefined();
        expect(await store.read(async (tx) => tx.merchantSeen('mnd_root', HOST))).toBe(true);
        expect(await store.read(async (tx) => tx.merchantSeen('mnd_root', 'other.example'))).toBe(
          false,
        );
        expect(await store.read(async (tx) => tx.killed('mnd_root'))).toBe(true);

        await store.transact(async (tx) => {
          await tx.putStepUp({ ...approval, used: true });
          // Marking a merchant twice must not be an error.
          await tx.markMerchant('mnd_root', HOST);
          await tx.setKilled('mnd_root', false);
        });
        expect((await store.read(async (tx) => tx.getStepUp('stp_1')))!.used).toBe(true);
        expect(await store.read(async (tx) => tx.killed('mnd_root'))).toBe(false);
      });
    });

    it('answers findStepUps exactly as matchesStepUpQuery does', async () => {
      await withStore(at, async (store) => {
        const corpus: StepUpApproval[] = [];
        let i = 0;
        for (const state of ['pending', 'approved', 'denied'] as const) {
          for (const used of [false, true]) {
            for (const root of ['mnd_root', 'mnd_other']) {
              for (const expiresAt of [NOW - 100, NOW + 100]) {
                corpus.push(
                  fixtureStepUp({
                    handle: `stp_${String(++i).padStart(3, '0')}`,
                    state,
                    used,
                    root,
                    expiresAt,
                    requestedAt: NOW - (i % 5),
                  }),
                );
              }
            }
          }
        }
        await store.transact(async (tx) => {
          for (const a of corpus) await tx.putStepUp(a);
        });

        const queries: StepUpQuery[] = [
          {},
          { state: [] },
          { state: ['pending'] },
          { state: ['approved', 'denied'] },
          { root: 'mnd_root' },
          { unused: true },
          { unused: false },
          { notExpiredAt: NOW },
          { state: ['pending'], unused: true, notExpiredAt: NOW },
          { state: ['pending'], root: 'mnd_root', unused: true, notExpiredAt: NOW, limit: 2 },
        ];

        for (const q of queries) {
          const expected = corpus
            .filter((a) => matchesStepUpQuery(a, q))
            .sort(compareStepUps)
            .slice(0, q.limit ?? corpus.length);
          const actual = await store.read(async (tx) => tx.findStepUps(q));
          expect(actual.map((a) => a.handle), `query ${JSON.stringify(q)}`).toEqual(
            expected.map((a) => a.handle),
          );
        }
      });
    });

    it('drops spend history past the retention window', async () => {
      await withStore(at, async (store) => {
        await store.transact(async (tx) => {
          await tx.appendHistory('mnd_root', {
            ts: NOW - HISTORY_RETENTION_SECONDS - 1,
            amountScaled: 1n,
          });
          await tx.appendHistory('mnd_root', { ts: NOW - 60, amountScaled: 2n });
          await tx.appendHistory('mnd_root', { ts: NOW, amountScaled: -3n });
        });
        const kept = await store.read(async (tx) => tx.historySince('mnd_root', 0));
        expect(kept.map((e) => e.amountScaled).sort()).toEqual([-3n, 2n].sort());
        const recent = await store.read(async (tx) => tx.historySince('mnd_root', NOW - 10));
        expect(recent).toEqual([{ ts: NOW, amountScaled: -3n }]);
      });
    });
  });

  // ---------------------------------------------------------------- concurrency

  describe(`no overdraw under concurrency [${h.name}, ${h.runs} runs]`, () => {
    const arbAmount = fc.integer({ min: 1, max: 400 }).map((c) => {
      const whole = Math.floor(c / 100);
      return usd(`${whole}.${String(c % 100).padStart(2, '0')}`);
    });

    interface Fixture {
      ledger: Ledger;
      left: string[];
      right: string[];
    }

    function build(
      store: LedgerStore,
      clock: () => number,
      principal: AgentKey,
      agentA: AgentKey,
      b1: AgentKey,
      b2: AgentKey,
      ledgerKey: AgentKey,
      rootBudget: string,
      childBudget: string,
    ): Fixture {
      let n = 0;
      const ledger = new Ledger({
        url: 'https://ledger.example.com',
        key: ledgerKey,
        store,
        isTrustedRootIssuer: trustOnly(principal),
        clock,
        idFactory: (p) => `${p}_${String(++n).padStart(6, '0')}`,
        breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
      });

      const root = {
        max_total: usd(rootBudget),
        max_per_txn: usd('100.00'),
        aud: [HOST],
        depth: 2,
        delegable: true,
      };
      const chainFor = (holder: AgentKey, jti: string) =>
        buildChain(principal, [
          { holder: agentA, cav: root, exp: NOW + 86400, jti: 'mnd_root' },
          { holder, cav: { max_total: usd(childBudget) }, exp: NOW + 3600, jti },
        ]);

      return { ledger, left: chainFor(b1, 'mnd_left'), right: chainFor(b2, 'mnd_right') };
    }

    it('holds for interleaved reserves across two siblings', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(fc.tuple(fc.boolean(), arbAmount), { minLength: 4, maxLength: 30 }),
          async (ops) => {
            const clock = NOW + 10;
            await withStore(
              () => clock,
              async (store) => {
                const { ledger, left, right } = build(
                  store,
                  () => clock,
                  generateAgentKey(),
                  generateAgentKey(),
                  generateAgentKey(),
                  generateAgentKey(),
                  generateAgentKey(),
                  '20.00',
                  '12.00',
                );

                const results = await Promise.all(
                  ops.map(([useLeft, amount]) =>
                    ledger.reserve({
                      tokens: useLeft ? left : right,
                      request: { resource: RESOURCE, amount },
                    }),
                  ),
                );

                const committed = ops
                  .map(([useLeft, amount], i) => ({ useLeft, amount, ok: results[i]!.ok }))
                  .filter((r) => r.ok);

                const total = committed.reduce((a, r) => a + toScaled(r.amount), 0n);
                const leftTotal = committed
                  .filter((r) => r.useLeft)
                  .reduce((a, r) => a + toScaled(r.amount), 0n);
                const rightTotal = total - leftTotal;

                // Every node's declared budget is respected...
                expect(total).toBeLessThanOrEqual(toScaled(usd('20.00')));
                expect(leftTotal).toBeLessThanOrEqual(toScaled(usd('12.00')));
                expect(rightTotal).toBeLessThanOrEqual(toScaled(usd('12.00')));

                // ...and the recorded counters agree with what actually committed.
                const rootLeft = await ledger.remaining('mnd_root');
                expect(toScaled(rootLeft!)).toBe(toScaled(usd('20.00')) - total);
              },
            );
          },
        ),
        { numRuns: h.runs },
      );
    });

    it('conserves funds across interleaved reserve, settle and refund', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(
            fc.tuple(fc.boolean(), arbAmount, fc.constantFrom('settle', 'refund', 'leave')),
            { minLength: 4, maxLength: 24 },
          ),
          async (ops) => {
            const clock = NOW + 10;
            await withStore(
              () => clock,
              async (store) => {
                const { ledger, left, right } = build(
                  store,
                  () => clock,
                  generateAgentKey(),
                  generateAgentKey(),
                  generateAgentKey(),
                  generateAgentKey(),
                  generateAgentKey(),
                  '20.00',
                  '12.00',
                );

                const outcomes = await Promise.all(
                  ops.map(async ([useLeft, amount, action]) => {
                    const r = await ledger.reserve({
                      tokens: useLeft ? left : right,
                      request: { resource: RESOURCE, amount },
                    });
                    if (!r.ok) return { held: 0n };
                    if (action === 'settle') {
                      await ledger.settle(r.spendId);
                      return { held: toScaled(amount) };
                    }
                    if (action === 'refund') {
                      await ledger.refund(r.spendId, 'test');
                      return { held: 0n };
                    }
                    return { held: toScaled(amount) }; // still reserved
                  }),
                );

                const held = outcomes.reduce((a, o) => a + o.held, 0n);
                const remaining = await ledger.remaining('mnd_root');

                // Refunds restore exactly what they debited; nothing leaks either way.
                expect(toScaled(remaining!)).toBe(toScaled(usd('20.00')) - held);
                expect(toScaled(remaining!)).toBeGreaterThanOrEqual(0n);
              },
            );
          },
        ),
        { numRuns: h.runs },
      );
    });

    it('never lets a rate caveat be exceeded within its window', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 12 }),
          fc.integer({ min: 1, max: 20 }),
          async (n, attempts) => {
            const clock = NOW + 10;
            await withStore(
              () => clock,
              async (store) => {
                const principal = generateAgentKey();
                const agentA = generateAgentKey();
                const ledger = new Ledger({
                  url: 'https://ledger.example.com',
                  key: generateAgentKey(),
                  store,
                  isTrustedRootIssuer: trustOnly(principal),
                  clock: () => clock,
                  breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
                });
                const tokens = buildChain(principal, [
                  {
                    holder: agentA,
                    exp: NOW + 86400,
                    jti: 'mnd_root',
                    cav: {
                      max_total: usd('1000.00'),
                      max_per_txn: usd('1.00'),
                      aud: [HOST],
                      rate: { n, per: 'PT1H' },
                    },
                  },
                ]);

                const results = await Promise.all(
                  Array.from({ length: attempts }, () =>
                    ledger.reserve({
                      tokens,
                      request: { resource: RESOURCE, amount: usd('0.01') },
                    }),
                  ),
                );
                expect(results.filter((r) => r.ok).length).toBe(Math.min(n, attempts));
              },
            );
          },
        ),
        { numRuns: h.runs },
      );
    });

    /**
     * The first spend against a mandate is the case a row lock cannot cover:
     * there is no row to lock yet.
     *
     * A store that reads-to-lock will match nothing, so every concurrent first
     * spend sees `spent = 0`, passes the budget check, and writes a row derived
     * from that reading — leaving one debit recorded instead of five. This is
     * not a rare interleaving; it is what happens on the first two concurrent
     * calls against any newly issued mandate.
     */
    it('debits every one of several concurrent first spends on a fresh mandate', async () => {
      const clock = NOW + 10;
      await withStore(
        () => clock,
        async (store) => {
          const principal = generateAgentKey();
          const agentA = generateAgentKey();
          const ledger = new Ledger({
            url: 'https://ledger.example.com',
            key: generateAgentKey(),
            store,
            isTrustedRootIssuer: trustOnly(principal),
            clock: () => clock,
            breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
          });
          const tokens = buildChain(principal, [
            {
              holder: agentA,
              exp: NOW + 86400,
              jti: 'mnd_root',
              cav: { max_total: usd('10.00'), max_per_txn: usd('10.00'), aud: [HOST] },
            },
          ]);

          // Nothing has ever been written for this mandate. All five race the
          // creation of its node.
          const results = await Promise.all(
            Array.from({ length: 5 }, () =>
              ledger.reserve({ tokens, request: { resource: RESOURCE, amount: usd('2.00') } }),
            ),
          );

          expect(results.filter((r) => r.ok).length).toBe(5);
          expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(0n);

          // And the budget is genuinely gone, not merely reported gone.
          const over = await ledger.reserve({
            tokens,
            request: { resource: RESOURCE, amount: usd('0.01') },
          });
          expect(over.ok).toBe(false);
          if (!over.ok) expect(over.code).toBe('budget_exhausted');
        },
      );
    });

    /**
     * A step-up approval is one human saying yes once, and it must stay once
     * under concurrency. Consuming it is a read-then-write, serialized by the
     * root node's lock rather than by anything on the handle itself — every
     * reserve that could consume a given handle locks that handle's root first.
     *
     * The first half of this test is the more important one: an agent holding a
     * handle it was just given, and nothing else, gets nowhere.
     */
    it('spends a step-up approval exactly once under concurrent presentation', async () => {
      const clock = NOW + 10;
      await withStore(
        () => clock,
        async (store) => {
          const principal = generateAgentKey();
          const agentA = generateAgentKey();
          let n = 0;
          const ledger = new Ledger({
            url: 'https://ledger.example.com',
            key: generateAgentKey(),
            store,
            isTrustedRootIssuer: trustOnly(principal),
            clock: () => clock,
            idFactory: (p) => `${p}_${String(++n).padStart(6, '0')}`,
            breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
          });
          const tokens = buildChain(principal, [
            {
              holder: agentA,
              exp: NOW + 86400,
              jti: 'mnd_root',
              cav: {
                max_total: usd('100.00'),
                max_per_txn: usd('10.00'),
                aud: [HOST],
                step_up: { over: usd('1.00') },
              },
            },
          ]);
          const request = { resource: RESOURCE, amount: usd('5.00') };

          const blocked = await ledger.reserve({ tokens, request });
          expect(blocked.ok).toBe(false);
          if (blocked.ok) return;
          expect(blocked.code).toBe('step_up_required');
          const handle = blocked.stepUpHandle!;

          // The handle alone buys nothing. It was handed to the agent in the
          // error response, so if possession were consent the agent would be
          // approving its own spend.
          const unapproved = await Promise.all(
            Array.from({ length: 8 }, () =>
              ledger.reserve({ tokens, request, stepUpHandle: handle }),
            ),
          );
          expect(unapproved.filter((r) => r.ok).length).toBe(0);
          // ...and polling with it does not enqueue eight more questions.
          expect(await ledger.pendingStepUps()).toHaveLength(1);

          const decision = signStepUpDecision(
            {
              v: 'am/1',
              typ: 'approval',
              handle,
              iss: principal.did,
              verdict: 'approve',
              root: 'mnd_root',
              res: RESOURCE,
              amt: usd('5.00'),
              iat: clock,
              exp: clock + 900,
            },
            principal,
          );
          expect((await ledger.decideStepUp(decision)).ok).toBe(true);

          const racers = await Promise.all(
            Array.from({ length: 8 }, () =>
              ledger.reserve({ tokens, request, stepUpHandle: handle }),
            ),
          );

          expect(racers.filter((r) => r.ok).length).toBe(1);
          expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(
            toScaled(usd('100.00')) - toScaled(usd('5.00')),
          );
        },
      );
    });

    /**
     * The task ceiling is the one breaker keyed by something other than the
     * mandate path. Two principals sharing a task id are serialized by nothing
     * else — no shared root row, no shared path — so this is the case that fails
     * if `taskTotal` reads without locking.
     */
    it('holds the task ceiling across two principals sharing a task', async () => {
      const clock = NOW + 10;
      await withStore(
        () => clock,
        async (store) => {
          const p1 = generateAgentKey();
          const p2 = generateAgentKey();
          const holder1 = generateAgentKey();
          const holder2 = generateAgentKey();
          const ledger = new Ledger({
            url: 'https://ledger.example.com',
            key: generateAgentKey(),
            store,
            isTrustedRootIssuer: (iss) => iss === p1.did || iss === p2.did,
            clock: () => clock,
            breakers: {
              novelMerchant: 'off',
              velocityMinSamples: 1e9,
              taskCeilingScaled: toScaled(usd('5.00')),
            },
          });

          const cav = {
            max_total: usd('100.00'),
            max_per_txn: usd('10.00'),
            aud: [HOST],
          };
          const chainA = buildChain(p1, [
            { holder: holder1, cav, exp: NOW + 86400, jti: 'mnd_rootA' },
          ]);
          const chainB = buildChain(p2, [
            { holder: holder2, cav, exp: NOW + 86400, jti: 'mnd_rootB' },
          ]);

          const results = await Promise.all(
            Array.from({ length: 12 }, (_, i) =>
              ledger.reserve({
                tokens: i % 2 === 0 ? chainA : chainB,
                request: { resource: RESOURCE, amount: usd('1.00'), taskId: 'shared-task' },
              }),
            ),
          );

          // Five $1.00 spends reach the $5.00 ceiling exactly; the sixth is over.
          expect(results.filter((r) => r.ok).length).toBe(5);
          expect(await store.read(async (tx) => tx.taskTotal('shared-task'))).toBe(
            toScaled(usd('5.00')),
          );
        },
      );
    });

    it('keeps consumption state across a new Ledger over the same store', async () => {
      const clock = NOW + 10;
      await withStore(
        () => clock,
        async (store) => {
          const principal = generateAgentKey();
          const agentA = generateAgentKey();
          const cfg = {
            url: 'https://ledger.example.com',
            key: generateAgentKey(),
            store,
            isTrustedRootIssuer: trustOnly(principal),
            clock: () => clock,
            breakers: { novelMerchant: 'off' as const, velocityMinSamples: 1e9 },
          };
          const tokens = buildChain(principal, [
            {
              holder: agentA,
              exp: NOW + 86400,
              jti: 'mnd_root',
              cav: { max_total: usd('10.00'), max_per_txn: usd('10.00'), aud: [HOST] },
            },
          ]);

          const first = new Ledger(cfg);
          expect(
            (await first.reserve({ tokens, request: { resource: RESOURCE, amount: usd('6.00') } }))
              .ok,
          ).toBe(true);

          // A different Ledger instance, same store: the budget is spent state,
          // not instance state.
          const second = new Ledger(cfg);
          expect(toScaled((await second.remaining('mnd_root'))!)).toBe(toScaled(usd('4.00')));
          const over = await second.reserve({
            tokens,
            request: { resource: RESOURCE, amount: usd('5.00') },
          });
          expect(over.ok).toBe(false);
          if (!over.ok) expect(over.code).toBe('budget_exhausted');
        },
      );
    });
  });
}
