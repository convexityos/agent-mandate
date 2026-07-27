import { beforeEach, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { Reconciler, type Escalation } from '../src/ledger/reconciler.js';
import { MemoryLedgerStore, type Reservation } from '../src/ledger/store.js';
import { toScaled } from '../src/money.js';
import type { NonCustodialRail } from '../src/rail/noncustodial.js';
import type { PayResult, RailStatus, SettlementRail } from '../src/rail/rail.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §12.2.1 and open question 8 — the pass that decides whether inventing
 * `settling` was worth it.
 *
 * The rail below is controllable rather than realistic on purpose: the whole
 * point of the state is what happens when a rail *will not say*, and no real
 * rail can be asked to be indefinitely undecided on cue.
 */

const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;

let principal: AgentKey;
let agent: AgentKey;
let clock: number;
let ids = 0;

/** A rail whose `pay` and `status` answers are set by the test. */
class ControllableRail implements SettlementRail {
  readonly name = 'controllable';
  payResult: PayResult = { ok: false, terminal: false, detail: 'timed out' };
  statusResult: RailStatus = { state: 'unknown', detail: 'still pending' };
  statusCalls = 0;
  throwOnStatus = false;

  async pay(): Promise<PayResult> {
    return this.payResult;
  }

  async status(): Promise<RailStatus> {
    this.statusCalls++;
    if (this.throwOnStatus) throw new Error('rail is down');
    return this.statusResult;
  }
}

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  clock = NOW + 10;
  ids = 0;
});

function setup(rail?: SettlementRail) {
  const ledger = new Ledger({
    url: 'https://ledger.example.com',
    key: generateAgentKey(),
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    idFactory: (p) => `${p}_${String(++ids).padStart(6, '0')}`,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
    reservationGraceSeconds: 60,
    ...(rail !== undefined ? { rail } : {}),
  });

  const tokens = buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: { max_total: usd('10.00'), max_per_txn: usd('5.00'), aud: [HOST] },
    },
  ]);

  const reserve = async (amt = '1.00') => {
    const r = await ledger.reserve({
      tokens,
      request: { resource: RESOURCE, amount: usd(amt), taskId: 'tsk_01' },
    });
    if (!r.ok) throw new Error(`reserve failed: ${r.detail}`);
    return r.spendId;
  };

  const remaining = async () => toScaled((await ledger.remaining('mnd_root'))!);
  return { ledger, reserve, remaining };
}

/** Drive a reservation into `settling` by making the rail indeterminate. */
async function intoSettling(
  ledger: Ledger,
  rail: ControllableRail,
  reserve: () => Promise<string>,
): Promise<string> {
  rail.payResult = { ok: false, terminal: false, detail: 'connection reset' };
  const spendId = await reserve();
  const settled = await ledger.settle(spendId);
  expect(settled.ok).toBe(false);
  expect((await ledger.reservation(spendId))!.status).toBe('settling');
  return spendId;
}

describe('resolving what the rail can answer', () => {
  it('settles a payment the rail confirms landed', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve, remaining } = setup(rail);
    const spendId = await intoSettling(ledger, rail, reserve);

    rail.statusResult = { state: 'paid', ref: '0xabc' };
    const pass = await new Reconciler({ ledger, stuckAfterSeconds: 300 }).pass();

    expect(pass.settled).toEqual([spendId]);
    expect(pass.outstanding).toBe(0);
    const r = await ledger.reservation(spendId);
    expect(r!.status).toBe('settled');
    expect(r!.railRef).toBe('0xabc');
    expect(await remaining()).toBe(toScaled(usd('9.00')));
  });

  it('refunds a payment the rail confirms never happened', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve, remaining } = setup(rail);
    const spendId = await intoSettling(ledger, rail, reserve);

    rail.statusResult = { state: 'not_paid' };
    const pass = await new Reconciler({ ledger, stuckAfterSeconds: 300 }).pass();

    expect(pass.refunded).toEqual([spendId]);
    expect((await ledger.reservation(spendId))!.status).toBe('refunded');
    // Credited back on every node the debit touched.
    expect(await remaining()).toBe(toScaled(usd('10.00')));
  });

  /**
   * The rule the whole state exists for. "Don't know" is not "didn't happen",
   * and refunding on it pays the merchant and hands the money back as well.
   */
  it('leaves an undecided payment debited and waiting', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve, remaining } = setup(rail);
    const spendId = await intoSettling(ledger, rail, reserve);

    rail.statusResult = { state: 'unknown', detail: 'no answer' };
    const pass = await new Reconciler({ ledger, stuckAfterSeconds: 300 }).pass();

    expect(pass.stillUnknown).toEqual([spendId]);
    expect(pass.settled).toEqual([]);
    expect(pass.refunded).toEqual([]);
    expect((await ledger.reservation(spendId))!.status).toBe('settling');
    expect(await remaining()).toBe(toScaled(usd('9.00')));
  });
});

describe('escalation — the answer to open question 8', () => {
  it('says nothing while the payment is younger than the threshold', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve } = setup(rail);
    await intoSettling(ledger, rail, reserve);

    const seen: Escalation[] = [];
    const reconciler = new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      clock: () => clock,
      onEscalation: (e) => void seen.push(e),
    });

    clock += 299;
    const pass = await reconciler.pass();
    expect(pass.escalated).toEqual([]);
    expect(seen).toEqual([]);
    expect(pass.outstanding).toBe(1);
    expect(pass.oldestOutstandingSeconds).toBe(299);
  });

  it('tells a human once the payment has sat too long, and only once', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve, remaining } = setup(rail);
    const spendId = await intoSettling(ledger, rail, reserve);

    const seen: Escalation[] = [];
    const reconciler = new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      clock: () => clock,
      onEscalation: (e) => void seen.push(e),
    });

    clock += 400;
    const first = await reconciler.pass();
    expect(first.escalated).toHaveLength(1);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      spendId,
      ageSeconds: 400,
      // The amount as the agent requested it, carried through untouched —
      // not reconstructed from the scaled integer, which would render '1.00'
      // as '1' and quietly disagree with the receipt.
      amount: { cur: 'USD', amt: '1.00' },
      merchant: HOST,
      root: 'mnd_root',
      agent: agent.did,
      taskId: 'tsk_01',
      railName: 'controllable',
    });

    // Escalation moves no money — the reservation is here precisely because
    // nobody knows whether it landed.
    expect((await ledger.reservation(spendId))!.status).toBe('settling');
    expect(await remaining()).toBe(toScaled(usd('9.00')));

    // A second pass keeps reporting it as outstanding but does not re-page.
    clock += 400;
    const second = await reconciler.pass();
    expect(second.escalated).toEqual([]);
    expect(seen).toHaveLength(1);
    expect(second.outstanding).toBe(1);
    expect(second.oldestOutstandingSeconds).toBe(800);
  });

  it('does not escalate something the rail resolves in the same pass', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve } = setup(rail);
    await intoSettling(ledger, rail, reserve);

    // Old enough to escalate, but the rail answers this time. Asking before
    // escalating is what keeps a human from being woken for nothing.
    clock += 5000;
    rail.statusResult = { state: 'paid', ref: '0xfeed' };
    const pass = await new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      clock: () => clock,
    }).pass();

    expect(pass.settled).toHaveLength(1);
    expect(pass.escalated).toEqual([]);
    expect(pass.outstanding).toBe(0);
  });

  it('records the escalation durably, not just in the callback', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve } = setup(rail);
    const spendId = await intoSettling(ledger, rail, reserve);

    clock += 400;
    await new Reconciler({ ledger, stuckAfterSeconds: 300, clock: () => clock }).pass();

    const r = await ledger.reservation(spendId);
    expect(r!.escalated).toMatchObject({ at: clock });
    expect(r!.escalated!.reason).toContain('settling');
  });
});

/**
 * §12.4.5 — the non-custodial path escalates on the rail's own capabilities
 * rather than on a clock: without `hardExpiry` a payment can still land after
 * the deadline, so "unconfirmed" never becomes "never happened".
 *
 * It also escalates reservations still at `reserved` — an agent can execute a
 * directive and never report — which is why the reconciler cannot learn about
 * these from the `settling` queue.
 */
describe('escalations the rail raises itself', () => {
  class SoftExpiryRail implements NonCustodialRail {
    readonly name = 'soft-expiry';
    readonly payer = '0xpayer';
    readonly capabilities = {
      trustlessOracle: true,
      // The property that makes auto-refund unsound.
      hardExpiry: false,
      decimals: 6,
      reversible: false,
    };

    prepare(reservation: Reservation) {
      return {
        ok: true as const,
        prepared: {
          intent: { to: '0xmerchant', value: reservation.amountScaled.toString() },
          payer: this.payer,
          expiresAt: NOW + 100,
          decidableAt: NOW + 200,
        },
      };
    }

    verifyProof() {
      return { ok: true as const, ref: '0xproof' };
    }

    async confirm(): Promise<RailStatus> {
      return { state: 'not_paid' };
    }
  }

  it('reports a rail-raised escalation to the pager', async () => {
    const rail = new SoftExpiryRail();
    const ledger = new Ledger({
      url: 'https://ledger.example.com',
      key: generateAgentKey(),
      store: new MemoryLedgerStore(() => clock),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
      idFactory: (p) => `${p}_${String(++ids).padStart(6, '0')}`,
      breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
      nonCustodialRail: rail,
    });

    const reserved = await ledger.reserve({
      tokens: buildChain(principal, [
        {
          holder: agent,
          exp: NOW + 86400,
          jti: 'mnd_root',
          cav: { max_total: usd('10.00'), max_per_txn: usd('5.00'), aud: [HOST] },
        },
      ]),
      request: { resource: RESOURCE, amount: usd('1.00') },
    });
    expect(reserved.ok).toBe(true);
    if (!reserved.ok) return;

    const seen: Escalation[] = [];
    const pass = await new Reconciler({
      ledger,
      // Deliberately enormous: this escalation is nothing to do with age, and a
      // reconciler that only looked at its own clock would miss it entirely.
      stuckAfterSeconds: 1_000_000,
      clock: () => clock,
      onEscalation: (e) => void seen.push(e),
    }).pass();

    expect(pass.escalated).toHaveLength(1);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.spendId).toBe(reserved.spendId);
    expect(seen[0]!.reason).toContain('cannot guarantee');

    // Still `reserved`, still debited: the rail says it sees no settlement but
    // cannot promise one will not arrive, so refunding would double-spend.
    const r = await ledger.reservation(reserved.spendId);
    expect(r!.status).toBe('reserved');
    expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(toScaled(usd('9.00')));
  });
});

describe('sweeping, and the rule it must not break', () => {
  it('expires a token nobody redeemed and credits the path back', async () => {
    const { ledger, reserve, remaining } = setup();
    const spendId = await reserve();

    clock += 3600;
    const pass = await new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      clock: () => clock,
    }).pass();

    expect(pass.expired).toEqual([spendId]);
    expect((await ledger.reservation(spendId))!.status).toBe('expired');
    expect(await remaining()).toBe(toScaled(usd('10.00')));
  });

  it('never sweeps a reservation still in flight with the rail', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve } = setup(rail);
    const spendId = await intoSettling(ledger, rail, reserve);

    // Long past expiry, but `settling` is a payment in flight, not a token
    // nobody redeemed. §12.2.1: expiry applies to the latter only.
    clock += 100_000;
    const pass = await new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      clock: () => clock,
    }).pass();

    expect(pass.expired).toEqual([]);
    expect((await ledger.reservation(spendId))!.status).toBe('settling');
  });

  it('honours the sweep limit rather than locking every stale reservation at once', async () => {
    const { ledger, reserve } = setup();
    for (let i = 0; i < 5; i++) await reserve('0.50');

    clock += 3600;
    const reconciler = new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      sweepLimit: 2,
      clock: () => clock,
    });

    expect((await reconciler.pass()).expired).toHaveLength(2);
    expect((await reconciler.pass()).expired).toHaveLength(2);
    expect((await reconciler.pass()).expired).toHaveLength(1);
    expect((await reconciler.pass()).expired).toHaveLength(0);
  });
});

describe('a pass that goes wrong', () => {
  it('records a failing rail and keeps going', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve } = setup(rail);
    await intoSettling(ledger, rail, reserve);
    rail.throwOnStatus = true;

    clock += 3600;
    const pass = await new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      clock: () => clock,
    }).pass();

    expect(pass.errors.some((e) => e.startsWith('reconcile:'))).toBe(true);
    // The rail dying did not stop the pass: the stuck payment was still
    // escalated and the expiry sweep still ran.
    expect(pass.escalated).toHaveLength(1);
    expect(pass.expired).toEqual([]);
    expect(pass.outstanding).toBe(1);
  });

  it('does not lose an escalation to a dead pager', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve } = setup(rail);
    const spendId = await intoSettling(ledger, rail, reserve);

    clock += 400;
    const pass = await new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      clock: () => clock,
      onEscalation: () => {
        throw new Error('pagerduty is down');
      },
    }).pass();

    expect(pass.errors.some((e) => e.includes('pagerduty is down'))).toBe(true);
    // Recorded on the reservation regardless, so it degrades to somebody having
    // to look rather than to nobody knowing.
    expect((await ledger.reservation(spendId))!.escalated).toBeDefined();
  });

  it('is a no-op on a ledger that settles nothing', async () => {
    const { ledger } = setup();
    const pass = await new Reconciler({ ledger, stuckAfterSeconds: 300 }).pass();
    expect(pass).toMatchObject({
      settled: [],
      refunded: [],
      escalated: [],
      expired: [],
      outstanding: 0,
      oldestOutstandingSeconds: null,
      errors: [],
    });
  });
});

describe('running on a timer', () => {
  it('runs passes and stops when told', async () => {
    const { ledger, reserve } = setup();
    await reserve();
    clock += 3600;

    const passes: number[] = [];
    const reconciler = new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      intervalMs: 10,
      clock: () => clock,
      onPass: (p) => void passes.push(p.at),
    });

    reconciler.start();
    await new Promise((r) => setTimeout(r, 60));
    reconciler.stop();
    await reconciler.drain();

    expect(passes.length).toBeGreaterThan(0);
    const after = passes.length;
    await new Promise((r) => setTimeout(r, 40));
    expect(passes.length).toBe(after);
  });

  /**
   * Two concurrent passes would both ask the rail about the same reservations.
   * On a rail that bills per query that is a bill, not merely noise.
   */
  it('will not run two passes at once', async () => {
    const rail = new ControllableRail();
    const { ledger, reserve } = setup(rail);
    await intoSettling(ledger, rail, reserve);

    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    rail.status = async () => {
      rail.statusCalls++;
      await gate;
      return { state: 'unknown', detail: 'slow' };
    };

    const reconciler = new Reconciler({
      ledger,
      stuckAfterSeconds: 300,
      intervalMs: 5,
      clock: () => clock,
    });

    reconciler.start();
    await new Promise((r) => setTimeout(r, 60)); // many ticks, one slow pass
    expect(rail.statusCalls).toBe(1);

    release();
    reconciler.stop();
    await reconciler.drain();
  });
});
