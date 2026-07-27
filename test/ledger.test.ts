import { beforeEach, describe, expect, it } from 'vitest';

import type { Caveats } from '../src/caveats.js';
import { type AuditEvent, Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { type StepUpDecisionClaims, signStepUpDecision } from '../src/stepup.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

let principal: AgentKey;
let agentA: AgentKey;
let b1: AgentKey;
let b2: AgentKey;
let clock: number;
let ledgerKey: AgentKey;
let store: MemoryLedgerStore;
let ledger: Ledger;
let ids = 0;

const RESOURCE = 'https://api.weatherco.com/v3/forecast/94110';

function makeLedger(overrides: Partial<ConstructorParameters<typeof Ledger>[0]> = {}) {
  store = new MemoryLedgerStore(() => clock);
  return new Ledger({
    url: 'https://ledger.example.com',
    key: ledgerKey,
    store,
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    idFactory: (p) => `${p}_${String(++ids).padStart(6, '0')}`,
    ...overrides,
  });
}

beforeEach(() => {
  principal = generateAgentKey();
  agentA = generateAgentKey();
  b1 = generateAgentKey();
  b2 = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
  ids = 0;
  ledger = makeLedger();
});

const request = (amt: string, taskId = 'tsk_01') => ({
  resource: RESOURCE,
  amount: usd(amt),
  purpose: 'research.readonly',
  taskId,
});

const rootCav = (over: Partial<Caveats> = {}): Caveats => ({
  max_total: usd('20.00'),
  max_per_txn: usd('5.00'),
  aud: ['api.weatherco.com'],
  purpose: ['research.readonly'],
  depth: 2,
  delegable: true,
  ...over,
});

function singleChain(cav: Caveats = rootCav()) {
  return buildChain(principal, [{ holder: agentA, cav, exp: NOW + 86400, jti: 'mnd_root' }]);
}

/** Two subagents under one root, sharing the root's budget node. */
function siblingChains(rootBudget: string, childBudget: string) {
  const root = rootCav({ max_total: usd(rootBudget) });
  const child = (jti: string): Caveats => ({ max_total: usd(childBudget), delegable: false });
  return {
    left: buildChain(principal, [
      { holder: agentA, cav: root, exp: NOW + 86400, jti: 'mnd_root' },
      { holder: b1, cav: child('l'), exp: NOW + 3600, jti: 'mnd_left' },
    ]),
    right: buildChain(principal, [
      { holder: agentA, cav: root, exp: NOW + 86400, jti: 'mnd_root' },
      { holder: b2, cav: child('r'), exp: NOW + 3600, jti: 'mnd_right' },
    ]),
  };
}

describe('§10.1 — consumption debits the whole path', () => {
  it('debits every ancestor, not just the leaf', async () => {
    const { left } = siblingChains('20.00', '10.00');
    const r = await ledger.reserve({ tokens: left, request: request('2.00') });
    expect(r.ok).toBe(true);

    expect((await ledger.remaining('mnd_root'))?.amt).toBe('18');
    expect((await ledger.remaining('mnd_left'))?.amt).toBe('8');
  });

  it('bounds sibling collusion by the common ancestor', async () => {
    // Two subagents, $10 each, under a $20 parent. Jointly they can reach $20,
    // never $40 — and neither needs to know the other exists.
    const { left, right } = siblingChains('20.00', '10.00');

    for (let i = 0; i < 2; i++) {
      expect((await ledger.reserve({ tokens: left, request: request('5.00') })).ok).toBe(true);
      expect((await ledger.reserve({ tokens: right, request: request('5.00') })).ok).toBe(true);
    }
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0');
    expect((await ledger.remaining('mnd_left'))?.amt).toBe('0');

    const over = await ledger.reserve({ tokens: right, request: request('0.01') });
    expect(over.ok).toBe(false);
    if (!over.ok) expect(over.code).toBe('budget_exhausted');
  });

  it('reports the exhausted ancestor even when the leaf still has room', async () => {
    // A child can never *declare* more than its parent — the verifier rejects
    // that before the ledger is consulted. The interesting case is a leaf whose
    // own budget is intact while a sibling has drained the shared ancestor.
    const root = rootCav({ max_total: usd('20.00') });
    const left = buildChain(principal, [
      { holder: agentA, cav: root, exp: NOW + 86400, jti: 'mnd_root' },
      { holder: b1, cav: { max_total: usd('10.00') }, exp: NOW + 3600, jti: 'mnd_left' },
    ]);
    const right = buildChain(principal, [
      { holder: agentA, cav: root, exp: NOW + 86400, jti: 'mnd_root' },
      { holder: b2, cav: { max_total: usd('20.00') }, exp: NOW + 3600, jti: 'mnd_right' },
    ]);

    for (let i = 0; i < 3; i++) {
      expect((await ledger.reserve({ tokens: right, request: request('5.00') })).ok).toBe(true);
    }
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('5');
    // Nodes materialize on first presentation, so the left child has no state yet.
    expect(await ledger.remaining('mnd_left')).toBeNull();

    const r = await ledger.reserve({ tokens: left, request: request('5.00') });
    expect(r.ok).toBe(true); // exactly drains the root
    expect((await ledger.remaining('mnd_left'))?.amt).toBe('5');

    const over = await ledger.reserve({ tokens: left, request: request('0.01') });
    expect(over.ok).toBe(false);
    if (!over.ok) {
      expect(over.code).toBe('budget_exhausted');
      expect(over.detail).toContain('mnd_root');
    }
  });

  it('treats a link with no declared budget as unbounded, bounded by its ancestors', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, cav: rootCav({ max_total: usd('3.00') }), exp: NOW + 86400, jti: 'mnd_root' },
      { holder: b1, cav: {}, exp: NOW + 3600, jti: 'mnd_child' },
    ]);
    expect((await ledger.reserve({ tokens: chain, request: request('3.00') })).ok).toBe(true);
    expect(await ledger.remaining('mnd_child')).toBeNull();
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0');
  });

  it('rejects a jti reused with different content', async () => {
    const original = singleChain(rootCav({ max_total: usd('5.00') }));
    expect((await ledger.reserve({ tokens: original, request: request('5.00') })).ok).toBe(true);

    // Same jti, freshly signed, larger budget: a legitimate signature over a
    // mandate that would silently reset the consumption counter.
    const reissued = singleChain(rootCav({ max_total: usd('500.00') }));
    const r = await ledger.reserve({ tokens: reissued, request: request('5.00') });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toContain('different content');
  });
});

describe('§10.2 — rate limiting at every ancestor', () => {
  it('enforces an ancestor rate the leaf never declared', async () => {
    const chain = buildChain(principal, [
      {
        holder: agentA,
        cav: rootCav({ rate: { n: 2, per: 'PT1H' } }),
        exp: NOW + 86400,
        jti: 'mnd_root',
      },
      { holder: b1, cav: {}, exp: NOW + 3600, jti: 'mnd_child' },
    ]);

    expect((await ledger.reserve({ tokens: chain, request: request('0.01') })).ok).toBe(true);
    expect((await ledger.reserve({ tokens: chain, request: request('0.01') })).ok).toBe(true);

    const third = await ledger.reserve({ tokens: chain, request: request('0.01') });
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.code).toBe('rate_exceeded');

    clock += 3601; // window rolls
    expect((await ledger.reserve({ tokens: chain, request: request('0.01') })).ok).toBe(true);
  });
});

describe('§10.3 — revocation kills the subtree', () => {
  it('revoking an ancestor stops every descendant', async () => {
    const { left, right } = siblingChains('20.00', '10.00');
    expect((await ledger.reserve({ tokens: left, request: request('1.00') })).ok).toBe(true);

    expect(await ledger.revoke('mnd_root')).toBe(true);

    for (const tokens of [left, right]) {
      const r = await ledger.reserve({ tokens, request: request('1.00') });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('mandate_revoked');
    }
  });

  it('revoking a leaf leaves its sibling alone', async () => {
    const { left, right } = siblingChains('20.00', '10.00');
    await ledger.reserve({ tokens: left, request: request('1.00') });
    await ledger.reserve({ tokens: right, request: request('1.00') });

    await ledger.revoke('mnd_left');
    expect((await ledger.reserve({ tokens: left, request: request('1.00') })).ok).toBe(false);
    expect((await ledger.reserve({ tokens: right, request: request('1.00') })).ok).toBe(true);
  });
});

describe('§12 — settlement', () => {
  it('settles immediately and produces a dual-signable receipt', async () => {
    const chain = singleChain();
    const r = await ledger.reserve({ tokens: chain, request: request('1.00') });
    expect(r.ok).toBe(true);
    if (!r.ok) return;

    const s = await ledger.settle(r.spendId, {
      respHash: 'sha256:abc',
      respBytes: 42,
      merchantSig: 'merchant-sig',
    });
    expect(s.ok).toBe(true);
    if (!s.ok) return;
    expect(s.status).toBe('settled');
    expect(s.receipt.claims.path).toEqual(['mnd_root']);
    expect(s.receipt.claims.resp_hash).toBe('sha256:abc');
    expect(s.receipt.sigs.merchant).toBe('merchant-sig');
    expect(s.receipt.sigs.ledger).toMatch(/^[A-Za-z0-9_-]+$/);
    // Funds stay debited.
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('19');
  });

  it('escrow_schema refunds when the response fails validation', async () => {
    const chain = singleChain(rootCav({ settle: 'escrow_schema' }));
    const r = await ledger.reserve({
      tokens: chain,
      request: request('1.00'),
      quote: { schema: 'sha256:schema' },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('19');

    const s = await ledger.settle(r.spendId, { schemaValid: false, respHash: 'sha256:junk' });
    expect(s.ok).toBe(true);
    if (s.ok) expect(s.status).toBe('refunded');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('20');
  });

  it('escrow_schema will not settle without a verdict', async () => {
    const chain = singleChain(rootCav({ settle: 'escrow_schema' }));
    const r = await ledger.reserve({ tokens: chain, request: request('1.00') });
    if (!r.ok) throw new Error('reserve failed');
    const s = await ledger.settle(r.spendId, {});
    expect(s.ok).toBe(false);
  });

  it('escrow_human holds until approved', async () => {
    const chain = singleChain(rootCav({ settle: 'escrow_human' }));
    const r = await ledger.reserve({ tokens: chain, request: request('1.00') });
    if (!r.ok) throw new Error('reserve failed');

    const held = await ledger.settle(r.spendId, {});
    expect(held.ok && held.status).toBe('reserved');
    expect((await ledger.reservation(r.spendId))?.status).toBe('reserved');

    const released = await ledger.settle(r.spendId, { humanApproved: true });
    expect(released.ok && released.status).toBe('settled');
  });

  it('refuses to settle the same reservation twice', async () => {
    const chain = singleChain();
    const r = await ledger.reserve({ tokens: chain, request: request('1.00') });
    if (!r.ok) throw new Error('reserve failed');
    expect((await ledger.settle(r.spendId)).ok).toBe(true);
    const again = await ledger.settle(r.spendId);
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.code).toBe('token_replayed');
  });

  it('expiry refunds rather than captures', async () => {
    const chain = singleChain();
    const r = await ledger.reserve({ tokens: chain, request: request('4.00') });
    if (!r.ok) throw new Error('reserve failed');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('16');

    clock += 60 + 300 + 1;
    const swept = await ledger.sweepExpired();
    expect(swept).toEqual([r.spendId]);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('20');
    expect((await ledger.reservation(r.spendId))?.status).toBe('expired');
  });

  it('credits budget on refund but not the rate counter', async () => {
    const chain = singleChain(rootCav({ rate: { n: 2, per: 'PT1H' } }));
    const first = await ledger.reserve({ tokens: chain, request: request('1.00') });
    if (!first.ok) throw new Error('reserve failed');
    await ledger.refund(first.spendId, 'merchant returned 500');

    // Budget restored...
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('20');
    // ...but the request slot is gone. A failing endpoint must not become an
    // unlimited-rate endpoint, which is the shape of a retry storm.
    expect((await ledger.reserve({ tokens: chain, request: request('1.00') })).ok).toBe(true);
    const third = await ledger.reserve({ tokens: chain, request: request('1.00') });
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.code).toBe('rate_exceeded');
  });
});

describe('§10.5 — step-up', () => {
  const stepUpChain = () => singleChain(rootCav({ step_up: { over: usd('1.00') } }));

  /** A decision as the principal would sign it, with fields overridable to forge one. */
  const decide = (
    over: Partial<StepUpDecisionClaims> & { handle: string },
    signer: AgentKey = principal,
  ) =>
    signStepUpDecision(
      {
        v: 'am/1',
        typ: 'approval',
        iss: signer.did,
        verdict: 'approve',
        root: 'mnd_root',
        res: RESOURCE,
        amt: usd('2.00'),
        iat: clock,
        exp: clock + 900,
        ...over,
      },
      signer,
    );

  /**
   * The property that was missing entirely. The Ledger hands the handle to the
   * agent in the `step_up_required` response, so a design that treats holding
   * the handle as approval is approved by the agent — and `step_up` is the only
   * mechanism in the protocol for keeping a high-value spend attended.
   */
  it('does not accept its own handle back as approval', async () => {
    const chain = stepUpChain();

    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    expect(blocked.ok).toBe(false);
    if (blocked.ok) return;
    expect(blocked.code).toBe('step_up_required');
    const handle = blocked.stepUpHandle!;

    const replayed = await ledger.reserve({
      tokens: chain,
      request: request('2.00'),
      stepUpHandle: handle,
    });
    expect(replayed.ok).toBe(false);
    if (!replayed.ok) {
      expect(replayed.code).toBe('step_up_required');
      expect(replayed.detail).toBe('awaiting approval');
      // Polling returns the same question rather than asking a new one.
      expect(replayed.stepUpHandle).toBe(handle);
    }
    expect((await ledger.stepUp(handle))!.state).toBe('pending');
  });

  it('spends once a principal has signed, and only once', async () => {
    const chain = stepUpChain();
    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    if (blocked.ok) return;
    const handle = blocked.stepUpHandle!;

    const decision = await ledger.decideStepUp(decide({ handle }));
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.approval.state).toBe('approved');
      expect(decision.approval.decision?.by).toBe(principal.did);
    }

    const approved = await ledger.reserve({
      tokens: chain,
      request: request('2.00'),
      stepUpHandle: handle,
    });
    expect(approved.ok).toBe(true);

    const reused = await ledger.reserve({
      tokens: chain,
      request: request('2.00'),
      stepUpHandle: handle,
    });
    expect(reused.ok).toBe(false);
  });

  it('refuses a decision signed by anyone but the principal', async () => {
    const chain = stepUpChain();
    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    if (blocked.ok) return;
    const handle = blocked.stepUpHandle!;

    // The agent holds a key. It is not the key that granted the mandate.
    const forged = await ledger.decideStepUp(decide({ handle, iss: agentA.did }, agentA));
    expect(forged.ok).toBe(false);
    if (!forged.ok) expect(forged.code).toBe('pop_failed');

    // Nor can it claim to be the principal while signing with its own key.
    const impersonated = await ledger.decideStepUp(
      decide({ handle, iss: principal.did }, agentA),
    );
    expect(impersonated.ok).toBe(false);
    if (!impersonated.ok) expect(impersonated.code).toBe('pop_failed');

    expect((await ledger.stepUp(handle))!.state).toBe('pending');
  });

  /**
   * A signature over a bare handle attests only that the principal saw an opaque
   * string. The decision restates the terms so the bytes signed are the terms
   * agreed, and the Ledger re-checks them against its own record.
   */
  it('refuses a decision whose signed terms do not match the request', async () => {
    const chain = stepUpChain();
    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    if (blocked.ok) return;
    const handle = blocked.stepUpHandle!;

    const wrongAmount = await ledger.decideStepUp(decide({ handle, amt: usd('0.50') }));
    expect(wrongAmount.ok).toBe(false);
    if (!wrongAmount.ok) expect(wrongAmount.code).toBe('amount_exceeds_cap');

    const wrongResource = await ledger.decideStepUp(
      decide({ handle, res: 'https://api.weatherco.com/v3/forecast/00000' }),
    );
    expect(wrongResource.ok).toBe(false);
    if (!wrongResource.ok) expect(wrongResource.code).toBe('resource_not_covered');

    expect((await ledger.stepUp(handle))!.state).toBe('pending');
  });

  it('honours a denial and does not let the agent retry into a yes', async () => {
    const chain = stepUpChain();
    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    if (blocked.ok) return;
    const handle = blocked.stepUpHandle!;

    const denied = await ledger.decideStepUp(
      decide({ handle, verdict: 'deny', reason: 'not this vendor' }),
    );
    expect(denied.ok).toBe(true);

    const after = await ledger.reserve({
      tokens: chain,
      request: request('2.00'),
      stepUpHandle: handle,
    });
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.detail).toContain('not this vendor');

    // And the decision is final — a second bite is a replay, not a re-vote.
    const flipped = await ledger.decideStepUp(decide({ handle }));
    expect(flipped.ok).toBe(false);
    if (!flipped.ok) expect(flipped.code).toBe('token_replayed');
  });

  it('queues one question per distinct request, however often the agent retries', async () => {
    const chain = stepUpChain();
    for (let i = 0; i < 4; i++) await ledger.reserve({ tokens: chain, request: request('2.00') });

    const pending = await ledger.pendingStepUps();
    expect(pending).toHaveLength(1);
    expect(pending[0]!.state).toBe('pending');
    expect(pending[0]!.agent).toBe(agentA.did);
    expect(pending[0]!.taskId).toBe('tsk_01');

    // A genuinely different amount is a different question.
    await ledger.reserve({ tokens: chain, request: request('3.00') });
    expect(await ledger.pendingStepUps()).toHaveLength(2);
  });

  it('notifies an approver once the request has actually committed', async () => {
    const seen: string[] = [];
    ledger = makeLedger({ approver: { requested: (n) => void seen.push(n.handle) } });
    const chain = stepUpChain();

    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    if (blocked.ok) return;
    expect(seen).toEqual([blocked.stepUpHandle]);

    // Polling does not re-notify.
    await ledger.reserve({
      tokens: chain,
      request: request('2.00'),
      stepUpHandle: blocked.stepUpHandle!,
    });
    expect(seen).toHaveLength(1);
  });

  it('survives an approver that throws', async () => {
    ledger = makeLedger({
      approver: {
        requested: () => {
          throw new Error('pager is down');
        },
      },
    });
    const blocked = await ledger.reserve({ tokens: stepUpChain(), request: request('2.00') });
    expect(blocked.ok).toBe(false);
    // The request is still durable and still visible, so a dead notifier
    // degrades to polling rather than to a lost spend.
    expect(await ledger.pendingStepUps()).toHaveLength(1);
  });

  it('runs the approved window from the decision, not the request', async () => {
    const chain = stepUpChain();
    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    if (blocked.ok) return;
    const handle = blocked.stepUpHandle!;

    // A human who approves in the 59th minute of an hour-long request has not
    // agreed to give the agent one minute to act.
    clock += 3540;
    const decision = await ledger.decideStepUp(decide({ handle, iat: clock, exp: clock + 900 }));
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.approval.expiresAt).toBe(clock + 900);

    clock += 600;
    expect(
      (await ledger.reserve({ tokens: chain, request: request('2.00'), stepUpHandle: handle })).ok,
    ).toBe(true);
  });

  it('will not decide a request that has already lapsed', async () => {
    const chain = stepUpChain();
    const blocked = await ledger.reserve({ tokens: chain, request: request('2.00') });
    if (blocked.ok) return;

    clock += 3601;
    const late = await ledger.decideStepUp(
      decide({ handle: blocked.stepUpHandle!, iat: clock, exp: clock + 900 }),
    );
    expect(late.ok).toBe(false);
    if (!late.ok) expect(late.code).toBe('token_expired');
  });

  it('lets sub-threshold spends through untouched', async () => {
    const chain = stepUpChain();
    expect((await ledger.reserve({ tokens: chain, request: request('0.99') })).ok).toBe(true);
    expect(await ledger.pendingStepUps()).toHaveLength(0);
  });
});

describe('§10.4 — circuit breakers', () => {
  it('global kill halts a principal', async () => {
    const chain = singleChain();
    await ledger.setGlobalKill('mnd_root', true);
    const r = await ledger.reserve({ tokens: chain, request: request('0.01') });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('breaker_tripped');

    await ledger.setGlobalKill('mnd_root', false);
    expect((await ledger.reserve({ tokens: chain, request: request('0.01') })).ok).toBe(true);
  });

  it('enforces a per-task ceiling across separate mandates', async () => {
    ledger = makeLedger({ breakers: { taskCeilingScaled: 2_000_000_000n } }); // $2
    const { left, right } = siblingChains('20.00', '10.00');

    expect((await ledger.reserve({ tokens: left, request: request('1.50') })).ok).toBe(true);
    const over = await ledger.reserve({ tokens: right, request: request('1.00') });
    expect(over.ok).toBe(false);
    if (!over.ok) expect(over.code).toBe('breaker_tripped');

    // A different task is unaffected.
    expect(
      (await ledger.reserve({ tokens: right, request: request('1.00', 'tsk_other') })).ok,
    ).toBe(true);
  });

  it('alerts on a novel merchant without blocking', async () => {
    const chain = singleChain();
    const r = await ledger.reserve({ tokens: chain, request: request('0.01') });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.alerts.map((a) => a.name)).toContain('novel_merchant');

    const second = await ledger.reserve({ tokens: chain, request: request('0.01') });
    expect(second.ok && second.alerts.map((a) => a.name)).not.toContain('novel_merchant');
  });

  it('blocks a velocity anomaly against the rolling baseline', async () => {
    ledger = makeLedger({
      breakers: { velocityMultiple: 5, velocityWindowSeconds: 60, velocityMinSamples: 3 },
    });
    const chain = singleChain(rootCav({ max_total: usd('1000.00'), max_per_txn: usd('100.00') }));

    // Establish a quiet baseline: one small spend per window.
    for (let i = 0; i < 8; i++) {
      clock += 60;
      expect((await ledger.reserve({ tokens: chain, request: request('0.10') })).ok).toBe(true);
    }
    clock += 60;
    const spike = await ledger.reserve({ tokens: chain, request: request('100.00') });
    expect(spike.ok).toBe(false);
    if (!spike.ok) expect(spike.code).toBe('breaker_tripped');
  });
});

/**
 * §7 step 3 has two halves and only one of them lives in `verifyChain`.
 *
 * "All links agree on `ledger`" makes a chain internally consistent. It does not
 * make the ledger reading it the one the principal named, and consumption state
 * is per-ledger — so until `reserve` also checked, `max_total` was a cap per
 * ledger rather than a cap, full stop.
 */
describe('§7 step 3 — the chain must name this ledger', () => {
  const OTHER = 'https://ledger.b.example';

  /**
   * A genuine chain — signed by the trusted principal, every link agreeing with
   * every other — that simply names a different ledger. `tamper` runs before the
   * signature, so this is not a forgery: it is exactly the credential a
   * principal would hold if they banked at B.
   */
  const foreignChain = () =>
    buildChain(principal, [
      {
        holder: agentA,
        cav: rootCav(),
        exp: NOW + 86400,
        jti: 'mnd_root',
        tamper: (c) => {
          c.ledger = OTHER;
        },
      },
    ]);

  it('refuses a chain addressed to another ledger', async () => {
    const r = await ledger.reserve({ tokens: foreignChain(), request: request('1.00') });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('chain_invalid');
      // Both sides named, because this is a misconfiguration as often as it is
      // an attack and the log should say which ledger thought what.
      expect(r.detail).toContain(OTHER);
      expect(r.detail).toContain('https://ledger.example.com');
    }
  });

  it('refuses even when every link agrees — agreement is not address', async () => {
    const tokens = buildChain(principal, [
      {
        holder: agentA,
        cav: rootCav(),
        exp: NOW + 86400,
        jti: 'mnd_root',
        tamper: (c) => {
          c.ledger = OTHER;
        },
      },
      {
        holder: b1,
        cav: { max_total: usd('10.00') },
        exp: NOW + 3600,
        jti: 'mnd_leaf',
        tamper: (c) => {
          c.ledger = OTHER;
        },
      },
    ]);
    // The rule `verifyChain` does enforce is satisfied: no link disagrees.
    const r = await ledger.reserve({ tokens, request: request('1.00') });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('chain_invalid');
  });

  /**
   * The consequence, stated as money rather than as a code.
   *
   * One mandate, `max_total` 20.00, drained at the ledger it names. A second
   * ledger keeps its own consumption state and so has 20.00 of headroom to
   * offer — the same grant, spent twice, with no rule in §7 broken along the
   * way. Reverting `reserve`'s check turns this test red at the last line.
   */
  it('does not let one mandate be spent in full at every ledger that takes it', async () => {
    const tokens = singleChain(); // names https://ledger.example.com
    for (let i = 0; i < 4; i++) {
      expect((await ledger.reserve({ tokens, request: request('5.00') })).ok).toBe(true);
    }
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0');
    expect((await ledger.reserve({ tokens, request: request('5.00') })).ok).toBe(false);

    const elsewhere = makeLedger({ url: OTHER });
    const again = await elsewhere.reserve({ tokens, request: request('5.00') });
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.code).toBe('chain_invalid');
  });

  it('records the refusal, like every other §7 refusal', async () => {
    const audit: AuditEvent[] = [];
    const audited = makeLedger({ audit: { record: (e) => void audit.push(e) } });
    await audited.reserve({ tokens: foreignChain(), request: request('1.00') });
    expect(audit.map((e) => [e.event, e.code])).toEqual([['reserve.rejected', 'chain_invalid']]);
  });

  it('refuses to register one either — a list nobody would fetch is worse than none', async () => {
    // The status list URI is `{ledger}/v1/status/{root}`, so a merchant holding
    // this chain looks to B. Materializing it here would record it as revocable
    // by a ledger that cannot reach anyone holding it.
    const r = await ledger.register(foreignChain());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('chain_invalid');

    expect((await ledger.register(singleChain())).ok).toBe(true);
  });

  it('treats a trailing slash as the same ledger, as statusListUri already does', async () => {
    const slashed = makeLedger({ url: 'https://ledger.example.com/' });
    expect((await slashed.reserve({ tokens: singleChain(), request: request('1.00') })).ok).toBe(
      true,
    );
  });
});

describe('currency', () => {
  it('rejects a request denominated differently from the mandate', async () => {
    const chain = singleChain();
    const r = await ledger.reserve({
      tokens: chain,
      request: { ...request('1.00'), amount: { cur: 'EUR', amt: '1.00' } },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('currency_mismatch');
  });
});
