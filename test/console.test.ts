import { beforeEach, describe, expect, it } from 'vitest';

import {
  type ControlDecisionClaims,
  signControlDecision,
  verifyControlDecision,
} from '../src/control.js';
import { ConsoleService, type ConsoleOverview } from '../src/http/console.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §5.2 — the console, and §10.6, the signed control actions under it.
 *
 * `setGlobalKill` and `revoke` never asked who was calling. That was survivable
 * while the only caller was code inside the deployment; a console puts them on a
 * network whose most likely other occupant is the agent the kill switch exists
 * to stop.
 */

let alice: AgentKey; // a principal
let bob: AgentKey; // a different principal, on the same ledger
let agent: AgentKey;
let clock: number;
let ledger: Ledger;

const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;

const trustEither = (iss: string) => iss === alice.did || iss === bob.did;

beforeEach(() => {
  alice = generateAgentKey();
  bob = generateAgentKey();
  agent = generateAgentKey();
  clock = NOW + 10;
  ledger = new Ledger({
    url: 'https://ledger.example.com',
    key: generateAgentKey(),
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustEither,
    clock: () => clock,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
  });
});

function chainFor(principal: AgentKey, jti: string, cav: Record<string, unknown> = {}) {
  return buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti,
      cav: {
        max_total: usd('100.00'),
        max_per_txn: usd('50.00'),
        aud: [HOST],
        step_up: { over: usd('10.00') },
        ...cav,
      },
    },
  ]);
}

const spend = async (tokens: string[], amt = '1.00') =>
  ledger.reserve({ tokens, request: { resource: RESOURCE, amount: usd(amt), taskId: 'tsk_01' } });

const control = (
  over: Partial<ControlDecisionClaims> & { action: ControlDecisionClaims['action'] },
  signer: AgentKey = alice,
) =>
  signControlDecision(
    {
      v: 'am/1',
      typ: 'control',
      jti: `ctl_${Math.abs(over.iat ?? clock)}_${over.action}_${over.target ?? 'x'}`,
      iss: signer.did,
      root: 'mnd_alice',
      iat: clock,
      exp: clock + 300,
      ...over,
    } as ControlDecisionClaims,
    signer,
  );

describe('signed control actions', () => {
  it('halts and releases a principal that owns the root', async () => {
    const tokens = chainFor(alice, 'mnd_alice');
    expect((await spend(tokens)).ok).toBe(true);

    expect((await ledger.applyControl(control({ action: 'kill' }))).ok).toBe(true);

    const blocked = await spend(tokens);
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) expect(blocked.code).toBe('breaker_tripped');

    expect((await ledger.applyControl(control({ action: 'release' }))).ok).toBe(true);
    expect((await spend(tokens)).ok).toBe(true);
  });

  /**
   * The reason `MandateNode.issuer` exists. `isTrustedRootIssuer` answers "is
   * this DID a principal we trust", not "is this DID *this subtree's*
   * principal", so without the ownership check any trusted principal could halt
   * or revoke any other's mandates.
   */
  it('will not let one principal halt another principal', async () => {
    const aliceTokens = chainFor(alice, 'mnd_alice');
    expect((await spend(aliceTokens)).ok).toBe(true);

    // Bob is a perfectly trusted root issuer. He just did not issue this root.
    const forged = await ledger.applyControl(control({ action: 'kill' }, bob));
    expect(forged.ok).toBe(false);
    if (!forged.ok) expect(forged.code).toBe('pop_failed');

    // Alice's agent is unaffected.
    expect((await spend(aliceTokens)).ok).toBe(true);
  });

  it('refuses a decision signed by the agent', async () => {
    const tokens = chainFor(alice, 'mnd_alice');
    await spend(tokens);

    const forged = await ledger.applyControl(control({ action: 'kill' }, agent));
    expect(forged.ok).toBe(false);
    if (!forged.ok) expect(forged.code).toBe('pop_failed');
  });

  /**
   * A step-up decision names a one-shot handle, so replay is caught by the
   * handle being spent. A control action names nothing of the sort: a captured
   * `release` would otherwise sit and wait for the next incident.
   */
  it('consumes a decision exactly once', async () => {
    const tokens = chainFor(alice, 'mnd_alice');
    await spend(tokens);

    const kill = control({ action: 'kill' });
    expect((await ledger.applyControl(kill)).ok).toBe(true);

    const replayed = await ledger.applyControl(kill);
    expect(replayed.ok).toBe(false);
    if (!replayed.ok) expect(replayed.code).toBe('token_replayed');

    // The dangerous direction: a captured release replayed after a later halt.
    const release = control({ action: 'release', jti: 'ctl_release_once' });
    expect((await ledger.applyControl(release)).ok).toBe(true);
    expect((await ledger.applyControl(control({ action: 'kill', jti: 'ctl_kill_2' }))).ok).toBe(
      true,
    );

    const replayedRelease = await ledger.applyControl(release);
    expect(replayedRelease.ok).toBe(false);
    if (!replayedRelease.ok) expect(replayedRelease.code).toBe('token_replayed');

    const stillBlocked = await spend(tokens);
    expect(stillBlocked.ok).toBe(false);
  });

  it('revokes a mandate in its own subtree and refuses one outside it', async () => {
    const aliceTokens = chainFor(alice, 'mnd_alice');
    const bobTokens = chainFor(bob, 'mnd_bob');
    await spend(aliceTokens);
    await spend(bobTokens);

    const crossTree = await ledger.applyControl(
      control({ action: 'revoke', target: 'mnd_bob', jti: 'ctl_cross' }),
    );
    expect(crossTree.ok).toBe(false);
    if (!crossTree.ok) expect(crossTree.code).toBe('attenuation_violation');

    const own = await ledger.applyControl(
      control({ action: 'revoke', target: 'mnd_alice', jti: 'ctl_own' }),
    );
    expect(own.ok).toBe(true);

    const after = await spend(aliceTokens);
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.code).toBe('mandate_revoked');

    // Bob's subtree is untouched.
    expect((await spend(bobTokens)).ok).toBe(true);
  });

  it('rejects an expired or malformed decision', async () => {
    await spend(chainFor(alice, 'mnd_alice'));

    const stale = control({ action: 'kill', iat: clock - 1000, exp: clock - 500 });
    const r = await ledger.applyControl(stale);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('token_expired');

    // A revoke naming nothing to revoke is malformed, not a no-op.
    const noTarget = await verifyControlDecision(
      signControlDecision(
        {
          v: 'am/1',
          typ: 'control',
          jti: 'ctl_x',
          iss: alice.did,
          action: 'revoke',
          root: 'mnd_alice',
          iat: clock,
          exp: clock + 300,
        },
        alice,
      ),
      { now: clock, isTrustedRootIssuer: trustEither },
    );
    expect(noTarget.ok).toBe(false);
  });

  it('refuses to act on a root that has never been spent against', async () => {
    // No node, so no recorded issuer, so nothing that can be authorized — and
    // nothing yet worth halting either.
    const r = await ledger.applyControl(control({ action: 'kill' }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('chain_invalid');
  });
});

describe('the console surface', () => {
  const service = (servePage = true) =>
    new ConsoleService({ ledger, basePath: '/console', servePage });

  const overview = async (root = 'mnd_alice') => {
    const res = await service().handle({
      method: 'GET',
      path: '/console/api/overview',
      query: { root },
    });
    expect(res.status).toBe(200);
    return res.body as ConsoleOverview;
  };

  it('renders the budget tree in money, with what is left', async () => {
    const tokens = buildChain(alice, [
      {
        holder: agent,
        exp: NOW + 86400,
        jti: 'mnd_alice',
        cav: { max_total: usd('100.00'), max_per_txn: usd('50.00'), aud: [HOST] },
      },
      { holder: generateAgentKey(), exp: NOW + 3600, jti: 'mnd_child', cav: { max_total: usd('20.00') } },
    ]);
    await ledger.reserve({ tokens, request: { resource: RESOURCE, amount: usd('4.00') } });

    const body = await overview();
    expect(body.killed).toBe(false);
    expect(body.tree).toHaveLength(2);

    const root = body.tree.find((n) => n.jti === 'mnd_alice')!;
    expect(root.parent).toBeNull();
    expect(root.issuer).toBe(alice.did);
    expect(root.budget).toEqual({ cur: 'USD', amt: '100' });
    expect(root.remaining).toEqual({ cur: 'USD', amt: '96' });

    const child = body.tree.find((n) => n.jti === 'mnd_child')!;
    expect(child.parent).toBe('mnd_alice');
    expect(child.remaining).toEqual({ cur: 'USD', amt: '16' });
  });

  it('shows the spend feed newest first and the step-up queue', async () => {
    const tokens = chainFor(alice, 'mnd_alice');
    await spend(tokens, '1.00');
    clock += 10;
    await spend(tokens, '2.00');
    // Over the step_up threshold, so this one queues instead of spending.
    clock += 10;
    await spend(tokens, '20.00');

    const body = await overview();
    expect(body.spends).toHaveLength(2);
    expect(body.spends[0]!.amount.amt).toBe('2.00');
    expect(body.stepUps).toHaveLength(1);
    expect(body.stepUps[0]!.amount).toEqual({ cur: 'USD', amt: '20' });
  });

  /**
   * Every timestamp in the payload is relative to the *ledger's* clock, which is
   * authoritative and which a deployment may run on a skew. A page that
   * subtracted its own `Date.now()` renders ages that disagree with the ledger,
   * and against a simulated clock renders them negative — which is exactly what
   * the first version of the console did.
   */
  it('carries the ledger clock so ages are not computed against the reader', async () => {
    const tokens = chainFor(alice, 'mnd_alice');
    await spend(tokens);

    clock += 5000; // the ledger's clock runs well ahead of any wall clock here
    const body = await overview();

    expect(body.now).toBe(clock);
    const newest = body.spends[0]!;
    expect(body.now - newest.createdAt).toBeGreaterThan(0);
  });

  it('reflects the kill switch', async () => {
    const tokens = chainFor(alice, 'mnd_alice');
    await spend(tokens);
    expect((await overview()).killed).toBe(false);

    await ledger.applyControl(control({ action: 'kill' }));
    expect((await overview()).killed).toBe(true);
  });

  it('accepts a signed control action over HTTP and refuses an unsigned one', async () => {
    await spend(chainFor(alice, 'mnd_alice'));

    const bad = await service().handle({
      method: 'POST',
      path: '/console/api/control',
      body: { decision: 'not-a-jws' },
    });
    expect(bad.status).toBe(400);

    const good = await service().handle({
      method: 'POST',
      path: '/console/api/control',
      body: { decision: control({ action: 'kill' }) },
    });
    expect(good.status).toBe(200);
    expect(good.body).toMatchObject({ ok: true, action: 'kill', root: 'mnd_alice' });

    const byBob = await service().handle({
      method: 'POST',
      path: '/console/api/control',
      body: { decision: control({ action: 'release', jti: 'ctl_bob' }, bob) },
    });
    expect(byBob.status).toBe(401);
    expect((await overview()).killed).toBe(true);
  });

  it('mints a receipt on demand, and says so about what it is', async () => {
    const tokens = chainFor(alice, 'mnd_alice');
    const r = await spend(tokens);
    if (!r.ok) throw new Error('expected a reserve');

    const res = await service().handle({
      method: 'GET',
      path: `/console/api/receipt/${r.spendId}`,
    });
    expect(res.status).toBe(200);
    const receipt = res.body as { claims: Record<string, unknown>; sigs: { ledger: string } };
    expect(receipt.claims['spend']).toBe(r.spendId);
    expect(receipt.claims['principal']).toBe('mnd_alice');
    expect(receipt.sigs.ledger).toBeTruthy();

    expect(
      (await service().handle({ method: 'GET', path: '/console/api/receipt/spn_nope' })).status,
    ).toBe(404);
  });

  it('serves a self-contained page with a strict policy, or none at all', async () => {
    const page = await service().handle({ method: 'GET', path: '/console' });
    expect(page.status).toBe(200);
    expect(page.headers['content-type']).toContain('text/html');

    const csp = page.headers['content-security-policy']!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");

    const html = page.body as string;
    expect(html).toContain('Principal console');
    // Non-extractable import is the whole basis of the in-browser key story.
    expect(html).toContain("'jwk', jwk, { name: 'Ed25519' }, false, ['sign']");
    // Nothing fetched from anywhere else, and nothing persisted.
    expect(html).not.toContain('localStorage');
    expect(html).not.toContain('//cdn');
    expect(html).not.toContain('http://');

    expect((await service(false).handle({ method: 'GET', path: '/console' })).status).toBe(404);
  });

  it('requires a root and 404s the rest', async () => {
    expect(
      (await service().handle({ method: 'GET', path: '/console/api/overview' })).status,
    ).toBe(400);
    expect((await service().handle({ method: 'GET', path: '/console/api/nope' })).status).toBe(404);
    expect(
      (await service().handle({ method: 'GET', path: '/console/api/control' })).status,
    ).toBe(405);
  });
});
