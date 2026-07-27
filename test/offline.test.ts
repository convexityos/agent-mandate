import { beforeEach, describe, expect, it } from 'vitest';

import type { Caveats } from '../src/caveats.js';
import {
  MAX_OFFLINE_WINDOW_SECONDS,
  checkOfflineProfile,
  offlineExposureOf,
  offlineRiskBudget,
} from '../src/offline.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { verifyChain } from '../src/verify.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §13 — the offline profile, and the exposure it creates.
 *
 * Written because the threat catalogue asked what proved the
 * `cross-merchant-parallel-spend` mitigation and the answer was nothing. §13 is
 * five constraints that only bound anything *together*, and every one of them
 * was individually expressible in a caveat while no code anywhere held a mandate
 * to all five at once.
 */

let principal: AgentKey;
let agent: AgentKey;
const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
});

/** The profile, satisfied. Each test breaks exactly one constraint. */
const offlineCav = (over: Partial<Caveats> = {}): Caveats => ({
  aud: [HOST],
  max_total: usd('20.00'),
  settle: 'immediate',
  ...over,
});

const window = (span = 3600) => ({ nbf: NOW, exp: NOW + span });

const verifyOffline = (cav: Caveats, span = 3600) =>
  verifyChain(buildChain(principal, [{ holder: agent, cav, nbf: NOW, exp: NOW + span }]), {
    now: NOW + 10,
    request: { resource: RESOURCE, amount: usd('1.00') },
    isTrustedRootIssuer: trustOnly(principal),
    offline: true,
  });

describe('the profile', () => {
  it('admits a chain that satisfies all four checkable constraints', () => {
    expect(checkOfflineProfile(offlineCav(), window()).ok).toBe(true);
  });

  it('refuses a wildcard audience, which names a set rather than a merchant', () => {
    // The one that passes a naive `aud.length === 1` check while naming every
    // subdomain there is — and the one that makes the risk budget unbounded,
    // because "the sum over merchants named" has no upper limit.
    const wild = checkOfflineProfile(offlineCav({ aud: ['*.weatherco.com'] }), window());
    expect(wild).toMatchObject({ ok: false, code: 'offline_profile_violated' });
  });

  it('refuses more than one audience, and none at all', () => {
    for (const aud of [[HOST, 'api.other.example'], [], undefined]) {
      expect(
        checkOfflineProfile(offlineCav({ aud }), window()),
        `aud ${JSON.stringify(aud)}`,
      ).toMatchObject({ ok: false, code: 'offline_profile_violated' });
    }
  });

  it('refuses a mandate with no max_total, because there is nothing to bound', () => {
    expect(
      checkOfflineProfile(offlineCav({ max_total: undefined }), window()),
    ).toMatchObject({ ok: false, code: 'offline_profile_violated' });
  });

  it('refuses a window over an hour, to the second', () => {
    expect(checkOfflineProfile(offlineCav(), window(MAX_OFFLINE_WINDOW_SECONDS)).ok).toBe(true);
    expect(
      checkOfflineProfile(offlineCav(), window(MAX_OFFLINE_WINDOW_SECONDS + 1)),
    ).toMatchObject({ ok: false, code: 'offline_profile_violated' });
  });

  it('refuses escrow, and refuses leaving settle unconstrained', () => {
    // The one place absence being ⊤ is the wrong answer: ⊤ on `settle` includes
    // escrow, and escrow requires Ledger participation, which is the one thing
    // an offline merchant does not have.
    expect(checkOfflineProfile(offlineCav({ settle: 'escrow_schema' }), window())).toMatchObject({
      ok: false,
      code: 'offline_profile_violated',
    });
    expect(checkOfflineProfile(offlineCav({ settle: undefined }), window())).toMatchObject({
      ok: false,
      code: 'offline_profile_violated',
    });
  });
});

describe('verifyChain in offline mode', () => {
  it('admits a conforming chain and refuses one that is merely valid', async () => {
    expect((await verifyOffline(offlineCav())).ok).toBe(true);

    // Perfectly valid as a credential; simply not settleable without the Ledger.
    const wide = await verifyOffline(offlineCav({ aud: ['*.weatherco.com'] }));
    expect(wide).toMatchObject({ ok: false, code: 'offline_profile_violated' });
  });

  it('leaves online verification exactly as it was', async () => {
    // §17.3 in miniature: the same chain an offline merchant refuses is admitted
    // online, because online the Ledger is on the spend path and the caps bound
    // nothing that is not already bounded.
    const tokens = buildChain(principal, [
      { holder: agent, cav: { aud: ['*.weatherco.com'] }, nbf: NOW, exp: NOW + 86400 },
    ]);
    const online = await verifyChain(tokens, {
      now: NOW + 10,
      request: { resource: RESOURCE, amount: usd('1.00') },
      isTrustedRootIssuer: trustOnly(principal),
    });
    expect(online.ok).toBe(true);
  });

  it('checks the fold, not any one link', async () => {
    // A root that names a wildcard and a leaf that narrows to one host is fine
    // offline; only the effective authority can tell that from the reverse.
    const narrowing = buildChain(principal, [
      {
        holder: agent,
        cav: { aud: ['*.weatherco.com'], max_total: usd('20.00'), settle: 'immediate' },
        nbf: NOW,
        exp: NOW + 3600,
      },
      {
        holder: generateAgentKey(),
        cav: { aud: [HOST] },
        nbf: NOW,
        exp: NOW + 3600,
      },
    ]);
    const leaf = narrowing.length;
    expect(leaf).toBe(2);

    const result = await verifyChain(narrowing, {
      now: NOW + 10,
      request: { resource: RESOURCE, amount: usd('1.00') },
      isTrustedRootIssuer: trustOnly(principal),
      offline: true,
    });
    expect(result.ok).toBe(true);
  });
});

describe('the risk budget §13 says MUST be surfaced', () => {
  const grant = (host: string, amt: string, exp = NOW + 3600) => ({
    host,
    maxTotal: usd(amt),
    exp,
  });

  it('sums worst-case exposure per merchant', () => {
    const risk = offlineRiskBudget(
      [
        grant(HOST, '20.00'),
        grant(HOST, '5.00'),
        grant('api.other.example', '100.00'),
      ],
      NOW,
    );

    // Amounts come back in the codebase's canonical minimal form — `100`, not
    // `100.00` — because every reported amount goes through `fromScaled`. The
    // one-grant and two-grant rows therefore render the same way, which is the
    // property worth pinning: a report that formatted them differently would
    // read as a discrepancy in the money.
    expect(risk.perMerchant).toEqual([
      { host: 'api.other.example', currency: 'USD', exposure: usd('100'), mandates: 1 },
      { host: HOST, currency: 'USD', exposure: usd('25'), mandates: 2 },
    ]);
    expect(risk.totals).toEqual([usd('125')]);
  });

  it('drops grants that have expired, and counts them', () => {
    const risk = offlineRiskBudget(
      [grant(HOST, '20.00'), grant(HOST, '999.00', NOW - 1)],
      NOW,
    );
    expect(risk.totals).toEqual([usd('20')]);
    expect(risk.expired).toBe(1);
  });

  it('totals per currency rather than inventing a rate', () => {
    const risk = offlineRiskBudget(
      [grant(HOST, '20.00'), { host: HOST, maxTotal: { cur: 'EUR', amt: '10.00' }, exp: NOW + 60 }],
      NOW,
    );
    expect(risk.totals).toEqual([{ cur: 'EUR', amt: '10' }, usd('20')]);
    // Same host, two currencies, two rows — not one row with a made-up sum.
    expect(risk.perMerchant.map((m) => m.currency)).toEqual(['EUR', 'USD']);
  });

  it('does not net off what has already been spent', () => {
    // Deliberate. The exposure is what a mandate *could* spend at a merchant
    // that has not reported yet; consumption the Ledger already knows about is
    // precisely the part not at risk of being counted twice.
    const risk = offlineRiskBudget([grant(HOST, '20.00')], NOW);
    expect(risk.totals).toEqual([usd('20')]);
  });

  it('is empty, not undefined, when nothing is outstanding', () => {
    expect(offlineRiskBudget([], NOW)).toEqual({
      now: NOW,
      perMerchant: [],
      totals: [],
      expired: 0,
    });
  });
});

describe('deriving an exposure from a chain', () => {
  it('records one only for a chain that would have been admitted offline', () => {
    expect(offlineExposureOf(offlineCav(), window(), 'mnd_root')).toEqual({
      host: HOST,
      maxTotal: usd('20.00'),
      exp: NOW + 3600,
      root: 'mnd_root',
    });
    // The seam that matters: a chain no offline merchant would take cannot
    // contribute to a budget that claims to bound offline loss.
    expect(offlineExposureOf(offlineCav({ aud: ['*.weatherco.com'] }), window())).toBeNull();
    expect(offlineExposureOf(offlineCav(), window(7200))).toBeNull();
  });
});
