import type { Caveats } from './caveats.js';
import { type Check, OK, fail } from './errors.js';
import { type Money, fromScaled, toScaled } from './money.js';
import type { Window } from './types.js';
import { hostOfUri } from './uri.js';

/**
 * §13 — the offline profile, and the exposure it creates.
 *
 * Offline mode lets a merchant settle without contacting the Ledger. That is a
 * genuinely different security posture, not a performance tweak: nothing is
 * authoritative at spend time, so the same mandate presented to four merchants
 * in the same minute spends four times. §13 does not prevent that. It **bounds**
 * it, with five constraints that together cap the loss — and a bound only holds
 * if something checks the constraints.
 *
 * Nothing did. §13 was specified, the caveats it constrains were all
 * individually enforceable, and no code anywhere held a mandate to the profile
 * as a unit. This exists because writing the threat catalogue asked "what proves
 * this?" and the answer was nothing.
 *
 * ## Four of the five are checkable here; the fifth is not
 *
 *   1. `aud` resolves to exactly one host — no wildcards.   ✓
 *   2. `max_total` is present, and therefore scoped to that host by (1).  ✓
 *   3. `exp` − `nbf` ≤ 1 hour.                              ✓
 *   4. `settle` is `immediate`.                             ✓
 *   5. The merchant reports consumption at least every 60s. ✗
 *
 * The fifth is a property of a running deployment, not of a credential, and
 * saying so is more useful than a check that pretends to cover it. It is also
 * the constraint the §10.3.1 status list rides on, so a merchant that has wired
 * one is already making the call this requires.
 *
 * ## Why the caps are conjunctive
 *
 * Each constraint is load-bearing only alongside the others. A one-hour window
 * with a wildcard `aud` bounds nothing, because "the sum over merchants named in
 * live offline mandates" is unbounded when a mandate names them all. A single
 * host with no `max_total` bounds nothing either. So this is one check that
 * passes or fails, not four independent ones a caller might apply some of.
 */

/** §13.3 — the cap that makes revocation-by-expiry tolerable. */
export const MAX_OFFLINE_WINDOW_SECONDS = 3600;

/**
 * Hold effective authority to the §13 profile.
 *
 * Takes the *effective* caveats — the fold of the whole chain — rather than any
 * one link's, because that is what actually governs. A root with a wildcard
 * `aud` and a leaf that narrows to one host is fine; the reverse is not, and
 * only the fold can tell them apart.
 */
export function checkOfflineProfile(eff: Caveats, window: Window): Check {
  if (eff.aud === undefined || eff.aud.length !== 1) {
    return fail(
      'offline_profile_violated',
      `offline mandates must name exactly one host, got ${eff.aud?.length ?? 0}`,
    );
  }
  const host = eff.aud[0]!;
  // A wildcard resolves to a set, and a set is not a merchant. `*.example.com`
  // passes a naive "length === 1" check while naming every subdomain there is.
  if (host.includes('*')) {
    return fail('offline_profile_violated', `offline aud must not be a wildcard: ${host}`);
  }

  if (eff.max_total === undefined) {
    return fail('offline_profile_violated', 'offline mandates must declare max_total');
  }

  const span = window.exp - window.nbf;
  if (span > MAX_OFFLINE_WINDOW_SECONDS) {
    return fail(
      'offline_profile_violated',
      `offline window is ${span}s, over the ${MAX_OFFLINE_WINDOW_SECONDS}s cap`,
    );
  }

  // Absence is ⊤ here as everywhere, and ⊤ on `settle` includes escrow — which
  // requires Ledger participation and therefore cannot happen offline at all.
  // So this is one of the few places where "unconstrained" is the wrong answer
  // and the mandate has to say `immediate` out loud.
  if (eff.settle !== 'immediate') {
    return fail(
      'offline_profile_violated',
      `offline settlement must be immediate, got ${eff.settle ?? '(unconstrained)'}`,
    );
  }

  return OK;
}

/** One live offline grant, as a deployment tracks it. */
export interface OfflineMandate {
  /** The single host from `aud`. */
  host: string;
  /** The effective `max_total` — the whole of it is at risk, spent or not. */
  maxTotal: Money;
  /** When this grant stops being presentable. */
  exp: number;
  /** For attributing exposure back to a subtree. */
  root?: string;
}

export interface OfflineExposure {
  host: string;
  currency: string;
  exposure: Money;
  /** How many live grants contribute. */
  mandates: number;
}

export interface OfflineRisk {
  now: number;
  /** Per host and currency, worst case, descending by amount. */
  perMerchant: OfflineExposure[];
  /**
   * One total per currency. Not one number: summing across currencies would
   * require a rate, and this codebase does not invent one anywhere else either.
   */
  totals: Money[];
  /** Grants excluded because they have expired. */
  expired: number;
}

/**
 * §13 — the figure implementations **MUST** surface to the principal.
 *
 * Worst-case loss from parallel presentation is the sum of `max_total` across
 * live offline grants, per merchant. The spec is emphatic that this is a
 * *configured risk budget* rather than an implementation detail, and the reason
 * is that it is the only honest description of what offline mode costs: not
 * "revocation is slower" but "this many dollars are simultaneously spendable at
 * these hosts, and no amount of care at spend time changes it".
 *
 * Spent-to-date is deliberately not subtracted. The exposure is what a mandate
 * *could* spend at a merchant that has not yet reported, and consumption the
 * Ledger already knows about is exactly the consumption that is not at risk of
 * being double-counted.
 */
export function offlineRiskBudget(mandates: OfflineMandate[], now: number): OfflineRisk {
  const live = mandates.filter((m) => m.exp >= now);

  // Accumulated as scaled integers and rendered once at the end, rather than
  // seeded with the first grant's own `amt` string. `fromScaled` reports the
  // minimal form — `20.00` comes back as `20` — so seeding from the input would
  // make a one-grant host render differently from a two-grant host holding the
  // same money, which is the sort of inconsistency a reader assumes is a bug in
  // the numbers rather than in the formatting. The key groups by currency, so no
  // addition here crosses one.
  const acc = new Map<
    string,
    { host: string; currency: string; total: bigint; mandates: number }
  >();
  for (const m of live) {
    const key = `${m.host} ${m.maxTotal.cur}`;
    const seen = acc.get(key);
    if (seen === undefined) {
      acc.set(key, {
        host: m.host,
        currency: m.maxTotal.cur,
        total: toScaled(m.maxTotal),
        mandates: 1,
      });
    } else {
      seen.total += toScaled(m.maxTotal);
      seen.mandates += 1;
    }
  }

  const totals = new Map<string, bigint>();
  for (const s of acc.values()) {
    totals.set(s.currency, (totals.get(s.currency) ?? 0n) + s.total);
  }

  return {
    now,
    perMerchant: [...acc.values()]
      .sort(
        (a, b) =>
          (a.currency < b.currency ? -1 : a.currency > b.currency ? 1 : 0) ||
          (b.total > a.total ? 1 : b.total < a.total ? -1 : 0) ||
          (a.host < b.host ? -1 : 1),
      )
      .map((s) => ({
        host: s.host,
        currency: s.currency,
        exposure: fromScaled(s.total, s.currency),
        mandates: s.mandates,
      })),
    totals: [...totals]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([cur, scaled]) => fromScaled(scaled, cur)),
    expired: mandates.length - live.length,
  };
}

/**
 * Derive the exposure a verified chain represents, or `null` if it is not an
 * offline-profile chain at all.
 *
 * The seam between "this chain is offline-presentable" and "here is what it adds
 * to the risk budget", so a deployment cannot record an exposure for a chain
 * that would not have been admitted.
 */
export function offlineExposureOf(
  eff: Caveats,
  window: Window,
  root?: string,
): OfflineMandate | null {
  if (!checkOfflineProfile(eff, window).ok) return null;
  const host = hostOfUri(`https://${eff.aud![0]!}/`) ?? eff.aud![0]!;
  return {
    host,
    maxTotal: eff.max_total!,
    exp: window.exp,
    ...(root !== undefined ? { root } : {}),
  };
}
