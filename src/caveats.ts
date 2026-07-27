import { type Check, OK, fail } from './errors.js';
import { type Money, isMoney, moneyLeq, moneyMin, moneyEq } from './money.js';
import { isDuration, parseDuration } from './duration.js';
import { hostSetContains, uriSetContains } from './uri.js';

/**
 * Spec §6 — the caveat registry and attenuation lattice.
 *
 * One rule governs everything here:
 *
 *   Every caveat declares a partial order ORIENTED BY AUTHORITY GRANTED.
 *   Absence means ⊤ (maximum authority on that dimension).
 *   A child link is valid iff  child.cav ⊑ parent.cav.
 *
 * Caveats that look numerically inverted (`settle`, `step_up`) need no special
 * case once ordered by authority rather than by magnitude: escrow grants less
 * freedom than immediate settlement, so it sits lower in the lattice.
 *
 * Because absence is ⊤, `narrows` never has to materialize a ⊤ value — a caveat
 * missing from the parent auto-passes, since everything is ≤ ⊤.
 */

export type Settle = 'immediate' | 'escrow_schema' | 'escrow_human';

/** Ordered most-authority first; index doubles as the lattice position. */
const SETTLE_ORDER: readonly Settle[] = ['immediate', 'escrow_schema', 'escrow_human'];

/**
 * §6.2 — blast radius, as distinct from cost.
 *
 * The rest of this registry is money-shaped: amounts, rates, hosts, windows.
 * Agentic risk is not only money. Fetching a quote and placing an equity order
 * can be priced identically and are not remotely the same act, and a mandate
 * that bounds dollars but not consequence is half a control plane.
 *
 *   irreversible — may do anything, including what cannot be undone
 *   write        — may cause effects that can be reversed
 *   read         — may observe and change nothing
 *
 * Ordered most-authority first, so a child may narrow toward `read` and never
 * widen. Structurally identical to `settle`; deliberately so, because that
 * shape is already exercised by the lattice property tests.
 *
 * Absence is ⊤ — an unconstrained mandate grants `irreversible`. That is the
 * uniform rule the whole algebra depends on and it is not special-cased here.
 * Failing closed on an *unclassified tool* is an enforcement-layer policy and
 * belongs there, not in the lattice; see `src/mcp/gateway.ts`.
 */
export type Effect = 'irreversible' | 'write' | 'read';

export const EFFECT_ORDER: readonly Effect[] = ['irreversible', 'write', 'read'];

export interface Rate {
  n: number;
  per: string;
}

export interface StepUp {
  over: Money;
}

export interface Caveats {
  exp?: number;
  nbf?: number;
  max_total?: Money;
  max_per_txn?: Money;
  rate?: Rate;
  aud?: string[];
  resources?: string[];
  purpose?: string[];
  task?: string;
  payer?: string;
  depth?: number;
  delegable?: boolean;
  currency?: string;
  settle?: Settle;
  step_up?: StepUp;
  effect?: Effect;
}

interface CaveatSpec {
  validate(v: unknown): boolean;
  /** child ⊑ parent in the authority order. */
  leq(child: never, parent: never): Check;
  /**
   * A lower bound of both operands. Precondition: both operands validate.
   * Need not be the *greatest* lower bound — see `rate` and the pattern sets,
   * where an exact meet is either undefined or not worth computing. Soundness
   * is asserted post-hoc in verifyChain, which re-checks the folded result
   * against every link.
   */
  meet(a: never, b: never): unknown;
}

/**
 * ⊥ — "grants nothing on this dimension".
 *
 * Discrete caveats (`task`, `currency`) and cross-currency amounts have no
 * common lower bound inside their own domain: the meet of task `t1` and task
 * `t2` is not `t1`, and it is not `t2`. Returning either makes `meet`
 * non-commutative, which is exactly what the property tests caught.
 *
 * ⊥ is a valid lattice element but is deliberately not a valid wire value, so a
 * fold that reaches it fails validation and the chain is rejected. Unreachable
 * in a chain that passed `narrows`, which rejects the mismatch first.
 */
export const BOTTOM: unique symbol = Symbol.for('am/1:bottom');
export type Bottom = typeof BOTTOM;

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);
const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === 'string' && x.length > 0);

function setLeq(child: string[], parent: string[], what: string): Check {
  const p = new Set(parent);
  const extra = child.filter((c) => !p.has(c));
  return extra.length === 0
    ? OK
    : fail('attenuation_violation', `${what} not granted by parent: ${extra.join(', ')}`);
}

/**
 * Meet for pattern sets: keep every pattern that BOTH operands cover.
 *
 * The obvious implementation — "if a contains b return b, else if b contains a
 * return a" — is not commutative when the two sets cover each other without
 * being equal (`[api/*, other/*]` vs `[api/*, api/v1/*, other/*]`). Building
 * the result element-wise from both sides is symmetric by construction, and
 * every retained element is individually covered by both, so it is still a
 * lower bound. Sorted and deduped so equal sets are also equal arrays.
 */
function patternMeet(
  a: string[],
  b: string[],
  contains: (parent: string[], child: string[]) => boolean,
): string[] {
  const kept = [...a.filter((x) => contains(b, [x])), ...b.filter((x) => contains(a, [x]))];
  return [...new Set(kept)].sort();
}

/**
 * NOT in the registry, deliberately:
 *
 *   `exp` / `nbf` — top-level claims, not caveats. Listing them in both places
 *   creates two sources of truth for the validity window. verifyChain narrows
 *   and folds them structurally from the claims.
 *
 *   the `depth` decrement — `child.depth ≤ parent.depth − 1` is not reflexive,
 *   so it is not a partial order and cannot live in the lattice without
 *   breaking meet, the post-condition check, and every algebraic law the
 *   property tests rely on. The registry entry below carries the ordinary
 *   `≤` order; the mandatory decrement is a chain-structural rule in verifyChain.
 */
const REGISTRY: Readonly<Record<string, CaveatSpec>> = Object.freeze({
  max_total: {
    validate: isMoney,
    leq: (c: Money, p: Money) => moneyLeq(c, p),
    meet: (a: Money, b: Money) => (a.cur === b.cur ? moneyMin(a, b) : BOTTOM),
  },

  max_per_txn: {
    validate: isMoney,
    leq: (c: Money, p: Money) => moneyLeq(c, p),
    meet: (a: Money, b: Money) => (a.cur === b.cur ? moneyMin(a, b) : BOTTOM),
  },

  /**
   * Deliberately conservative (§6.5): `500/PT1H` and `100/PT10M` are genuinely
   * incomparable — the child permits fewer per burst but 600/hour sustained —
   * so we reject rather than guess. Safe to be strict here because the ledger
   * enforces every ancestor's rate independently at spend time (§10.2); this
   * comparator is an issuance-time sanity gate, not the enforcement point.
   */
  rate: {
    validate: (v: unknown): v is Rate => {
      if (typeof v !== 'object' || v === null) return false;
      const r = v as Record<string, unknown>;
      return isInt(r['n']) && (r['n'] as number) > 0 && isDuration(r['per']);
    },
    leq: (c: Rate, p: Rate) => {
      const cp = parseDuration(c.per)!;
      const pp = parseDuration(p.per)!;
      if (c.n <= p.n && cp >= pp) return OK;
      return fail(
        'attenuation_violation',
        `rate ${c.n}/${c.per} is not uniformly narrower than ${p.n}/${p.per}`,
      );
    },
    meet: (a: Rate, b: Rate): Rate => {
      const [da, db] = [parseDuration(a.per)!, parseDuration(b.per)!];
      // Tie-break lexicographically: PT60M and PT1H are the same window but
      // different strings, and picking "whichever came first" is not commutative.
      const per = da === db ? (a.per <= b.per ? a.per : b.per) : da > db ? a.per : b.per;
      return { n: Math.min(a.n, b.n), per };
    },
  },

  aud: {
    validate: isStringArray,
    leq: (c: string[], p: string[]) =>
      hostSetContains(p, c)
        ? OK
        : fail('attenuation_violation', `aud ${c.join(',')} not contained by ${p.join(',')}`),
    meet: (a: string[], b: string[]) => patternMeet(a, b, hostSetContains),
  },

  resources: {
    validate: isStringArray,
    leq: (c: string[], p: string[]) =>
      uriSetContains(p, c)
        ? OK
        : fail('attenuation_violation', `resources ${c.join(',')} not contained by ${p.join(',')}`),
    meet: (a: string[], b: string[]) => patternMeet(a, b, uriSetContains),
  },

  purpose: {
    validate: isStringArray,
    leq: (c: string[], p: string[]) => setLeq(c, p, 'purpose'),
    meet: (a: string[], b: string[]) => {
      const s = new Set(b);
      return [...new Set(a.filter((x) => s.has(x)))].sort();
    },
  },

  task: {
    validate: (v: unknown) => typeof v === 'string' && v.length > 0,
    leq: (c: string, p: string) =>
      c === p ? OK : fail('attenuation_violation', `task ${c} differs from parent ${p}`),
    meet: (a: string, b: string) => (a === b ? a : BOTTOM),
  },

  /**
   * §12.4.4 — which funding account may settle this. Discrete equality, exactly
   * like `task`: pin it, never widen it, ⊥ on disagreement.
   *
   * This is how a parent hands a subagent a small hot wallet without exposing
   * the treasury account its own mandate could otherwise reach.
   */
  payer: {
    validate: (v: unknown) => typeof v === 'string' && v.length > 0,
    leq: (c: string, p: string) =>
      c === p ? OK : fail('attenuation_violation', `payer ${c} differs from parent ${p}`),
    meet: (a: string, b: string) => (a === b ? a : BOTTOM),
  },

  depth: {
    validate: (v: unknown) => isInt(v) && (v as number) >= 0,
    // Ordinary ≤ only. The mandatory per-hop decrement is structural; see above.
    leq: (c: number, p: number) =>
      c <= p ? OK : fail('depth_exceeded', `depth ${c} exceeds parent ${p}`),
    meet: (a: number, b: number) => Math.min(a, b),
  },

  delegable: {
    validate: (v: unknown) => typeof v === 'boolean',
    leq: (c: boolean, p: boolean) =>
      p || !c ? OK : fail('attenuation_violation', 'cannot restore delegable on a sealed mandate'),
    meet: (a: boolean, b: boolean) => a && b,
  },

  currency: {
    validate: (v: unknown) => typeof v === 'string' && /^[A-Z]{3,8}$/.test(v),
    leq: (c: string, p: string) =>
      c === p ? OK : fail('currency_mismatch', `currency ${c} differs from parent ${p}`),
    meet: (a: string, b: string) => (a === b ? a : BOTTOM),
  },

  settle: {
    validate: (v: unknown): v is Settle => SETTLE_ORDER.includes(v as Settle),
    leq: (c: Settle, p: Settle) =>
      SETTLE_ORDER.indexOf(c) >= SETTLE_ORDER.indexOf(p)
        ? OK
        : fail('attenuation_violation', `settle ${c} is looser than parent ${p}`),
    meet: (a: Settle, b: Settle) =>
      SETTLE_ORDER.indexOf(a) >= SETTLE_ORDER.indexOf(b) ? a : b,
  },

  step_up: {
    validate: (v: unknown): v is StepUp =>
      typeof v === 'object' &&
      v !== null &&
      Object.keys(v).length === 1 &&
      isMoney((v as Record<string, unknown>)['over']),
    leq: (c: StepUp, p: StepUp) => moneyLeq(c.over, p.over),
    meet: (a: StepUp, b: StepUp) =>
      a.over.cur === b.over.cur ? { over: moneyMin(a.over, b.over) } : BOTTOM,
  },

  /** §6.2 — blast radius. See `EFFECT_ORDER` for why the order runs this way. */
  effect: {
    validate: (v: unknown): v is Effect => EFFECT_ORDER.includes(v as Effect),
    leq: (c: Effect, p: Effect) =>
      EFFECT_ORDER.indexOf(c) >= EFFECT_ORDER.indexOf(p)
        ? OK
        : fail('attenuation_violation', `effect ${c} is broader than parent ${p}`),
    meet: (a: Effect, b: Effect) =>
      EFFECT_ORDER.indexOf(a) >= EFFECT_ORDER.indexOf(b) ? a : b,
  },
} satisfies Record<string, CaveatSpec>);

export const REGISTERED_CAVEATS: readonly string[] = Object.freeze(Object.keys(REGISTRY));

/** Structural validation of one link's caveat object. Unknown keys fail closed. */
export function validateCaveats(cav: unknown): Check {
  if (typeof cav !== 'object' || cav === null || Array.isArray(cav)) {
    return fail('chain_invalid', 'cav must be an object');
  }
  for (const [key, value] of Object.entries(cav)) {
    if (value === undefined) continue;
    const spec = REGISTRY[key];
    if (spec === undefined) {
      return fail('unknown_caveat', `unregistered caveat "${key}"`);
    }
    if ((value as unknown) === BOTTOM) {
      return fail('chain_invalid', `caveat "${key}" is unsatisfiable`);
    }
    if (!spec.validate(value)) {
      return fail('chain_invalid', `malformed caveat "${key}"`);
    }
  }
  return OK;
}

/**
 * §6.1 — is `child` no more authoritative than `parent` on every dimension?
 *
 * Only keys present in `child` are compared: a caveat absent from the parent is
 * ⊤, so a child introducing it is narrowing. A child *omitting* a key its
 * parent constrains also passes; `foldMeet` is what re-applies it.
 *
 * NOT TRANSITIVE, and deliberately so. With a={settle:'escrow_schema'}, b={},
 * c={settle:'immediate'}: narrows(b,a) holds (b declares nothing), narrows(c,b)
 * holds (b is ⊤ on settle), but narrows(c,a) fails. An intermediate link that
 * omits a caveat is ⊤ on that dimension, so pairwise checks let a grandchild
 * re-declare what its grandparent forbade.
 *
 * Callers verifying a chain MUST therefore compare each link against the
 * accumulated meet of everything above it, not against its immediate parent.
 * verifyChain does exactly that. Comparing pairwise is the natural-looking
 * implementation and it is wrong.
 */
export function narrows(child: Caveats, parent: Caveats): Check {
  const p = parent as Record<string, unknown>;
  for (const [key, cv] of Object.entries(child)) {
    if (cv === undefined) continue;

    const spec = REGISTRY[key];
    if (spec === undefined) return fail('unknown_caveat', `unregistered caveat "${key}"`);
    if (!spec.validate(cv)) return fail('chain_invalid', `malformed caveat "${key}"`);

    const pv = p[key];
    if (pv === undefined) continue; // parent is ⊤ on this dimension
    if (!spec.validate(pv)) return fail('chain_invalid', `malformed parent caveat "${key}"`);

    const r = (spec.leq as (c: unknown, p: unknown) => Check)(cv, pv);
    if (!r.ok) return r;
  }
  return OK;
}

/** Greatest-lower-bound of two caveat sets. Absence is ⊤, so a missing side yields the other. */
export function meetCaveats(a: Caveats, b: Caveats): Caveats {
  const av = a as Record<string, unknown>;
  const bv = b as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of new Set([...Object.keys(av), ...Object.keys(bv)])) {
    const x = av[key];
    const y = bv[key];
    if (x === undefined && y === undefined) continue;
    if (x === undefined) {
      out[key] = y;
      continue;
    }
    if (y === undefined) {
      out[key] = x;
      continue;
    }
    const spec = REGISTRY[key];
    if (spec === undefined) continue; // unreachable after validateCaveats
    out[key] = (spec.meet as (p: unknown, q: unknown) => unknown)(x, y);
  }
  return out as Caveats;
}

/**
 * Effective authority of a chain.
 *
 * THIS IS NOT DEFENSIVE — it is load-bearing. `narrows` only inspects keys the
 * child declares, so a child that simply *omits* `max_total` passes attenuation
 * while declaring itself unbounded on that dimension. The fold is what re-applies
 * every ancestor's constraint to the leaf. Deleting it does not weaken a
 * redundant check; it removes the only thing standing between a subagent and its
 * grandparent's entire balance.
 */
export function foldMeet(links: Caveats[]): Caveats {
  return links.reduce<Caveats>((acc, cav) => meetCaveats(acc, cav), {});
}

export function caveatsEqual(a: Caveats, b: Caveats): boolean {
  const av = a as Record<string, unknown>;
  const bv = b as Record<string, unknown>;
  const keys = new Set([...Object.keys(av), ...Object.keys(bv)]);
  for (const k of keys) {
    const x = av[k];
    const y = bv[k];
    if (x === undefined || y === undefined) return x === y;
    if (k === 'max_total' || k === 'max_per_txn') {
      if (!moneyEq(x as Money, y as Money)) return false;
    } else if (k === 'step_up') {
      if (!moneyEq((x as StepUp).over, (y as StepUp).over)) return false;
    } else if (Array.isArray(x) && Array.isArray(y)) {
      if (x.length !== y.length || [...x].sort().join() !== [...y].sort().join()) return false;
    } else if (typeof x === 'object' && x !== null) {
      if (JSON.stringify(x) !== JSON.stringify(y)) return false;
    } else if (x !== y) {
      return false;
    }
  }
  return true;
}
