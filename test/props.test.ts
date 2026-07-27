import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  type Caveats,
  caveatsEqual,
  foldMeet,
  meetCaveats,
  narrows,
  validateCaveats,
} from '../src/caveats.js';
import { fromScaled, toScaled } from '../src/money.js';
import {
  canonicalizeUri,
  hostMatches,
  hostPatternContains,
  parseHostPattern,
  parseUriPattern,
  uriMatches,
  uriPatternContains,
} from '../src/uri.js';

/**
 * Domains are deliberately small. The interesting properties are conditional
 * ("if b narrows a and c narrows b, then c narrows a"), and a wide domain makes
 * the premise almost never hold, so fast-check spends its budget generating
 * vacuous passes.
 */
const AMOUNTS = ['0.001', '0.50', '2.00', '10.00', '50.00'];
const HOSTS = ['*.example.com', 'api.example.com', 'b.example.com', 'other.net'];
const RESOURCES = [
  'https://api.example.com/*',
  'https://api.example.com/v1/*',
  'https://api.example.com/v1/x',
  'https://other.net/*',
];
const PURPOSES = ['read', 'write', 'admin'];

const RATE_N = [10, 100, 500];
const RATE_PER = ['PT1H', 'PT2H', 'P1D'];
const SETTLES = ['immediate', 'escrow_schema', 'escrow_human'] as const;
const EFFECTS = ['irreversible', 'write', 'read'] as const;

const arbMoney = fc.constantFrom(...AMOUNTS).map((amt) => ({ cur: 'USD', amt }));
const arbSubset = <T>(pool: readonly T[]) => fc.subarray([...pool], { minLength: 1 });

const BASE: Record<string, fc.Arbitrary<unknown>> = {
  max_total: arbMoney,
  max_per_txn: arbMoney,
  rate: fc.record({ n: fc.constantFrom(...RATE_N), per: fc.constantFrom(...RATE_PER) }),
  aud: arbSubset(HOSTS),
  resources: arbSubset(RESOURCES),
  purpose: arbSubset(PURPOSES),
  task: fc.constantFrom('t1', 't2'),
  depth: fc.integer({ min: 0, max: 3 }),
  delegable: fc.boolean(),
  settle: fc.constantFrom(...SETTLES),
  step_up: fc.record({ over: arbMoney }),
  effect: fc.constantFrom(...EFFECTS),
};

const arbCaveats = fc.record(BASE, { requiredKeys: [] }) as fc.Arbitrary<Caveats>;

const tighterMoney = (m: { cur: string; amt: string }) =>
  fc
    .constantFrom(...AMOUNTS.filter((a) => toScaled({ cur: m.cur, amt: a }) <= toScaled(m)))
    .map((amt) => ({ cur: m.cur, amt }));

/**
 * Generates a caveat set that genuinely narrows `parent`, by tightening each
 * declared dimension rather than sampling and filtering. Rejection sampling on
 * three independent sets skips ~200k times per hit, which is how you get a
 * property that reports "passed" having tested almost nothing.
 */
function arbNarrowerThan(parent: Caveats): fc.Arbitrary<Caveats> {
  const p = parent as Record<string, never>;
  const model: Record<string, fc.Arbitrary<unknown>> = { ...BASE };

  if (p['max_total']) model['max_total'] = tighterMoney(p['max_total']);
  if (p['max_per_txn']) model['max_per_txn'] = tighterMoney(p['max_per_txn']);
  if (p['step_up']) {
    model['step_up'] = tighterMoney((p['step_up'] as { over: { cur: string; amt: string } }).over)
      .map((over) => ({ over }));
  }
  if (p['rate']) {
    const r = p['rate'] as { n: number; per: string };
    const rp = RATE_PER.filter((x) => parseDurationSeconds(x) >= parseDurationSeconds(r.per));
    model['rate'] = fc.record({
      n: fc.constantFrom(...RATE_N.filter((n) => n <= r.n)),
      per: fc.constantFrom(...rp),
    });
  }
  for (const key of ['aud', 'resources', 'purpose']) {
    if (p[key]) model[key] = fc.subarray([...(p[key] as string[])], { minLength: 1 });
  }
  if (p['task']) model['task'] = fc.constant(p['task']);
  if (p['depth'] !== undefined) model['depth'] = fc.integer({ min: 0, max: p['depth'] as number });
  if (p['delegable'] === false) model['delegable'] = fc.constant(false);
  if (p['settle']) {
    model['settle'] = fc.constantFrom(...SETTLES.slice(SETTLES.indexOf(p['settle'])));
  }
  if (p['effect']) {
    model['effect'] = fc.constantFrom(...EFFECTS.slice(EFFECTS.indexOf(p['effect'])));
  }

  return fc.record(model, { requiredKeys: [] }) as fc.Arbitrary<Caveats>;
}

const DURATIONS: Record<string, number> = { PT1H: 3600, PT2H: 7200, P1D: 86400 };
const parseDurationSeconds = (s: string) => DURATIONS[s]!;

/** meet may legitimately produce ⊥ (empty sets); ⊥ is not a valid wire value. */
const wellFormed = (c: Caveats) => validateCaveats(c).ok;

const RUNS = { numRuns: 2000 } as const;

describe('lattice algebra', () => {
  it('narrows is reflexive', () => {
    fc.assert(
      fc.property(arbCaveats, (a) => {
        expect(narrows(a, a).ok).toBe(true);
      }),
      RUNS,
    );
  });

  it('narrows is NOT pairwise transitive — an omitted caveat is ⊤', () => {
    // Regression-locks the reason verifyChain folds as it goes. If this ever
    // starts passing, the accumulate-then-compare logic can be simplified;
    // until then, comparing a link against its immediate parent is a bug.
    const a: Caveats = { settle: 'escrow_schema' };
    const b: Caveats = {};
    const c: Caveats = { settle: 'immediate' };
    expect(narrows(b, a).ok).toBe(true);
    expect(narrows(c, b).ok).toBe(true);
    expect(narrows(c, a).ok).toBe(false);
  });

  it('narrowing against the accumulated meet IS transitive', () => {
    const arbChain = arbCaveats.chain((a) =>
      arbNarrowerThan(a).chain((b) => {
        const ab = meetCaveats(a, b);
        return arbNarrowerThan(ab).map((c) => [a, b, c] as const);
      }),
    );

    fc.assert(
      fc.property(arbChain, ([a, b, c]) => {
        // Preconditions hold by construction, so assert them rather than skip.
        expect(narrows(b, a).ok).toBe(true);
        const ab = meetCaveats(a, b);
        expect(wellFormed(ab)).toBe(true);
        expect(narrows(c, ab).ok).toBe(true);

        const abc = meetCaveats(ab, c);
        expect(wellFormed(abc)).toBe(true);
        // The folded authority is bounded by every link that produced it.
        for (const link of [a, b, c]) {
          expect(narrows(abc, link).ok).toBe(true);
        }
      }),
      RUNS,
    );
  });

  it('meet is a lower bound of both operands', () => {
    fc.assert(
      fc.property(arbCaveats, arbCaveats, (a, b) => {
        const m = meetCaveats(a, b);
        fc.pre(wellFormed(m));
        expect(narrows(m, a).ok).toBe(true);
        expect(narrows(m, b).ok).toBe(true);
      }),
      RUNS,
    );
  });

  it('meet is idempotent, commutative and associative', () => {
    fc.assert(
      fc.property(arbCaveats, arbCaveats, arbCaveats, (a, b, c) => {
        expect(caveatsEqual(meetCaveats(a, a), a)).toBe(true);
        expect(caveatsEqual(meetCaveats(a, b), meetCaveats(b, a))).toBe(true);

        const left = meetCaveats(meetCaveats(a, b), c);
        const right = meetCaveats(a, meetCaveats(b, c));
        fc.pre(wellFormed(left) && wellFormed(right));
        expect(caveatsEqual(left, right)).toBe(true);
      }),
      RUNS,
    );
  });
});

describe('the properties that actually protect the principal', () => {
  it('a child cannot escape a parent caveat by omitting it', () => {
    fc.assert(
      fc.property(arbCaveats, arbCaveats, (parent, child) => {
        fc.pre(narrows(child, parent).ok);
        const eff = foldMeet([parent, child]);
        // Every dimension the parent constrained is still constrained.
        for (const key of Object.keys(parent) as (keyof Caveats)[]) {
          expect(eff[key]).toBeDefined();
        }
        expect(narrows(eff, parent).ok).toBe(true);
      }),
      RUNS,
    );
  });

  it('extending a chain never increases effective authority', () => {
    fc.assert(
      fc.property(fc.array(arbCaveats, { minLength: 1, maxLength: 4 }), arbCaveats, (links, next) => {
        const before = foldMeet(links);
        const after = foldMeet([...links, next]);
        fc.pre(wellFormed(before) && wellFormed(after));
        expect(narrows(after, before).ok).toBe(true);
      }),
      RUNS,
    );
  });

  it('an unregistered caveat key rejects the whole comparison', () => {
    fc.assert(
      fc.property(arbCaveats, fc.string({ minLength: 1 }), (a, key) => {
        fc.pre(!(key in a) && !['__proto__', 'constructor', 'prototype'].includes(key));
        const r = narrows({ ...a, [key]: 1 } as Caveats, a);
        expect(r.ok).toBe(false);
        expect(r.ok === false && r.code).toBe('unknown_caveat');
      }),
      RUNS,
    );
  });

  it('folding with an empty caveat set is identity', () => {
    fc.assert(
      fc.property(arbCaveats, (a) => {
        expect(caveatsEqual(foldMeet([a, {}]), a)).toBe(true);
        expect(caveatsEqual(foldMeet([{}, a]), a)).toBe(true);
      }),
      RUNS,
    );
  });
});

describe('pattern containment is sound', () => {
  const arbConcreteUri = fc
    .tuple(
      fc.constantFrom('https', 'http'),
      fc.constantFrom('api.example.com', 'b.example.com', 'a.b.example.com', 'other.net'),
      fc.constantFrom('/', '/v1', '/v1/', '/v1/x', '/v1/x/y', '/v10/x', '/v2/z'),
    )
    .map(([s, h, p]) => `${s}://${h}${p}`);

  const arbUriPattern = fc.constantFrom(
    'https://api.example.com/*',
    'https://api.example.com/v1/*',
    'https://api.example.com/v1/x',
    'https://*.example.com/v1/*',
    'https://*.example.com/*',
    'http://api.example.com/*',
    'https://other.net/*',
  );

  it('containment implies every URI matching the child matches the parent', () => {
    fc.assert(
      fc.property(arbUriPattern, arbUriPattern, arbConcreteUri, (pp, cp, raw) => {
        const parent = parseUriPattern(pp)!;
        const child = parseUriPattern(cp)!;
        fc.pre(uriPatternContains(parent, child));
        const uri = canonicalizeUri(raw)!;
        if (uriMatches(child, uri)) {
          expect(uriMatches(parent, uri)).toBe(true);
        }
      }),
      RUNS,
    );
  });

  it('host containment implies every host matching the child matches the parent', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...HOSTS),
        fc.constantFrom(...HOSTS),
        fc.constantFrom('api.example.com', 'b.example.com', 'a.b.example.com', 'example.com', 'other.net'),
        (pp, cp, host) => {
          const parent = parseHostPattern(pp)!;
          const child = parseHostPattern(cp)!;
          fc.pre(hostPatternContains(parent, child));
          if (hostMatches(child, host)) {
            expect(hostMatches(parent, host)).toBe(true);
          }
        },
      ),
      RUNS,
    );
  });

  it('containment is transitive', () => {
    fc.assert(
      fc.property(arbUriPattern, arbUriPattern, arbUriPattern, (a, b, c) => {
        const [pa, pb, pc] = [parseUriPattern(a)!, parseUriPattern(b)!, parseUriPattern(c)!];
        fc.pre(uriPatternContains(pa, pb) && uriPatternContains(pb, pc));
        expect(uriPatternContains(pa, pc)).toBe(true);
      }),
      RUNS,
    );
  });

  it('canonicalization is idempotent and never yields a traversal', () => {
    fc.assert(
      fc.property(
        fc.webUrl({ withQueryParameters: true, withFragments: true }),
        (url) => {
          const once = canonicalizeUri(url);
          fc.pre(once !== null);
          expect(canonicalizeUri(once)).toBe(once);
          expect(once.split('/').includes('..')).toBe(false);
        },
      ),
      RUNS,
    );
  });
});

describe('money is exact', () => {
  it('round-trips through the scaled representation', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: 10n ** 18n }), (n) => {
        const m = fromScaled(n, 'USD');
        expect(toScaled(m)).toBe(n);
      }),
      RUNS,
    );
  });
});
