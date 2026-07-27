import { describe, expect, it } from 'vitest';

import {
  type Caveats,
  foldMeet,
  meetCaveats,
  narrows,
  validateCaveats,
} from '../src/caveats.js';
import { usd } from './helpers.js';

const ok = (c: Caveats, p: Caveats) => narrows(c, p).ok;
const codeOf = (c: Caveats, p: Caveats) => {
  const r = narrows(c, p);
  return r.ok ? null : r.code;
};

describe('validateCaveats', () => {
  it('fails closed on unregistered keys', () => {
    const r = validateCaveats({ max_total: usd('1.00'), max_totaI: usd('999.00') });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('unknown_caveat');
  });

  it('rejects exp/nbf in cav — they are top-level claims, not caveats', () => {
    expect(validateCaveats({ exp: 123 }).ok).toBe(false);
    expect(validateCaveats({ nbf: 123 }).ok).toBe(false);
  });

  it('rejects malformed values', () => {
    expect(validateCaveats({ max_total: { cur: 'usd', amt: '1' } }).ok).toBe(false);
    expect(validateCaveats({ max_total: { cur: 'USD', amt: '1.0000000000' } }).ok).toBe(false);
    expect(validateCaveats({ rate: { n: 0, per: 'PT1H' } }).ok).toBe(false);
    expect(validateCaveats({ rate: { n: 5, per: 'P1M' } }).ok).toBe(false); // calendar month
    expect(validateCaveats({ aud: [] }).ok).toBe(false);
  });
});

describe('narrows — the Appendix A table', () => {
  const parent: Caveats = {
    max_total: usd('50.00'),
    max_per_txn: usd('2.00'),
    aud: ['*.datavendor.io', 'api.weatherco.com'],
    purpose: ['research.readonly'],
    depth: 2,
    delegable: true,
  };

  it('accepts the worked child', () => {
    expect(
      ok(
        {
          max_total: usd('10.00'),
          max_per_txn: usd('0.50'),
          aud: ['api.weatherco.com'],
          resources: ['https://api.weatherco.com/v3/forecast/*'],
          purpose: ['research.readonly'],
          task: 'tsk_01',
          rate: { n: 200, per: 'PT1H' },
          depth: 1,
          delegable: false,
        },
        parent,
      ),
    ).toBe(true);
  });

  it('rejects each documented widening', () => {
    expect(codeOf({ max_total: usd('60.00') }, parent)).toBe('attenuation_violation');
    expect(codeOf({ aud: ['blob.datavendor.io', 'evil.test'] }, parent)).toBe(
      'attenuation_violation',
    );
    expect(codeOf({ depth: 3 }, parent)).toBe('depth_exceeded');
    expect(codeOf({ delegable: true }, { ...parent, delegable: false })).toBe(
      'attenuation_violation',
    );
    expect(codeOf({ max_total: { cur: 'EUR', amt: '1.00' } }, parent)).toBe('currency_mismatch');
    expect(codeOf({ purpose: ['research.readonly', 'write'] }, parent)).toBe(
      'attenuation_violation',
    );
  });

  it('lets a child introduce a caveat the parent lacks (absence is ⊤)', () => {
    expect(ok({ rate: { n: 10, per: 'PT1H' } }, {})).toBe(true);
    expect(ok({ task: 'tsk_01' }, {})).toBe(true);
    expect(ok({ settle: 'escrow_human' }, {})).toBe(true);
    expect(ok({ step_up: { over: usd('1.00') } }, {})).toBe(true);
  });

  it('orders settle and step_up by authority, not magnitude', () => {
    expect(ok({ settle: 'escrow_schema' }, { settle: 'immediate' })).toBe(true);
    expect(ok({ settle: 'immediate' }, { settle: 'escrow_schema' })).toBe(false);
    expect(ok({ step_up: { over: usd('1.00') } }, { step_up: { over: usd('5.00') } })).toBe(true);
    expect(ok({ step_up: { over: usd('9.00') } }, { step_up: { over: usd('5.00') } })).toBe(false);
  });

  it('orders effect by blast radius, narrowing only toward read', () => {
    expect(ok({ effect: 'write' }, { effect: 'irreversible' })).toBe(true);
    expect(ok({ effect: 'read' }, { effect: 'write' })).toBe(true);
    expect(ok({ effect: 'read' }, { effect: 'irreversible' })).toBe(true);
    expect(ok({ effect: 'irreversible' }, { effect: 'write' })).toBe(false);
    expect(ok({ effect: 'write' }, { effect: 'read' })).toBe(false);
    expect(ok({ effect: 'read' }, { effect: 'read' })).toBe(true);

    // Absence is ⊤ on this dimension exactly as on every other: a mandate that
    // says nothing about effect grants `irreversible`. Failing closed on an
    // unclassified *tool* is the gateway's job, not the lattice's.
    expect(ok({ effect: 'read' }, {})).toBe(true);
    expect(meetCaveats({ effect: 'irreversible' }, {}).effect).toBe('irreversible');
  });

  it('meets effect at the smaller blast radius', () => {
    expect(meetCaveats({ effect: 'irreversible' }, { effect: 'read' }).effect).toBe('read');
    expect(meetCaveats({ effect: 'write' }, { effect: 'irreversible' }).effect).toBe('write');
    expect(meetCaveats({ effect: 'write' }, { effect: 'write' }).effect).toBe('write');
  });

  /**
   * The §7 non-transitivity trap, on the new axis. A middle link that omits
   * `effect` is ⊤ on it, so pairwise checks would let a grandchild re-declare
   * `irreversible` after its grandparent restricted to `read`.
   */
  it('stops a grandchild re-declaring an effect its grandparent forbade', () => {
    const grandparent: Caveats = { effect: 'read' };
    const parent: Caveats = {};
    const child: Caveats = { effect: 'irreversible' };

    expect(ok(parent, grandparent)).toBe(true);
    expect(ok(child, parent)).toBe(true); // pairwise: passes
    expect(ok(child, foldMeet([grandparent, parent]))).toBe(false); // against the fold: caught
  });

  it('treats incomparable rates as violations rather than guessing', () => {
    // 100/10min is 600/hr sustained but a smaller burst than 500/1hr.
    expect(ok({ rate: { n: 100, per: 'PT10M' } }, { rate: { n: 500, per: 'PT1H' } })).toBe(false);
    expect(ok({ rate: { n: 100, per: 'PT1H' } }, { rate: { n: 500, per: 'PT1H' } })).toBe(true);
    expect(ok({ rate: { n: 500, per: 'PT2H' } }, { rate: { n: 500, per: 'PT1H' } })).toBe(true);
  });
});

describe('foldMeet is load-bearing, not defensive', () => {
  it('re-applies a constraint the child silently omitted', () => {
    const parent: Caveats = { max_total: usd('50.00'), resources: ['https://a.test/v1/*'] };
    const child: Caveats = { max_per_txn: usd('0.50') };

    // The child omits max_total entirely, and narrows() is happy: it only
    // inspects keys the child declares.
    expect(narrows(child, parent).ok).toBe(true);

    // Taking the leaf's caveats as effective would grant an unbounded budget.
    expect(child.max_total).toBeUndefined();

    // The fold is what stops that.
    const eff = foldMeet([parent, child]);
    expect(eff.max_total).toEqual(usd('50.00'));
    expect(eff.resources).toEqual(['https://a.test/v1/*']);
    expect(eff.max_per_txn).toEqual(usd('0.50'));
  });

  it('meet picks the narrower operand', () => {
    expect(meetCaveats({ max_total: usd('50.00') }, { max_total: usd('10.00') }).max_total).toEqual(
      usd('10.00'),
    );
    expect(meetCaveats({ delegable: true }, { delegable: false }).delegable).toBe(false);
    expect(meetCaveats({ settle: 'immediate' }, { settle: 'escrow_human' }).settle).toBe(
      'escrow_human',
    );
    expect(
      meetCaveats({ rate: { n: 500, per: 'PT1H' } }, { rate: { n: 100, per: 'PT2H' } }).rate,
    ).toEqual({ n: 100, per: 'PT2H' });
  });
});
