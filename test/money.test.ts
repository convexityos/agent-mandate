import { describe, expect, it } from 'vitest';

import { fromScaled, isMoney, moneyLeq, moneyMin, toScaled } from '../src/money.js';
import { parseDuration } from '../src/duration.js';

describe('money', () => {
  it('accepts only canonical decimal strings', () => {
    expect(isMoney({ cur: 'USD', amt: '0.02' })).toBe(true);
    expect(isMoney({ cur: 'USD', amt: '0.000000001' })).toBe(true);
    expect(isMoney({ cur: 'USD', amt: '0.0000000001' })).toBe(false); // 10 dp
    expect(isMoney({ cur: 'USD', amt: '01.00' })).toBe(false);
    expect(isMoney({ cur: 'USD', amt: '.5' })).toBe(false);
    expect(isMoney({ cur: 'USD', amt: '-1.00' })).toBe(false);
    expect(isMoney({ cur: 'usd', amt: '1.00' })).toBe(false);
    expect(isMoney({ cur: 'USD', amt: 1 as unknown as string })).toBe(false);
  });

  it('compares exactly where floats would not', () => {
    // 0.1 + 0.2 !== 0.3 in binary floating point; the ledger cannot afford that.
    const a = toScaled({ cur: 'USD', amt: '0.1' }) + toScaled({ cur: 'USD', amt: '0.2' });
    expect(fromScaled(a, 'USD').amt).toBe('0.3');
    expect(moneyLeq({ cur: 'USD', amt: '0.3' }, fromScaled(a, 'USD')).ok).toBe(true);
  });

  it('fails closed across currencies rather than returning false', () => {
    const r = moneyLeq({ cur: 'EUR', amt: '0.01' }, { cur: 'USD', amt: '100.00' });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.code).toBe('currency_mismatch');
  });

  it('min picks the smaller', () => {
    expect(moneyMin({ cur: 'USD', amt: '2.00' }, { cur: 'USD', amt: '0.50' }).amt).toBe('0.50');
  });
});

describe('duration', () => {
  it('parses fixed-length designators', () => {
    expect(parseDuration('PT1H')).toBe(3600);
    expect(parseDuration('PT10M')).toBe(600);
    expect(parseDuration('P1D')).toBe(86400);
    expect(parseDuration('P1W')).toBe(604800);
    expect(parseDuration('PT1H30M')).toBe(5400);
  });

  it('rejects calendar-relative and malformed durations', () => {
    // Months and years are not fixed-length, so they cannot be totally ordered
    // independent of a calendar position — and an undecidable comparator cannot
    // decide attenuation.
    expect(parseDuration('P1M')).toBeNull();
    expect(parseDuration('P1Y')).toBeNull();
    expect(parseDuration('P')).toBeNull();
    expect(parseDuration('PT')).toBeNull();
    expect(parseDuration('1H')).toBeNull();
    expect(parseDuration('PT0S')).toBeNull();
  });
});
