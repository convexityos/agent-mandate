import { type Check, OK, fail } from './errors.js';

/**
 * Spec §4.3. Monetary amounts are exact decimal strings scaled to 9 fractional
 * digits internally. Binary floating point never touches an amount at any point
 * in the pipeline — per-call pricing routinely runs below one cent, and float
 * drift on a ledger is unrecoverable.
 */
export const MONEY_SCALE = 9;
const SCALE_FACTOR = 10n ** BigInt(MONEY_SCALE);

const AMOUNT_RE = /^(0|[1-9][0-9]*)(\.[0-9]{1,9})?$/;
const CURRENCY_RE = /^[A-Z]{3,8}$/;

export interface Money {
  cur: string;
  amt: string;
}

export function isMoney(v: unknown): v is Money {
  if (typeof v !== 'object' || v === null) return false;
  const m = v as Record<string, unknown>;
  if (Object.keys(m).length !== 2) return false;
  return (
    typeof m['cur'] === 'string' &&
    CURRENCY_RE.test(m['cur']) &&
    typeof m['amt'] === 'string' &&
    AMOUNT_RE.test(m['amt'])
  );
}

/** Scaled integer representation. Precondition: `isMoney(m)`. */
export function toScaled(m: Money): bigint {
  const dot = m.amt.indexOf('.');
  if (dot === -1) return BigInt(m.amt) * SCALE_FACTOR;
  const whole = m.amt.slice(0, dot);
  const frac = m.amt.slice(dot + 1).padEnd(MONEY_SCALE, '0');
  return BigInt(whole) * SCALE_FACTOR + BigInt(frac);
}

export function fromScaled(n: bigint, cur: string): Money {
  const whole = n / SCALE_FACTOR;
  const frac = (n % SCALE_FACTOR).toString().padStart(MONEY_SCALE, '0').replace(/0+$/, '');
  return { cur, amt: frac.length > 0 ? `${whole}.${frac}` : `${whole}` };
}

/**
 * Cross-currency comparison fails closed with `currency_mismatch` rather than
 * returning false. A false would read as "not narrower" at some call sites and
 * "not over the cap" at others; only one of those is safe.
 */
export function moneyLeq(child: Money, parent: Money): Check {
  if (child.cur !== parent.cur) {
    return fail('currency_mismatch', `cannot compare ${child.cur} against ${parent.cur}`);
  }
  return toScaled(child) <= toScaled(parent)
    ? OK
    : fail('attenuation_violation', `${child.amt} exceeds ${parent.amt} ${parent.cur}`);
}

export function moneyMin(a: Money, b: Money): Money {
  if (a.cur !== b.cur) return b; // unreachable once narrows() has passed; see caveats.ts meet precondition
  return toScaled(a) <= toScaled(b) ? a : b;
}

export function moneyEq(a: Money, b: Money): boolean {
  return a.cur === b.cur && toScaled(a) === toScaled(b);
}
