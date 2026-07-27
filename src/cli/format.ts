import type { Caveats } from '../caveats.js';
import type { Money } from '../money.js';

/**
 * Rendering for the CLI.
 *
 * Kept separate from the commands because the whole value of `am inspect` is in
 * what the output makes obvious, and that is a formatting problem rather than a
 * protocol one.
 */

const useColour = process.stdout.isTTY === true && process.env['NO_COLOR'] === undefined;

const wrap = (code: string) => (s: string) => (useColour ? `[${code}m${s}[0m` : s);

export const dim = wrap('2');
export const bold = wrap('1');
export const red = wrap('31');
export const green = wrap('32');
export const yellow = wrap('33');
export const cyan = wrap('36');

/** DIDs are 48 characters of base58 and never the interesting part of a line. */
export function shortDid(did: string): string {
  if (did.length <= 24) return did;
  return `${did.slice(0, 14)}…${did.slice(-6)}`;
}

export const money = (m: Money): string => `${m.amt} ${m.cur}`;

/**
 * One caveat as `key value`, in the spelling the spec uses.
 *
 * Deliberately not `JSON.stringify`: the point of this output is that a human
 * can compare two caveat sets at a glance, and `{"cur":"USD","amt":"1.00"}`
 * defeats that.
 */
export function caveat(key: string, value: unknown): string {
  switch (key) {
    case 'max_total':
    case 'max_per_txn':
      return `${key} ${money(value as Money)}`;
    case 'step_up':
      return `step_up over ${money((value as { over: Money }).over)}`;
    case 'rate': {
      const r = value as { n: number; per: string };
      return `rate ${r.n}/${r.per}`;
    }
    case 'aud':
    case 'resources':
    case 'purpose':
      return `${key} ${(value as string[]).join(' ')}`;
    default:
      return `${key} ${String(value)}`;
  }
}

/** A caveat set on one line, or `—` when it declares nothing. */
export function caveats(c: Caveats): string {
  const entries = Object.entries(c).filter(([, v]) => v !== undefined);
  if (entries.length === 0) return dim('—');
  return entries
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([k, v]) => caveat(k, v))
    .join(dim(' · '));
}

/** Wrap a long single-line caveat rendering to a width, indenting continuations. */
export function indent(text: string, prefix: string, width = 84): string {
  const parts = text.split(dim(' · '));
  const lines: string[] = [];
  let line = '';
  for (const part of parts) {
    // Length is measured on the visible text, so colour codes do not make the
    // wrap point wander.
    const visible = (s: string) => s.replace(/\[\d+m/g, '').length;
    if (line !== '' && visible(line) + visible(part) + 3 > width) {
      lines.push(line);
      line = part;
    } else {
      line = line === '' ? part : `${line}${dim(' · ')}${part}`;
    }
  }
  if (line !== '') lines.push(line);
  return lines.map((l, i) => (i === 0 ? l : `${prefix}${l}`)).join('\n');
}
