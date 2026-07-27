/**
 * ISO 8601 durations for the `rate` caveat's window.
 *
 * Years and months are deliberately unsupported: they are not fixed-length, so
 * `P1M >= PT720H` has no answer independent of a calendar position, and a
 * comparator that cannot totally order its inputs cannot decide attenuation.
 * Supported: PnW, PnD, and PT[nH][nM][nS].
 */
const DURATION_RE =
  /^P(?!$)(?:(\d+)W|(?:(\d+)D)?(?:T(?!$)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?)$/;

/** Returns seconds, or null if unparseable / uses calendar-relative units. */
export function parseDuration(s: string): number | null {
  if (typeof s !== 'string') return null;
  const m = DURATION_RE.exec(s);
  if (!m) return null;

  const [, w, d, h, min, sec] = m;
  let total = 0;
  if (w !== undefined) total += Number(w) * 604800;
  if (d !== undefined) total += Number(d) * 86400;
  if (h !== undefined) total += Number(h) * 3600;
  if (min !== undefined) total += Number(min) * 60;
  if (sec !== undefined) total += Number(sec);

  if (!Number.isFinite(total) || total <= 0) return null;
  return total;
}

export function isDuration(v: unknown): v is string {
  return typeof v === 'string' && parseDuration(v) !== null;
}
