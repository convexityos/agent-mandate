import type { LedgerTx } from './store.js';

/**
 * Spec §10.4 — circuit breakers.
 *
 * These exist because autonomous spend fails catastrophically rather than
 * gradually. A retry loop against a $0.05 endpoint burns $500 overnight while
 * nobody is watching, and every individual charge in that loop is within every
 * caveat the principal signed. Caveats bound what an agent *may* do; breakers
 * catch what it is *actually* doing.
 *
 * They act on the subtree, keyed by root, using the same path the debit walks.
 */

export type BreakerSeverity = 'alert' | 'block';

export interface BreakerVerdict {
  name: string;
  severity: BreakerSeverity;
  detail: string;
}

export interface BreakerConfig {
  /** Trip when trailing-window spend exceeds this multiple of the baseline median. */
  velocityMultiple: number;
  velocityWindowSeconds: number;
  /** Number of prior windows used to compute the baseline. */
  velocityBaselineWindows: number;
  /** Minimum baseline sample before velocity is evaluated at all. */
  velocityMinSamples: number;
  /** Alert when projected time-to-exhaustion drops below this. */
  burnRateWarnSeconds: number;
  /** Hard ceiling on cumulative spend for a single task, scaled. null disables. */
  taskCeilingScaled: bigint | null;
  /** Whether a first-ever spend to a host blocks or merely alerts. */
  novelMerchant: BreakerSeverity | 'off';
}

export const DEFAULT_BREAKERS: BreakerConfig = {
  velocityMultiple: 10,
  velocityWindowSeconds: 3600,
  velocityBaselineWindows: 24,
  velocityMinSamples: 6,
  burnRateWarnSeconds: 900,
  taskCeilingScaled: null,
  novelMerchant: 'alert',
};

export interface BreakerInput {
  root: string;
  host: string;
  taskId: string | null;
  amountScaled: bigint;
  /** Remaining budget on the binding (smallest) node in the path, or null if unbounded. */
  remainingScaled: bigint | null;
  now: number;
}

function median(values: bigint[]): bigint {
  if (values.length === 0) return 0n;
  const s = [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2n;
}

export async function evaluateBreakers(
  tx: LedgerTx,
  cfg: BreakerConfig,
  input: BreakerInput,
): Promise<BreakerVerdict[]> {
  const verdicts: BreakerVerdict[] = [];

  if (await tx.killed(input.root)) {
    verdicts.push({ name: 'global_kill', severity: 'block', detail: 'principal spending halted' });
    return verdicts; // nothing else matters
  }

  if (cfg.taskCeilingScaled !== null && input.taskId !== null) {
    const after = (await tx.taskTotal(input.taskId)) + input.amountScaled;
    if (after > cfg.taskCeilingScaled) {
      verdicts.push({
        name: 'task_ceiling',
        severity: 'block',
        detail: `task ${input.taskId} would reach ${after} against ceiling ${cfg.taskCeilingScaled}`,
      });
    }
  }

  // Velocity: trailing window against the median of prior windows of the same
  // size. Median rather than mean, because one legitimate burst in the baseline
  // period should not raise the bar for the next fortnight.
  const w = cfg.velocityWindowSeconds;
  const windowStart = input.now - w;
  const baselineStart = input.now - w * (cfg.velocityBaselineWindows + 1);

  // One fetch, not two: the baseline window contains the trailing window, so a
  // single read covers both and — more to the point over a durable store — both
  // figures come from the same snapshot instead of two round trips that could
  // straddle a concurrent commit.
  const events = await tx.historySince(input.root, Math.min(baselineStart, windowStart));
  const current =
    events.filter((e) => e.ts >= windowStart).reduce((a, e) => a + e.amountScaled, 0n) +
    input.amountScaled;
  const prior = events.filter((e) => e.ts >= baselineStart && e.ts < windowStart);
  if (prior.length >= cfg.velocityMinSamples) {
    const buckets = new Map<number, bigint>();
    for (const e of prior) {
      const b = Math.floor((e.ts - baselineStart) / w);
      buckets.set(b, (buckets.get(b) ?? 0n) + e.amountScaled);
    }
    const base = median([...buckets.values()]);
    if (base > 0n && current > base * BigInt(Math.round(cfg.velocityMultiple))) {
      verdicts.push({
        name: 'velocity_anomaly',
        severity: 'block',
        detail: `${current} in the trailing window vs baseline median ${base}`,
      });
    }
  }

  // Burn rate: alert only. Spending fast is not by itself wrong, and blocking on
  // it would turn a legitimate batch job into an outage.
  if (input.remainingScaled !== null && current > 0n) {
    const perSecond = Number(current) / w;
    if (perSecond > 0) {
      const secondsLeft = Number(input.remainingScaled) / perSecond;
      if (secondsLeft < cfg.burnRateWarnSeconds) {
        verdicts.push({
          name: 'burn_rate',
          severity: 'alert',
          detail: `budget exhausts in ~${Math.round(secondsLeft)}s at the current rate`,
        });
      }
    }
  }

  if (cfg.novelMerchant !== 'off' && !(await tx.merchantSeen(input.root, input.host))) {
    verdicts.push({
      name: 'novel_merchant',
      severity: cfg.novelMerchant,
      detail: `first spend to ${input.host} for this principal`,
    });
  }

  return verdicts;
}
