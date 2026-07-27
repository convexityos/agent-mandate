import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { Effect } from '../caveats.js';
import type { ErrorCode } from '../errors.js';
import type { Ledger } from '../ledger/ledger.js';
import type { Money } from '../money.js';

/**
 * §2.3 — harness integration.
 *
 * A `PreToolUse` hook that reserves against a mandate before a priced tool
 * fires, and a `PostToolUse` hook that settles or refunds when it returns. It
 * makes the control plane something that runs in the loop you already use
 * rather than something you demo.
 *
 * ## How this differs from the MCP gateway
 *
 * The gateway *is* the channel to a wrapped server, so everything through it is
 * in scope and an unpriced tool is refused — the agent cannot call what it was
 * never shown.
 *
 * The hook sits in front of **every** tool the harness has, including reading
 * files and running builds. Refusing everything unpriced would not be a
 * spending control, it would be an outage. So the default is the other way
 * round: unpriced tools pass through untouched, and the hook meters exactly what
 * it is told to meter.
 *
 * That is not a weaker security posture, it is a different job. Claude Code
 * already has a permission system; this is not it. This decides whether a spend
 * fits inside a budget the principal granted, and it can only do that for calls
 * somebody has priced.
 *
 * ## Why there is a state directory
 *
 * `PreToolUse` and `PostToolUse` are separate process invocations with no shared
 * memory, and the reservation minted by the first has to be settled by the
 * second. The correlation is written to a file keyed by the session, the tool
 * and a hash of its input — one file per call rather than one shared file,
 * because concurrent tool calls in one session would otherwise race on a
 * read-modify-write.
 */

/** The subset of the hook payload this needs. Field names are the harness's. */
export interface HookEvent {
  session_id?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: unknown;
  tool_result?: unknown;
  cwd?: string;
}

export interface HookOutput {
  /** 0 to proceed, 2 to block with `systemMessage` fed back to the model. */
  exitCode: 0 | 2;
  hookSpecificOutput?: { permissionDecision: 'allow' | 'deny' | 'ask' };
  systemMessage?: string;
  /** What actually happened, for tests and for a caller that wants to log. */
  outcome:
    | { kind: 'unpriced' }
    | { kind: 'reserved'; spendId: string; amount: Money }
    | { kind: 'refused'; code: ErrorCode; detail: string; stepUpHandle?: string }
    | { kind: 'settled'; spendId: string }
    | { kind: 'refunded'; spendId: string }
    | { kind: 'unknown_call' }
    | { kind: 'error'; detail: string };
}

export interface ToolPrice {
  price: Money;
  effect: Effect;
}

export interface MandateHookConfig {
  ledger: Ledger;
  tokens: string[];
  /** Tool name → what it costs and how far it reaches. Anything absent is unmetered. */
  prices: Record<string, ToolPrice>;
  /** Where Pre→Post correlation is written. */
  stateDir: string;
  taskId?: string;
  /**
   * What to do when the ledger cannot be reached at all.
   *
   * Defaults to `deny`. Allowing means unmetered spending for as long as the
   * outage lasts, which is the failure this component exists to prevent;
   * denying means a ledger outage stops priced work, which is visible and
   * recoverable. A deployment that would rather take the former risk has to say
   * so.
   */
  onLedgerError?: 'deny' | 'allow';
  /** Whether a tool result counts as a failure. Defaults to common shapes. */
  isError?: (toolResult: unknown) => boolean;
  clock?: () => number;
}

/**
 * `mcp__server__tool` is how a harness names a tool from an MCP server, and
 * `mcp://server/tool` is how the gateway names the same thing. Mapping them onto
 * one URI means a single `resources` caveat covers a tool whether it was called
 * through the gateway or straight from the harness.
 */
export function resourceForTool(toolName: string): string {
  const mcp = /^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/.exec(toolName);
  if (mcp !== null) return `mcp://${mcp[1]!.replace(/_/g, '-')}/${mcp[2]!}`;
  return `tool://claude-code/${toolName}`;
}

const defaultIsError = (result: unknown): boolean => {
  if (typeof result !== 'object' || result === null) return false;
  const r = result as Record<string, unknown>;
  return r['is_error'] === true || r['isError'] === true || typeof r['error'] === 'string';
};

export class MandateHook {
  private readonly clock: () => number;

  constructor(private readonly cfg: MandateHookConfig) {
    this.clock = cfg.clock ?? (() => Math.floor(Date.now() / 1000));
    mkdirSync(cfg.stateDir, { recursive: true });
  }

  /**
   * One file per in-flight call, named by session + tool + input.
   *
   * Not one shared file: two tools running concurrently in a session would race
   * on a read-modify-write and lose a reservation, which then sits `reserved`
   * until it expires. Separate files make the concurrency question disappear
   * rather than need solving.
   */
  private pendingPath(event: HookEvent): string {
    const key = JSON.stringify([
      event.session_id ?? '',
      event.tool_name ?? '',
      event.tool_input ?? null,
    ]);
    return join(this.cfg.stateDir, `${createHash('sha256').update(key, 'utf8').digest('hex')}.json`);
  }

  async handle(event: HookEvent): Promise<HookOutput> {
    return event.hook_event_name === 'PostToolUse' ? this.post(event) : this.pre(event);
  }

  // ------------------------------------------------------------------ before

  private async pre(event: HookEvent): Promise<HookOutput> {
    const tool = event.tool_name ?? '';
    const policy = this.cfg.prices[tool];
    // Unmetered. Silent on purpose: a hook that annotated every unpriced call
    // would bury the ones it actually refused.
    if (policy === undefined) return { exitCode: 0, outcome: { kind: 'unpriced' } };

    const resource = resourceForTool(tool);

    let reserved;
    try {
      reserved = await this.cfg.ledger.reserve({
        tokens: this.cfg.tokens,
        request: {
          resource,
          amount: policy.price,
          effect: policy.effect,
          ...(this.cfg.taskId !== undefined ? { taskId: this.cfg.taskId } : {}),
        },
      });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      if (this.cfg.onLedgerError === 'allow') {
        return {
          exitCode: 0,
          outcome: { kind: 'error', detail },
          systemMessage: `mandate ledger unreachable (${detail}); allowing ${tool} unmetered`,
        };
      }
      return {
        exitCode: 2,
        hookSpecificOutput: { permissionDecision: 'deny' },
        systemMessage: `mandate ledger unreachable (${detail}); ${tool} refused`,
        outcome: { kind: 'error', detail },
      };
    }

    if (!reserved.ok) {
      // `ask` rather than `deny` for a step-up: the answer is "a human has to
      // say yes", and the harness already has a way to put that question in
      // front of one. Denying would tell the model to give up on something that
      // is one approval away.
      const awaiting = reserved.code === 'step_up_required';
      return {
        exitCode: 2,
        hookSpecificOutput: { permissionDecision: awaiting ? 'ask' : 'deny' },
        systemMessage: awaiting
          ? `${tool} needs approval from the principal: ${reserved.detail}` +
            (reserved.stepUpHandle !== undefined ? ` (handle ${reserved.stepUpHandle})` : '')
          : `mandate refused ${tool}: ${reserved.detail} [${reserved.code}]`,
        outcome: {
          kind: 'refused',
          code: reserved.code,
          detail: reserved.detail,
          ...(reserved.stepUpHandle !== undefined ? { stepUpHandle: reserved.stepUpHandle } : {}),
        },
      };
    }

    writeFileSync(
      this.pendingPath(event),
      JSON.stringify({ spendId: reserved.spendId, effect: policy.effect, at: this.clock() }),
      'utf8',
    );

    return {
      exitCode: 0,
      hookSpecificOutput: { permissionDecision: 'allow' },
      outcome: { kind: 'reserved', spendId: reserved.spendId, amount: policy.price },
    };
  }

  // ------------------------------------------------------------------- after

  private async post(event: HookEvent): Promise<HookOutput> {
    const path = this.pendingPath(event);
    let pending: { spendId: string; effect: Effect };
    try {
      pending = JSON.parse(readFileSync(path, 'utf8'));
    } catch {
      // No reservation for this call: it was unpriced, or the hook was added
      // mid-session. Neither is an error.
      return { exitCode: 0, outcome: { kind: 'unknown_call' } };
    }
    rmSync(path, { force: true });

    const failed = (this.cfg.isError ?? defaultIsError)(event.tool_result);

    // The same three-outcome rule the gateway uses, and for the same reason: a
    // tool that reports an error has not proved it had no effect. A failed read
    // definitely did nothing. A failed write may have written.
    if (failed && pending.effect === 'read') {
      await this.cfg.ledger.refund(pending.spendId, `${event.tool_name} failed; read has no effect`);
      return { exitCode: 0, outcome: { kind: 'refunded', spendId: pending.spendId } };
    }

    await this.cfg.ledger.settle(pending.spendId);
    return { exitCode: 0, outcome: { kind: 'settled', spendId: pending.spendId } };
  }
}

/** Serialize a `HookOutput` the way the harness expects to read it. */
export function renderHookOutput(out: HookOutput): { stdout: string; stderr: string; code: 0 | 2 } {
  const payload: Record<string, unknown> = {};
  if (out.hookSpecificOutput !== undefined) {
    payload['hookSpecificOutput'] = {
      hookEventName: 'PreToolUse',
      ...out.hookSpecificOutput,
    };
  }
  if (out.systemMessage !== undefined) payload['systemMessage'] = out.systemMessage;
  const body = Object.keys(payload).length === 0 ? '' : JSON.stringify(payload);

  // Exit 2 puts the message in front of the model, and the harness reads that
  // from stderr. Exit 0 goes to stdout.
  return out.exitCode === 2
    ? { stdout: '', stderr: body, code: 2 }
    : { stdout: body, stderr: '', code: 0 };
}
