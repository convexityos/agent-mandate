import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  type HookEvent,
  MandateHook,
  renderHookOutput,
  resourceForTool,
} from '../src/harness/hook.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { toScaled } from '../src/money.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §2.3 — the harness hook.
 *
 * The motivating case is the one this very session demonstrated: a Claude Code
 * session carrying tools that place live brokerage orders, with nothing in front
 * of them. The MCP gateway covers those when they are reached through it; this
 * covers them when they are not.
 */

let principal: AgentKey;
let agent: AgentKey;
let clock: number;
let ledger: Ledger;
let stateDir: string;

const PRICES = {
  'mcp__public-com__get_quotes': { price: usd('0.01'), effect: 'read' as const },
  'mcp__public-com__place_order': { price: usd('0.01'), effect: 'irreversible' as const },
  WebFetch: { price: usd('0.02'), effect: 'read' as const },
};

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  clock = NOW + 10;
  stateDir = mkdtempSync(join(tmpdir(), 'am-hook-'));

  ledger = new Ledger({
    url: 'https://ledger.local',
    key: generateAgentKey(),
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
  });
});

afterEach(() => rmSync(stateDir, { recursive: true, force: true }));

const chain = (over: Record<string, unknown> = {}) =>
  buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: usd('1.00'),
        max_per_txn: usd('0.50'),
        aud: ['public-com', 'claude-code'],
        ...over,
      },
    },
  ]);

const hook = (over: Record<string, unknown> = {}) =>
  new MandateHook({
    ledger,
    tokens: chain(),
    prices: PRICES,
    stateDir,
    clock: () => clock,
    ...over,
  });

const pre = (tool: string, input: unknown = {}): HookEvent => ({
  session_id: 'sess-1',
  hook_event_name: 'PreToolUse',
  tool_name: tool,
  tool_input: input,
});

const post = (tool: string, input: unknown, result: unknown): HookEvent => ({
  session_id: 'sess-1',
  hook_event_name: 'PostToolUse',
  tool_name: tool,
  tool_input: input,
  tool_result: result,
});

const remaining = async () => {
  const left = await ledger.remaining('mnd_root');
  return left === null ? toScaled(usd('1.00')) : toScaled(left);
};

describe('tool names map onto mandate resources', () => {
  it('folds an MCP tool onto the same URI the gateway uses', () => {
    // One `resources` caveat then covers a tool whether it was called through
    // the gateway or straight from the harness.
    expect(resourceForTool('mcp__public-com__place_order')).toBe(
      'mcp://public-com/place_order',
    );
    expect(resourceForTool('mcp__github__create_issue')).toBe('mcp://github/create_issue');
  });

  it('gives a built-in tool its own scheme', () => {
    expect(resourceForTool('WebFetch')).toBe('tool://claude-code/WebFetch');
    expect(resourceForTool('Bash')).toBe('tool://claude-code/Bash');
  });
});

describe('metering', () => {
  it('lets an unpriced tool through untouched and silently', async () => {
    // The hook fronts every tool the harness has, including reading files.
    // Refusing what nobody priced would be an outage, not a control.
    const out = await hook().handle(pre('Read', { file_path: '/etc/hosts' }));
    expect(out.exitCode).toBe(0);
    expect(out.outcome).toEqual({ kind: 'unpriced' });
    expect(out.systemMessage).toBeUndefined();
    expect(await remaining()).toBe(toScaled(usd('1.00')));
    expect(readdirSync(stateDir)).toHaveLength(0);
  });

  it('reserves before a priced tool fires', async () => {
    const out = await hook().handle(pre('mcp__public-com__get_quotes', { symbol: 'AAPL' }));
    expect(out.exitCode).toBe(0);
    expect(out.hookSpecificOutput).toEqual({ permissionDecision: 'allow' });
    expect(out.outcome.kind).toBe('reserved');
    expect(await remaining()).toBe(toScaled(usd('0.99')));
  });

  it('blocks with a reason the model can read', async () => {
    // effect: read, so the irreversible order is refused at any price.
    const h = hook({ tokens: chain({ effect: 'read' }) });
    const out = await h.handle(pre('mcp__public-com__place_order', { qty: 100 }));

    expect(out.exitCode).toBe(2);
    expect(out.hookSpecificOutput).toEqual({ permissionDecision: 'deny' });
    expect(out.systemMessage).toContain('effect_not_permitted');
    expect(out.outcome).toMatchObject({ kind: 'refused', code: 'effect_not_permitted' });
    expect(await remaining()).toBe(toScaled(usd('1.00')));

    // The read tool at the same price still works, which is the point of a
    // separate axis rather than a lower price.
    expect((await h.handle(pre('mcp__public-com__get_quotes'))).exitCode).toBe(0);
  });

  it('asks rather than denies when a human could say yes', async () => {
    const h = hook({ tokens: chain({ step_up: { over: usd('0.001') } }) });
    const out = await h.handle(pre('mcp__public-com__place_order', { qty: 1 }));

    // Denying would tell the model to give up on something one approval away.
    expect(out.hookSpecificOutput).toEqual({ permissionDecision: 'ask' });
    expect(out.systemMessage).toContain('needs approval from the principal');
    expect(out.systemMessage).toMatch(/stp_/);
  });

  it('stops spending once the budget is gone', async () => {
    const h = hook();
    for (let i = 0; i < 100; i++) {
      await h.handle(pre('mcp__public-com__get_quotes', { n: i }));
    }
    expect(await remaining()).toBe(0n);

    const out = await h.handle(pre('mcp__public-com__get_quotes', { n: 'last' }));
    expect(out.exitCode).toBe(2);
    expect(out.outcome).toMatchObject({ code: 'budget_exhausted' });
  });
});

describe('settling across two process invocations', () => {
  it('correlates PostToolUse back to the reservation the pre-hook made', async () => {
    const input = { symbol: 'AAPL' };
    // Deliberately two separate instances: the hooks are separate processes and
    // share nothing but the state directory.
    const before = await hook().handle(pre('mcp__public-com__get_quotes', input));
    expect(before.outcome.kind).toBe('reserved');
    expect(readdirSync(stateDir)).toHaveLength(1);

    const after = await hook().handle(
      post('mcp__public-com__get_quotes', input, { content: 'ok' }),
    );
    expect(after.outcome).toMatchObject({ kind: 'settled' });
    // The correlation file is cleaned up, so the directory does not grow without
    // bound over a long session.
    expect(readdirSync(stateDir)).toHaveLength(0);
    expect(await remaining()).toBe(toScaled(usd('0.99')));
  });

  it('keeps concurrent calls apart', async () => {
    const h = hook();
    await Promise.all([
      h.handle(pre('mcp__public-com__get_quotes', { symbol: 'AAPL' })),
      h.handle(pre('mcp__public-com__get_quotes', { symbol: 'MSFT' })),
      h.handle(pre('WebFetch', { url: 'https://example.com' })),
    ]);
    // One file per in-flight call. A single shared file would have lost two of
    // these to a read-modify-write race.
    expect(readdirSync(stateDir)).toHaveLength(3);

    await h.handle(post('mcp__public-com__get_quotes', { symbol: 'AAPL' }, {}));
    expect(readdirSync(stateDir)).toHaveLength(2);
  });

  it('shrugs at a post-hook for a call it never saw', async () => {
    // The hook was added mid-session, or the tool was unpriced.
    const out = await hook().handle(post('Read', { file_path: '/x' }, {}));
    expect(out.exitCode).toBe(0);
    expect(out.outcome).toEqual({ kind: 'unknown_call' });
  });
});

describe('what happens when a tool fails', () => {
  it('refunds a failed read', async () => {
    const h = hook();
    const input = { symbol: 'AAPL' };
    await h.handle(pre('mcp__public-com__get_quotes', input));
    await h.handle(post('mcp__public-com__get_quotes', input, { is_error: true }));
    expect(await remaining()).toBe(toScaled(usd('1.00')));
  });

  /**
   * The rule the gateway already follows, for the same reason. An order that
   * comes back with an error may still have reached the venue, and refunding it
   * hands the agent budget to place it again.
   */
  it('consumes the allowance when an irreversible tool fails', async () => {
    const h = hook();
    const input = { qty: 100 };
    await h.handle(pre('mcp__public-com__place_order', input));
    await h.handle(post('mcp__public-com__place_order', input, { is_error: true }));
    expect(await remaining()).toBe(toScaled(usd('0.99')));
  });

  it('recognises the usual error shapes, and takes a custom predicate', async () => {
    const h = hook();
    for (const [i, result] of [{ is_error: true }, { isError: true }, { error: 'nope' }].entries()) {
      const input = { n: i };
      await h.handle(pre('mcp__public-com__get_quotes', input));
      await h.handle(post('mcp__public-com__get_quotes', input, result));
    }
    expect(await remaining()).toBe(toScaled(usd('1.00')));

    const custom = hook({ isError: (r: unknown) => (r as { status: number }).status >= 400 });
    const input = { n: 'custom' };
    await custom.handle(pre('mcp__public-com__get_quotes', input));
    await custom.handle(post('mcp__public-com__get_quotes', input, { status: 500 }));
    expect(await remaining()).toBe(toScaled(usd('1.00')));
  });
});

describe('when the ledger cannot be reached', () => {
  const broken = () =>
    ({
      reserve: () => {
        throw new Error('ECONNREFUSED');
      },
    }) as unknown as Ledger;

  it('refuses by default, because unmetered spending is the failure it exists to prevent', async () => {
    const out = await hook({ ledger: broken() }).handle(pre('mcp__public-com__place_order'));
    expect(out.exitCode).toBe(2);
    expect(out.hookSpecificOutput).toEqual({ permissionDecision: 'deny' });
    expect(out.systemMessage).toContain('ledger unreachable');
  });

  it('can be told to allow instead, but only deliberately', async () => {
    const out = await hook({ ledger: broken(), onLedgerError: 'allow' }).handle(
      pre('mcp__public-com__place_order'),
    );
    expect(out.exitCode).toBe(0);
    expect(out.systemMessage).toContain('unmetered');
  });
});

describe('the wire format the harness reads', () => {
  it('puts an allow on stdout and exits 0', async () => {
    const rendered = renderHookOutput(
      await hook().handle(pre('mcp__public-com__get_quotes')),
    );
    expect(rendered.code).toBe(0);
    expect(JSON.parse(rendered.stdout)).toEqual({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
    });
    expect(rendered.stderr).toBe('');
  });

  it('puts a block on stderr and exits 2, which is where the model reads it', async () => {
    const h = hook({ tokens: chain({ effect: 'read' }) });
    const rendered = renderHookOutput(await h.handle(pre('mcp__public-com__place_order')));

    expect(rendered.code).toBe(2);
    expect(rendered.stdout).toBe('');
    const body = JSON.parse(rendered.stderr) as {
      hookSpecificOutput: { permissionDecision: string };
      systemMessage: string;
    };
    expect(body.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(body.systemMessage).toContain('effect_not_permitted');
  });

  it('says nothing at all for an unpriced tool', async () => {
    const rendered = renderHookOutput(await hook().handle(pre('Read')));
    expect(rendered).toEqual({ stdout: '', stderr: '', code: 0 });
  });
});

/**
 * The one guarantee that can only be observed from outside the process.
 *
 * On a block the harness reads **stderr** as the reason it shows the model, and
 * Node writes its own diagnostics to the same stream — loading `node:sqlite`
 * prints an ExperimentalWarning, and a `process.on('warning')` listener does not
 * suppress it. So `bin/am-hook.mjs` swallows stderr and re-emits only its own
 * output. Nothing inside the module can prove that; this spawns it.
 */
describe('the executable keeps the reason channel clean', () => {
  const built = join(process.cwd(), 'dist', 'src', 'index.js');

  it.skipIf(!existsSync(built))(
    'writes nothing to stderr but its own JSON, even with sqlite loaded',
    async () => {
      const dir = mkdtempSync(join(tmpdir(), 'am-hook-bin-'));
      try {
        // Expiry against the *real* clock: the spawned binary has no injected
        // one, and the fixture epoch is months in the past, so a chain built the
        // way the in-process tests build theirs is already expired out there.
        const tokens = buildChain(principal, [
          {
            holder: agent,
            exp: Math.floor(Date.now() / 1000) + 3600,
            jti: 'mnd_root',
            cav: { max_total: usd('1.00'), max_per_txn: usd('0.50'), aud: ['public-com'], effect: 'read' },
          },
        ]);
        const configPath = join(dir, 'config.json');
        writeFileSync(
          configPath,
          JSON.stringify({
            tokens,
            stateDir: join(dir, 'state'),
            // A durable store, so the ExperimentalWarning is actually emitted.
            store: { kind: 'sqlite', location: join(dir, 'am.db') },
            ledgerKeySeed: '09'.repeat(32),
            trustedRootIssuer: principal.did,
            prices: {
              'mcp__public-com__place_order': {
                price: { cur: 'USD', amt: '0.01' },
                effect: 'irreversible',
              },
            },
          }),
        );

        const child = spawnSync(
          process.execPath,
          [join(process.cwd(), 'bin', 'am-hook.mjs')],
          {
            input: JSON.stringify({
              session_id: 's',
              hook_event_name: 'PreToolUse',
              tool_name: 'mcp__public-com__place_order',
              tool_input: { qty: 1 },
            }),
            env: { ...process.env, AM_HOOK_CONFIG: configPath },
            encoding: 'utf8',
          },
        );

        expect(child.status).toBe(2);
        expect(child.stderr).not.toContain('ExperimentalWarning');
        // Parses cleanly, which it would not if a warning were stapled to it.
        const reason = JSON.parse(child.stderr) as {
          hookSpecificOutput: { permissionDecision: string };
          systemMessage: string;
        };
        expect(reason.hookSpecificOutput.permissionDecision).toBe('deny');
        expect(reason.systemMessage).toContain('effect_not_permitted');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});
