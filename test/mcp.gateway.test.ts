import { beforeEach, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import {
  McpMandateGateway,
  type ToolPolicy,
  type UpstreamServer,
} from '../src/mcp/gateway.js';
import { LineFramer, MANDATE_DENIED, parseMessage } from '../src/mcp/jsonrpc.js';
import type { JsonRpcResponse } from '../src/mcp/jsonrpc.js';
import { toScaled } from '../src/money.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * The gateway, against the case it exists for.
 *
 * The tool names below are the ones a Claude Code session on this machine
 * actually carries: a quote lookup and an equity order, identically cheap and
 * not remotely comparable in consequence. Nothing here contacts a broker — the
 * upstream is a fake — but the shape is the real one.
 */

let principal: AgentKey;
let agent: AgentKey;
let ledgerKey: AgentKey;

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  ledgerKey = generateAgentKey();
});

interface FakeTool {
  name: string;
  description?: string;
}

/** An MCP server that records what it was asked and answers however told to. */
class FakeUpstream implements UpstreamServer {
  readonly calls: Array<{ method: string; params: unknown }> = [];
  behaviour: 'ok' | 'isError' | 'rpcError' | 'throw' = 'ok';

  constructor(private readonly tools: FakeTool[]) {}

  async request(method: string, params?: unknown): Promise<JsonRpcResponse> {
    this.calls.push({ method, params });

    if (method === 'tools/list') {
      return { jsonrpc: '2.0', id: 1, result: { tools: this.tools } };
    }
    if (method !== 'tools/call') {
      return { jsonrpc: '2.0', id: 1, result: {} };
    }

    switch (this.behaviour) {
      case 'throw':
        throw new Error('socket closed');
      case 'rpcError':
        return { jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'upstream said no' } };
      case 'isError':
        return {
          jsonrpc: '2.0',
          id: 1,
          result: { isError: true, content: [{ type: 'text', text: 'rejected by venue' }] },
        };
      default:
        return {
          jsonrpc: '2.0',
          id: 1,
          result: { content: [{ type: 'text', text: 'ok' }] },
        };
    }
  }
}

const QUOTES: ToolPolicy = { price: usd('0.01'), effect: 'read' };
const ORDER: ToolPolicy = { price: usd('0.01'), effect: 'irreversible' };

const TOOLS: FakeTool[] = [
  { name: 'get_equity_quotes', description: 'Latest quote' },
  { name: 'place_equity_order', description: 'Submit an order' },
  { name: 'get_portfolio', description: 'Positions' },
];

interface SetupOptions {
  cav?: Record<string, unknown>;
  tools?: Record<string, ToolPolicy>;
  taskId?: string;
}

function setup(opts: SetupOptions = {}) {
  const clock = NOW + 10;
  const store = new MemoryLedgerStore(() => clock);
  const ledger = new Ledger({
    url: 'https://ledger.example.com',
    key: ledgerKey,
    store,
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
  });

  const budget = (opts.cav?.['max_total'] as { cur: string; amt: string } | undefined) ??
    usd('1.00');

  const tokens = buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: budget,
        max_per_txn: usd('0.50'),
        aud: ['public-com'],
        resources: ['mcp://public-com/*'],
        ...opts.cav,
      },
    },
  ]);

  const upstream = new FakeUpstream(TOOLS);
  const gateway = new McpMandateGateway({
    ledger,
    tokens,
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    upstreams: [
      {
        name: 'public-com',
        server: upstream,
        tools: opts.tools ?? {
          get_equity_quotes: QUOTES,
          place_equity_order: ORDER,
        },
      },
    ],
    ...(opts.taskId !== undefined ? { taskId: opts.taskId } : {}),
  });

  // The ledger materializes a node on first debit, so a mandate that has never
  // been spent against has no row and `remaining` answers null rather than the
  // declared budget. For these assertions "never debited" and "full budget
  // left" are the same claim — which matters, because the denial tests expect
  // exactly that: no reservation, and therefore no node.
  const remaining = async () => {
    const left = await ledger.remaining('mnd_root');
    return left === null ? toScaled(budget) : toScaled(left);
  };
  return { gateway, ledger, upstream, remaining };
}

describe('the gateway as a control plane', () => {
  it('prices, forwards and settles a permitted call', async () => {
    const { gateway, upstream, remaining } = setup();

    const out = await gateway.callTool('public-com__get_equity_quotes', { symbol: 'AAPL' });
    expect(out).not.toBeNull();
    expect(out!.outcome.disposition).toBe('settled');

    // The upstream saw its own tool name, not the namespaced one, and its
    // arguments untouched.
    const call = upstream.calls.find((c) => c.method === 'tools/call');
    expect(call!.params).toEqual({
      name: 'get_equity_quotes',
      arguments: { symbol: 'AAPL' },
    });

    expect(await remaining()).toBe(toScaled(usd('0.99')));
  });

  it('refuses an irreversible tool under a read-only mandate', async () => {
    const { gateway, upstream, remaining } = setup({ cav: { effect: 'read' } });

    const out = await gateway.callTool('public-com__place_equity_order', {
      symbol: 'AAPL',
      quantity: 100,
      side: 'buy',
    });

    expect(out!.outcome.disposition).toBe('denied');
    expect(out!.outcome.code).toBe('effect_not_permitted');

    // The refusal happened before the upstream was contacted at all. This is the
    // whole claim: it is a preventive control, not an audit trail.
    expect(upstream.calls.filter((c) => c.method === 'tools/call')).toHaveLength(0);
    expect(await remaining()).toBe(toScaled(usd('1.00')));

    // The read tool at the identical price still works, which is the point of a
    // separate axis rather than a lower price.
    const quote = await gateway.callTool('public-com__get_equity_quotes', { symbol: 'AAPL' });
    expect(quote!.outcome.disposition).toBe('settled');
  });

  it('stops spending when the budget is gone', async () => {
    const { gateway, remaining } = setup({ cav: { max_total: usd('0.02') } });

    expect((await gateway.callTool('public-com__get_equity_quotes', {}))!.outcome.disposition).toBe(
      'settled',
    );
    expect((await gateway.callTool('public-com__get_equity_quotes', {}))!.outcome.disposition).toBe(
      'settled',
    );

    const third = await gateway.callTool('public-com__get_equity_quotes', {});
    expect(third!.outcome.disposition).toBe('denied');
    expect(third!.outcome.code).toBe('budget_exhausted');
    expect(await remaining()).toBe(0n);
  });

  it('refuses a call over max_per_txn', async () => {
    const { gateway } = setup({
      tools: { get_equity_quotes: { price: usd('0.90'), effect: 'read' } },
    });
    const out = await gateway.callTool('public-com__get_equity_quotes', {});
    expect(out!.outcome.disposition).toBe('denied');
    expect(out!.outcome.code).toBe('amount_exceeds_cap');
  });

  it('reports a denial as a distinguishable JSON-RPC error carrying the am/1 code', async () => {
    const { gateway } = setup({ cav: { effect: 'read' } });
    const reply = await gateway.handle({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'public-com__place_equity_order', arguments: {} },
    });

    expect(reply).toMatchObject({
      id: 7,
      error: { code: MANDATE_DENIED, data: { code: 'effect_not_permitted' } },
    });
  });
});

describe('what happens when a tool fails', () => {
  it('refunds a failed read, because a failed read did nothing', async () => {
    for (const behaviour of ['isError', 'rpcError'] as const) {
      const { gateway, upstream, remaining } = setup();
      upstream.behaviour = behaviour;

      const out = await gateway.callTool('public-com__get_equity_quotes', {});
      expect(out!.outcome.disposition, behaviour).toBe('refunded');
      expect(await remaining(), behaviour).toBe(toScaled(usd('1.00')));
    }
  });

  /**
   * The one that matters. An order that comes back with `isError` may still have
   * reached the venue, and refunding it hands the agent budget to place it
   * again. Consuming the allowance risks charging for something that did not
   * happen; refunding risks a position nobody asked for. Only the first is
   * recoverable by reading a receipt.
   */
  it('consumes the allowance when an irreversible tool fails', async () => {
    for (const behaviour of ['isError', 'rpcError'] as const) {
      const { gateway, upstream, remaining } = setup();
      upstream.behaviour = behaviour;

      const out = await gateway.callTool('public-com__place_equity_order', { quantity: 100 });
      expect(out!.outcome.disposition, behaviour).toBe('settled');
      expect(await remaining(), behaviour).toBe(toScaled(usd('0.99')));
    }
  });

  it('holds the reservation when the transport dies mid-call', async () => {
    const { gateway, upstream, ledger, remaining } = setup();
    upstream.behaviour = 'throw';

    const out = await gateway.callTool('public-com__place_equity_order', {});
    expect(out!.outcome.disposition).toBe('held');

    // Neither settled nor refunded: whether the order reached the venue is not
    // knowable from here, and guessing either way is how you double-spend or
    // strand funds. It stays `reserved` for the reconciler.
    const reservation = await ledger.reservation(out!.outcome.spendId!);
    expect(reservation?.status).toBe('reserved');
    expect(await remaining()).toBe(toScaled(usd('0.99')));
  });

  it('passes the upstream response through unedited', async () => {
    const { gateway, upstream } = setup();
    upstream.behaviour = 'isError';

    const out = await gateway.callTool('public-com__get_equity_quotes', {});
    expect(out!.response).toMatchObject({
      result: { isError: true, content: [{ type: 'text', text: 'rejected by venue' }] },
    });
  });
});

describe('tools/list is the mandate, rendered', () => {
  it('hides unpriced tools rather than refusing them later', async () => {
    const { gateway } = setup();
    const tools = await gateway.listTools();

    // get_portfolio exists upstream but carries no policy.
    expect(tools.map((t) => t.name)).toEqual([
      'public-com__get_equity_quotes',
      'public-com__place_equity_order',
    ]);

    // And it is not reachable by guessing the name either.
    expect(await gateway.callTool('public-com__get_portfolio', {})).toBeNull();
  });

  it('hides what the mandate does not permit', async () => {
    const { gateway } = setup({ cav: { effect: 'read' } });
    const tools = await gateway.listTools();
    expect(tools.map((t) => t.name)).toEqual(['public-com__get_equity_quotes']);
  });

  it('tells the model what a call costs and how far it reaches', async () => {
    const { gateway } = setup();
    const tools = await gateway.listTools();
    const order = tools.find((t) => t.name === 'public-com__place_equity_order');
    expect(order!.description).toContain('Submit an order');
    expect(order!.description).toContain('price 0.01 USD');
    expect(order!.description).toContain('effect irreversible');
  });

  it('scopes the budget to a task when configured', async () => {
    const { gateway } = setup({ cav: { task: 'tsk_research' }, taskId: 'tsk_research' });
    expect((await gateway.callTool('public-com__get_equity_quotes', {}))!.outcome.disposition).toBe(
      'settled',
    );

    const wrong = setup({ cav: { task: 'tsk_research' }, taskId: 'tsk_other' });
    const out = await wrong.gateway.callTool('public-com__get_equity_quotes', {});
    expect(out!.outcome.disposition).toBe('denied');
    expect(out!.outcome.code).toBe('purpose_not_covered');
  });
});

describe('protocol surface', () => {
  it('answers initialize, echoing the client protocol version', async () => {
    const { gateway } = setup();
    const reply = await gateway.handle({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {} },
    });
    expect(reply).toMatchObject({
      id: 1,
      result: { protocolVersion: '2025-06-18', capabilities: { tools: {} } },
    });
  });

  it('refuses methods it does not understand rather than picking an upstream', async () => {
    const { gateway } = setup();
    const reply = await gateway.handle({
      jsonrpc: '2.0',
      id: 2,
      method: 'resources/read',
      params: {},
    });
    expect(reply).toMatchObject({ id: 2, error: { code: -32601 } });
  });

  it('has no reply for a notification', async () => {
    const { gateway } = setup();
    expect(
      await gateway.handle({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    ).toBeNull();
  });

  it('rejects two upstreams claiming the same exposed name', () => {
    const dup = () =>
      new McpMandateGateway({
        ledger: {} as never,
        tokens: [],
        isTrustedRootIssuer: () => true,
        upstreams: [
          { name: 'a', server: new FakeUpstream([]), tools: { t: QUOTES } },
          { name: 'a', server: new FakeUpstream([]), tools: { t: QUOTES } },
        ],
      });
    expect(dup).toThrow(/both expose/);
  });
});

describe('stdio framing', () => {
  it('reassembles messages split across chunks', () => {
    const framer = new LineFramer();
    expect(framer.push('{"jsonrpc":"2.0",')).toEqual([]);
    expect(framer.push('"id":1,"method":"ping"}\n')).toEqual([
      '{"jsonrpc":"2.0","id":1,"method":"ping"}',
    ]);
  });

  it('splits several messages arriving in one chunk, and tolerates CRLF', () => {
    const framer = new LineFramer();
    const lines = framer.push('{"jsonrpc":"2.0","id":1,"result":{}}\r\n{"jsonrpc":"2.0","id":2,"result":{}}\n\n');
    expect(lines).toHaveLength(2);
    expect(parseMessage(lines[0]!)).toMatchObject({ id: 1 });
    expect(parseMessage(lines[1]!)).toMatchObject({ id: 2 });
  });

  it('holds a multi-byte character split across a chunk boundary', () => {
    const framer = new LineFramer();
    const payload = Buffer.from('{"jsonrpc":"2.0","id":1,"result":"€"}\n', 'utf8');
    const cut = payload.indexOf(0xe2) + 1; // mid-euro-sign

    expect(framer.push(new Uint8Array(payload.subarray(0, cut)))).toEqual([]);
    const lines = framer.push(new Uint8Array(payload.subarray(cut)));
    expect(lines).toHaveLength(1);
    expect(parseMessage(lines[0]!)).toMatchObject({ result: '€' });
  });

  it('rejects non-JSON-RPC payloads instead of guessing', () => {
    expect(parseMessage('not json')).toBeNull();
    expect(parseMessage('{"id":1}')).toBeNull(); // no jsonrpc
    expect(parseMessage('{"jsonrpc":"2.0","id":1}')).toBeNull(); // neither method nor outcome
    expect(parseMessage('[]')).toBeNull();
  });
});
