import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { McpMandateGateway } from '../src/mcp/gateway.js';
import { LineFramer, type JsonRpcMessage, encodeLine, parseMessage } from '../src/mcp/jsonrpc.js';
import { StdioUpstream, serveStdio } from '../src/mcp/stdio.js';
import { toScaled } from '../src/money.js';
import { generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * End to end over real pipes: a client speaking JSON-RPC into `serveStdio`, a
 * gateway in the middle, and a genuine child-process MCP server upstream.
 *
 * The in-process tests prove the policy. This proves the wire — framing,
 * handshake, id correlation and process lifetime — which is the part that fails
 * for reasons no amount of unit testing surfaces.
 */

const SERVER = fileURLToPath(new URL('./fixtures/echo-mcp-server.mjs', import.meta.url));

let upstream: StdioUpstream;
let stopServing: (() => void) | null = null;
let toGateway: PassThrough;
let fromGateway: PassThrough;
let ledger: Ledger;

/** Drives the gateway the way a client would, and waits for the matching id. */
async function call(message: JsonRpcMessage & { id: number }): Promise<JsonRpcMessage> {
  const framer = new LineFramer();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no reply to id ${message.id}`)), 15_000);
    const onData = (chunk: Buffer) => {
      for (const line of framer.push(new Uint8Array(chunk))) {
        const msg = parseMessage(line);
        if (msg !== null && 'id' in msg && msg.id === message.id) {
          clearTimeout(timer);
          fromGateway.off('data', onData);
          resolve(msg);
        }
      }
    };
    fromGateway.on('data', onData);
    toGateway.write(encodeLine(message));
  });
}

beforeEach(async () => {
  const principal = generateAgentKey();
  const agent = generateAgentKey();
  const clock = NOW + 10;

  ledger = new Ledger({
    url: 'https://ledger.example.com',
    key: generateAgentKey(),
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
  });

  const tokens = buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: usd('1.00'),
        max_per_txn: usd('0.50'),
        aud: ['echo'],
        resources: ['mcp://echo/*'],
      },
    },
  ]);

  upstream = new StdioUpstream({ command: process.execPath, args: [SERVER] });
  await upstream.start();

  const gateway = new McpMandateGateway({
    ledger,
    tokens,
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    upstreams: [
      {
        name: 'echo',
        server: upstream,
        tools: {
          echo: { price: usd('0.01'), effect: 'read' },
          boom: { price: usd('0.01'), effect: 'read' },
        },
      },
    ],
  });

  toGateway = new PassThrough();
  fromGateway = new PassThrough();
  stopServing = serveStdio(gateway, { input: toGateway, output: fromGateway });
});

afterEach(async () => {
  stopServing?.();
  await upstream.close();
});

describe('gateway over stdio, against a real child process', () => {
  it('completes the handshake and lists only priced tools', async () => {
    const init = await call({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {} },
    });
    expect(init).toMatchObject({ result: { capabilities: { tools: {} } } });

    const listed = await call({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    const names = ((listed as { result: { tools: Array<{ name: string }> } }).result.tools ?? []).map(
      (t) => t.name,
    );
    // The fixture serves three tools; `unpriced` has no policy and so is absent.
    expect(names).toEqual(['echo__echo', 'echo__boom']);
  });

  it('round-trips a call and debits the budget', async () => {
    const reply = await call({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'echo__echo', arguments: { hello: 'world' } },
    });

    expect(reply).toMatchObject({
      id: 3,
      result: { content: [{ type: 'text', text: '{"hello":"world"}' }] },
    });
    expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(toScaled(usd('0.99')));
  });

  it('refunds a failed read across the wire', async () => {
    await call({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'echo__boom', arguments: {} },
    });
    // Debited then credited back, so a node exists and reads full again.
    expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(toScaled(usd('1.00')));
  });

  it('denies an unpriced tool without reaching the upstream', async () => {
    const reply = await call({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'echo__unpriced', arguments: {} },
    });
    expect(reply).toMatchObject({ id: 5, error: { code: -32601 } });
  });

  it('answers each request with its own id under pipelined load', async () => {
    // Ids must not cross, and the sequential handling in `serveStdio` must not
    // drop any: five calls at $0.01 against a $1.00 budget all succeed.
    const replies = await Promise.all(
      [10, 11, 12, 13, 14].map((id) =>
        call({
          jsonrpc: '2.0',
          id,
          method: 'tools/call',
          params: { name: 'echo__echo', arguments: { n: id } },
        }),
      ),
    );

    for (const [i, id] of [10, 11, 12, 13, 14].entries()) {
      expect(replies[i]).toMatchObject({
        id,
        result: { content: [{ type: 'text', text: `{"n":${id}}` }] },
      });
    }
    expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(toScaled(usd('0.95')));
  });
});
