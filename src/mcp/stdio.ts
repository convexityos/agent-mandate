import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';

import type { McpMandateGateway, UpstreamServer } from './gateway.js';
import {
  INTERNAL_ERROR,
  LineFramer,
  type JsonRpcId,
  type JsonRpcResponse,
  encodeLine,
  errorResponse,
  isResponse,
  parseMessage,
} from './jsonrpc.js';

/**
 * MCP's stdio transport: newline-delimited JSON-RPC over a child process's
 * stdin/stdout.
 *
 * The one rule that matters on both sides of this file: **stdout carries
 * protocol and nothing else.** A stray `console.log` anywhere in a server's
 * process corrupts the stream, and the symptom is a parse error somewhere
 * unrelated. Diagnostics go to stderr.
 */

export interface StdioUpstreamOptions {
  command: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** How long to wait for a response before giving up on it. */
  requestTimeoutMs?: number;
  /** Called with the child's stderr, which is where a failing server explains itself. */
  onStderr?: (chunk: string) => void;
}

interface Pending {
  resolve: (r: JsonRpcResponse) => void;
  timer: NodeJS.Timeout;
}

/** A wrapped MCP server, spawned as a child process. */
export class StdioUpstream implements UpstreamServer {
  private child: ChildProcessWithoutNullStreams | null = null;
  private readonly framer = new LineFramer();
  private readonly pending = new Map<string, Pending>();
  private nextId = 1;
  private readonly timeoutMs: number;

  constructor(private readonly opts: StdioUpstreamOptions) {
    this.timeoutMs = opts.requestTimeoutMs ?? 30_000;
  }

  async start(): Promise<void> {
    const child = spawn(this.opts.command, this.opts.args ?? [], {
      stdio: ['pipe', 'pipe', 'pipe'],
      ...(this.opts.cwd !== undefined ? { cwd: this.opts.cwd } : {}),
      ...(this.opts.env !== undefined ? { env: this.opts.env } : {}),
    }) as ChildProcessWithoutNullStreams;
    this.child = child;

    child.stdout.on('data', (chunk: Buffer) => {
      for (const line of this.framer.push(chunk)) {
        const msg = parseMessage(line);
        if (msg === null || !isResponse(msg)) continue;
        this.settle(msg.id, msg);
      }
    });

    child.stderr.on('data', (chunk: Buffer) => this.opts.onStderr?.(chunk.toString('utf8')));

    // A dead child must not leave callers waiting for the full timeout each.
    child.on('exit', (code) => {
      for (const key of [...this.pending.keys()]) {
        this.settle(
          key,
          errorResponse(key, INTERNAL_ERROR, `upstream exited with code ${code ?? 'null'}`),
        );
      }
    });

    // MCP requires the handshake before any other request.
    await this.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'am-mandate-gateway', version: '1' },
    });
    this.notify('notifications/initialized');
  }

  private settle(id: JsonRpcId, response: JsonRpcResponse): void {
    const key = String(id);
    const p = this.pending.get(key);
    if (p === undefined) return;
    clearTimeout(p.timer);
    this.pending.delete(key);
    p.resolve(response);
  }

  private notify(method: string, params?: unknown): void {
    this.child?.stdin.write(
      encodeLine({ jsonrpc: '2.0', method, ...(params !== undefined ? { params } : {}) }),
    );
  }

  /**
   * Resolves with a JSON-RPC failure rather than rejecting on timeout.
   *
   * A timeout is a real answer here — "the upstream did not say" — and the
   * gateway has to distinguish it from a thrown transport error, because the two
   * imply different things about whether the tool ran. Rejecting would collapse
   * them.
   */
  async request(method: string, params?: unknown): Promise<JsonRpcResponse> {
    const child = this.child;
    if (child === null) throw new Error('upstream not started');

    const id = this.nextId++;
    return new Promise<JsonRpcResponse>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(String(id));
        resolve(errorResponse(id, INTERNAL_ERROR, `upstream timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      // Node keeps the process alive for a pending timer; this one is a deadline,
      // not work, and should not hold a CLI open.
      timer.unref?.();

      this.pending.set(String(id), { resolve, timer });
      child.stdin.write(
        encodeLine({
          jsonrpc: '2.0',
          id,
          method,
          ...(params !== undefined ? { params } : {}),
        }),
      );
    });
  }

  async close(): Promise<void> {
    this.child?.kill();
    this.child = null;
  }
}

export interface ServeOptions {
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream;
  onError?: (err: unknown) => void;
}

/**
 * Serve a gateway over a stdio pair.
 *
 * Requests are handled **sequentially**. MCP permits concurrent in-flight
 * requests and a throughput-minded proxy would pipeline them, but every
 * `tools/call` here opens a ledger transaction, and an agent that fires three
 * calls at once against a nearly-exhausted budget should get a deterministic
 * answer about which one wins rather than a race. The ledger would stay correct
 * either way; the *explanation* would not.
 */
export function serveStdio(gateway: McpMandateGateway, opts: ServeOptions): () => void {
  const framer = new LineFramer();
  let chain: Promise<void> = Promise.resolve();

  const onData = (chunk: Buffer | string) => {
    for (const line of framer.push(typeof chunk === 'string' ? chunk : new Uint8Array(chunk))) {
      const msg = parseMessage(line);
      if (msg === null) continue;
      chain = chain.then(async () => {
        try {
          const reply = await gateway.handle(msg);
          if (reply !== null) opts.output.write(encodeLine(reply));
        } catch (err) {
          opts.onError?.(err);
          if ('id' in msg) {
            opts.output.write(
              encodeLine(errorResponse(msg.id, INTERNAL_ERROR, 'gateway error')),
            );
          }
        }
      });
    }
  };

  opts.input.on('data', onData);
  return () => opts.input.off('data', onData);
}
