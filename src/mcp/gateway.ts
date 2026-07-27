import type { Effect } from '../caveats.js';
import type { ErrorCode } from '../errors.js';
import type { Money } from '../money.js';
import type { ReserveRequest, ReserveResult, SettleInput, SettleResult } from '../ledger/ledger.js';
import { PROTOCOL_VERSION } from '../types.js';
import { verifyChain, type KeyResolver } from '../verify.js';
import {
  INTERNAL_ERROR,
  INVALID_PARAMS,
  MANDATE_DENIED,
  METHOD_NOT_FOUND,
  type JsonRpcMessage,
  type JsonRpcRequest,
  type JsonRpcResponse,
  errorResponse,
  isRequest,
} from './jsonrpc.js';

/**
 * Spec §2.1 (roadmap) — a mandate gateway for MCP.
 *
 * An MCP server to the client, an MCP client to each server it fronts, and a
 * mandate in between. Every `tools/call` is priced, reserved against the ledger,
 * forwarded, and then settled or refunded. **The wrapped server implements
 * nothing** — it does not know it is behind a mandate, which is the same
 * zero-integration wedge that made paying x402 on the agent's behalf the right
 * call, pointed at the ecosystem agents actually run in.
 *
 * The motivating case is not hypothetical. A Claude Code session routinely
 * carries ~140 MCP tools, several of which place live brokerage orders, and
 * nothing today puts a `max_per_txn` in front of any of them.
 *
 * ## What this can and cannot do
 *
 * This is a **preventive** control, unlike the non-custodial rail: the gateway is
 * on the call path, so a denied call does not happen. That holds exactly as long
 * as the client reaches the wrapped server only through here. A client that also
 * has the upstream server configured directly has simply routed around it — the
 * gateway constrains a channel, not an agent.
 */

/** What the gateway needs from the ledger. `Ledger` satisfies it structurally. */
export interface GatewayLedger {
  /**
   * The ledger's base URL, so the gateway can hold a chain to §7 step 3 before
   * advertising a tool the ledger would refuse on the chain's address. Part of
   * this interface rather than a separate config field because the two must not
   * be able to disagree about which ledger this is.
   */
  readonly url: string;
  reserve(req: ReserveRequest): Promise<ReserveResult>;
  settle(spendId: string, input?: SettleInput): Promise<SettleResult>;
  refund(spendId: string, reason: string): Promise<SettleResult>;
}

/** What the gateway needs from a server it fronts. */
export interface UpstreamServer {
  request(method: string, params?: unknown): Promise<JsonRpcResponse>;
}

/**
 * Per-tool policy. Both fields are mandatory, and that is the point.
 *
 * A tool with no entry is not callable and is not listed. Default-allow would
 * mean `place_equity_order` sails through because somebody adding a server
 * forgot to price it, and the failure mode of this component is somebody's
 * money.
 */
export interface ToolPolicy {
  price: Money;
  /** §6.2 blast radius. `get_quotes` and `place_order` can cost the same. */
  effect: Effect;
}

export interface UpstreamConfig {
  /**
   * Becomes the host of `mcp://<name>/<tool>` and therefore what `aud` matches.
   * Must be a valid host label — `hostOfUri` has to be able to return it.
   */
  name: string;
  server: UpstreamServer;
  tools: Record<string, ToolPolicy>;
}

export interface GatewayConfig {
  ledger: GatewayLedger;
  /** The mandate chain every call under this gateway spends against. */
  tokens: string[];
  upstreams: UpstreamConfig[];
  isTrustedRootIssuer: (iss: string) => boolean;
  /** Scopes the budget to a task, per §6.2 `task`. */
  taskId?: string;
  /** Advertised to clients in `initialize`. */
  serverName?: string;
  clock?: () => number;
  resolveKey?: KeyResolver;
  /** Separator between upstream name and tool name in the exposed tool name. */
  separator?: string;
  /**
   * Where an `ApprovalService` is mounted, e.g. `https://ledger.internal/step-ups`.
   * Set, a step-up refusal carries the URL a human can answer it at.
   */
  approvalBaseUrl?: string;
}

export interface ToolCallOutcome {
  /** Present unless the call was refused before any reservation was made. */
  spendId?: string;
  /**
   * `awaiting_approval` is distinct from `denied` on purpose: one is a question
   * a human has not answered yet and the call is worth retrying, the other is a
   * no. Collapsing them teaches an agent to abandon a spend that was about to be
   * approved.
   */
  disposition: 'settled' | 'refunded' | 'denied' | 'held' | 'awaiting_approval';
  code?: ErrorCode;
  detail?: string;
  stepUpHandle?: string;
}

const DEFAULT_SEPARATOR = '__';

interface McpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/** `content` plus MCP's in-band failure flag. */
interface ToolResult {
  isError?: boolean;
  [k: string]: unknown;
}

export class McpMandateGateway {
  private readonly cfg: Required<
    Omit<GatewayConfig, 'taskId' | 'resolveKey'>
  > & { taskId?: string; resolveKey?: KeyResolver };

  private readonly byName = new Map<string, { up: UpstreamConfig; tool: string }>();

  /**
   * Outstanding step-up handles, keyed by resource URI.
   *
   * §10.5 has the agent hold its handle and re-present it. Here the agent is an
   * MCP client that implements nothing — that is the entire premise — so the
   * gateway holds it on the agent's behalf and presents it on the next call for
   * the same tool. Without this, every retry looks like a brand new request and
   * an approval already granted can never be spent.
   *
   * Kept per resource because that is what the ledger binds an approval to, and
   * deliberately in memory: a handle is short-lived and a restarted gateway
   * asking again is a correct, if mildly annoying, outcome.
   */
  private readonly outstanding = new Map<string, string>();

  constructor(config: GatewayConfig) {
    this.cfg = {
      ledger: config.ledger,
      tokens: config.tokens,
      upstreams: config.upstreams,
      isTrustedRootIssuer: config.isTrustedRootIssuer,
      serverName: config.serverName ?? 'am-mandate-gateway',
      clock: config.clock ?? (() => Math.floor(Date.now() / 1000)),
      separator: config.separator ?? DEFAULT_SEPARATOR,
      approvalBaseUrl: (config.approvalBaseUrl ?? '').replace(/\/$/, ''),
      ...(config.taskId !== undefined ? { taskId: config.taskId } : {}),
      ...(config.resolveKey !== undefined ? { resolveKey: config.resolveKey } : {}),
    };

    for (const up of config.upstreams) {
      for (const tool of Object.keys(up.tools)) {
        const exposed = `${up.name}${this.cfg.separator}${tool}`;
        if (this.byName.has(exposed)) {
          throw new Error(`two upstreams both expose ${exposed}`);
        }
        this.byName.set(exposed, { up, tool });
      }
    }
  }

  /** `mcp://<server>/<tool>` — canonicalizes, and `hostOfUri` yields the server. */
  resourceUri(upstream: string, tool: string): string {
    return `mcp://${upstream}/${tool}`;
  }

  /**
   * Would this call be admitted right now, without spending anything?
   *
   * Used to build `tools/list`, so the list a client sees is the mandate
   * rendered rather than the upstream's full menu. An agent cannot misuse a tool
   * it was never shown, and hiding what is not permitted is worth more on a
   * 140-tool session than any number of refusals after the fact.
   *
   * This is a *consumption-free* check: it re-runs §7 verification and the §8
   * coverage rules, which deliberately exclude `max_total` and `rate` because
   * those are ledger state. A tool listed here can still be refused at call time
   * for want of budget, and that is the correct division.
   */
  private async permitted(up: UpstreamConfig, tool: string): Promise<boolean> {
    const policy = up.tools[tool];
    if (policy === undefined) return false;
    const verified = await verifyChain(this.cfg.tokens, {
      now: this.cfg.clock(),
      request: this.requestContext(up, tool, policy),
      // The same ledger the spend would go to, so `tools/list` cannot advertise a
      // tool that `reserve` will refuse on the chain's address.
      ledger: this.cfg.ledger.url,
      isTrustedRootIssuer: this.cfg.isTrustedRootIssuer,
      ...(this.cfg.resolveKey !== undefined ? { resolveKey: this.cfg.resolveKey } : {}),
    });
    return verified.ok;
  }

  private requestContext(up: UpstreamConfig, tool: string, policy: ToolPolicy) {
    return {
      resource: this.resourceUri(up.name, tool),
      amount: policy.price,
      effect: policy.effect,
      ...(this.cfg.taskId !== undefined ? { taskId: this.cfg.taskId } : {}),
    };
  }

  async listTools(): Promise<McpTool[]> {
    const out: McpTool[] = [];

    for (const up of this.cfg.upstreams) {
      const res = await up.server.request('tools/list', {});
      if ('error' in res) continue;
      const tools = ((res.result as { tools?: McpTool[] } | undefined)?.tools ?? []).filter(
        (t): t is McpTool => typeof t?.name === 'string',
      );

      for (const t of tools) {
        const policy = up.tools[t.name];
        if (policy === undefined) continue; // unpriced is unreachable, so unlisted
        if (!(await this.permitted(up, t.name))) continue;

        out.push({
          name: `${up.name}${this.cfg.separator}${t.name}`,
          // Surfaced to the model on purpose: an agent that can see what a call
          // costs and how far it reaches can budget, and the alternative is an
          // agent discovering both by being refused.
          description: `${t.description ?? ''}\n\n[am/1] price ${policy.price.amt} ${policy.price.cur} · effect ${policy.effect}`.trim(),
          ...(t.inputSchema !== undefined ? { inputSchema: t.inputSchema } : {}),
        });
      }
    }
    return out;
  }

  /**
   * The enforcement path: reserve, forward, then settle or refund.
   *
   * ## Why a failed tool does not simply refund
   *
   * MCP reports tool failure two ways — a JSON-RPC error, or a result carrying
   * `isError: true` — and neither means the call had no effect. A `place_order`
   * that returns an error may still have placed the order; an upstream that
   * dies mid-call tells you nothing at all.
   *
   * This is the three-outcome problem the ledger already models for settlement
   * (§12), reappearing one layer up, and it gets the same answer:
   *
   *   - `read` failed → nothing happened. Refund.
   *   - `write` / `irreversible` failed → cannot be shown that nothing happened.
   *     Settle. The allowance is consumed.
   *
   * Refunding a failed irreversible call is how an agent retries a trade it
   * already placed, on budget it should no longer have. Consuming the allowance
   * costs the principal a charge they may not have incurred; the other way costs
   * them a position they never wanted. Only one of those is recoverable by
   * looking at a receipt.
   */
  async callTool(
    exposedName: string,
    args: unknown,
  ): Promise<{ response: JsonRpcResponse; outcome: ToolCallOutcome } | null> {
    const route = this.byName.get(exposedName);
    if (route === undefined) return null;

    const { up, tool } = route;
    const policy = up.tools[tool]!;
    const resource = this.resourceUri(up.name, tool);
    const held = this.outstanding.get(resource);

    const reserved = await this.cfg.ledger.reserve({
      tokens: this.cfg.tokens,
      request: this.requestContext(up, tool, policy),
      ...(held !== undefined ? { stepUpHandle: held } : {}),
    });

    // Remember a handle for the retry; forget it the moment it stops being the
    // live question — either because it was just spent, or because the refusal
    // was about something else entirely.
    if (!reserved.ok && reserved.stepUpHandle !== undefined) {
      this.outstanding.set(resource, reserved.stepUpHandle);
    } else {
      this.outstanding.delete(resource);
    }

    if (!reserved.ok) {
      // A step-up is not a refusal, it is a question — so it is reported as its
      // own disposition and the message tells the model to wait rather than to
      // give up or try something cheaper. `stepUpUrl` is where a human can
      // answer it; the agent is given it so it can say *where* it is stuck,
      // which is the only useful thing it can do next.
      const awaiting = reserved.code === 'step_up_required';
      return {
        response: errorResponse(
          null,
          MANDATE_DENIED,
          awaiting
            ? `${exposedName} needs human approval: ${reserved.detail}`
            : `mandate refused ${exposedName}: ${reserved.detail}`,
          {
            code: reserved.code,
            resource,
            ...(reserved.stepUpHandle !== undefined
              ? {
                  stepUpHandle: reserved.stepUpHandle,
                  ...(this.cfg.approvalBaseUrl !== ''
                    ? {
                        stepUpUrl: `${this.cfg.approvalBaseUrl}/${reserved.stepUpHandle}`,
                      }
                    : {}),
                  retryable: true,
                }
              : {}),
          },
        ),
        outcome: {
          disposition: awaiting ? 'awaiting_approval' : 'denied',
          code: reserved.code,
          detail: reserved.detail,
          ...(reserved.stepUpHandle !== undefined
            ? { stepUpHandle: reserved.stepUpHandle }
            : {}),
        },
      };
    }

    const spendId = reserved.spendId;

    let upstreamResponse: JsonRpcResponse;
    try {
      upstreamResponse = await up.server.request('tools/call', { name: tool, arguments: args });
    } catch (err) {
      // The transport failed. Whether the tool ran is unknowable from here, so
      // the reservation is left standing rather than refunded — the same reason
      // `settle` parks an indeterminate rail result instead of guessing.
      return {
        response: errorResponse(null, INTERNAL_ERROR, `upstream ${up.name} failed`, {
          spendId,
          detail: err instanceof Error ? err.message : String(err),
        }),
        outcome: {
          spendId,
          disposition: 'held',
          detail: 'upstream transport failed; reservation held for reconciliation',
        },
      };
    }

    const failed =
      'error' in upstreamResponse ||
      (upstreamResponse.result as ToolResult | undefined)?.isError === true;

    if (failed && policy.effect === 'read') {
      await this.cfg.ledger.refund(spendId, `tool ${exposedName} failed; read has no effect`);
      return {
        response: upstreamResponse,
        outcome: { spendId, disposition: 'refunded', detail: 'failed read refunded' },
      };
    }

    await this.cfg.ledger.settle(spendId);
    return {
      response: upstreamResponse,
      outcome: {
        spendId,
        disposition: 'settled',
        ...(failed ? { detail: `failed ${policy.effect} call; allowance consumed` } : {}),
      },
    };
  }

  /**
   * Handle one client message.
   *
   * Returns `null` for notifications, which have no reply.
   *
   * Only the `tools` capability is advertised, and unknown methods are refused
   * rather than forwarded. With several upstreams there is no defensible target
   * for a method the gateway does not understand, and picking one silently is
   * worse than saying no.
   */
  async handle(message: JsonRpcMessage): Promise<JsonRpcMessage | null> {
    if (!isRequest(message)) return null;
    const req = message as JsonRpcRequest;

    switch (req.method) {
      case 'initialize': {
        const requested = (req.params as { protocolVersion?: string } | undefined)
          ?.protocolVersion;
        return {
          jsonrpc: '2.0',
          id: req.id,
          result: {
            // Echoed back: the gateway relays whatever the upstreams speak and
            // adds no protocol surface of its own.
            protocolVersion: requested ?? '2025-06-18',
            capabilities: { tools: {} },
            serverInfo: { name: this.cfg.serverName, version: PROTOCOL_VERSION },
          },
        };
      }

      case 'ping':
        return { jsonrpc: '2.0', id: req.id, result: {} };

      case 'tools/list':
        return { jsonrpc: '2.0', id: req.id, result: { tools: await this.listTools() } };

      case 'tools/call': {
        const params = req.params as { name?: unknown; arguments?: unknown } | undefined;
        if (typeof params?.name !== 'string') {
          return errorResponse(req.id, INVALID_PARAMS, 'tools/call requires a string name');
        }
        const called = await this.callTool(params.name, params.arguments);
        if (called === null) {
          return errorResponse(
            req.id,
            METHOD_NOT_FOUND,
            `no such tool ${params.name}`,
          );
        }
        // The upstream's response is returned as-is apart from the id, which is
        // ours to answer. A gateway that rewrote tool output would be editing
        // what the agent sees, and it has no business doing that.
        return { ...called.response, id: req.id };
      }

      default:
        return errorResponse(req.id, METHOD_NOT_FOUND, `unsupported method ${req.method}`);
    }
  }
}
