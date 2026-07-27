import type { ErrorCode } from '../errors.js';
import type { Ledger, ReserveResult, SettleResult } from '../ledger/ledger.js';
import type { Money } from '../money.js';
import type { RequestContext } from '../types.js';
import type { ApprovalRequest, ApprovalResponse } from './approval.js';
import { PROBLEM_CONTENT_TYPE, problem } from './problem.js';

/**
 * §1.2 — the ledger as a service.
 *
 * An HTTP surface over the objects that already exist: §8 presentation, §9 mint,
 * settle, refund, report, receipt read, and the §10.6 control door. The protocol
 * work was done; what this adds is the part that gets written last and matters
 * most at three in the morning.
 *
 * ## Idempotency is not a feature of this file
 *
 * `Idempotency-Key` is passed straight through to `Ledger.reserve`, which
 * claims it **inside the same transaction as the debit**. That placement is the
 * whole point. A service that claimed the key, called the ledger, and then
 * recorded the response would have three failure windows: crash before the call
 * and the key is stranded, crash after and the retry debits twice, and two
 * concurrent first uses race unless the claim itself is atomic.
 *
 * Which is the same dual-write problem this ledger already solved once for
 * settlement, and it gets the same answer: put both halves in one transaction.
 *
 * ## What this deliberately does not do
 *
 * **It does not authenticate the presenter.** §7 step 9 binds a chain to the key
 * that presents it, and the binding check needs a thumbprint the transport has
 * already verified — RFC 9421 in [`signature.ts`](./signature.ts), or whatever a
 * deployment's proxy terminates. So `presenterJkt` is an input here, supplied by
 * `resolvePresenter`. A deployment that does not wire one has proof-of-
 * possession disabled, and `requirePresenter` exists so that has to be chosen
 * rather than defaulted into.
 */

export interface LedgerServiceConfig {
  ledger: Ledger;
  basePath?: string;
  /**
   * Resolve the verified key thumbprint of whoever sent this request — from an
   * RFC 9421 signature, or a header a trusted proxy set. Returning null means
   * unauthenticated.
   */
  resolvePresenter?: (req: ApprovalRequest) => Promise<string | null> | string | null;
  /**
   * Refuse a mint that arrives without a verified presenter. Defaults to true,
   * because §7 step 9 exists and a chain nobody proved they hold is a chain
   * anyone who copied it can spend.
   */
  requirePresenter?: boolean;
  /** Refuse a mint with no `Idempotency-Key`. Defaults to true. */
  requireIdempotencyKey?: boolean;
}

const JSON_HEADERS = { 'content-type': 'application/json' };

function fail(code: ErrorCode, detail: string, extra: Record<string, unknown> = {}): ApprovalResponse {
  const p = problem(code, detail, extra);
  return { status: p.status, headers: { 'content-type': PROBLEM_CONTENT_TYPE }, body: p };
}

const bad = (status: number, error: string): ApprovalResponse => ({
  status,
  headers: JSON_HEADERS,
  body: { error },
});

/** What a mint request carries. Mirrors `ReserveRequest` minus what the transport supplies. */
export interface MintBody {
  tokens?: unknown;
  request?: unknown;
  stepUpHandle?: unknown;
  quote?: unknown;
}

function isMoney(v: unknown): v is Money {
  return (
    typeof v === 'object' &&
    v !== null &&
    typeof (v as Money).cur === 'string' &&
    typeof (v as Money).amt === 'string'
  );
}

/**
 * Routes, relative to `basePath`:
 *
 *   POST /v1/mint                — §8 presentation → §9 mint. Idempotency-Key.
 *   POST /v1/spends/:id/settle
 *   POST /v1/spends/:id/refund   — `{ "reason": "..." }`
 *   POST /v1/spends/:id/report   — §12.4.6, `{ "proof": ... }`
 *   GET  /v1/spends/:id
 *   GET  /v1/spends/:id/receipt
 *   POST /v1/control             — §10.6, `{ "decision": "<jws>" }`
 *   GET  /healthz
 *   GET  /metrics
 */
export class LedgerService {
  private readonly base: string;

  constructor(private readonly cfg: LedgerServiceConfig) {
    this.base = (cfg.basePath ?? '').replace(/\/$/, '');
  }

  async handle(req: ApprovalRequest): Promise<ApprovalResponse> {
    const path = req.path.startsWith(this.base) ? req.path.slice(this.base.length) : req.path;
    const rest = path.replace(/^\/+/, '').replace(/\/+$/, '');

    if (rest === 'healthz') return this.health();
    if (rest === 'metrics') return this.metrics();
    if (rest === 'v1/mint') return this.mint(req);
    if (rest === 'v1/control') return this.control(req);

    const spend = /^v1\/spends\/([^/]+)(?:\/(settle|refund|report|receipt))?$/.exec(rest);
    if (spend !== null) return this.spend(req, spend[1]!, spend[2]);

    return bad(404, 'not found');
  }

  // ------------------------------------------------------------------ mint

  private async mint(req: ApprovalRequest): Promise<ApprovalResponse> {
    if (req.method !== 'POST') return bad(405, 'method not allowed');

    const body = (req.body ?? {}) as MintBody;
    if (!Array.isArray(body.tokens) || body.tokens.some((t) => typeof t !== 'string')) {
      return fail('chain_invalid', 'tokens must be an array of compact JWS strings');
    }
    const ctx = body.request as RequestContext | undefined;
    if (typeof ctx?.resource !== 'string' || !isMoney(ctx.amount)) {
      return fail('chain_invalid', 'request must carry a resource and an amount');
    }

    const key = header(req, 'idempotency-key');
    if (key === null && this.cfg.requireIdempotencyKey !== false) {
      // Refused rather than defaulted to a random key. A key the *server* made
      // up is not idempotency — the whole mechanism depends on the client
      // sending the same one on the retry.
      return fail('chain_invalid', 'Idempotency-Key is required on mint');
    }

    const presenter = (await this.cfg.resolvePresenter?.(req)) ?? null;
    if (presenter === null && this.cfg.requirePresenter !== false) {
      return fail('pop_failed', 'no verified presenter key on this request');
    }

    const result: ReserveResult = await this.cfg.ledger.reserve({
      tokens: body.tokens as string[],
      request: ctx,
      ...(presenter !== null ? { presenterJkt: presenter } : {}),
      ...(typeof body.stepUpHandle === 'string' ? { stepUpHandle: body.stepUpHandle } : {}),
      ...(body.quote !== undefined ? { quote: body.quote as never } : {}),
      ...(key !== null ? { idempotencyKey: key } : {}),
    });

    if (!result.ok) {
      return fail(result.code, result.detail, {
        ...(result.stepUpHandle !== undefined ? { stepUpHandle: result.stepUpHandle } : {}),
        ...(result.alerts !== undefined ? { alerts: result.alerts } : {}),
      });
    }
    return { status: 201, headers: JSON_HEADERS, body: result };
  }

  // ----------------------------------------------------------------- spend

  private async spend(
    req: ApprovalRequest,
    spendId: string,
    action: string | undefined,
  ): Promise<ApprovalResponse> {
    if (action === undefined || action === 'receipt') {
      if (req.method !== 'GET') return bad(405, 'method not allowed');
      if (action === 'receipt') {
        const receipt = await this.cfg.ledger.receiptFor(spendId);
        return receipt === null
          ? bad(404, 'not found')
          : { status: 200, headers: JSON_HEADERS, body: receipt };
      }
      const reservation = await this.cfg.ledger.reservation(spendId);
      return reservation === undefined
        ? bad(404, 'not found')
        : { status: 200, headers: JSON_HEADERS, body: reservation };
    }

    if (req.method !== 'POST') return bad(405, 'method not allowed');
    const body = (req.body ?? {}) as Record<string, unknown>;

    let result: SettleResult;
    if (action === 'settle') {
      result = await this.cfg.ledger.settle(spendId, body as never);
    } else if (action === 'refund') {
      const reason = typeof body['reason'] === 'string' ? body['reason'] : 'refund requested';
      result = await this.cfg.ledger.refund(spendId, reason);
    } else {
      result = await this.cfg.ledger.report(spendId, body['proof']);
    }

    return result.ok
      ? { status: 200, headers: JSON_HEADERS, body: result }
      : fail(result.code, result.detail);
  }

  // --------------------------------------------------------------- control

  private async control(req: ApprovalRequest): Promise<ApprovalResponse> {
    if (req.method !== 'POST') return bad(405, 'method not allowed');
    const jws = (req.body as { decision?: unknown } | undefined)?.decision;
    if (typeof jws !== 'string' || jws.length === 0) {
      return fail('chain_invalid', 'body must be {"decision": "<jws>"}');
    }
    const result = await this.cfg.ledger.applyControl(jws);
    return result.ok
      ? { status: 200, headers: JSON_HEADERS, body: result }
      : fail(result.code, result.detail);
  }

  // ------------------------------------------------------- health, metrics

  private async health(): Promise<ApprovalResponse> {
    // Deliberately shallow: liveness, not readiness. A health check that walks
    // the database turns a slow query into a restart loop.
    return { status: 200, headers: JSON_HEADERS, body: { ok: true, now: this.cfg.ledger.now() } };
  }

  /**
   * The number to page on is `settling_outstanding`.
   *
   * A reservation in `settling` is money that is neither spent nor available,
   * and the count trending upward means a rail has stopped answering. Everything
   * else here is context for that one line.
   */
  private async metrics(): Promise<ApprovalResponse> {
    const now = this.cfg.ledger.now();
    const settling = await this.cfg.ledger.stuckSettlements();
    const escalated = settling.filter((r) => r.escalated !== undefined).length;
    const oldest = settling.reduce(
      (max, r) => Math.max(max, now - (r.settlingSince ?? r.createdAt)),
      0,
    );
    const pending = await this.cfg.ledger.pendingStepUps();

    const lines = [
      '# HELP am_settling_outstanding Reservations awaiting a rail answer.',
      '# TYPE am_settling_outstanding gauge',
      `am_settling_outstanding ${settling.length}`,
      '# HELP am_settling_oldest_seconds Age of the oldest outstanding settlement.',
      '# TYPE am_settling_oldest_seconds gauge',
      `am_settling_oldest_seconds ${settling.length === 0 ? 0 : oldest}`,
      '# HELP am_settling_escalated Outstanding settlements a human has been told about.',
      '# TYPE am_settling_escalated gauge',
      `am_settling_escalated ${escalated}`,
      '# HELP am_stepups_pending Step-up requests waiting on a human.',
      '# TYPE am_stepups_pending gauge',
      `am_stepups_pending ${pending.length}`,
    ];
    return {
      status: 200,
      headers: { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' },
      body: `${lines.join('\n')}\n`,
    };
  }
}

/** Case-insensitive, because HTTP field names are and they arrive in every case. */
function header(req: ApprovalRequest, name: string): string | null {
  const headers = (req as { headers?: Record<string, string | string[] | undefined> }).headers;
  if (headers === undefined) return null;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== name) continue;
    const value = Array.isArray(v) ? v[0] : v;
    return value === undefined || value === '' ? null : value;
  }
  return null;
}
