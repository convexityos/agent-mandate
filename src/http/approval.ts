import type { ErrorCode } from '../errors.js';
import { parseCompactJws } from '../jws.js';
import type { Ledger } from '../ledger/ledger.js';
import type { StepUpApproval } from '../ledger/store.js';
import { fromScaled } from '../money.js';
import { PROBLEM_CONTENT_TYPE, type ProblemDetails, problem } from './problem.js';

/**
 * §10.5 — the surface a human uses to say no.
 *
 * Framework-agnostic like the merchant side: it takes a parsed request and
 * returns a status, headers and a body, so it drops into whatever HTTP server a
 * deployment already runs without any of them being able to skip a step.
 *
 * ## This endpoint is not the trust boundary
 *
 * It carries no authentication of its own, and that is deliberate rather than
 * missing. The authority in a decision is the **signature inside it**: a
 * decision is a JWS from the principal, and `Ledger.decideStepUp` verifies it
 * against the chain's trusted root issuer and re-checks the signed terms against
 * the stored request. An attacker who can reach this endpoint can submit
 * decisions; they cannot make one verify.
 *
 * That is what makes it safe to expose to the agent's own network, which
 * matters, because the alternative — a bearer secret — has to live somewhere,
 * and the most convenient somewhere is the environment the agent is running in.
 *
 * The read side is the part to put behind ordinary access control: the queue
 * discloses what an agent is trying to spend, on what, and for whom.
 */

export interface ApprovalRequest {
  method: string;
  /** Path only; the router decides where to mount this. */
  path: string;
  /** Parsed query parameters, if any. */
  query?: Record<string, string | undefined>;
  /** Parsed JSON body, if any. */
  body?: unknown;
  /**
   * Raw headers, as the server received them. Needed by `LedgerService` for
   * `Idempotency-Key` and by any `resolvePresenter` that reads an RFC 9421
   * signature. Case is preserved rather than normalized, because the field names
   * arrive in whatever case the client sent and lookups here are
   * case-insensitive by hand.
   */
  headers?: Record<string, string | string[] | undefined>;
}

export interface ApprovalResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface ApprovalServiceConfig {
  ledger: Ledger;
  /** Prefix the routes are mounted under, e.g. `/step-ups`. */
  basePath?: string;
}

const JSON_HEADERS = { 'content-type': 'application/json' };

function problemResponse(code: ErrorCode, detail: string): ApprovalResponse {
  const p: ProblemDetails = problem(code, detail);
  return { status: p.status, headers: { 'content-type': PROBLEM_CONTENT_TYPE }, body: p };
}

/**
 * The queue as a human should read it.
 *
 * `maxAmountScaled` is a `BigInt` of minor units at scale 9, which is correct
 * for a ledger and unreadable for a person. It is rendered as `Money` here so
 * whatever displays the question shows `240.00 USD` rather than
 * `240000000000` — a step-up that is hard to read is a step-up that gets
 * approved without being read.
 */
export interface StepUpView {
  handle: string;
  root: string;
  resource: string;
  amount: { cur: string; amt: string };
  agent: string;
  taskId: string | null;
  state: StepUpApproval['state'];
  requestedAt: number;
  expiresAt: number;
  decision?: { at: number; by: string; reason?: string };
}

export function toView(a: StepUpApproval): StepUpView {
  return {
    handle: a.handle,
    root: a.root,
    resource: a.resource,
    amount: fromScaled(a.maxAmountScaled, a.currency),
    agent: a.agent,
    taskId: a.taskId,
    state: a.state,
    requestedAt: a.requestedAt,
    expiresAt: a.expiresAt,
    ...(a.decision !== undefined
      ? {
          decision: {
            at: a.decision.at,
            by: a.decision.by,
            ...(a.decision.reason !== undefined ? { reason: a.decision.reason } : {}),
          },
        }
      : {}),
  };
}

/**
 * Three routes, relative to `basePath`:
 *
 *   GET  /            — the pending queue, oldest first; `?root=` to filter
 *   GET  /:handle     — one request, including its decision if it has one
 *   POST /:handle     — submit a signed decision: `{ "decision": "<jws>" }`
 *
 * `POST` carries the whole JWS rather than a verdict field, because the verdict
 * has to be inside the signature. An endpoint that took `{"verdict":"approve"}`
 * alongside a signature would be inviting the two to disagree.
 */
export class ApprovalService {
  private readonly base: string;

  constructor(private readonly cfg: ApprovalServiceConfig) {
    this.base = (cfg.basePath ?? '').replace(/\/$/, '');
  }

  async handle(req: ApprovalRequest): Promise<ApprovalResponse> {
    const path = req.path.startsWith(this.base) ? req.path.slice(this.base.length) : req.path;
    const rest = path.replace(/^\/+/, '').replace(/\/+$/, '');

    if (req.method === 'GET' && rest === '') {
      const root = req.query?.['root'];
      const pending = await this.cfg.ledger.pendingStepUps(root);
      return { status: 200, headers: JSON_HEADERS, body: { stepUps: pending.map(toView) } };
    }

    if (rest === '') {
      return { status: 405, headers: JSON_HEADERS, body: { error: 'method not allowed' } };
    }
    if (rest.includes('/')) {
      return { status: 404, headers: JSON_HEADERS, body: { error: 'not found' } };
    }

    if (req.method === 'GET') {
      const found = await this.cfg.ledger.stepUp(rest);
      if (found === undefined) {
        return { status: 404, headers: JSON_HEADERS, body: { error: 'not found' } };
      }
      return { status: 200, headers: JSON_HEADERS, body: toView(found) };
    }

    if (req.method === 'POST') {
      const jws = (req.body as { decision?: unknown } | undefined)?.decision;
      if (typeof jws !== 'string' || jws.length === 0) {
        return problemResponse('chain_invalid', 'body must be {"decision": "<jws>"}');
      }

      // Checked *before* deciding, not after: the handle in the path is only a
      // routing convenience, but discovering a mismatch after `decideStepUp` has
      // run would mean the state transition already happened and the error is a
      // lie. Read unverified here purely to compare — `decideStepUp` is still
      // what verifies the signature and the terms.
      const claimed = parseCompactJws(jws)?.payload['handle'];
      if (claimed !== rest) {
        return problemResponse(
          'chain_invalid',
          `decision is for ${typeof claimed === 'string' ? claimed : '(none)'}, not ${rest}`,
        );
      }

      const result = await this.cfg.ledger.decideStepUp(jws);
      if (!result.ok) return problemResponse(result.code, result.detail);

      return { status: 200, headers: JSON_HEADERS, body: toView(result.approval) };
    }

    return { status: 405, headers: JSON_HEADERS, body: { error: 'method not allowed' } };
  }
}
