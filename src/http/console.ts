import { parseCompactJws } from '../jws.js';
import type { BudgetNode, Ledger } from '../ledger/ledger.js';
import type { Reservation } from '../ledger/store.js';
import { CONSOLE_HTML } from './console-page.js';
import { type ApprovalRequest, type ApprovalResponse, toView } from './approval.js';
import { PROBLEM_CONTENT_TYPE, problem } from './problem.js';

/**
 * §5.2 — the principal's console.
 *
 * A control plane whose whole premise is *delegated* authority needs a surface
 * where the delegator can watch and intervene. Until this, the principal was the
 * only party in the protocol with no interface: they could grant authority, and
 * then only find out what had been done with it by reading a database.
 *
 * Framework-agnostic like the merchant and approval surfaces — a parsed request
 * in, a status/headers/body out.
 *
 * ## What is authenticated and what is not
 *
 * **Control actions carry their own authority.** Kill, release and revoke are
 * signed decisions verified against the root node's recorded issuer (§10.6), so
 * reaching this endpoint is not the same as being allowed to use it. That
 * matters more here than anywhere else in the codebase: the most likely thing on
 * the far side of this network is the agent the kill switch exists to stop.
 *
 * **The read side is not authenticated, and must be.** The queue and the feed
 * disclose what an agent is spending, on what, for whom, and the shape of the
 * delegation tree — the org chart, in other words. Put it behind whatever access
 * control the deployment already has. There is nothing this module can do about
 * that which would not be security theatre.
 */

export interface ConsoleConfig {
  ledger: Ledger;
  basePath?: string;
  /** Serve the bundled HTML page at the base path. Off leaves a pure JSON API. */
  servePage?: boolean;
}

const JSON_HEADERS = { 'content-type': 'application/json' };
const HTML_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  // The page holds a spending key in memory. No inline anything it did not
  // ship with, no outbound connections, nothing embeddable in someone else's
  // frame.
  'content-security-policy':
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
};

/** A reservation as the console shows it: money readable, directive summarised. */
export interface SpendView {
  spendId: string;
  status: Reservation['status'];
  amount: { cur: string; amt: string };
  merchant: string;
  resource: string;
  agent: string;
  taskId: string | null;
  path: string[];
  createdAt: number;
  settlingSince?: number;
  rail?: string;
  railRef?: string;
  refundReason?: string;
  escalated?: { at: number; reason: string };
}

export function toSpendView(r: Reservation): SpendView {
  return {
    spendId: r.id,
    status: r.status,
    amount: r.amount,
    merchant: r.merchant,
    resource: r.resource,
    agent: r.agent,
    taskId: r.taskId,
    path: r.path,
    createdAt: r.createdAt,
    ...(r.settlingSince !== undefined ? { settlingSince: r.settlingSince } : {}),
    ...(r.railName !== undefined ? { rail: r.railName } : {}),
    ...(r.railRef !== undefined ? { railRef: r.railRef } : {}),
    ...(r.refundReason !== undefined ? { refundReason: r.refundReason } : {}),
    ...(r.escalated !== undefined ? { escalated: r.escalated } : {}),
  };
}

export interface ConsoleOverview {
  root: string;
  /**
   * The ledger's clock at the moment this was built.
   *
   * Every timestamp below is relative to this, not to the reader's wall clock.
   * The ledger's clock is authoritative (§7 step 7) and a deployment may run it
   * on a skew or, in a simulation, well ahead of real time — a page that
   * subtracted `Date.now()` would render ages that are merely wrong, and in the
   * simulated case visibly negative.
   */
  now: number;
  killed: boolean;
  tree: BudgetNode[];
  spends: SpendView[];
  stepUps: ReturnType<typeof toView>[];
  /** Reservations waiting on a rail, and the age of the oldest. */
  settling: { count: number; oldestSeconds: number | null };
  escalations: SpendView[];
}

/**
 * Routes, relative to `basePath`:
 *
 *   GET  /                      — the page, when `servePage`
 *   GET  /api/overview?root=…   — everything the page renders, in one call
 *   GET  /api/receipt/:spendId  — a receipt minted now for one reservation
 *   POST /api/control           — `{ "decision": "<jws>" }`
 *
 * One overview call rather than five: a console that fires a request per panel
 * renders a tree, a feed and a breaker state from three different instants, and
 * the moment that matters most — someone deciding whether to hit the kill
 * switch — is exactly when those disagreeing is worst.
 */
export class ConsoleService {
  private readonly base: string;

  constructor(private readonly cfg: ConsoleConfig) {
    this.base = (cfg.basePath ?? '').replace(/\/$/, '');
  }

  async overview(root: string, feedLimit = 50): Promise<ConsoleOverview> {
    const [tree, spends, stepUps, settling] = await Promise.all([
      this.cfg.ledger.budgetTree(root),
      this.cfg.ledger.spendFeed(root, feedLimit),
      this.cfg.ledger.pendingStepUps(root),
      this.cfg.ledger.stuckSettlements(),
    ]);

    const mine = settling.filter((r) => r.root === root);
    // The ledger's clock, not this process's: ages shown here have to mean the
    // same thing as the ages the reconciler escalates on.
    const now = this.cfg.ledger.now();

    return {
      root,
      now,
      killed: tree[0]?.killed ?? false,
      tree,
      spends: spends.map(toSpendView),
      stepUps: stepUps.map(toView),
      settling: {
        count: mine.length,
        oldestSeconds:
          mine.length === 0
            ? null
            : Math.max(...mine.map((r) => now - (r.settlingSince ?? r.createdAt))),
      },
      escalations: spends.filter((r) => r.escalated !== undefined).map(toSpendView),
    };
  }

  async handle(req: ApprovalRequest): Promise<ApprovalResponse> {
    const path = req.path.startsWith(this.base) ? req.path.slice(this.base.length) : req.path;
    const rest = path.replace(/^\/+/, '').replace(/\/+$/, '');

    if (req.method === 'GET' && rest === '') {
      if (this.cfg.servePage === false) {
        return { status: 404, headers: JSON_HEADERS, body: { error: 'not found' } };
      }
      return { status: 200, headers: HTML_HEADERS, body: CONSOLE_HTML };
    }

    if (req.method === 'GET' && rest === 'api/overview') {
      const root = req.query?.['root'];
      if (root === undefined || root === '') {
        return {
          status: 400,
          headers: JSON_HEADERS,
          body: { error: 'root is required' },
        };
      }
      return { status: 200, headers: JSON_HEADERS, body: await this.overview(root) };
    }

    if (req.method === 'GET' && rest.startsWith('api/receipt/')) {
      const spendId = rest.slice('api/receipt/'.length);
      const receipt = await this.cfg.ledger.receiptFor(spendId);
      if (receipt === null) {
        return { status: 404, headers: JSON_HEADERS, body: { error: 'not found' } };
      }
      return { status: 200, headers: JSON_HEADERS, body: receipt };
    }

    // Step-up decisions go through the console's own base path rather than
    // straight to `ApprovalService`. The two are separately mountable, and a
    // page that hardcoded the approval prefix would break the moment the console
    // was served from anywhere but the origin root.
    if (rest.startsWith('api/step-up/')) {
      if (req.method !== 'POST') {
        return { status: 405, headers: JSON_HEADERS, body: { error: 'method not allowed' } };
      }
      const handle = decodeURIComponent(rest.slice('api/step-up/'.length));
      const jws = (req.body as { decision?: unknown } | undefined)?.decision;
      if (typeof jws !== 'string' || jws.length === 0) {
        const p = problem('chain_invalid', 'body must be {"decision": "<jws>"}');
        return { status: p.status, headers: { 'content-type': PROBLEM_CONTENT_TYPE }, body: p };
      }
      // Same ordering rule as `ApprovalService`: the path/signature mismatch is
      // caught before the decision is applied, not after.
      const claimed = parseCompactJws(jws)?.payload['handle'];
      if (claimed !== handle) {
        const p = problem(
          'chain_invalid',
          `decision is for ${typeof claimed === 'string' ? claimed : '(none)'}, not ${handle}`,
        );
        return { status: p.status, headers: { 'content-type': PROBLEM_CONTENT_TYPE }, body: p };
      }
      const decided = await this.cfg.ledger.decideStepUp(jws);
      if (!decided.ok) {
        const p = problem(decided.code, decided.detail);
        return { status: p.status, headers: { 'content-type': PROBLEM_CONTENT_TYPE }, body: p };
      }
      return { status: 200, headers: JSON_HEADERS, body: toView(decided.approval) };
    }

    if (rest === 'api/control') {
      if (req.method !== 'POST') {
        return { status: 405, headers: JSON_HEADERS, body: { error: 'method not allowed' } };
      }
      const jws = (req.body as { decision?: unknown } | undefined)?.decision;
      if (typeof jws !== 'string' || jws.length === 0) {
        const p = problem('chain_invalid', 'body must be {"decision": "<jws>"}');
        return { status: p.status, headers: { 'content-type': PROBLEM_CONTENT_TYPE }, body: p };
      }

      const result = await this.cfg.ledger.applyControl(jws);
      if (!result.ok) {
        const p = problem(result.code, result.detail);
        return { status: p.status, headers: { 'content-type': PROBLEM_CONTENT_TYPE }, body: p };
      }
      return { status: 200, headers: JSON_HEADERS, body: result };
    }

    return { status: 404, headers: JSON_HEADERS, body: { error: 'not found' } };
  }
}
