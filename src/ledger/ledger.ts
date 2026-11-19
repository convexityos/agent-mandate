import { createHash, randomUUID, sign as cryptoSign } from 'node:crypto';

import { encodeSegment } from '../jws.js';

import { type ControlAction, verifyControlDecision } from '../control.js';
import type { Caveats } from '../caveats.js';
import type { ErrorCode } from '../errors.js';
import { parseDuration } from '../duration.js';
import { type Money, fromScaled, toScaled } from '../money.js';
import { isQuoteHash } from '../quote.js';
import { type Receipt, type ReceiptClaims, signReceipt } from '../receipt.js';
import { type AgentKey } from '../sign.js';
import {
  DEFAULT_SPEND_TTL_SECONDS,
  type SpendClaims,
  mintSpendToken,
} from '../spend.js';
import {
  type StepUpDecisionClaims,
  decisionMatches,
  verifyStepUpDecision,
} from '../stepup.js';
import { DEFAULT_STATUS_TTL_SECONDS, buildStatusList, signStatusList } from '../status.js';
import { PROTOCOL_VERSION, type RequestContext } from '../types.js';
import { canonicalizeUri, hostOfUri } from '../uri.js';
import { NO_REQUEST, type KeyResolver, verifyChain } from '../verify.js';
import {
  type BreakerConfig,
  type BreakerVerdict,
  DEFAULT_BREAKERS,
  evaluateBreakers,
} from './breakers.js';
import type { SettlementRail } from '../rail/rail.js';
import {
  type Directive,
  type NonCustodialRail,
  intentHash,
} from '../rail/noncustodial.js';
import type {
  LedgerStore,
  LedgerTx,
  MandateNode,
  Reservation,
  StepUpApproval,
} from './store.js';

/**
 * §10.5 — what a human is told when a spend needs them.
 *
 * Everything a decision turns on, so a notifier can render the question without
 * a second round trip to the ledger. A human approving `stp_9f3c` and a human
 * approving "$240 to api.vendor.example for task tsk_01" are not doing the same
 * thing, and only the second one is consent.
 */
export interface StepUpRequestNotice {
  handle: string;
  root: string;
  resource: string;
  amount: Money;
  agent: string;
  taskId: string | null;
  requestedAt: number;
  expiresAt: number;
}

/**
 * The other end of `step_up_required`.
 *
 * Notification only — deciding happens through `decideStepUp`, which takes a
 * signature. An `Approver` that could itself approve would put the decision back
 * inside the ledger's own trust boundary, which is the thing §10.5 is trying to
 * get it out of.
 */
export interface Approver {
  requested(notice: StepUpRequestNotice): void | Promise<void>;
}

/**
 * One thing that happened, flat enough to be a log line.
 *
 * Keyed by `spendId` wherever there is one, because the question asked during an
 * incident is always about a particular spend: what was authorized, when did it
 * change state, and who decided. A log that records only what the service
 * returned cannot answer that — the transitions that matter most are the ones a
 * reconciler makes at 3am with nobody's request to attribute them to.
 */
export interface AuditEvent {
  at: number;
  /** Dotted and stable: `reserve.ok`, `settle.settled`, `stepup.decided`. */
  event: string;
  spendId?: string;
  root?: string;
  agent?: string;
  amount?: Money;
  resource?: string;
  taskId?: string | null;
  /** The §15 code, on anything that refused. */
  code?: ErrorCode;
  detail?: string;
  [extra: string]: unknown;
}

/**
 * Where audit events go. Synchronous-looking on purpose: a sink that blocks the
 * ledger is worse than a sink that drops, so implementations should buffer.
 * Exceptions are swallowed — see `emit`.
 */
export interface AuditSink {
  record(event: AuditEvent): void | Promise<void>;
}

export type StepUpDecisionResult =
  | { ok: true; approval: StepUpApproval; claims: StepUpDecisionClaims }
  | { ok: false; code: ErrorCode; detail: string };

export type ControlResult =
  | { ok: true; action: ControlAction; root: string; target?: string }
  | { ok: false; code: ErrorCode; detail: string };

/** One node of the console's budget tree, in money rather than scaled integers. */
export interface BudgetNode {
  jti: string;
  parent: string | null;
  issuer: string;
  /** null where the link declares no budget of its own. */
  budget: Money | null;
  spent: Money;
  remaining: Money | null;
  rate: import('../caveats.js').Rate | null;
  revoked: boolean;
  exp: number;
  /** Whether the whole subtree is halted. Same value on every node. */
  killed: boolean;
}

export interface LedgerConfig {
  /** Public base URL; becomes the `iss` of every spend token. */
  url: string;
  key: AgentKey;
  store: LedgerStore;
  isTrustedRootIssuer: (iss: string) => boolean;
  /**
   * Where money actually moves. Omitted, the ledger keeps books and settles
   * nothing — a legitimate development posture, and the reason this is optional
   * rather than required.
   */
  rail?: SettlementRail;
  /**
   * §12.4 — non-custodial settlement. Mutually exclusive with `rail`: either the
   * Ledger pays, or it authorizes the agent to. Configuring both is a
   * contradiction about who holds the money, so the constructor rejects it.
   */
  nonCustodialRail?: NonCustodialRail;
  breakers?: Partial<BreakerConfig>;
  spendTtlSeconds?: number;
  /** Grace period after a spend token expires before an unsettled reservation is swept. */
  reservationGraceSeconds?: number;
  /**
   * How long a §9 idempotency key is remembered.
   *
   * Long enough to outlast any client's retry budget, and short enough that the
   * recorded spend token has not long expired by the time a replay returns it.
   */
  idempotencyTtlSeconds?: number;
  /**
   * §10.5 — notified when a spend needs a human. Absent, step-ups still queue
   * and are still visible through `pendingStepUps`; nobody is told.
   */
  approver?: Approver;
  /** Structured audit log. Absent, transitions happen and nothing records them. */
  audit?: AuditSink;
  /** How long a step-up request waits for a human before it lapses. */
  stepUpRequestTtlSeconds?: number;
  /**
   * How long an *approved* step-up stays spendable, measured from the decision
   * rather than the request. A human who approves at the 59th minute of a
   * one-hour request should not hand the agent a one-minute window.
   */
  stepUpApprovalTtlSeconds?: number;
  clock?: () => number;
  idFactory?: (prefix: string) => string;
  resolveKey?: KeyResolver;
}

export interface ReserveRequest {
  tokens: string[];
  request: RequestContext;
  presenterJkt?: string;
  /** Returned by a previous `step_up_required`, after a human approved it. */
  stepUpHandle?: string;
  /**
   * From the merchant's 402 challenge (§14.1). `schema` is what escrow releases
   * against; `rail` is the rail-specific quote the agent received, which the
   * non-custodial path pins into a directive without ever contacting the
   * merchant itself.
   */
  quote?: { quoteId?: string; quoteHash?: string; schema?: string; rail?: unknown };
  /**
   * §9 — makes this mint replay-safe.
   *
   * A caller that retries because a response was slow must not be debited
   * twice. Supply a key that is stable across retries of the *same* mint and
   * different for a genuinely new one; the same key with a different request is
   * refused rather than answered with the earlier result.
   */
  idempotencyKey?: string;
}

export type ReserveResult =
  | {
      ok: true;
      spendId: string;
      token: string;
      expiresAt: number;
      effective: Caveats;
      alerts: BreakerVerdict[];
      /** §12.4 — present when a non-custodial rail is configured. */
      directive?: Directive;
      /** The same directive, ledger-signed, for the agent to keep as evidence. */
      directiveJws?: string;
    }
  | {
      ok: false;
      code: ErrorCode;
      detail: string;
      stepUpHandle?: string;
      alerts?: BreakerVerdict[];
    };

export interface SettleInput {
  respHash?: string;
  respBytes?: number;
  merchantSig?: string;
  /** For `escrow_schema`: did the response validate against the declared schema? */
  schemaValid?: boolean;
  /** For `escrow_human`: has the principal approved release? */
  humanApproved?: boolean;
}

export type SettleResult =
  | { ok: true; status: 'settled' | 'refunded' | 'reserved'; receipt: Receipt }
  | { ok: false; code: ErrorCode; detail: string };

const sha256 = (s: string) => `sha256:${createHash('sha256').update(s, 'ascii').digest('hex')}`;

/**
 * UTF-8, unlike `sha256` above.
 *
 * That one hashes JWS tokens, which are base64url and therefore ASCII by
 * construction, so the encoding cannot matter. This one hashes a JSON request
 * that may contain anything — and Node's `'ascii'` is latin1-equivalent on
 * encode, truncating code points above U+00FF modulo 256. `Ł` (U+0141) becomes
 * byte 0x41, which is `A`: a request for `/Łedger` and one for `/Aedger` hash
 * identically, and the second caller is handed the first one's reservation.
 */
const sha256Utf8 = (s: string) =>
  `sha256:${createHash('sha256').update(s, 'utf8').digest('hex')}`;

/**
 * A link's node, created on first presentation (§10.1).
 *
 * Shared by `reserve` and `register` so the two cannot drift: a mandate that was
 * registered first and spent later must produce exactly the node a mandate that
 * went straight to a spend would, or the second presentation trips the
 * token-hash binding check against a node the ledger itself wrote differently.
 *
 * The revocation seed is the part worth reading twice. `revoked` used to be a
 * literal `false` here, which meant a mandate the principal had already revoked
 * came into existence unrevoked — because a revocation before a mandate's first
 * spend had nowhere to live, and was refused. See `LedgerTx.putRevocation`.
 */
async function materialize(
  tx: LedgerTx,
  link: import('../types.js').MandateClaims,
  parent: string | null,
  root: string,
  tokenHash: string,
): Promise<MandateNode> {
  const budget = link.cav.max_total;
  return {
    jti: link.jti,
    parent,
    root,
    // Who granted this link. On the root that is the principal, and it is what
    // §10.6 checks a control decision against — `isTrustedRootIssuer` only says
    // a DID is *a* principal this deployment trusts.
    issuer: link.iss,
    tokenHash,
    budgetScaled: budget === undefined ? null : toScaled(budget),
    currency: budget?.cur ?? link.cav.currency ?? null,
    spentScaled: 0n,
    rate: link.cav.rate ?? null,
    rateEvents: [],
    revoked: await tx.isRevoked(root, link.jti),
    statusIdx: link.st ?? null,
    exp: link.exp,
  };
}

export const DIRECTIVE_TYP = 'application/agent-directive+jwt';

/** Ledger-signed directive, so the agent holds evidence of what it was told to do. */
export function signDirective(directive: Directive, key: AgentKey): string {
  const header = { alg: 'EdDSA', typ: DIRECTIVE_TYP, kid: `${directive.iss}#ledger` };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(directive)}`;
  return `${signingInput}.${cryptoSign(null, Buffer.from(signingInput, 'ascii'), key.privateKey).toString('base64url')}`;
}

export class Ledger {
  private readonly cfg: Required<
    Omit<
      LedgerConfig,
      'breakers' | 'resolveKey' | 'rail' | 'nonCustodialRail' | 'approver' | 'audit'
    >
  > & {
    breakers: BreakerConfig;
    resolveKey?: KeyResolver;
    rail?: SettlementRail;
    nonCustodialRail?: NonCustodialRail;
    approver?: Approver;
    audit?: AuditSink;
  };

  constructor(config: LedgerConfig) {
    if (config.rail !== undefined && config.nonCustodialRail !== undefined) {
      throw new Error(
        'configure `rail` or `nonCustodialRail`, not both: they disagree about who holds the funds',
      );
    }
    this.cfg = {
      url: config.url,
      key: config.key,
      store: config.store,
      isTrustedRootIssuer: config.isTrustedRootIssuer,
      breakers: { ...DEFAULT_BREAKERS, ...config.breakers },
      spendTtlSeconds: config.spendTtlSeconds ?? DEFAULT_SPEND_TTL_SECONDS,
      reservationGraceSeconds: config.reservationGraceSeconds ?? 300,
      idempotencyTtlSeconds: config.idempotencyTtlSeconds ?? 86400,
      stepUpRequestTtlSeconds: config.stepUpRequestTtlSeconds ?? 3600,
      stepUpApprovalTtlSeconds: config.stepUpApprovalTtlSeconds ?? 900,
      clock: config.clock ?? (() => Math.floor(Date.now() / 1000)),
      idFactory: config.idFactory ?? ((p) => `${p}_${randomUUID().replace(/-/g, '')}`),
      ...(config.resolveKey !== undefined ? { resolveKey: config.resolveKey } : {}),
      ...(config.approver !== undefined ? { approver: config.approver } : {}),
      ...(config.audit !== undefined ? { audit: config.audit } : {}),
      ...(config.rail !== undefined ? { rail: config.rail } : {}),
      ...(config.nonCustodialRail !== undefined
        ? { nonCustodialRail: config.nonCustodialRail }
        : {}),
    };
  }

  /**
   * This ledger's base URL — the one a chain must name to be spendable here
   * (§7 step 3). Public so an enforcement layer in front of the ledger can hold
   * a chain to the same rule the ledger will.
   */
  get url(): string {
    return this.cfg.url;
  }

  /**
   * Spec §10.1 — verify the chain, then debit consumption along the whole
   * ancestor path in one critical section, then mint the spend token.
   *
   * Verification is async and therefore interleavable, which is why everything
   * from the balance check to the debit sits inside `transact`. What makes that
   * safe is the store's serialization, not an absence of `await`: the closure
   * awaits the store throughout, and awaiting anything *else* in here — a rail,
   * a fetch, a timer — holds the critical section open across it and is the one
   * thing this shape must not grow.
   */
  async reserve(req: ReserveRequest): Promise<ReserveResult> {
    const now = this.cfg.clock();

    const verified = await verifyChain(req.tokens, {
      now,
      request: req.request,
      // §7 step 3: a chain addressed to another ledger is refused on its address,
      // before anything here reads its contents.
      ledger: this.cfg.url,
      isTrustedRootIssuer: this.cfg.isTrustedRootIssuer,
      ...(this.cfg.resolveKey !== undefined ? { resolveKey: this.cfg.resolveKey } : {}),
      ...(req.presenterJkt !== undefined ? { presenterJkt: req.presenterJkt } : {}),
    });
    if (!verified.ok) {
      // Audited even though it never reached the ledger's state. A refusal at
      // §7 is the *most* common one — a request outside the grant — and a log
      // that only records what got as far as a transaction cannot answer "what
      // did this agent try?", which is the question an incident actually asks.
      this.emit('reserve.rejected', {
        amount: req.request.amount,
        resource: req.request.resource,
        taskId: req.request.taskId ?? null,
        code: verified.code,
        detail: verified.detail,
      });
      return { ok: false, code: verified.code, detail: verified.detail };
    }

    const uri = canonicalizeUri(req.request.resource);
    const host = uri === null ? null : hostOfUri(uri);
    if (uri === null || host === null) {
      this.emit('reserve.rejected', {
        agent: verified.leaf.sub,
        amount: req.request.amount,
        resource: req.request.resource,
        code: 'resource_not_covered',
        detail: 'uncanonicalizable resource',
      });
      return { ok: false, code: 'resource_not_covered', detail: 'uncanonicalizable resource' };
    }

    if (req.quote?.quoteHash !== undefined && !isQuoteHash(req.quote.quoteHash)) {
      this.emit('reserve.rejected', {
        agent: verified.leaf.sub,
        amount: req.request.amount,
        resource: req.request.resource,
        code: 'chain_invalid',
        detail: 'malformed quoteHash',
      });
      return { ok: false, code: 'chain_invalid', detail: 'malformed quoteHash' };
    }

    const amountScaled = toScaled(req.request.amount);
    const currency = req.request.amount.cur;
    const taskId = req.request.taskId ?? null;
    const { links, path, effective, chainHash } = verified;
    const root = path[0]!;

    // The id is minted before the critical section because a non-custodial
    // directive's idempotency key is derived from it, and the intent has to be
    // pinned before there is anything to debit against. Burning an id on a
    // rejected reserve costs nothing.
    const spendId = this.cfg.idFactory('spn');

    const nc = this.cfg.nonCustodialRail;
    let prepared: Directive | null = null;

    if (nc !== undefined) {
      if (effective.payer !== undefined && effective.payer !== nc.payer) {
        return {
          ok: false,
          code: 'attenuation_violation',
          detail: `mandate pins payer ${effective.payer}, this ledger settles from ${nc.payer}`,
        };
      }

      const draft: Reservation = {
        id: spendId,
        path,
        root,
        agent: verified.leaf.sub,
        taskId,
        merchant: host,
        resource: uri,
        amount: req.request.amount,
        amountScaled,
        settle: effective.settle ?? 'immediate',
        schema: req.quote?.schema ?? null,
        ...(req.quote?.quoteId !== undefined ? { quoteId: req.quote.quoteId } : {}),
        ...(req.quote?.quoteHash !== undefined ? { quoteHash: req.quote.quoteHash } : {}),
        chainHash,
        status: 'reserved',
        createdAt: now,
        expiresAt: now + this.cfg.spendTtlSeconds,
      };

      const result = await nc.prepare(draft, req.quote?.rail);
      if (!result.ok) {
        return {
          ok: false,
          code: result.terminal ? 'chain_invalid' : 'breaker_tripped',
          detail: `directive could not be prepared: ${result.detail}`,
        };
      }
      prepared = {
        v: PROTOCOL_VERSION,
        typ: 'directive',
        jti: spendId,
        iss: this.cfg.url,
        sub: verified.leaf.sub,
        chainHash,
        rail: nc.name,
        intentHash: intentHash(result.prepared.intent),
        iat: now,
        cnf: { jkt: verified.leaf.cnf.jkt },
        ...result.prepared,
      };
    }

    // Set inside the critical section when a step-up is newly queued, sent once
    // the transaction has committed. A notification about a spend that rolled
    // back is worse than no notification: it trains a human to ignore them.
    let pendingNotice: StepUpRequestNotice | null = null;

    // §9 — the request this key is bound to. The chain, the exact request and
    // the quote, so a key reused for anything else is caught rather than
    // answered with the wrong reservation.
    const requestHash =
      req.idempotencyKey === undefined
        ? null
        : sha256Utf8(
            JSON.stringify([
              req.tokens,
              req.request,
              req.quote ?? null,
              req.stepUpHandle ?? null,
            ]),
          );

    const result = await this.cfg.store.transact(async (tx): Promise<ReserveResult> => {
      pendingNotice = null; // this closure may be retried; only the last run committed

      // --- idempotency (§9) ---
      //
      // Inside the transaction, deliberately. Claiming the key in one
      // transaction and debiting in another is the dual-write problem this
      // ledger already solved once for settlement: a crash between them either
      // strands the key, so the caller can never learn what happened, or leaves
      // it unclaimed, so the retry debits a second time.
      //
      // The store locks the key on read even when no row exists yet, so two
      // concurrent first uses serialize here rather than both proceeding.
      if (req.idempotencyKey !== undefined) {
        const seen = await tx.getIdempotent(req.idempotencyKey);
        if (seen !== undefined) {
          if (seen.requestHash !== requestHash) {
            return {
              ok: false,
              code: 'chain_invalid',
              detail: `idempotency key ${req.idempotencyKey} was already used for a different request`,
            };
          }
          return seen.response as ReserveResult;
        }
      }

      // Wrapped so every exit from the decision below is recorded under the key
      // by the single write at the bottom, rather than each of the dozen
      // `return`s having to remember to do it.
      const outcome: ReserveResult = await (async (): Promise<ReserveResult> => {
      // --- materialize, verifying that each jti still means what it meant ---
      //
      // One `lockPath` rather than a `getNode` per link: the lock ordering the
      // store depends on is then a property of the store, not of the direction
      // this loop happens to run in.
      const locked = await tx.lockPath(path);
      const nodes: MandateNode[] = [];
      for (let i = 0; i < links.length; i++) {
        const l = links[i]!;
        const tokenHash = sha256(req.tokens[i]!);
        const existing = locked[i];
        if (existing !== undefined) {
          // A jti is the key for consumption state. Letting the same jti carry
          // different caveats on a later presentation would reset the budget.
          if (existing.tokenHash !== tokenHash) {
            return {
              ok: false,
              code: 'chain_invalid',
              detail: `jti ${l.jti} already recorded with different content`,
            };
          }
          nodes.push(existing);
          continue;
        }
        nodes.push(await materialize(tx, l, i === 0 ? null : links[i - 1]!.jti, root, tokenHash));
      }

      // --- revocation: any revoked ancestor kills the whole subtree (§10.3) ---
      for (const n of nodes) {
        if (n.revoked) {
          return { ok: false, code: 'mandate_revoked', detail: `mandate ${n.jti} is revoked` };
        }
      }

      // --- currency ---
      for (const n of nodes) {
        if (n.currency !== null && n.currency !== currency) {
          return {
            ok: false,
            code: 'currency_mismatch',
            detail: `mandate ${n.jti} is denominated in ${n.currency}, request is ${currency}`,
          };
        }
      }

      // --- budget: every ancestor must independently afford it (§10.1) ---
      let bindingRemaining: bigint | null = null;
      for (const n of nodes) {
        if (n.budgetScaled === null) continue;
        const remaining = n.budgetScaled - n.spentScaled;
        if (remaining < amountScaled) {
          return {
            ok: false,
            code: 'budget_exhausted',
            detail: `mandate ${n.jti} has ${fromScaled(remaining, currency).amt} remaining`,
          };
        }
        bindingRemaining =
          bindingRemaining === null || remaining < bindingRemaining ? remaining : bindingRemaining;
      }

      // --- rate: every ancestor's window evaluated independently (§10.2) ---
      for (const n of nodes) {
        if (n.rate === null) continue;
        const windowSeconds = parseDuration(n.rate.per);
        if (windowSeconds === null) {
          return { ok: false, code: 'chain_invalid', detail: `bad rate window on ${n.jti}` };
        }
        const since = now - windowSeconds;
        const recent = n.rateEvents.filter((t) => t >= since);
        if (recent.length + 1 > n.rate.n) {
          return {
            ok: false,
            code: 'rate_exceeded',
            detail: `mandate ${n.jti} at ${recent.length}/${n.rate.n} per ${n.rate.per}`,
          };
        }
      }

      // --- step-up (§10.5) ---
      //
      // The handle is not the approval. The Ledger hands the handle to the agent
      // in the `step_up_required` response, so treating possession of it as
      // consent means the agent approves its own spend — which is what this used
      // to do. Only `state: 'approved'`, set by `decideStepUp` against a
      // signature from the principal, admits a spend.
      const stepUp = effective.step_up;
      if (stepUp !== undefined && amountScaled > toScaled(stepUp.over)) {
        const presented =
          req.stepUpHandle === undefined ? undefined : await tx.getStepUp(req.stepUpHandle);

        const onPoint =
          presented !== undefined &&
          presented.root === root &&
          presented.resource === uri &&
          presented.currency === currency &&
          presented.expiresAt >= now &&
          amountScaled <= presented.maxAmountScaled;

        if (onPoint && presented.state === 'approved' && !presented.used) {
          await tx.putStepUp({ ...presented, used: true });
        } else if (onPoint && presented.state === 'pending') {
          // Still waiting on a human. Hand back the *same* handle rather than
          // minting another: §10.5 has the agent polling, and a fresh request
          // per poll would bury the human in duplicates of one question.
          return {
            ok: false,
            code: 'step_up_required',
            detail: 'awaiting approval',
            stepUpHandle: presented.handle,
          };
        } else if (onPoint && presented.state === 'denied') {
          return {
            ok: false,
            code: 'step_up_required',
            detail: `denied${presented.decision?.reason !== undefined ? `: ${presented.decision.reason}` : ''}`,
            stepUpHandle: presented.handle,
          };
        } else {
          // No usable handle. Reuse an open request for the same terms if one is
          // already queued, for the same reason — an agent that retries without
          // its handle should not enqueue the question twice.
          const open = await tx.findStepUps({
            state: ['pending'],
            root,
            unused: true,
            notExpiredAt: now,
          });
          const duplicate = open.find(
            (a) =>
              a.resource === uri &&
              a.currency === currency &&
              a.maxAmountScaled === amountScaled,
          );

          if (duplicate !== undefined) {
            return {
              ok: false,
              code: 'step_up_required',
              detail: 'awaiting approval',
              stepUpHandle: duplicate.handle,
            };
          }

          const handle = this.cfg.idFactory('stp');
          const request: StepUpApproval = {
            handle,
            root,
            resource: uri,
            maxAmountScaled: amountScaled,
            currency,
            expiresAt: now + this.cfg.stepUpRequestTtlSeconds,
            used: false,
            state: 'pending',
            requestedAt: now,
            agent: verified.leaf.sub,
            taskId,
          };
          await tx.putStepUp(request);

          // Notification cannot happen here — it is I/O, and this is the
          // critical section. Recorded for the caller to send after commit, and
          // reassigned rather than appended because a store may retry this
          // closure and only the committed attempt is real.
          pendingNotice = {
            handle,
            root,
            resource: uri,
            amount: req.request.amount,
            agent: verified.leaf.sub,
            taskId,
            requestedAt: now,
            expiresAt: request.expiresAt,
          };

          return {
            ok: false,
            code: 'step_up_required',
            detail: `amount exceeds the step-up threshold of ${stepUp.over.amt} ${stepUp.over.cur}`,
            stepUpHandle: handle,
          };
        }
      }

      // --- circuit breakers (§10.4) ---
      const verdicts = await evaluateBreakers(tx, this.cfg.breakers, {
        root,
        host,
        taskId,
        amountScaled,
        remainingScaled: bindingRemaining,
        now,
      });
      const blocking = verdicts.filter((v) => v.severity === 'block');
      if (blocking.length > 0) {
        return {
          ok: false,
          code: 'breaker_tripped',
          detail: blocking.map((v) => `${v.name}: ${v.detail}`).join('; '),
          alerts: verdicts,
        };
      }

      // --- commit: debit every node on the path ---
      for (const n of nodes) {
        const updated: MandateNode = { ...n, spentScaled: n.spentScaled + amountScaled };
        if (n.rate !== null) {
          const windowSeconds = parseDuration(n.rate.per)!;
          updated.rateEvents = [...n.rateEvents.filter((t) => t >= now - windowSeconds), now];
        }
        await tx.putNode(updated);
      }
      await tx.appendHistory(root, { ts: now, amountScaled });
      if (taskId !== null) await tx.addTaskTotal(taskId, amountScaled);
      await tx.markMerchant(root, host);

      const expiresAt = now + this.cfg.spendTtlSeconds;
      const reservation: Reservation = {
        id: spendId,
        path,
        root,
        agent: verified.leaf.sub,
        taskId,
        merchant: host,
        resource: uri,
        amount: req.request.amount,
        amountScaled,
        settle: effective.settle ?? 'immediate',
        schema: req.quote?.schema ?? null,
        ...(req.quote?.quoteId !== undefined ? { quoteId: req.quote.quoteId } : {}),
        ...(req.quote?.quoteHash !== undefined ? { quoteHash: req.quote.quoteHash } : {}),
        chainHash,
        status: 'reserved',
        createdAt: now,
        expiresAt,
        ...(prepared !== null ? { directive: prepared, railName: nc!.name } : {}),
      };
      await tx.putReservation(reservation);

      const claims: SpendClaims = {
        v: PROTOCOL_VERSION,
        typ: 'spend',
        jti: spendId,
        iss: this.cfg.url,
        aud: host,
        sub: verified.leaf.sub,
        chain_hash: chainHash,
        amt: req.request.amount,
        res: uri,
        settle: reservation.settle,
        ...(req.quote?.schema !== undefined ? { schema: req.quote.schema } : {}),
        ...(req.quote?.quoteId !== undefined ? { quote_id: req.quote.quoteId } : {}),
        ...(req.quote?.quoteHash !== undefined ? { quote_hash: req.quote.quoteHash } : {}),
        iat: now,
        exp: expiresAt,
        cnf: { jkt: verified.leaf.cnf.jkt },
      };

      // The Spend Token and the Directive are orthogonal: one tells a §14
      // merchant the charge is authorized, the other tells the agent exactly
      // what it may execute. A deployment can use either, or both.
      return {
        ok: true,
        spendId,
        token: mintSpendToken(claims, this.cfg.key),
        expiresAt,
        effective,
        alerts: verdicts,
        ...(prepared !== null
          ? { directive: prepared, directiveJws: signDirective(prepared, this.cfg.key) }
          : {}),
      };
      })();

      // Recorded whatever the verdict. A retry with the same key is asking
      // "did my request go through?", and "yes, and it was refused" is the
      // honest answer — including for `step_up_required`, where replaying must
      // return the same handle rather than queue a second question. A caller
      // that wants a genuinely fresh attempt uses a fresh key.
      if (req.idempotencyKey !== undefined && requestHash !== null) {
        await tx.putIdempotent({
          key: req.idempotencyKey,
          requestHash,
          response: outcome,
          createdAt: now,
          expiresAt: now + this.cfg.idempotencyTtlSeconds,
        });
      }
      return outcome;
    });

    if (result.ok) {
      this.emit('reserve.ok', {
        spendId: result.spendId,
        root,
        agent: verified.leaf.sub,
        amount: req.request.amount,
        resource: uri,
        taskId,
        expiresAt: result.expiresAt,
        alerts: result.alerts.map((a) => a.name),
      });
    } else {
      this.emit(result.code === 'step_up_required' ? 'reserve.step_up' : 'reserve.denied', {
        root,
        agent: verified.leaf.sub,
        amount: req.request.amount,
        resource: uri,
        taskId,
        code: result.code,
        detail: result.detail,
        ...(result.stepUpHandle !== undefined ? { handle: result.stepUpHandle } : {}),
      });
    }

    if (pendingNotice !== null) {
      try {
        await this.cfg.approver?.requested(pendingNotice);
      } catch {
        // A notifier that throws must not turn a correctly-recorded refusal into
        // an error. The request is durable and visible through `pendingStepUps`;
        // a lost notification degrades to polling rather than to a lost spend.
      }
    }
    return result;
  }

  /**
   * §10.5 — record a principal's decision on a step-up request.
   *
   * Two checks, and both are load-bearing:
   *
   *   1. the decision verifies as a signature by a **trusted root issuer** —
   *      the agent cannot mint one, which is the whole point;
   *   2. the signed terms match what the Ledger recorded for that handle. A
   *      signature over a bare handle would attest only that the principal saw
   *      some opaque string, so `decisionMatches` re-checks root, resource,
   *      currency and amount against the stored request.
   *
   * Signature verification happens before the transaction because it is async
   * crypto and has no business inside a critical section; the state transition
   * happens inside one because deciding twice is a race.
   */
  async decideStepUp(jws: string): Promise<StepUpDecisionResult> {
    const now = this.cfg.clock();

    const verdict = await verifyStepUpDecision(jws, {
      now,
      isTrustedRootIssuer: this.cfg.isTrustedRootIssuer,
      ...(this.cfg.resolveKey !== undefined ? { resolveKey: this.cfg.resolveKey } : {}),
    });
    if (!verdict.ok) return { ok: false, code: verdict.code, detail: verdict.detail };
    const claims = verdict.claims;

    const decided = await this.cfg.store.transact(async (tx): Promise<StepUpDecisionResult> => {
      const record = await tx.getStepUp(claims.handle);
      if (record === undefined) {
        return { ok: false, code: 'chain_invalid', detail: `unknown handle ${claims.handle}` };
      }
      if (record.state !== 'pending') {
        return { ok: false, code: 'token_replayed', detail: `already ${record.state}` };
      }
      if (record.used) {
        return { ok: false, code: 'token_replayed', detail: 'already spent' };
      }
      if (record.expiresAt < now) {
        return { ok: false, code: 'token_expired', detail: 'the request has lapsed' };
      }

      const terms = decisionMatches(claims, record);
      if (!terms.ok) return { ok: false, code: terms.code, detail: terms.detail };

      const approved = claims.verdict === 'approve';
      const updated: StepUpApproval = {
        ...record,
        state: approved ? 'approved' : 'denied',
        // The spendable window runs from the decision, not the request: a
        // principal who approves in the 59th minute of an hour-long request has
        // not agreed to give the agent one minute to act.
        expiresAt: approved ? now + this.cfg.stepUpApprovalTtlSeconds : record.expiresAt,
        decision: {
          at: now,
          by: claims.iss,
          jws,
          ...(claims.reason !== undefined ? { reason: claims.reason } : {}),
        },
      };
      await tx.putStepUp(updated);
      return { ok: true, approval: updated, claims };
    });

    if (decided.ok) {
      this.emit('stepup.decided', {
        handle: claims.handle,
        root: decided.approval.root,
        agent: decided.approval.agent,
        resource: decided.approval.resource,
        verdict: claims.verdict,
        by: claims.iss,
        ...(claims.reason !== undefined ? { detail: claims.reason } : {}),
      });
    } else {
      this.emit('stepup.refused', {
        handle: claims.handle,
        by: claims.iss,
        code: decided.code,
        detail: decided.detail,
      });
    }
    return decided;
  }

  /** The approval queue: what is waiting on a human, oldest first. */
  async pendingStepUps(root?: string): Promise<StepUpApproval[]> {
    const now = this.cfg.clock();
    return this.cfg.store.read(async (tx) =>
      tx.findStepUps({
        state: ['pending'],
        unused: true,
        notExpiredAt: now,
        ...(root !== undefined ? { root } : {}),
      }),
    );
  }

  async stepUp(handle: string): Promise<StepUpApproval | undefined> {
    return this.cfg.store.read(async (tx) => tx.getStepUp(handle));
  }

  /**
   * §12.4.6 — the agent reports what it executed.
   *
   * A report is never proof. It is checked against the directive so a mis-signed
   * or redirected payment is attributable immediately, but settlement is only
   * ever confirmed by `reconcile()` against the rail's oracle. An agent that
   * reports success against an authorization that never executed gets its budget
   * back and a permanent mark on the reservation — the benign explanation and
   * the malicious one are indistinguishable from here.
   */
  async report(spendId: string, proof: unknown): Promise<SettleResult> {
    const nc = this.cfg.nonCustodialRail;
    if (nc === undefined) {
      return { ok: false, code: 'chain_invalid', detail: 'this ledger is not non-custodial' };
    }

    const existing = await this.cfg.store.read(async (tx) => tx.getReservation(spendId));
    if (existing === undefined || existing.directive === undefined) {
      return { ok: false, code: 'chain_invalid', detail: `no directive for ${spendId}` };
    }
    if (existing.status !== 'reserved' && existing.status !== 'settling') {
      return { ok: false, code: 'token_replayed', detail: `already ${existing.status}` };
    }

    const verdict = await nc.verifyProof(existing.directive, proof);
    const now = this.cfg.clock();

    return this.cfg.store.transact(async (tx): Promise<SettleResult> => {
      const current = (await tx.getReservation(spendId)) ?? existing;
      const reported = {
        at: now,
        ok: verdict.ok,
        ...(verdict.ok ? {} : { detail: verdict.detail }),
        ...(verdict.ok && verdict.ref !== undefined ? { ref: verdict.ref } : {}),
      };

      if (!verdict.ok) {
        // The proof does not match the directive. The funds, if any moved, went
        // somewhere this Ledger never authorized.
        await this.creditPath(tx, current);
        const updated: Reservation = {
          ...current,
          status: 'refunded',
          reported,
          refundReason: `proof rejected: ${verdict.detail}`,
        };
        await tx.putReservation(updated);
        return {
          ok: true,
          status: 'refunded',
          receipt: this.buildReceipt(updated, 'refunded', now),
        };
      }

      // Proof is well-formed. Money may or may not have moved; only the oracle
      // can say, so the reservation waits for reconciliation.
      const updated: Reservation = { ...current, status: 'settling', settlingSince: now, reported };
      await tx.putReservation(updated);
      return {
        ok: false,
        code: 'breaker_tripped',
        detail: 'proof accepted; awaiting oracle confirmation',
      };
    });
  }

  /**
   * Spec §12 — release or refund a reservation.
   *
   * Three phases, because paying is an external call and external calls cannot
   * happen inside the critical section:
   *
   *   1. decide, atomically, and claim the reservation by marking it `settling`
   *   2. call the rail, outside any lock
   *   3. finalize, atomically
   *
   * Claiming in phase 1 is what stops a concurrent `settle` from paying twice:
   * the second caller finds a status that is no longer `reserved`.
   */
  async settle(spendId: string, input: SettleInput = {}): Promise<SettleResult> {
    const now = this.cfg.clock();

    type Phase1 =
      // `reservation` rides along on the done paths purely so the audit event
      // emitted after commit can carry root, agent and amount rather than a
      // bare spendId. Absent only when there was no reservation to find.
      | { kind: 'done'; result: SettleResult; reservation?: Reservation }
      | { kind: 'pay'; reservation: Reservation };

    const phase1 = await this.cfg.store.transact(async (tx): Promise<Phase1> => {
      const r = await tx.getReservation(spendId);
      if (r === undefined) {
        return {
          kind: 'done',
          result: { ok: false, code: 'chain_invalid', detail: `unknown reservation ${spendId}` },
        };
      }
      if (r.status !== 'reserved') {
        return {
          kind: 'done',
          result: { ok: false, code: 'token_replayed', detail: `already ${r.status}` },
        };
      }

      if (r.settle === 'escrow_schema' && input.schemaValid === undefined) {
        return {
          kind: 'done',
          result: {
            ok: false,
            code: 'chain_invalid',
            detail: 'escrow_schema settlement requires a schemaValid verdict',
          },
        };
      }

      // Refund paths never touch the rail: no money moved, so none comes back.
      if (r.settle === 'escrow_schema' && input.schemaValid === false) {
        await this.creditPath(tx, r);
        const updated = this.applyInput(
          { ...r, status: 'refunded', refundReason: 'response failed schema validation' },
          input,
        );
        await tx.putReservation(updated);
        return {
          kind: 'done',
          result: {
            ok: true,
            status: 'refunded',
            receipt: this.buildReceipt(updated, 'refunded', now, input),
          },
        };
      }

      if (r.settle === 'escrow_human' && input.humanApproved !== true) {
        // Stays reserved. Sweeping is the sweep's job, not settle's.
        return {
          kind: 'done',
          reservation: r,
          result: { ok: true, status: 'reserved', receipt: this.buildReceipt(r, 'reserved', now, input) },
        };
      }

      if (this.cfg.rail === undefined) {
        const updated = this.applyInput({ ...r, status: 'settled' }, input);
        await tx.putReservation(updated);
        return {
          kind: 'done',
          reservation: updated,
          result: {
            ok: true,
            status: 'settled',
            receipt: this.buildReceipt(updated, 'settled', now, input),
          },
        };
      }

      const claimed = this.applyInput({ ...r, status: 'settling', settlingSince: now }, input);
      await tx.putReservation(claimed);
      return { kind: 'pay', reservation: claimed };
    });

    if (phase1.kind === 'done') {
      const subject =
        phase1.reservation === undefined ? { spendId } : Ledger.subject(phase1.reservation);
      if (phase1.result.ok) this.emit(`settle.${phase1.result.status}`, subject);
      else {
        this.emit('settle.refused', {
          ...subject,
          code: phase1.result.code,
          detail: phase1.result.detail,
        });
      }
      return phase1.result;
    }

    const rail = this.cfg.rail!;
    this.emit('settle.settling', { ...Ledger.subject(phase1.reservation), rail: rail.name });
    const paid = await rail.pay(phase1.reservation);

    const settled = await this.cfg.store.transact(async (tx): Promise<SettleResult> => {
      const current = (await tx.getReservation(spendId)) ?? phase1.reservation;

      if (paid.ok) {
        const updated: Reservation = {
          ...current,
          status: 'settled',
          railRef: paid.ref,
          railName: rail.name,
        };
        await tx.putReservation(updated);
        return {
          ok: true,
          status: 'settled',
          receipt: this.buildReceipt(updated, 'settled', this.cfg.clock(), input),
        };
      }

      if (paid.terminal) {
        await this.creditPath(tx, current);
        const updated: Reservation = {
          ...current,
          status: 'refunded',
          refundReason: `rail declined: ${paid.detail}`,
          railName: rail.name,
        };
        await tx.putReservation(updated);
        return {
          ok: true,
          status: 'refunded',
          receipt: this.buildReceipt(updated, 'refunded', this.cfg.clock(), input),
        };
      }

      // Indeterminate. Budget stays debited — the conservative side — and the
      // reservation waits for reconcile(). Refunding here on a timeout is how you
      // pay a merchant and hand the money back to the agent as well.
      await tx.putReservation({ ...current, railName: rail.name });
      return {
        ok: false,
        code: 'breaker_tripped',
        detail: `settlement indeterminate, awaiting reconciliation: ${paid.detail}`,
      };
    });

    const subject = Ledger.subject(phase1.reservation);
    if (settled.ok) this.emit(`settle.${settled.status}`, { ...subject, rail: rail.name });
    // Not a failure: the rail would not say. The reservation stays debited and
    // waits for the reconciler, and the log has to show that it is waiting
    // rather than that it failed.
    else this.emit('settle.indeterminate', { ...subject, rail: rail.name, detail: settled.detail });
    return settled;
  }

  /**
   * Resolve reservations stuck in `settling`. Run on a timer; this is the only
   * thing that closes the dual-write gap, and a deployment without it silently
   * accumulates funds that are neither spent nor available.
   */
  async reconcile(): Promise<
    Array<{ spendId: string; outcome: 'settled' | 'refunded' | 'still_unknown' | 'escalated' }>
  > {
    if (this.cfg.nonCustodialRail !== undefined) return this.reconcileNonCustodial();

    const rail = this.cfg.rail;
    if (rail === undefined) return [];

    const stuck = await this.cfg.store.read(async (tx) =>
      tx.findReservations({ status: ['settling'] }),
    );

    const out: Array<{ spendId: string; outcome: 'settled' | 'refunded' | 'still_unknown' }> = [];
    for (const r of stuck) {
      const status = await rail.status(r);
      const resolved = await this.cfg.store.transact(async (tx) => {
        const current = await tx.getReservation(r.id);
        if (current === undefined || current.status !== 'settling') return 'still_unknown' as const;

        if (status.state === 'paid') {
          await tx.putReservation({
            ...current,
            status: 'settled',
            railRef: status.ref,
            railName: rail.name,
          });
          return 'settled' as const;
        }
        if (status.state === 'not_paid') {
          await this.creditPath(tx, current);
          await tx.putReservation({
            ...current,
            status: 'refunded',
            refundReason: 'rail confirmed no payment was made',
          });
          return 'refunded' as const;
        }
        return 'still_unknown' as const;
      });
      out.push({ spendId: r.id, outcome: resolved });
    }
    return out;
  }

  /**
   * §12.4.5 — resolve non-custodial reservations against the rail's oracle.
   *
   * Covers `reserved` as well as `settling`: an agent may execute a directive
   * and never report, so a reservation sitting quietly at `reserved` past its
   * deadline is not evidence that nothing happened. This is also why
   * `sweepExpired` refuses to touch anything carrying a directive — blind-
   * refunding one would hand back money that has already left the payer.
   *
   * The rail's capabilities decide what an unconfirmed payment means:
   *
   *   - `hardExpiry` → past `decidableAt` the authorization is permanently
   *     unusable, so "not confirmed" is "never happened". Auto-refund is sound.
   *   - otherwise → a late settlement is still possible at any time. Refunding
   *     would double-spend, so the reservation escalates to a human instead.
   */
  private async reconcileNonCustodial(): Promise<
    Array<{ spendId: string; outcome: 'settled' | 'refunded' | 'still_unknown' | 'escalated' }>
  > {
    const nc = this.cfg.nonCustodialRail!;
    const now = this.cfg.clock();

    const open = await this.cfg.store.read(async (tx) =>
      tx.findReservations({
        status: ['settling', 'reserved'],
        hasDirective: true,
        escalated: false,
      }),
    );

    const out: Array<{
      spendId: string;
      outcome: 'settled' | 'refunded' | 'still_unknown' | 'escalated';
    }> = [];

    for (const r of open) {
      const directive = r.directive!;
      const status = await nc.confirm(directive);

      const resolved = await this.cfg.store.transact(async (tx) => {
        const current = await tx.getReservation(r.id);
        if (current === undefined || (current.status !== 'settling' && current.status !== 'reserved')) {
          return 'still_unknown' as const;
        }

        if (status.state === 'paid') {
          await tx.putReservation({
            ...current,
            status: 'settled',
            railRef: status.ref,
            railName: nc.name,
          });
          return 'settled' as const;
        }

        if (status.state === 'not_paid') {
          if (nc.capabilities.hardExpiry) {
            await this.creditPath(tx, current);
            await tx.putReservation({
              ...current,
              status: 'refunded',
              refundReason: 'authorization expired unexecuted',
            });
            return 'refunded' as const;
          }
          await tx.putReservation({
            ...current,
            escalated: {
              at: now,
              reason: `${nc.name} reports no settlement, but the rail cannot guarantee one will not arrive later`,
            },
          });
          return 'escalated' as const;
        }

        // Unknown. Only meaningful once the deadline has passed.
        if (now >= directive.decidableAt) {
          await tx.putReservation({
            ...current,
            escalated: {
              at: now,
              reason: `undecided past decidableAt: ${status.detail}`,
            },
          });
          return 'escalated' as const;
        }
        return 'still_unknown' as const;
      });

      out.push({ spendId: r.id, outcome: resolved });
    }
    return out;
  }

  /**
   * Emit an audit event. Never inside a transaction, and never fatal.
   *
   * After commit, because an event describing a state change that rolled back is
   * worse than no event — it is what makes a log untrustworthy. And swallowed,
   * because a failing log sink must not turn a completed spend into an error the
   * caller retries.
   */
  private emit(event: string, fields: Omit<AuditEvent, 'at' | 'event'> = {}): void {
    const sink = this.cfg.audit;
    if (sink === undefined) return;
    try {
      void Promise.resolve(sink.record({ at: this.cfg.clock(), event, ...fields })).catch(
        () => undefined,
      );
    } catch {
      // A sink that throws synchronously is still just a log.
    }
  }

  /** The fields every reservation event carries, so a log can be grouped by any of them. */
  private static subject(r: Reservation): Omit<AuditEvent, 'at' | 'event'> {
    return {
      spendId: r.id,
      root: r.root,
      agent: r.agent,
      amount: r.amount,
      resource: r.resource,
      taskId: r.taskId,
    };
  }

  private applyInput(r: Reservation, input: SettleInput): Reservation {
    return {
      ...r,
      ...(input.respHash !== undefined ? { respHash: input.respHash } : {}),
      ...(input.respBytes !== undefined ? { respBytes: input.respBytes } : {}),
      ...(input.merchantSig !== undefined ? { merchantSig: input.merchantSig } : {}),
    };
  }

  async refund(spendId: string, reason: string): Promise<SettleResult> {
    const now = this.cfg.clock();
    let refunded: Reservation | null = null;
    const result = await this.cfg.store.transact(async (tx): Promise<SettleResult> => {
      const r = await tx.getReservation(spendId);
      if (r === undefined) {
        return { ok: false, code: 'chain_invalid', detail: `unknown reservation ${spendId}` };
      }
      if (r.status !== 'reserved') {
        return { ok: false, code: 'token_replayed', detail: `already ${r.status}` };
      }
      await this.creditPath(tx, r);
      const updated: Reservation = { ...r, status: 'refunded', refundReason: reason };
      await tx.putReservation(updated);
      refunded = updated;
      return { ok: true, status: 'refunded', receipt: this.buildReceipt(updated, 'refunded', now) };
    });

    if (refunded !== null) this.emit('refund.ok', { ...Ledger.subject(refunded), detail: reason });
    return result;
  }

  /**
   * Sweep reservations whose spend token expired without settlement. Expiry
   * MUST refund rather than capture (§12): a token nobody redeemed bought
   * nothing.
   *
   * `limit` caps one sweep, oldest first. Uncapped is the historical behaviour
   * and is fine in memory; over a durable store a large backlog becomes one
   * transaction holding row locks on every stale reservation, which stalls live
   * spending for as long as it runs. A timer-driven sweeper should pass a bound
   * and call again while it keeps coming back full.
   */
  async sweepExpired(limit?: number): Promise<string[]> {
    const now = this.cfg.clock();
    const grace = this.cfg.reservationGraceSeconds;
    let swept: Reservation[] = [];
    const ids = await this.cfg.store.transact(async (tx) => {
      const stale = await tx.findReservations({
        status: ['reserved'],
        // Never sweep a reservation carrying a directive: the agent may have
        // executed it without reporting, and a blind refund would hand back
        // money that has already left the payer. Those go through
        // reconcileNonCustodial(), which asks the oracle first.
        hasDirective: false,
        expiresBefore: now - grace,
        ...(limit !== undefined ? { limit } : {}),
      });
      for (const r of stale) {
        await this.creditPath(tx, r);
        await tx.putReservation({
          ...r,
          status: 'expired',
          refundReason: 'spend token expired unused',
        });
      }
      swept = stale;
      return stale.map((r) => r.id);
    });

    for (const r of swept) {
      this.emit('sweep.expired', { ...Ledger.subject(r), detail: 'spend token expired unused' });
    }
    return ids;
  }

  /**
   * Spec §10.3 — revoking a jti kills its entire subtree on the next spend.
   *
   * Takes no credential and is therefore only for a caller already inside the
   * deployment; `applyControl` is the authenticated door to the same lever. It
   * needs an existing node because it derives the root from one — a principal
   * revoking a mandate the ledger has never seen goes through `applyControl`,
   * which is told the root by the decision it verified.
   */
  async revoke(jti: string): Promise<boolean> {
    return this.cfg.store.transact(async (tx) => {
      const n = await tx.getNode(jti);
      if (n === undefined) return false;
      await tx.putRevocation(n.root, jti, this.cfg.clock());
      await tx.putNode({ ...n, revoked: true });
      return true;
    });
  }

  /**
   * §10.1 materialization without a spend.
   *
   * Two things need this. A mandate cannot be revoked before it has been
   * presented — there was no node to mark, so the revocation was refused and the
   * first spend went through — and an *offline* mandate (§13) may never be
   * presented to the ledger at all, so its status-list index would never be
   * known and revoking it could not reach the merchant holding it.
   *
   * Registering is exactly the write `reserve` would have done, minus the debit:
   * same node shape, same `jti`-to-content binding, same revocation seed. It is
   * idempotent, and re-registering a `jti` whose content changed is refused for
   * the same reason a spend would be — the alternative is a reset budget.
   *
   * No authority is granted by registering, and none is needed to do it: the
   * chain is verified, and anyone holding a valid chain could have spent against
   * it anyway.
   */
  async register(tokens: string[]): Promise<{ ok: true; path: string[] } | { ok: false; code: ErrorCode; detail: string }> {
    const verified = await verifyChain(tokens, {
      now: this.cfg.clock(),
      // Registration authorizes nothing, so there is no request for §8 to cover.
      // Everything else — signatures, attenuation, depth, the window — is
      // checked exactly as a spend would check it.
      request: NO_REQUEST,
      // Needed here for a reason of its own: the status list URI is derived as
      // `{ledger}/v1/status/{root}` (§10.3), so registering a chain naming
      // another ledger would mint an index and a signed list nobody will ever
      // fetch, and record the mandate as revocable when it is not.
      ledger: this.cfg.url,
      isTrustedRootIssuer: this.cfg.isTrustedRootIssuer,
      ...(this.cfg.resolveKey !== undefined ? { resolveKey: this.cfg.resolveKey } : {}),
    });
    if (!verified.ok) return { ok: false, code: verified.code, detail: verified.detail };

    const links = verified.links;
    const root = links[0]!.jti;

    return this.cfg.store.transact(async (tx) => {
      const locked = await tx.lockPath(verified.path);
      for (let i = 0; i < links.length; i++) {
        const tokenHash = sha256(tokens[i]!);
        const existing = locked[i];
        if (existing !== undefined) {
          if (existing.tokenHash !== tokenHash) {
            return {
              ok: false as const,
              code: 'chain_invalid' as ErrorCode,
              detail: `jti ${links[i]!.jti} already recorded with different content`,
            };
          }
          continue;
        }
        await tx.putNode(
          await materialize(tx, links[i]!, i === 0 ? null : links[i - 1]!.jti, root, tokenHash),
        );
      }
      return { ok: true as const, path: verified.path };
    });
  }

  /**
   * §10.3 — the root's status list, signed and ready to serve.
   *
   * Built from the nodes rather than from the revocation records, because a bit
   * needs an index and only a mandate carries one. A revocation for a `jti` the
   * ledger has never materialized is durably recorded and enforced online, and
   * is invisible here — there is no index to set. That is the argument for
   * registering an offline mandate at issuance rather than at first spend.
   *
   * **Set-only, never clear.** The list is the union of the revoked nodes'
   * indices. Walking nodes and writing `bit[idx] = node.revoked` would look
   * equivalent and is not: two mandates sharing an index would have the later
   * unrevoked one clear the earlier revoked one's bit, and a revoked mandate
   * would read as live. Building by union makes an index collision cost an
   * unnecessary refusal instead of a missed one, which is the direction a
   * revocation mechanism has to fail in.
   */
  async publishStatusList(
    root: string,
    opts: { seq?: number; ttlSeconds?: number; bits?: number } = {},
  ): Promise<string> {
    const nodes = await this.cfg.store.read(async (tx) => tx.findNodes(root));
    const now = this.cfg.clock();
    const revoked = nodes.filter((n) => n.revoked && n.statusIdx !== null).map((n) => n.statusIdx!);
    const claims = buildStatusList({
      ledger: this.cfg.url,
      root,
      revoked,
      /**
       * How many are revoked — a function of the list's *content*, not of when
       * it was built.
       *
       * A wall clock is the obvious choice and it is wrong twice. At one-second
       * resolution two lists published in the same second share a `seq`, so a
       * revocation between them does not propagate; and a replica lagging on
       * replication publishes a *newer* timestamp over a *smaller* revocation
       * set, which is exactly the rollback the counter exists to prevent.
       *
       * Counting revocations fixes both, because revocation here is one-way —
       * nothing in §10.6 un-revokes, and `putRevocation` never deletes — so the
       * count only rises, and two lists under one root that agree on it agree on
       * every bit. The lagging replica publishes a lower number and is correctly
       * refused.
       */
      seq: opts.seq ?? revoked.length,
      iat: now,
      ttlSeconds: opts.ttlSeconds ?? DEFAULT_STATUS_TTL_SECONDS,
      ...(opts.bits !== undefined ? { bits: opts.bits } : {}),
    });
    return signStatusList(claims, this.cfg.key);
  }

  async setGlobalKill(root: string, on: boolean): Promise<void> {
    await this.cfg.store.transact(async (tx) => tx.setKilled(root, on));
  }

  /**
   * §10.6 — apply a control action a principal signed.
   *
   * `setGlobalKill` and `revoke` above take no credential, which is fine for a
   * caller inside the deployment and not fine for one reachable over a network.
   * This is the authenticated door to the same two levers.
   *
   * Three checks the signature alone cannot make, all inside one transaction:
   *
   *   1. **the nonce is fresh** — a control action names no one-shot handle, so
   *      without this a captured `release` can be replayed at the next incident;
   *   2. **the issuer owns the root** — `isTrustedRootIssuer` says a DID is *a*
   *      principal, not *this* subtree's principal;
   *   3. **a revoke target is in the subtree** — otherwise `root` is decorative
   *      and the ownership check above buys nothing.
   */
  async applyControl(jws: string): Promise<ControlResult> {
    const now = this.cfg.clock();

    const verdict = await verifyControlDecision(jws, {
      now,
      isTrustedRootIssuer: this.cfg.isTrustedRootIssuer,
      ...(this.cfg.resolveKey !== undefined ? { resolveKey: this.cfg.resolveKey } : {}),
    });
    if (!verdict.ok) return { ok: false, code: verdict.code, detail: verdict.detail };
    const claims = verdict.claims;

    const applied = await this.cfg.store.transact(async (tx): Promise<ControlResult> => {
      if (!(await tx.consumeNonce(claims.jti, claims.exp))) {
        return { ok: false, code: 'token_replayed', detail: `decision ${claims.jti} already used` };
      }

      // The root must exist. An unspent mandate has no node, and with no node
      // there is no recorded issuer to check ownership against — so there is
      // nothing here that can be authorized, and nothing yet worth halting.
      const rootNode = await tx.getNode(claims.root);
      if (rootNode === undefined) {
        return { ok: false, code: 'chain_invalid', detail: `unknown root ${claims.root}` };
      }
      if (rootNode.issuer !== claims.iss) {
        return {
          ok: false,
          code: 'pop_failed',
          detail: `${claims.iss} did not issue ${claims.root}`,
        };
      }

      if (claims.action === 'revoke') {
        const target = await tx.getNode(claims.target!);
        if (target !== undefined && target.root !== claims.root) {
          return {
            ok: false,
            code: 'attenuation_violation',
            detail: `${claims.target} is not under ${claims.root}`,
          };
        }
        // Recorded whether or not a node exists. It used to be refused as
        // "unknown mandate" when one did not, which meant a principal could not
        // revoke a mandate before its first spend — and the first spend then
        // materialized a node with `revoked: false` and went through. The
        // record is keyed by root, so a `jti` that later turns up under someone
        // else's root is unaffected by this, which is the check that cannot be
        // made against a node that does not exist yet.
        await tx.putRevocation(claims.root, claims.target!, now);
        if (target !== undefined) await tx.putNode({ ...target, revoked: true });
        return { ok: true, action: 'revoke', root: claims.root, target: claims.target! };
      }

      await tx.setKilled(claims.root, claims.action === 'kill');
      return { ok: true, action: claims.action, root: claims.root };
    });

    // Always logged, including the refusals. Somebody trying and failing to halt
    // a principal is exactly the thing an incident review needs to see.
    this.emit(applied.ok ? `control.${applied.action}` : 'control.refused', {
      root: claims.root,
      by: claims.iss,
      action: claims.action,
      ...(claims.target !== undefined ? { target: claims.target } : {}),
      ...(applied.ok ? {} : { code: applied.code, detail: applied.detail }),
      ...(claims.reason !== undefined ? { reason: claims.reason } : {}),
    });
    return applied;
  }

  /**
   * Every node under a root, with what each has left.
   *
   * The console's budget tree. Read-only and outside any critical section: a
   * dashboard that took row locks on the whole subtree to draw itself would
   * stall spending every time somebody refreshed a page.
   */
  async budgetTree(root: string): Promise<BudgetNode[]> {
    const [nodes, killed] = await this.cfg.store.read(async (tx) => [
      await tx.findNodes(root),
      await tx.killed(root),
    ]);
    return nodes.map((n) => ({
      jti: n.jti,
      parent: n.parent,
      issuer: n.issuer,
      budget: n.budgetScaled === null ? null : fromScaled(n.budgetScaled, n.currency ?? 'USD'),
      spent: fromScaled(n.spentScaled, n.currency ?? 'USD'),
      remaining:
        n.budgetScaled === null
          ? null
          : fromScaled(n.budgetScaled - n.spentScaled, n.currency ?? 'USD'),
      rate: n.rate,
      revoked: n.revoked,
      exp: n.exp,
      killed,
    }));
  }

  /**
   * Recent reservations under a root, newest first.
   *
   * Reservations rather than receipts, because receipts are not stored: §11
   * builds and signs one on demand from the reservation, so what a console can
   * honestly show is the record, plus a freshly-issued receipt for any row. It
   * cannot show *the* receipt a merchant was handed, and pretending otherwise
   * would put a different `jti` and `ts` in front of an auditor.
   */
  async spendFeed(root: string, limit = 50): Promise<Reservation[]> {
    return this.cfg.store.read(async (tx) => {
      const all = await tx.findReservations({});
      return all
        .filter((r) => r.root === root)
        .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? 1 : -1))
        .slice(0, limit);
    });
  }

  /** A signed receipt for a reservation, minted now. See `spendFeed`. */
  async receiptFor(spendId: string): Promise<Receipt | null> {
    const r = await this.reservation(spendId);
    return r === undefined ? null : this.buildReceipt(r, r.status, this.cfg.clock());
  }

  async remaining(jti: string): Promise<Money | null> {
    return this.cfg.store.read(async (tx) => {
      const n = await tx.getNode(jti);
      if (n === undefined || n.budgetScaled === null) return null;
      return fromScaled(n.budgetScaled - n.spentScaled, n.currency ?? 'USD');
    });
  }

  async reservation(spendId: string): Promise<Reservation | undefined> {
    return this.cfg.store.read(async (tx) => tx.getReservation(spendId));
  }

  /**
   * The ledger's clock, which is authoritative (§7 step 7).
   *
   * Exposed so surfaces built on top compute ages against the same instant the
   * ledger reserves and expires against, rather than against their own
   * `Date.now()` — two clocks in one system is how a dashboard ends up
   * disagreeing with the thing it is a dashboard of.
   */
  now(): number {
    return this.cfg.clock();
  }

  /**
   * Reservations sitting in `settling`, optionally only those that have sat
   * there a while.
   *
   * `settlingSince` has been written since the state was invented and, until
   * this existed, read by nothing. That is open question 8 in one field: the
   * ledger records how long a payment has been in limbo and nothing ever looks.
   *
   * Falls back to `createdAt` for a reservation that reached `settling` without
   * a stamp, so a missing field reads as *older* than it is and errs toward
   * telling somebody.
   */
  async stuckSettlements(olderThanSeconds = 0): Promise<Reservation[]> {
    const now = this.cfg.clock();
    return this.cfg.store.read(async (tx) => {
      const settling = await tx.findReservations({ status: ['settling'] });
      return settling.filter(
        (r) => now - (r.settlingSince ?? r.createdAt) >= olderThanSeconds,
      );
    });
  }

  /**
   * Mark a reservation as needing a human, exactly once.
   *
   * Escalation deliberately changes no money. The reservation stays `settling`
   * and stays debited, because the whole reason it is here is that nobody knows
   * whether the payment landed — and §12.2.1 is emphatic that guessing either
   * way is worse than waiting. What escalation changes is that somebody is now
   * told.
   *
   * Returns `true` only on the transition, so a caller can notify on the return
   * value without keeping its own set of what it has already reported.
   */
  async escalate(spendId: string, reason: string): Promise<boolean> {
    const now = this.cfg.clock();
    let escalated: Reservation | null = null;
    const raised = await this.cfg.store.transact(async (tx) => {
      const r = await tx.getReservation(spendId);
      if (r === undefined || r.escalated !== undefined) return false;
      await tx.putReservation({ ...r, escalated: { at: now, reason } });
      escalated = r;
      return true;
    });

    if (escalated !== null) {
      this.emit('escalated', { ...Ledger.subject(escalated), detail: reason });
    }
    return raised;
  }

  /**
   * Refunds credit the budget on every node the debit touched, symmetrically.
   *
   * Rate counters are deliberately NOT credited back: a refunded call still
   * reached the merchant and still consumed a request slot. Restoring it would
   * make a failing endpoint an unlimited-rate endpoint, which is exactly the
   * shape of a retry storm.
   *
   * The credit walks `r.path`, which is stored root-first, through the same
   * `lockPath` the debit used — so a refund and a concurrent reserve on an
   * overlapping path take the shared rows in the same order.
   */
  private async creditPath(tx: LedgerTx, r: Reservation): Promise<void> {
    const nodes = await tx.lockPath(r.path);
    for (const n of nodes) {
      if (n === undefined) continue;
      await tx.putNode({ ...n, spentScaled: n.spentScaled - r.amountScaled });
    }
    if (r.taskId !== null) await tx.addTaskTotal(r.taskId, -r.amountScaled);
    await tx.appendHistory(r.root, { ts: this.cfg.clock(), amountScaled: -r.amountScaled });
  }

  private buildReceipt(
    r: Reservation,
    status: Reservation['status'],
    now: number,
    input: SettleInput = {},
  ): Receipt {
    const claims: ReceiptClaims = {
      v: PROTOCOL_VERSION,
      typ: 'receipt',
      jti: this.cfg.idFactory('rcp'),
      spend: r.id,
      chain_hash: r.chainHash,
      path: r.path,
      agent: r.agent,
      principal: r.root,
      task: r.taskId,
      merchant: r.merchant,
      res: r.resource,
      amt: r.amount,
      ...(input.respHash ?? r.respHash) !== undefined
        ? { resp_hash: (input.respHash ?? r.respHash)! }
        : {},
      ...(input.respBytes ?? r.respBytes) !== undefined
        ? { resp_bytes: (input.respBytes ?? r.respBytes)! }
        : {},
      // Without the rail reference a "settled" receipt cannot be reconciled
      // against the rail's own records, which is most of what a receipt is for.
      ...(r.railName !== undefined ? { rail: r.railName } : {}),
      ...(r.railRef !== undefined ? { rail_ref: r.railRef } : {}),
      ...(r.quoteId !== undefined ? { quote_id: r.quoteId } : {}),
      ...(r.quoteHash !== undefined ? { quote_hash: r.quoteHash } : {}),
      status,
      ts: now,
    };
    return {
      claims,
      sigs: {
        ledger: signReceipt(claims, this.cfg.key),
        ...(input.merchantSig !== undefined ? { merchant: input.merchantSig } : {}),
      },
    };
  }
}
