import { sign as cryptoSign } from 'node:crypto';

import { type Check, OK, fail } from './errors.js';
import { type ParsedJws, encodeSegment, parseCompactJws, verifyJwsSignature } from './jws.js';
import { type Money, isMoney, toScaled } from './money.js';
import type { AgentKey } from './sign.js';
import { PROTOCOL_VERSION } from './types.js';
import { type KeyResolver, didKeyResolver } from './verify.js';

/**
 * Spec §10.5 — the human half of step-up.
 *
 * §10.5 says the Ledger returns `step_up_required` with a handle and "a human
 * approves out of band". A handle alone cannot carry that: the Ledger hands it
 * to the agent in the error response, so anything that treats *possession of the
 * handle* as approval is approved by the agent. The handle names the question.
 * This module is the answer, and it has to be unforgeable by the party asking.
 *
 * A decision is therefore a compact JWS signed by the **root issuer** — the
 * principal who granted the mandate in the first place. The same key that
 * created the authority is the one that may exceed its own threshold, which
 * needs no new trust root and no new key distribution.
 *
 * ## Why the decision restates the terms
 *
 * The obvious design signs the handle. That is a signature over an opaque
 * identifier, and it proves only that the principal saw *some* string. It cannot
 * distinguish "approve $5 to weatherco" from "approve $5,000 to attacker.example"
 * if whatever showed the human the terms was lying, or if the Ledger's record
 * moved between display and signature.
 *
 * So a decision restates `root`, `res` and `amt`, and the Ledger checks all
 * three against its own record before honouring it. The bytes the principal
 * signs are the terms they are agreeing to. Anything less is a confirm dialog
 * that says "are you sure?" and nothing else.
 */

export const APPROVAL_TYP = 'application/agent-approval+jwt';

export type Verdict = 'approve' | 'deny';

export interface StepUpDecisionClaims {
  v: string;
  typ: 'approval';
  /** The step-up handle this decides. */
  handle: string;
  /** The deciding principal. MUST be the chain's trusted root issuer. */
  iss: string;
  verdict: Verdict;
  /** The terms, restated so the signature covers them. See the note above. */
  root: string;
  res: string;
  amt: Money;
  iat: number;
  exp: number;
  /** Free text from the human, carried into the audit trail. */
  reason?: string;
}

/** Decisions are short-lived: a signed approval is a bearer credential. */
export const DEFAULT_DECISION_TTL_SECONDS = 900;

export function signStepUpDecision(claims: StepUpDecisionClaims, key: AgentKey): string {
  const header = { alg: 'EdDSA', typ: APPROVAL_TYP, kid: claims.iss };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  return `${signingInput}.${cryptoSign(null, Buffer.from(signingInput, 'ascii'), key.privateKey).toString('base64url')}`;
}

function parseClaims(payload: Record<string, unknown>): StepUpDecisionClaims | null {
  const { v, typ, handle, iss, verdict, root, res, amt, iat, exp, reason } = payload;
  if (v !== PROTOCOL_VERSION || typ !== 'approval') return null;
  if (typeof handle !== 'string' || handle.length === 0) return null;
  if (typeof iss !== 'string' || iss.length === 0) return null;
  if (verdict !== 'approve' && verdict !== 'deny') return null;
  if (typeof root !== 'string' || typeof res !== 'string') return null;
  if (!isMoney(amt)) return null;
  if (typeof iat !== 'number' || typeof exp !== 'number') return null;
  if (reason !== undefined && typeof reason !== 'string') return null;
  return {
    v,
    typ,
    handle,
    iss,
    verdict,
    root,
    res,
    amt,
    iat,
    exp,
    ...(reason !== undefined ? { reason } : {}),
  };
}

export interface VerifyDecisionOptions {
  now: number;
  /** The chain's root-issuer test. Only the principal may decide. */
  isTrustedRootIssuer: (iss: string) => boolean;
  resolveKey?: KeyResolver;
  skewSeconds?: number;
}

export type DecisionResult =
  | { ok: true; claims: StepUpDecisionClaims; jws: string }
  | { ok: false; code: import('./errors.js').ErrorCode; detail: string };

/**
 * Verify a decision in isolation: well-formed, in date, signed by a key the
 * deployment trusts as a root issuer.
 *
 * What this deliberately does **not** do is check the decision against the
 * Ledger's record of the handle. That comparison needs the stored request and
 * belongs in the critical section where the handle is consumed — see
 * `Ledger.decideStepUp`. Splitting it keeps the signature check free of ledger
 * state, and keeps the terms check somewhere it cannot be forgotten.
 */
export async function verifyStepUpDecision(
  jws: string,
  opts: VerifyDecisionOptions,
): Promise<DecisionResult> {
  const parsed: ParsedJws | null = parseCompactJws(jws);
  if (parsed === null) return { ok: false, code: 'chain_invalid', detail: 'unparseable decision' };
  if (parsed.header.typ !== APPROVAL_TYP) {
    return { ok: false, code: 'chain_invalid', detail: `unexpected typ ${parsed.header.typ}` };
  }

  const claims = parseClaims(parsed.payload);
  if (claims === null) {
    return { ok: false, code: 'chain_invalid', detail: 'malformed decision claims' };
  }

  // Trust before signature: an untrusted issuer is refused without spending a
  // verification, and the failure reads as "not your call" rather than "bad key".
  if (!opts.isTrustedRootIssuer(claims.iss)) {
    return { ok: false, code: 'pop_failed', detail: `${claims.iss} is not a trusted principal` };
  }

  const skew = opts.skewSeconds ?? 60;
  if (opts.now + skew < claims.iat) {
    return { ok: false, code: 'token_expired', detail: 'decision is not yet valid' };
  }
  if (opts.now - skew > claims.exp) {
    return { ok: false, code: 'token_expired', detail: 'decision has expired' };
  }

  const jwk = await (opts.resolveKey ?? didKeyResolver)(claims.iss);
  if (jwk === null) {
    return { ok: false, code: 'pop_failed', detail: `cannot resolve key for ${claims.iss}` };
  }
  if (!verifyJwsSignature(parsed, jwk)) {
    return { ok: false, code: 'pop_failed', detail: 'decision signature does not verify' };
  }

  return { ok: true, claims, jws };
}

/**
 * Do the signed terms match what the Ledger actually recorded?
 *
 * The `amt` comparison is `>=` rather than equality: the stored
 * `maxAmountScaled` is the amount that triggered the step-up, and a principal
 * approving *at least* that much is agreeing to the spend in front of them. A
 * decision for less is refused rather than silently clamped — a human who typed
 * a smaller number did not approve this request.
 */
export function decisionMatches(
  claims: StepUpDecisionClaims,
  record: { root: string; resource: string; maxAmountScaled: bigint; currency: string },
): Check {
  if (claims.root !== record.root) {
    return fail('attenuation_violation', `decision names root ${claims.root}`);
  }
  if (claims.res !== record.resource) {
    return fail('resource_not_covered', `decision names resource ${claims.res}`);
  }
  if (claims.amt.cur !== record.currency) {
    return fail('currency_mismatch', `decision is in ${claims.amt.cur}, request in ${record.currency}`);
  }
  if (toScaled(claims.amt) < record.maxAmountScaled) {
    return fail('amount_exceeds_cap', `decision covers only ${claims.amt.amt} ${claims.amt.cur}`);
  }
  return OK;
}
