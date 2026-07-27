import { sign as cryptoSign } from 'node:crypto';

import { type ParsedJws, encodeSegment, parseCompactJws, verifyJwsSignature } from './jws.js';
import type { AgentKey } from './sign.js';
import { PROTOCOL_VERSION } from './types.js';
import { type KeyResolver, didKeyResolver } from './verify.js';

/**
 * §10.6 — control actions a principal takes on their own subtree.
 *
 * `setGlobalKill` and `revoke` have existed since the ledger did, and neither
 * asked who was calling. That was tolerable while the only caller was code
 * running inside the deployment. It stops being tolerable the moment a console
 * exposes them over HTTP, because the most likely thing on the far side of that
 * network is the agent the kill switch was pulled to stop.
 *
 * So a control action is a signed statement, exactly as a step-up decision is
 * (§10.5), and for the same reason: the party being restrained must not be able
 * to lift the restraint.
 *
 * ## Two things this needs that a step-up decision does not
 *
 * **A nonce.** A step-up decision names a one-shot handle, so replaying it is
 * caught by the handle already being spent. A control action names no handle. A
 * replayed `kill` is harmless — it re-kills — but a replayed `release` restarts
 * spending that a principal deliberately halted, and an agent that captured one
 * release only has to wait for the next incident. Every decision carries a `jti`
 * that the ledger consumes exactly once, durably.
 *
 * **Ownership, not just trust.** `isTrustedRootIssuer` answers "is this DID a
 * principal we trust", not "is this DID *this subtree's* principal". A
 * deployment serving two principals would otherwise let either halt or revoke
 * the other's mandates. The ledger checks the decision's issuer against the root
 * node's recorded `issuer`.
 */

export const CONTROL_TYP = 'application/agent-control+jwt';

export type ControlAction = 'kill' | 'release' | 'revoke';

export interface ControlDecisionClaims {
  v: string;
  typ: 'control';
  /** One-time nonce. See the note on replay above. */
  jti: string;
  /** The deciding principal. Checked against the root node's issuer, not merely trusted. */
  iss: string;
  action: ControlAction;
  /** The root whose subtree this acts on. */
  root: string;
  /** For `revoke`: the mandate to revoke. MUST be in `root`'s subtree. */
  target?: string;
  iat: number;
  exp: number;
  reason?: string;
}

/**
 * Short by default. A signed control action is a bearer credential for as long
 * as it is valid, and the nonce only stops the *second* use — a captured
 * decision that has not been used yet is still live until it expires.
 */
export const DEFAULT_CONTROL_TTL_SECONDS = 300;

export function signControlDecision(claims: ControlDecisionClaims, key: AgentKey): string {
  const header = { alg: 'EdDSA', typ: CONTROL_TYP, kid: claims.iss };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  return `${signingInput}.${cryptoSign(null, Buffer.from(signingInput, 'ascii'), key.privateKey).toString('base64url')}`;
}

function parseClaims(payload: Record<string, unknown>): ControlDecisionClaims | null {
  const { v, typ, jti, iss, action, root, target, iat, exp, reason } = payload;
  if (v !== PROTOCOL_VERSION || typ !== 'control') return null;
  if (typeof jti !== 'string' || jti.length === 0) return null;
  if (typeof iss !== 'string' || iss.length === 0) return null;
  if (action !== 'kill' && action !== 'release' && action !== 'revoke') return null;
  if (typeof root !== 'string' || root.length === 0) return null;
  if (target !== undefined && (typeof target !== 'string' || target.length === 0)) return null;
  // A revoke with nothing to revoke is malformed, not a no-op.
  if (action === 'revoke' && target === undefined) return null;
  if (typeof iat !== 'number' || typeof exp !== 'number') return null;
  if (reason !== undefined && typeof reason !== 'string') return null;
  return {
    v,
    typ,
    jti,
    iss,
    action,
    root,
    ...(target !== undefined ? { target } : {}),
    iat,
    exp,
    ...(reason !== undefined ? { reason } : {}),
  };
}

export interface VerifyControlOptions {
  now: number;
  isTrustedRootIssuer: (iss: string) => boolean;
  resolveKey?: KeyResolver;
  skewSeconds?: number;
}

export type ControlVerifyResult =
  | { ok: true; claims: ControlDecisionClaims }
  | { ok: false; code: import('./errors.js').ErrorCode; detail: string };

/**
 * Shape, freshness and signature. Ownership and replay are checked by the
 * Ledger, which is the only place that knows the root's issuer and can consume
 * a nonce atomically.
 */
export async function verifyControlDecision(
  jws: string,
  opts: VerifyControlOptions,
): Promise<ControlVerifyResult> {
  const parsed: ParsedJws | null = parseCompactJws(jws);
  if (parsed === null) return { ok: false, code: 'chain_invalid', detail: 'unparseable decision' };
  if (parsed.header.typ !== CONTROL_TYP) {
    return { ok: false, code: 'chain_invalid', detail: `unexpected typ ${parsed.header.typ}` };
  }

  const claims = parseClaims(parsed.payload);
  if (claims === null) {
    return { ok: false, code: 'chain_invalid', detail: 'malformed control claims' };
  }
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

  return { ok: true, claims };
}
