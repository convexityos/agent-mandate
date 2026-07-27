import type { Ed25519Jwk } from '../didkey.js';
import { parseCompactJws, verifyJwsSignature } from '../jws.js';
import { DIRECTIVE_TYP } from '../ledger/ledger.js';
import { type Directive, intentHash } from '../rail/noncustodial.js';
import type { X402Intent } from '../rail/x402-noncustodial.js';
import { PROTOCOL_VERSION } from '../types.js';
import type { LocalEip3009Signer, SignedAuthorization } from './signer.js';

/**
 * Agent-side handling of a Ledger directive (§12.4).
 *
 * The agent checks the Ledger's work rather than trusting it. Two independent
 * gates stand between a directive and a signature: this module verifies the
 * directive is authentic and internally consistent, and the signer separately
 * enforces the principal's own limits on what it will authorize regardless.
 *
 * Both matter, and for different threats. This one catches a forged or altered
 * directive. The signer catches a *genuine* directive from a Ledger that has
 * been compromised or has a bug — which no amount of signature checking would.
 */

export type DirectiveCheck =
  | { ok: true; directive: Directive }
  | { ok: false; reason: string };

export interface VerifyDirectiveOptions {
  ledgerJwk: Ed25519Jwk;
  /** The Ledger URL this agent expects to be talking to. */
  ledgerUrl: string;
  now: number;
  /** The agent's own did:key thumbprint, checked against `cnf.jkt`. */
  jkt?: string;
  skewSeconds?: number;
}

export function verifyDirective(jws: string, opts: VerifyDirectiveOptions): DirectiveCheck {
  const skew = opts.skewSeconds ?? 60;

  const parsed = parseCompactJws(jws);
  if (parsed === null) return { ok: false, reason: 'malformed directive JWS' };
  if (parsed.header.typ !== undefined && parsed.header.typ !== DIRECTIVE_TYP) {
    return { ok: false, reason: `unexpected typ ${parsed.header.typ}` };
  }
  if (!verifyJwsSignature(parsed, opts.ledgerJwk)) {
    return { ok: false, reason: 'directive signature verification failed' };
  }

  const d = parsed.payload as unknown as Directive;
  if (d.v !== PROTOCOL_VERSION || d.typ !== 'directive') {
    return { ok: false, reason: 'not an am/1 directive' };
  }
  if (d.iss !== opts.ledgerUrl) {
    return { ok: false, reason: `issued by ${d.iss}, expected ${opts.ledgerUrl}` };
  }
  if (opts.jkt !== undefined && d.cnf?.jkt !== opts.jkt) {
    return { ok: false, reason: 'directive is bound to a different agent key' };
  }

  if (typeof d.intent !== 'object' || d.intent === null) {
    return { ok: false, reason: 'directive carries no intent' };
  }
  // The hash is what the Ledger recorded and what it will check the report
  // against. If it disagrees with the intent, one of them has been altered.
  if (intentHash(d.intent) !== d.intentHash) {
    return { ok: false, reason: 'intent does not match intentHash' };
  }

  if (typeof d.expiresAt !== 'number' || opts.now - skew > d.expiresAt) {
    return { ok: false, reason: 'directive has expired' };
  }
  if (typeof d.payer !== 'string' || d.payer === '') {
    return { ok: false, reason: 'directive names no payer' };
  }

  return { ok: true, directive: d };
}

export type ExecuteResult =
  | { ok: true; directive: Directive; signed: SignedAuthorization; report: { signature: string } }
  | { ok: false; reason: string };

export interface ExecuteOptions extends VerifyDirectiveOptions {
  signer: LocalEip3009Signer;
}

/**
 * Verify a directive and sign it, producing the proof the Ledger's `report()`
 * expects.
 *
 * This does **not** submit anything. Broadcasting the authorization to the
 * merchant is the agent runtime's job, and keeping it separate means a signature
 * can be produced, inspected, and discarded without any chance of it having
 * already been spent.
 */
export function executeDirective(jws: string, opts: ExecuteOptions): ExecuteResult {
  const check = verifyDirective(jws, opts);
  if (!check.ok) return { ok: false, reason: check.reason };

  const directive = check.directive;
  const intent = directive.intent as X402Intent;
  if (intent.rail !== 'x402' || typeof intent.domain !== 'object') {
    return { ok: false, reason: `unsupported intent rail: ${String(intent.rail)}` };
  }
  if (intent.authorization?.from?.toLowerCase() !== directive.payer.toLowerCase()) {
    return { ok: false, reason: 'intent funds an account other than the stated payer' };
  }
  if (directive.payer.toLowerCase() !== opts.signer.address.toLowerCase()) {
    return { ok: false, reason: `directive is for ${directive.payer}, this signer is ${opts.signer.address}` };
  }

  try {
    const signed = opts.signer.sign(intent.domain, intent.authorization);
    return { ok: true, directive, signed, report: { signature: signed.signature } };
  } catch (e) {
    // A policy refusal is a normal outcome, not an exception to propagate: the
    // agent should report it and stop, not crash mid-task.
    return { ok: false, reason: (e as Error).message };
  }
}
