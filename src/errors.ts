/**
 * Error codes from spec §15. Verifiers return these rather than throwing:
 * chain verification runs on untrusted input, and a thrown exception is far
 * too easy for a caller to accidentally swallow into an "allow".
 */
export type ErrorCode =
  | 'chain_invalid'
  | 'unknown_caveat'
  | 'attenuation_violation'
  | 'depth_exceeded'
  | 'mandate_expired'
  | 'mandate_revoked'
  | 'status_unknown'
  | 'offline_profile_violated'
  | 'pop_failed'
  | 'resource_not_covered'
  | 'audience_mismatch'
  | 'purpose_not_covered'
  | 'effect_not_permitted'
  | 'currency_mismatch'
  | 'amount_exceeds_cap'
  | 'budget_exhausted'
  | 'rate_exceeded'
  | 'step_up_required'
  | 'token_expired'
  | 'token_replayed'
  | 'breaker_tripped'
  | 'quote_mismatch'
  | 'quote_expired';

export const HTTP_STATUS: Readonly<Record<ErrorCode, number>> = {
  chain_invalid: 400,
  unknown_caveat: 400,
  attenuation_violation: 403,
  depth_exceeded: 403,
  mandate_expired: 403,
  mandate_revoked: 403,
  // 503, not 403. "This mandate is revoked" and "I could not find out whether
  // this mandate is revoked" are different facts, and only the first is a
  // decision about the credential. Collapsing them onto 403 tells an agent to
  // stop presenting a chain that is very likely fine, and hides a status-list
  // outage inside a wall of ordinary refusals.
  status_unknown: 503,
  // 403: the chain is perfectly valid, it simply may not be settled without the
  // Ledger. The same credential presented online is fine, so this is a refusal
  // about the *mode* rather than about the mandate.
  offline_profile_violated: 403,
  pop_failed: 401,
  resource_not_covered: 403,
  audience_mismatch: 403,
  purpose_not_covered: 403,
  effect_not_permitted: 403,
  currency_mismatch: 400,
  amount_exceeds_cap: 403,
  budget_exhausted: 402,
  rate_exceeded: 429,
  step_up_required: 403,
  token_expired: 401,
  token_replayed: 409,
  breaker_tripped: 403,
  // 409 Conflict: the quote hash, terms, or expiry disagree with the merchant's
  // current state. Distinct from 402 so clients do not mistake a rejected
  // payment for a fresh unattempted challenge.
  quote_mismatch: 409,
  quote_expired: 409,
};

export const PROBLEM_TYPE_BASE = 'https://agentmandate.org/errors/';

export type Check = { ok: true } | { ok: false; code: ErrorCode; detail: string };

export const OK: Check = Object.freeze({ ok: true });

export function fail(code: ErrorCode, detail: string): Check {
  return { ok: false, code, detail };
}
