import { HTTP_STATUS, PROBLEM_TYPE_BASE, type ErrorCode } from '../errors.js';

/**
 * RFC 9457 problem details. Errors are machine-readable because the client is a
 * machine: an agent that gets a 403 with prose cannot tell "your budget ran out,
 * stop" from "this needs human approval, ask for it".
 */

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  code: ErrorCode;
  [ext: string]: unknown;
}

const TITLES: Partial<Record<ErrorCode, string>> = {
  budget_exhausted: 'Budget exhausted',
  rate_exceeded: 'Rate limit exceeded',
  step_up_required: 'Human approval required',
  mandate_revoked: 'Mandate revoked',
  status_unknown: 'Revocation status could not be established',
  mandate_expired: 'Mandate outside its validity window',
  breaker_tripped: 'Spending halted by a circuit breaker',
  token_replayed: 'Spend token already used',
  token_expired: 'Spend token expired',
  pop_failed: 'Proof of possession failed',
  audience_mismatch: 'Token is for a different merchant',
};

export function problem(
  code: ErrorCode,
  detail: string,
  extensions: Record<string, unknown> = {},
): ProblemDetails {
  return {
    type: `${PROBLEM_TYPE_BASE}${code}`,
    title: TITLES[code] ?? code.replace(/_/g, ' '),
    status: HTTP_STATUS[code],
    detail,
    code,
    ...extensions,
  };
}

export const PROBLEM_CONTENT_TYPE = 'application/problem+json';
