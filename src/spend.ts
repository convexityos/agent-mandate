import { type ErrorCode } from './errors.js';
import type { Settle } from './caveats.js';
import type { Money } from './money.js';
import { type AgentKey } from './sign.js';
import { type Ed25519Jwk } from './didkey.js';
import { encodeSegment, parseCompactJws, verifyJwsSignature } from './jws.js';
import { DEFAULT_SKEW_SECONDS, PROTOCOL_VERSION } from './types.js';
import { sign as cryptoSign } from 'node:crypto';

/**
 * Spec §9 — the Spend Token.
 *
 * Single use, ~60s lifetime, amount-exact, audience-bound. This is the ONLY
 * artifact a merchant sees: it never receives the mandate chain, so it learns
 * nothing about the principal's internal delegation structure, and its entire
 * integration is the five checks in `verifySpendToken`.
 */

export const SPEND_TYP = 'application/agent-spend+jwt';
export const DEFAULT_SPEND_TTL_SECONDS = 60;

export interface SpendClaims {
  v: string;
  typ: 'spend';
  jti: string;
  iss: string;
  aud: string;
  sub: string;
  chain_hash: string;
  amt: Money;
  res: string;
  settle: Settle;
  schema?: string;
  quote_id?: string;
  iat: number;
  exp: number;
  cnf: { jkt: string };
}

export function mintSpendToken(claims: SpendClaims, key: AgentKey): string {
  const header = { alg: 'EdDSA', typ: SPEND_TYP, kid: `${claims.iss}#ledger` };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const sig = cryptoSign(null, Buffer.from(signingInput, 'ascii'), key.privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

export interface ReplayCache {
  /** Returns true if `jti` was already seen; records it either way. */
  seen(jti: string, expiresAt: number): boolean;
}

/**
 * Entries are held until 2× the token lifetime, per §9.2 — a cache that expires
 * entries at the token's own `exp` leaves a window where a token is simultaneously
 * still valid and no longer remembered.
 */
export class MemoryReplayCache implements ReplayCache {
  private readonly entries = new Map<string, number>();

  constructor(private readonly clock: () => number) {}

  seen(jti: string, expiresAt: number): boolean {
    const now = this.clock();
    for (const [k, until] of this.entries) {
      if (until < now) this.entries.delete(k);
    }
    if (this.entries.has(jti)) return true;
    this.entries.set(jti, expiresAt + DEFAULT_SPEND_TTL_SECONDS);
    return false;
  }
}

export interface MerchantVerifyOptions {
  /** The ledger's public key, fetched once from its did:web and cached. */
  ledgerJwk: Ed25519Jwk;
  /** This merchant's own host, as it appears in `aud`. */
  host: string;
  now: number;
  replay: ReplayCache;
  /** Thumbprint of the key that signed the HTTP request (RFC 9421). */
  presenterJkt?: string;
  skewSeconds?: number;
}

export type SpendVerifyResult =
  | { ok: true; claims: SpendClaims }
  | { ok: false; code: ErrorCode; detail: string };

/**
 * §9.2 — the entire merchant-side integration. Five checks, one public key, no
 * network call to the ledger on the hot path.
 */
export function verifySpendToken(token: string, opts: MerchantVerifyOptions): SpendVerifyResult {
  const skew = opts.skewSeconds ?? DEFAULT_SKEW_SECONDS;

  const jws = parseCompactJws(token);
  if (jws === null) return { ok: false, code: 'chain_invalid', detail: 'malformed spend token' };
  if (jws.header.typ !== undefined && jws.header.typ !== SPEND_TYP) {
    return { ok: false, code: 'chain_invalid', detail: `unexpected typ ${jws.header.typ}` };
  }

  // 1. Ledger signature — checked before any claim is trusted.
  if (!verifyJwsSignature(jws, opts.ledgerJwk)) {
    return { ok: false, code: 'chain_invalid', detail: 'ledger signature verification failed' };
  }

  const c = jws.payload as unknown as SpendClaims;
  if (c.v !== PROTOCOL_VERSION || c.typ !== 'spend' || typeof c.jti !== 'string') {
    return { ok: false, code: 'chain_invalid', detail: 'malformed spend claims' };
  }

  // 2. Audience
  if (c.aud !== opts.host) {
    return { ok: false, code: 'audience_mismatch', detail: `token is for ${c.aud}` };
  }

  // 3. Expiry
  if (typeof c.exp !== 'number' || opts.now - skew > c.exp) {
    return { ok: false, code: 'token_expired', detail: 'spend token expired' };
  }

  // 4. Replay. Deliberately after signature and audience: an unsigned or
  //    misaddressed token must not be able to burn a legitimate jti.
  if (opts.replay.seen(c.jti, c.exp)) {
    return { ok: false, code: 'token_replayed', detail: `${c.jti} already spent` };
  }

  // 5. Proof of possession
  if (opts.presenterJkt !== undefined && opts.presenterJkt !== c.cnf?.jkt) {
    return { ok: false, code: 'pop_failed', detail: 'presenter key does not match cnf.jkt' };
  }

  return { ok: true, claims: c };
}
