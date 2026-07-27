import { createHash } from 'node:crypto';

import { type Check, type ErrorCode, OK, fail } from './errors.js';
import { type Caveats, EFFECT_ORDER, meetCaveats, narrows, validateCaveats } from './caveats.js';
import { type Ed25519Jwk, jwkFromDidKey } from './didkey.js';
import { MANDATE_TYP, type ParsedJws, parseCompactJws, verifyJwsSignature } from './jws.js';
import { toScaled } from './money.js';
import {
  DEFAULT_SKEW_SECONDS,
  MAX_DEPTH,
  type MandateClaims,
  PROTOCOL_VERSION,
  type RequestContext,
  type Window,
} from './types.js';
import { canonicalizeUri, hostOfUri, hostSetContains, uriSetContains } from './uri.js';

export type KeyResolver = (kid: string) => Promise<Ed25519Jwk | null>;

export interface VerifyOptions {
  /** Unix seconds. In online mode this is the ledger's clock, which is authoritative. */
  now: number;
  request: RequestContext;
  isTrustedRootIssuer: (iss: string) => boolean;
  resolveKey?: KeyResolver;
  /**
   * Thumbprint of the key that signed the HTTP request (RFC 9421), as verified
   * by the caller. Message-signature verification is a transport concern and is
   * deliberately outside this module; what belongs here is only the binding
   * check against the leaf's `cnf.jkt`.
   */
  presenterJkt?: string;
  maxDepth?: number;
  skewSeconds?: number;
}

export type VerifyResult =
  | {
      ok: true;
      effective: Caveats;
      window: Window;
      leaf: MandateClaims;
      /** Every link, root first. The ledger debits consumption along this path. */
      links: MandateClaims[];
      /** `links.map(l => l.jti)`, root first. */
      path: string[];
      chainHash: string;
    }
  | { ok: false; code: ErrorCode; detail: string; link?: number };

function bad(code: ErrorCode, detail: string, link?: number): VerifyResult {
  return link === undefined ? { ok: false, code, detail } : { ok: false, code, detail, link };
}

/** did:key only. Sufficient for agents; a did:web resolver belongs in the ledger, with caching. */
export const didKeyResolver: KeyResolver = async (kid) => jwkFromDidKey(kid);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function parseClaims(payload: Record<string, unknown>): MandateClaims | null {
  const {
    v,
    typ,
    jti,
    iss,
    sub,
    par,
    iat,
    nbf,
    exp,
    cnf,
    ledger,
    cav,
    ...rest
  } = payload;

  if (Object.keys(rest).length > 0) return null; // unknown top-level claims fail closed
  if (v !== PROTOCOL_VERSION || typ !== 'mandate') return null;
  if (typeof jti !== 'string' || jti.length === 0) return null;
  if (typeof iss !== 'string' || typeof sub !== 'string') return null;
  if (par !== null && typeof par !== 'string') return null;
  if (!Number.isInteger(iat) || !Number.isInteger(nbf) || !Number.isInteger(exp)) return null;
  if ((nbf as number) > (exp as number)) return null;
  if (!isPlainObject(cnf) || typeof cnf['jkt'] !== 'string') return null;
  if (Object.keys(cnf).length !== 1) return null;
  if (typeof ledger !== 'string' || ledger.length === 0) return null;
  if (!isPlainObject(cav)) return null;

  return {
    v,
    typ: 'mandate',
    jti,
    iss,
    sub,
    par: par as string | null,
    iat: iat as number,
    nbf: nbf as number,
    exp: exp as number,
    cnf: { jkt: cnf['jkt'] },
    ledger,
    cav: cav as Caveats,
  };
}

export function chainHash(tokens: string[]): string {
  return `sha256:${createHash('sha256').update(tokens.join('\n'), 'ascii').digest('hex')}`;
}

/**
 * Spec §7 — chain verification.
 *
 * Returns a result rather than throwing. This runs on attacker-controlled input
 * on the spend path; a thrown exception is one stray try/catch away from being
 * swallowed into an allow.
 */
export async function verifyChain(
  tokens: string[],
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const maxDepth = opts.maxDepth ?? MAX_DEPTH;
  const skew = opts.skewSeconds ?? DEFAULT_SKEW_SECONDS;
  const resolveKey = opts.resolveKey ?? didKeyResolver;

  // 1–3. Structure
  if (!Array.isArray(tokens) || tokens.length < 1 || tokens.length > maxDepth) {
    return bad('chain_invalid', `chain length must be 1..${maxDepth}, got ${tokens?.length}`);
  }

  const parsed: ParsedJws[] = [];
  const links: MandateClaims[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const jws = parseCompactJws(tokens[i]!);
    if (jws === null) return bad('chain_invalid', 'malformed JWS', i);
    if (jws.header.typ !== undefined && jws.header.typ !== MANDATE_TYP) {
      return bad('chain_invalid', `unexpected typ "${jws.header.typ}"`, i);
    }
    const claims = parseClaims(jws.payload);
    if (claims === null) return bad('chain_invalid', 'malformed mandate claims', i);
    const cav = validateCaveats(claims.cav);
    if (!cav.ok) return bad(cav.code, cav.detail, i);
    parsed.push(jws);
    links.push(claims);
  }

  const root = links[0]!;
  const ledger = root.ledger;
  for (let i = 1; i < links.length; i++) {
    if (links[i]!.ledger !== ledger) {
      return bad('chain_invalid', 'links disagree on ledger', i);
    }
  }

  // 4. Root
  if (root.par !== null) return bad('chain_invalid', 'root has a parent', 0);
  if (!opts.isTrustedRootIssuer(root.iss)) {
    return bad('chain_invalid', `untrusted root issuer ${root.iss}`, 0);
  }
  const rootKey = await resolveKey(root.iss);
  if (rootKey === null) return bad('chain_invalid', `unresolvable issuer ${root.iss}`, 0);
  if (!verifyJwsSignature(parsed[0]!, rootKey)) {
    return bad('chain_invalid', 'root signature verification failed', 0);
  }

  // 5. Links + structural rules that are not lattice relations
  //
  // Each child is compared against the ACCUMULATED authority of everything
  // above it, not against its immediate parent. Pairwise narrowing is not
  // transitive: a middle link that simply omits a caveat is ⊤ on that
  // dimension, so a grandchild could re-declare something the root forbade
  // (`settle: escrow_schema` → omitted → `settle: immediate`) and every
  // pairwise check would pass. Folding as we go makes the relation transitive
  // by construction and rejects the escape at the link that attempts it.
  let acc: Caveats = root.cav;
  let remainingDepth = root.cav.depth ?? Number.POSITIVE_INFINITY;

  for (let i = 1; i < links.length; i++) {
    const parent = links[i - 1]!;
    const child = links[i]!;

    if (child.par !== parent.jti) return bad('chain_invalid', 'par does not match parent jti', i);
    if (child.iss !== parent.sub) {
      return bad('chain_invalid', 'child issuer is not the parent subject', i);
    }

    const parentKey = await resolveKey(parent.sub);
    if (parentKey === null) return bad('chain_invalid', `unresolvable subject ${parent.sub}`, i);
    if (!verifyJwsSignature(parsed[i]!, parentKey)) {
      return bad('chain_invalid', 'link signature verification failed', i);
    }

    if (acc.delegable === false) {
      return bad('attenuation_violation', 'an ancestor mandate is not delegable', i);
    }

    // Depth is a counter, not an order: each hop consumes one, and a link may
    // clamp it further. Omission inherits rather than resetting to unbounded.
    remainingDepth = Math.min(child.cav.depth ?? Number.POSITIVE_INFINITY, remainingDepth - 1);
    if (remainingDepth < 0) {
      return bad('depth_exceeded', 'delegation deeper than the grant permits', i);
    }

    // Validity window narrows structurally; exp/nbf are claims, not caveats.
    if (child.exp > parent.exp) return bad('attenuation_violation', 'child outlives parent', i);
    if (child.nbf < parent.nbf) return bad('attenuation_violation', 'child predates parent', i);

    const n = narrows(child.cav, acc);
    if (!n.ok) return bad(n.code, n.detail, i);

    acc = meetCaveats(acc, child.cav);
  }

  // 6. Effective authority
  const effective = acc;
  if (Number.isFinite(remainingDepth)) effective.depth = remainingDepth;

  const wellFormed = validateCaveats(effective);
  if (!wellFormed.ok) return bad(wellFormed.code, `effective authority: ${wellFormed.detail}`);
  const window: Window = {
    nbf: Math.max(...links.map((l) => l.nbf)),
    exp: Math.min(...links.map((l) => l.exp)),
  };

  // Post-condition. Cheap, and it converts a bug in narrows() or a meet()
  // implementation from a silent privilege escalation into a rejected chain.
  for (let i = 0; i < links.length; i++) {
    const post = narrows(effective, links[i]!.cav);
    if (!post.ok) {
      return bad('chain_invalid', `effective authority exceeds link ${i}: ${post.detail}`, i);
    }
  }

  // 7. Window
  if (opts.now + skew < window.nbf) return bad('mandate_expired', 'not yet valid');
  if (opts.now - skew > window.exp) return bad('mandate_expired', 'expired');

  // 8. Request coverage
  const cover = checkRequest(effective, opts.request);
  if (!cover.ok) return bad(cover.code, cover.detail);

  // 9. Proof of possession
  const leaf = links[links.length - 1]!;
  if (opts.presenterJkt !== undefined && opts.presenterJkt !== leaf.cnf.jkt) {
    return bad('pop_failed', 'presenter key does not match leaf cnf.jkt');
  }

  return {
    ok: true,
    effective,
    window,
    leaf,
    links,
    path: links.map((l) => l.jti),
    chainHash: chainHash(tokens),
  };
}

export function checkRequest(eff: Caveats, req: RequestContext): Check {
  const uri = canonicalizeUri(req.resource);
  if (uri === null) return fail('resource_not_covered', `uncanonicalizable resource`);

  const host = hostOfUri(uri);
  if (host === null) return fail('resource_not_covered', 'resource has no host');

  if (eff.aud !== undefined && !hostSetContains(eff.aud, [host])) {
    return fail('audience_mismatch', `${host} not in aud`);
  }
  if (eff.resources !== undefined && !uriSetContains(eff.resources, [uri])) {
    return fail('resource_not_covered', `${uri} not in resources`);
  }
  if (eff.purpose !== undefined) {
    if (req.purpose === undefined || !eff.purpose.includes(req.purpose)) {
      return fail('purpose_not_covered', `purpose ${req.purpose ?? '(none)'} not granted`);
    }
  }
  if (eff.task !== undefined && req.taskId !== eff.task) {
    return fail('purpose_not_covered', `task ${req.taskId ?? '(none)'} not granted`);
  }
  if (eff.effect !== undefined) {
    // Undeclared is ⊤, so a caller that does not classify the call is checked
    // as though it were irreversible. Any mandate that bounds `effect` at all
    // therefore rejects it, which is the intended direction to fail.
    const need = req.effect ?? 'irreversible';
    if (EFFECT_ORDER.indexOf(need) < EFFECT_ORDER.indexOf(eff.effect)) {
      return fail('effect_not_permitted', `effect ${need} exceeds granted ${eff.effect}`);
    }
  }
  if (eff.currency !== undefined && req.amount.cur !== eff.currency) {
    return fail('currency_mismatch', `${req.amount.cur} != ${eff.currency}`);
  }
  if (eff.max_per_txn !== undefined) {
    if (req.amount.cur !== eff.max_per_txn.cur) {
      return fail('currency_mismatch', `${req.amount.cur} != ${eff.max_per_txn.cur}`);
    }
    if (toScaled(req.amount) > toScaled(eff.max_per_txn)) {
      return fail('amount_exceeds_cap', `${req.amount.amt} exceeds ${eff.max_per_txn.amt}`);
    }
  }
  // max_total and rate are consumption state; the ledger enforces them by
  // walking the ancestor path (§10.1–10.2). They are intentionally not checked
  // here — a stateless verifier that pretended to enforce a budget would be
  // worse than one that visibly does not.
  return OK;
}
