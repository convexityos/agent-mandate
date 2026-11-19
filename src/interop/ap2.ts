import { type Caveats, type Effect, type Settle, validateCaveats } from '../caveats.js';
import { type ErrorCode } from '../errors.js';
import { type Money, isMoney, moneyLeq, moneyMin, toScaled } from '../money.js';
import { type Receipt, canonicalJson, sha256Hex } from '../receipt.js';
import { type AgentKey, signMandate } from '../sign.js';
import { MAX_DEPTH, type MandateClaims, PROTOCOL_VERSION } from '../types.js';
import { canonicalizeUri, hostOfUri, parseHostPattern, parseUriPattern } from '../uri.js';

/**
 * Agent Payments Protocol (AP2) interop adapter (spec §12.5).
 *
 * Maps AP2 IntentMandates and CartMandates onto root `am/1` mandates so that
 * downstream delegation, per-node budgets, circuit breakers, step-up approvals,
 * and dual-signed receipts apply uniformly above AP2 credentials. Also exports
 * signed `am/1` receipts into AP2 PaymentMandate payloads.
 *
 * Security posture is strictly fail-closed:
 *   - Missing, unparseable, or expired `intent_expiry` / `cart_expiry` fails.
 *   - Unbounded budgets are refused: every mapped mandate carries a positive
 *     finite `max_total` and `currency`.
 *   - `user_cart_confirmation_required: true` enforces `step_up: { over: 0 }`
 *     unless a CartMandate has already been explicitly confirmed by the user.
 *   - `requires_refundability: true` requires escrow settlement and rejects
 *     `'immediate'`.
 *   - Wildcard or malformed merchant patterns fail closed.
 */

export interface Ap2Money {
  currency: string;
  value: number | string;
}

export interface Ap2IntentMandate {
  user_cart_confirmation_required: boolean;
  natural_language_description: string;
  merchants?: string[];
  skus?: string[];
  requires_refundability?: boolean;
  intent_expiry: string;
  /** Optional spending cap extension; if absent, `opts.maxTotal` is required. */
  max_amount?: Ap2Money;
}

export interface Ap2DisplayItem {
  label: string;
  amount: Ap2Money;
}

export interface Ap2PaymentMethodData {
  supported_methods: string;
  data?: Record<string, unknown>;
}

export interface Ap2PaymentRequest {
  method_data?: Ap2PaymentMethodData[];
  details: {
    id: string;
    total: Ap2DisplayItem;
    display_items?: Ap2DisplayItem[];
  };
}

export interface Ap2CartContents {
  id: string;
  user_cart_confirmation_required: boolean;
  payment_request: Ap2PaymentRequest;
  cart_expiry: string;
  merchant_name: string;
  /** Optional canonical HTTPS endpoint or origin for the merchant. */
  merchant_url?: string;
}

export interface Ap2CartMandate {
  contents: Ap2CartContents;
  /** Merchant JWS / JWT over `contents`. Required by default. */
  merchant_authorization?: string;
}

export interface Ap2PaymentMandate {
  payment_mandate_contents: {
    payment_mandate_id: string;
    payment_details_id: string;
    payment_details_total: Ap2DisplayItem;
    payment_response: {
      request_id: string;
      method_name: string;
      details?: Record<string, unknown>;
    };
    merchant_agent: string;
    timestamp: string;
  };
  user_authorization?: string;
  am1_provenance: {
    spend_id: string;
    chain_hash: string;
    root_jti: string;
    receipt_jti: string;
    receipt_sig: string;
  };
}

export type Ap2AdapterResult =
  | { ok: true; claims: MandateClaims; provenanceHash: string }
  | { ok: false; code: ErrorCode; detail: string };

export type Ap2IssueResult =
  | { ok: true; token: string; claims: MandateClaims; provenanceHash: string }
  | { ok: false; code: ErrorCode; detail: string };

export interface Ap2CommonAdapterOptions {
  /** Root issuer DID (principal). */
  issuer: string;
  /** Initial agent subject DID. */
  subject: string;
  /** RFC 7638 JWK thumbprint of `subject`'s PoP key. */
  subjectJkt: string;
  /** Authoritative Ledger base URI. */
  ledger: string;
  /** Current UNIX epoch seconds. */
  now: number;
  /** Optional custom `jti`; defaults to deterministic `mnd_ap2_<digest>`. */
  jti?: string;
  /** Optional `nbf`; defaults to `now`. */
  nbf?: number;
  /** Optional offline revocation status list index (`st`). */
  statusIdx?: number;
  /** Optional `purpose` allowlist caveat. */
  purpose?: string[];
  /** Optional blast-radius `effect` caveat. */
  effect?: Effect;
  /** Optional `payer` account hint for non-custodial rails. */
  payer?: string;
}

export interface Ap2IntentAdapterOptions extends Ap2CommonAdapterOptions {
  /**
   * Required when `intent.max_amount` is absent. When both are present, the
   * stricter (smaller) cap wins and currencies must match.
   */
  maxTotal?: Money;
  /** Optional per-transaction cap; must be <= effective `max_total`. */
  maxPerTxn?: Money;
  /** Optional map from AP2 merchant names/identifiers to hostnames or HTTPS URLs. */
  merchantMap?: Readonly<Record<string, string>>;
  /** Optional delegation depth limit (default 2, capped at MAX_DEPTH). */
  maxDepth?: number;
  /** Whether the root mandate may be sub-delegated (default true). */
  delegable?: boolean;
  /**
   * Settlement mode used when `intent.requires_refundability` is true.
   * Must be `'escrow_human'` (default) or `'escrow_schema'`; `'immediate'` is refused.
   */
  refundableSettle?: Settle;
  /** Settlement mode when `requires_refundability` is false/absent. */
  settle?: Settle;
  /** Optional explicit task id (defaults to `ap2:<digest-prefix>`). */
  taskId?: string;
}

export interface Ap2CartAdapterOptions extends Ap2CommonAdapterOptions {
  /** Canonical HTTPS resource URI or pattern for the checkout endpoint. */
  resource?: string;
  /** Explicit merchant hostname when `resource` and `contents.merchant_url` are absent. */
  merchantHost?: string;
  /**
   * Require `cart.merchant_authorization` to be present (default true).
   * Set false only in explicit testing or when verified upstream.
   */
  requireMerchantAuthorization?: boolean;
  /**
   * Optional cryptographic verifier for `cart.merchant_authorization`.
   * Return true iff the signature validly covers `cart.contents`.
   */
  verifyMerchantAuthorization?: (cart: Ap2CartMandate) => boolean;
  /**
   * Set true only when the principal has already explicitly confirmed this
   * exact cart out of band; otherwise `user_cart_confirmation_required: true`
   * forces `step_up: { over: 0 }`.
   */
  userConfirmed?: boolean;
  /** Optional parent AP2 IntentMandate to enforce containment against. */
  parentIntent?: Ap2IntentMandate;
  /** Optional map from AP2 merchant names to hosts/URLs when checking `parentIntent.merchants`. */
  merchantMap?: Readonly<Record<string, string>>;
  /** Whether the cart mandate may be sub-delegated (default false). */
  delegable?: boolean;
  /** Settlement mode (default `'immediate'`, or `'escrow_human'` if `parentIntent.requires_refundability`). */
  settle?: Settle;
}

const DECIMAL_STR_RE = /^(0|[1-9][0-9]*)(\.[0-9]{1,9})?$/;

/**
 * Parse an AP2 `PaymentCurrencyAmount` into an exact protocol `Money`.
 * Never uses binary float rounding: rejects NaN, Infinity, negatives,
 * scientific notation with >9 decimals, or malformed currency codes.
 */
export function ap2MoneyToMoney(
  input: unknown,
): { ok: true; money: Money } | { ok: false; code: ErrorCode; detail: string } {
  if (typeof input !== 'object' || input === null) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 money must be an object' };
  }
  const obj = input as Record<string, unknown>;
  if (typeof obj['currency'] !== 'string' || obj['currency'].trim().length === 0) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 money missing currency' };
  }
  const cur = obj['currency'].trim().toUpperCase();
  const rawVal = obj['value'];

  let amt: string;
  if (typeof rawVal === 'string') {
    amt = rawVal.trim();
  } else if (typeof rawVal === 'number') {
    if (!Number.isFinite(rawVal) || rawVal < 0) {
      return { ok: false, code: 'chain_invalid', detail: 'AP2 money value must be a non-negative finite number' };
    }
    // Reject scientific notation or binary float artifacts beyond 9 decimal places.
    const s = String(rawVal);
    if (s.includes('e') || s.includes('E')) {
      return { ok: false, code: 'chain_invalid', detail: `AP2 money value "${s}" must be a plain decimal` };
    }
    amt = s;
  } else {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 money value must be a string or number' };
  }

  if (!DECIMAL_STR_RE.test(amt)) {
    return {
      ok: false,
      code: 'chain_invalid',
      detail: `AP2 money value "${amt}" is not a valid non-negative decimal (max 9 fractional digits)`,
    };
  }

  // Normalize trailing fractional zeros only if decimal point exists? Keep exact
  // representation because `isMoney` accepts valid decimal strings directly.
  const money: Money = { cur, amt };
  if (!isMoney(money)) {
    return { ok: false, code: 'chain_invalid', detail: `invalid AP2 currency or amount: ${cur} ${amt}` };
  }
  return { ok: true, money };
}

function parseIsoEpochSeconds(raw: unknown, label: string): { ok: true; epoch: number } | { ok: false; detail: string } {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    return { ok: false, detail: `${label} must be a non-empty ISO-8601 timestamp` };
  }
  // Require explicit timezone offset (`Z` or `±HH:MM`) so expiry is unambiguous across hosts.
  if (!/(?:Z|[+-]\d{2}:\d{2})$/.test(raw.trim())) {
    return { ok: false, detail: `${label} must include an explicit timezone offset (e.g. Z)` };
  }
  const ms = Date.parse(raw.trim());
  if (!Number.isFinite(ms)) {
    return { ok: false, detail: `${label} is not a valid ISO-8601 timestamp` };
  }
  return { ok: true, epoch: Math.floor(ms / 1000) };
}

function resolveMerchantEntry(
  raw: string,
  merchantMap?: Readonly<Record<string, string>>,
): { ok: true; host: string; resource?: string } | { ok: false; detail: string } {
  const mapped = merchantMap?.[raw] ?? raw;
  const trimmed = mapped.trim();
  if (trimmed.length === 0) {
    return { ok: false, detail: 'AP2 merchant entry cannot be empty' };
  }
  if (trimmed.includes('*')) {
    return { ok: false, detail: `wildcard merchant pattern refused: ${trimmed}` };
  }
  if (trimmed.includes('://')) {
    const canon = canonicalizeUri(trimmed);
    if (canon === null || !canon.startsWith('https://')) {
      return { ok: false, detail: `AP2 merchant URL must be a valid https URI: ${trimmed}` };
    }
    const host = hostOfUri(canon);
    if (host === null) {
      return { ok: false, detail: `cannot extract host from AP2 merchant URL: ${trimmed}` };
    }
    const pattern = canon.endsWith('/') ? `${canon}*` : `${canon}/*`;
    if (parseUriPattern(pattern) === null) {
      return { ok: false, detail: `invalid AP2 merchant resource pattern: ${pattern}` };
    }
    return { ok: true, host, resource: pattern };
  }
  const hostPat = parseHostPattern(trimmed);
  if (hostPat === null || hostPat.wildcard) {
    return { ok: false, detail: `invalid AP2 merchant host: ${trimmed}` };
  }
  return { ok: true, host: hostPat.host };
}

function validateCommonOptions(opts: Ap2CommonAdapterOptions): string | null {
  if (!opts.issuer || !opts.subject || !opts.subjectJkt || !opts.ledger) {
    return 'issuer, subject, subjectJkt, and ledger are required';
  }
  if (!Number.isInteger(opts.now) || opts.now <= 0) {
    return 'now must be a positive integer epoch timestamp';
  }
  const nbf = opts.nbf ?? opts.now;
  if (!Number.isInteger(nbf) || nbf <= 0) {
    return 'nbf must be a positive integer epoch timestamp';
  }
  if (opts.statusIdx !== undefined && (!Number.isInteger(opts.statusIdx) || opts.statusIdx < 0)) {
    return 'statusIdx must be a non-negative integer';
  }
  return null;
}

/** Deterministic SHA-256 provenance digest over an AP2 IntentMandate. */
export function ap2IntentDigest(intent: Ap2IntentMandate): string {
  return sha256Hex(canonicalJson(intent));
}

/** Deterministic SHA-256 provenance digest over an AP2 CartMandate contents block. */
export function ap2CartDigest(contents: Ap2CartContents): string {
  return sha256Hex(canonicalJson(contents));
}

/**
 * Translate an AP2 IntentMandate into root `am/1` MandateClaims.
 * Fails closed on missing budget, expired intent, invalid merchant entries,
 * or refundability/settlement mismatches.
 */
export function mandateClaimsFromAp2Intent(
  intent: Ap2IntentMandate,
  opts: Ap2IntentAdapterOptions,
): Ap2AdapterResult {
  const optErr = validateCommonOptions(opts);
  if (optErr !== null) return { ok: false, code: 'chain_invalid', detail: optErr };

  if (typeof intent !== 'object' || intent === null) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 IntentMandate must be an object' };
  }
  if (typeof intent.user_cart_confirmation_required !== 'boolean') {
    return {
      ok: false,
      code: 'chain_invalid',
      detail: 'AP2 IntentMandate missing boolean user_cart_confirmation_required',
    };
  }
  if (
    typeof intent.natural_language_description !== 'string' ||
    intent.natural_language_description.trim().length === 0
  ) {
    return {
      ok: false,
      code: 'chain_invalid',
      detail: 'AP2 IntentMandate missing natural_language_description',
    };
  }

  const expiry = parseIsoEpochSeconds(intent.intent_expiry, 'intent_expiry');
  if (!expiry.ok) return { ok: false, code: 'chain_invalid', detail: expiry.detail };
  if (expiry.epoch <= opts.now) {
    return { ok: false, code: 'mandate_expired', detail: 'AP2 IntentMandate is already expired' };
  }

  const nbf = opts.nbf ?? opts.now;
  if (nbf >= expiry.epoch) {
    return { ok: false, code: 'chain_invalid', detail: 'nbf must precede intent_expiry' };
  }

  // Resolve spending cap: never mint an unbounded mandate.
  let intentCap: Money | undefined;
  if (intent.max_amount !== undefined) {
    const parsed = ap2MoneyToMoney(intent.max_amount);
    if (!parsed.ok) return parsed;
    intentCap = parsed.money;
  }
  if (opts.maxTotal !== undefined && !isMoney(opts.maxTotal)) {
    return { ok: false, code: 'chain_invalid', detail: 'opts.maxTotal is not valid Money' };
  }

  let effectiveCap: Money;
  if (intentCap !== undefined && opts.maxTotal !== undefined) {
    if (intentCap.cur !== opts.maxTotal.cur) {
      return {
        ok: false,
        code: 'currency_mismatch',
        detail: `AP2 intent max_amount currency ${intentCap.cur} disagrees with maxTotal ${opts.maxTotal.cur}`,
      };
    }
    effectiveCap = moneyMin(intentCap, opts.maxTotal);
  } else if (intentCap !== undefined) {
    effectiveCap = intentCap;
  } else if (opts.maxTotal !== undefined) {
    effectiveCap = opts.maxTotal;
  } else {
    return {
      ok: false,
      code: 'chain_invalid',
      detail: 'AP2 IntentMandate requires a spending cap via intent.max_amount or opts.maxTotal',
    };
  }

  if (toScaled(effectiveCap) <= 0n) {
    return { ok: false, code: 'chain_invalid', detail: 'spending cap must be strictly positive' };
  }

  let maxPerTxn = effectiveCap;
  if (opts.maxPerTxn !== undefined) {
    if (!isMoney(opts.maxPerTxn)) {
      return { ok: false, code: 'chain_invalid', detail: 'opts.maxPerTxn is not valid Money' };
    }
    const leq = moneyLeq(opts.maxPerTxn, effectiveCap);
    if (!leq.ok) return leq;
    if (toScaled(opts.maxPerTxn) <= 0n) {
      return { ok: false, code: 'chain_invalid', detail: 'opts.maxPerTxn must be strictly positive' };
    }
    maxPerTxn = opts.maxPerTxn;
  }

  const maxDepth = opts.maxDepth ?? 2;
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > MAX_DEPTH) {
    return {
      ok: false,
      code: 'depth_exceeded',
      detail: `maxDepth must be an integer between 0 and ${MAX_DEPTH}`,
    };
  }

  // Settlement mode & refundability guarantee.
  let settle: Settle | undefined = opts.settle;
  if (intent.requires_refundability === true) {
    const requested = opts.refundableSettle ?? 'escrow_human';
    if (requested === 'immediate') {
      return {
        ok: false,
        code: 'attenuation_violation',
        detail: 'AP2 IntentMandate requires_refundability=true cannot map to immediate settlement',
      };
    }
    settle = requested;
  }

  // Merchants allowlist -> aud (+ resources when URLs are supplied).
  let aud: string[] | undefined;
  let resources: string[] | undefined;
  if (intent.merchants !== undefined) {
    if (!Array.isArray(intent.merchants) || intent.merchants.length === 0) {
      return {
        ok: false,
        code: 'chain_invalid',
        detail: 'AP2 IntentMandate merchants allowlist, when present, must be non-empty',
      };
    }
    const hosts = new Set<string>();
    const resPatterns = new Set<string>();
    for (const m of intent.merchants) {
      if (typeof m !== 'string') {
        return { ok: false, code: 'chain_invalid', detail: 'AP2 merchant entries must be strings' };
      }
      const resolved = resolveMerchantEntry(m, opts.merchantMap);
      if (!resolved.ok) return { ok: false, code: 'chain_invalid', detail: resolved.detail };
      hosts.add(resolved.host);
      if (resolved.resource !== undefined) resPatterns.add(resolved.resource);
    }
    aud = [...hosts].sort();
    if (resPatterns.size === intent.merchants.length) {
      resources = [...resPatterns].sort();
    }
  }

  const provenanceHash = ap2IntentDigest(intent);
  const hashSuffix = provenanceHash.slice('sha256:'.length, 'sha256:'.length + 16);

  const cav: Caveats = {
    currency: effectiveCap.cur,
    max_total: effectiveCap,
    max_per_txn: maxPerTxn,
    depth: maxDepth,
    delegable: opts.delegable ?? true,
    task: opts.taskId ?? `ap2:${hashSuffix}`,
  };
  if (aud !== undefined) cav.aud = aud;
  if (resources !== undefined) cav.resources = resources;
  if (settle !== undefined) cav.settle = settle;
  if (opts.purpose !== undefined) cav.purpose = opts.purpose;
  if (opts.effect !== undefined) cav.effect = opts.effect;
  if (opts.payer !== undefined) cav.payer = opts.payer;

  // Preserve human-in-the-loop cart confirmation by requiring step-up above 0.
  if (intent.user_cart_confirmation_required) {
    cav.step_up = { over: { cur: effectiveCap.cur, amt: '0' } };
  }

  const cavCheck = validateCaveats(cav);
  if (!cavCheck.ok) return cavCheck;

  const claims: MandateClaims = {
    v: PROTOCOL_VERSION,
    typ: 'mandate',
    jti: opts.jti ?? `mnd_ap2_${hashSuffix}`,
    iss: opts.issuer,
    sub: opts.subject,
    par: null,
    iat: opts.now,
    nbf,
    exp: expiry.epoch,
    cnf: { jkt: opts.subjectJkt },
    ledger: opts.ledger,
    cav,
  };
  if (opts.statusIdx !== undefined) claims.st = opts.statusIdx;

  return { ok: true, claims, provenanceHash };
}

/** Validate and sign a root `am/1` mandate from an AP2 IntentMandate. */
export function issueMandateFromAp2Intent(
  intent: Ap2IntentMandate,
  signer: AgentKey,
  opts: Omit<Ap2IntentAdapterOptions, 'issuer'> & { issuer?: string; kid?: string },
): Ap2IssueResult {
  const res = mandateClaimsFromAp2Intent(intent, {
    ...opts,
    issuer: opts.issuer ?? signer.did,
  });
  if (!res.ok) return res;
  const token = signMandate(res.claims, signer, opts.kid);
  return { ok: true, token, claims: res.claims, provenanceHash: res.provenanceHash };
}

/**
 * Translate an AP2 CartMandate into a tightly pinned one-shot root `am/1` mandate.
 * Enforces merchant authorization by default, checks display_items currency
 * consistency, validates against an optional parent IntentMandate, and preserves
 * `user_cart_confirmation_required` unless explicitly confirmed.
 */
export function mandateClaimsFromAp2Cart(
  cart: Ap2CartMandate,
  opts: Ap2CartAdapterOptions,
): Ap2AdapterResult {
  const optErr = validateCommonOptions(opts);
  if (optErr !== null) return { ok: false, code: 'chain_invalid', detail: optErr };

  if (typeof cart !== 'object' || cart === null || typeof cart.contents !== 'object' || cart.contents === null) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 CartMandate must contain a contents object' };
  }
  const c = cart.contents;
  if (typeof c.id !== 'string' || c.id.trim().length === 0) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 CartMandate contents.id is required' };
  }
  if (typeof c.merchant_name !== 'string' || c.merchant_name.trim().length === 0) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 CartMandate contents.merchant_name is required' };
  }
  if (typeof c.user_cart_confirmation_required !== 'boolean') {
    return {
      ok: false,
      code: 'chain_invalid',
      detail: 'AP2 CartMandate missing boolean user_cart_confirmation_required',
    };
  }

  // Merchant authorization check (fail-closed by default).
  const requireAuth = opts.requireMerchantAuthorization ?? true;
  if (requireAuth) {
    if (typeof cart.merchant_authorization !== 'string' || cart.merchant_authorization.trim().length === 0) {
      return {
        ok: false,
        code: 'chain_invalid',
        detail: 'AP2 CartMandate missing required merchant_authorization',
      };
    }
  }
  if (opts.verifyMerchantAuthorization !== undefined) {
    if (!opts.verifyMerchantAuthorization(cart)) {
      return {
        ok: false,
        code: 'pop_failed',
        detail: 'AP2 CartMandate merchant_authorization signature verification failed',
      };
    }
  }

  const expiry = parseIsoEpochSeconds(c.cart_expiry, 'cart_expiry');
  if (!expiry.ok) return { ok: false, code: 'chain_invalid', detail: expiry.detail };
  if (expiry.epoch <= opts.now) {
    return { ok: false, code: 'mandate_expired', detail: 'AP2 CartMandate is already expired' };
  }
  const nbf = opts.nbf ?? opts.now;
  if (nbf >= expiry.epoch) {
    return { ok: false, code: 'chain_invalid', detail: 'nbf must precede cart_expiry' };
  }

  const details = c.payment_request?.details;
  if (typeof details !== 'object' || details === null || typeof details.total !== 'object' || details.total === null) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 CartMandate missing payment_request.details.total' };
  }
  const totalParsed = ap2MoneyToMoney(details.total.amount);
  if (!totalParsed.ok) return totalParsed;
  const total = totalParsed.money;
  if (toScaled(total) <= 0n) {
    return { ok: false, code: 'chain_invalid', detail: 'AP2 CartMandate total must be strictly positive' };
  }

  if (details.display_items !== undefined) {
    if (!Array.isArray(details.display_items)) {
      return { ok: false, code: 'chain_invalid', detail: 'AP2 CartMandate display_items must be an array' };
    }
    for (const item of details.display_items) {
      const parsedItem = ap2MoneyToMoney(item?.amount);
      if (!parsedItem.ok) return parsedItem;
      if (parsedItem.money.cur !== total.cur) {
        return {
          ok: false,
          code: 'currency_mismatch',
          detail: `AP2 CartMandate display item currency ${parsedItem.money.cur} does not match total ${total.cur}`,
        };
      }
    }
  }

  // Resolve merchant host & resource pinning.
  let host: string | undefined;
  let resourcePattern: string | undefined;
  const rawResource = opts.resource ?? c.merchant_url;
  if (rawResource !== undefined) {
    const canon = canonicalizeUri(rawResource);
    if (canon === null || !canon.startsWith('https://')) {
      return { ok: false, code: 'chain_invalid', detail: `invalid AP2 cart merchant URL: ${rawResource}` };
    }
    const extracted = hostOfUri(canon);
    if (extracted === null) {
      return { ok: false, code: 'chain_invalid', detail: `cannot determine host from URL: ${rawResource}` };
    }
    host = extracted;
    resourcePattern = canon;
  } else if (opts.merchantHost !== undefined) {
    const hp = parseHostPattern(opts.merchantHost);
    if (hp === null || hp.wildcard) {
      return { ok: false, code: 'chain_invalid', detail: `invalid merchantHost: ${opts.merchantHost}` };
    }
    host = hp.host;
  }

  // Optional parent AP2 IntentMandate containment checks.
  let settle: Settle | undefined = opts.settle;
  if (opts.parentIntent !== undefined) {
    const intent = opts.parentIntent;
    const intentExp = parseIsoEpochSeconds(intent.intent_expiry, 'parentIntent.intent_expiry');
    if (!intentExp.ok) return { ok: false, code: 'chain_invalid', detail: intentExp.detail };
    if (expiry.epoch > intentExp.epoch) {
      return {
        ok: false,
        code: 'attenuation_violation',
        detail: 'AP2 CartMandate cart_expiry exceeds parent IntentMandate intent_expiry',
      };
    }
    if (intent.max_amount !== undefined) {
      const parentCap = ap2MoneyToMoney(intent.max_amount);
      if (!parentCap.ok) return parentCap;
      const capCheck = moneyLeq(total, parentCap.money);
      if (!capCheck.ok) return capCheck;
    }
    if (intent.merchants !== undefined && intent.merchants.length > 0) {
      const allowedNames = new Set(intent.merchants);
      const allowedHosts = new Set<string>();
      for (const m of intent.merchants) {
        const r = resolveMerchantEntry(m, opts.merchantMap);
        if (r.ok) allowedHosts.add(r.host);
      }
      const nameAllowed = allowedNames.has(c.merchant_name);
      const hostAllowed = host !== undefined && allowedHosts.has(host);
      if (!nameAllowed && !hostAllowed) {
        return {
          ok: false,
          code: 'audience_mismatch',
          detail: `AP2 CartMandate merchant "${c.merchant_name}" is not in parent IntentMandate allowlist`,
        };
      }
    }
    if (intent.requires_refundability === true) {
      if (settle === 'immediate') {
        return {
          ok: false,
          code: 'attenuation_violation',
          detail: 'parent IntentMandate requires_refundability=true forbids immediate settlement',
        };
      }
      settle = settle ?? 'escrow_human';
    }
  }

  const provenanceHash = ap2CartDigest(c);
  const hashSuffix = provenanceHash.slice('sha256:'.length, 'sha256:'.length + 16);

  const cav: Caveats = {
    currency: total.cur,
    max_total: total,
    max_per_txn: total,
    rate: { n: 1, per: 'PT24H' },
    depth: 0,
    delegable: opts.delegable ?? false,
    task: `ap2cart:${c.id}`,
  };
  if (host !== undefined) cav.aud = [host];
  if (resourcePattern !== undefined) cav.resources = [resourcePattern];
  if (settle !== undefined) cav.settle = settle;
  if (opts.purpose !== undefined) cav.purpose = opts.purpose;
  if (opts.effect !== undefined) cav.effect = opts.effect;
  if (opts.payer !== undefined) cav.payer = opts.payer;

  if (c.user_cart_confirmation_required && opts.userConfirmed !== true) {
    cav.step_up = { over: { cur: total.cur, amt: '0' } };
  }

  const cavCheck = validateCaveats(cav);
  if (!cavCheck.ok) return cavCheck;

  const claims: MandateClaims = {
    v: PROTOCOL_VERSION,
    typ: 'mandate',
    jti: opts.jti ?? `mnd_ap2c_${hashSuffix}`,
    iss: opts.issuer,
    sub: opts.subject,
    par: null,
    iat: opts.now,
    nbf,
    exp: expiry.epoch,
    cnf: { jkt: opts.subjectJkt },
    ledger: opts.ledger,
    cav,
  };
  if (opts.statusIdx !== undefined) claims.st = opts.statusIdx;

  return { ok: true, claims, provenanceHash };
}

/** Validate and sign a root `am/1` mandate from an AP2 CartMandate. */
export function issueMandateFromAp2Cart(
  cart: Ap2CartMandate,
  signer: AgentKey,
  opts: Omit<Ap2CartAdapterOptions, 'issuer'> & { issuer?: string; kid?: string },
): Ap2IssueResult {
  const res = mandateClaimsFromAp2Cart(cart, {
    ...opts,
    issuer: opts.issuer ?? signer.did,
  });
  if (!res.ok) return res;
  const token = signMandate(res.claims, signer, opts.kid);
  return { ok: true, token, claims: res.claims, provenanceHash: res.provenanceHash };
}

/**
 * Export a signed `am/1` receipt into an AP2 PaymentMandate structure carrying
 * cryptographic provenance back to the `am/1` spend and delegation chain.
 */
export function toAp2PaymentMandate(input: {
  receipt: Receipt;
  paymentDetailsId: string;
  methodName: string;
  methodDetails?: Record<string, unknown>;
  merchantAgent: string;
  label?: string;
  userAuthorization?: string;
}): Ap2PaymentMandate {
  const { claims, sigs } = input.receipt;
  return {
    payment_mandate_contents: {
      payment_mandate_id: `pm_${claims.spend}`,
      payment_details_id: input.paymentDetailsId,
      payment_details_total: {
        label: input.label ?? 'Total',
        amount: {
          currency: claims.amt.cur,
          value: claims.amt.amt,
        },
      },
      payment_response: {
        request_id: claims.spend,
        method_name: input.methodName,
        ...(input.methodDetails !== undefined ? { details: input.methodDetails } : {}),
      },
      merchant_agent: input.merchantAgent,
      timestamp: new Date(claims.ts * 1000).toISOString(),
    },
    ...(input.userAuthorization !== undefined ? { user_authorization: input.userAuthorization } : {}),
    am1_provenance: {
      spend_id: claims.spend,
      chain_hash: claims.chain_hash,
      root_jti: claims.path[0] ?? claims.principal,
      receipt_jti: claims.jti,
      receipt_sig: sigs.ledger,
    },
  };
}
