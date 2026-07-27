import { sign as cryptoSign } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';

import type { Ed25519Jwk } from './didkey.js';
import type { ErrorCode } from './errors.js';
import { type ParsedJws, encodeSegment, parseCompactJws, verifyJwsSignature } from './jws.js';
import type { AgentKey } from './sign.js';
import { PROTOCOL_VERSION } from './types.js';

/**
 * §10.3 / §13 — revocation distribution.
 *
 * Revoking a `jti` has always worked in the Ledger's own state, and in online
 * mode that is enough: the Ledger is on the spend path, so a revocation applies
 * to the next spend with no propagation delay at all. Offline mode (§13) has no
 * such luxury. A merchant settling without contacting the Ledger learns nothing
 * about revocation, which is why §13 bounds it only by `exp` and why `exp` is
 * capped at an hour.
 *
 * A **status list** is the standard answer: one bit per mandate, published as a
 * signed document, cached by the merchant and consulted offline. It replaces
 * "revocation reaches an offline merchant within an hour" with "within the
 * list's lifetime", which a deployment sets.
 *
 * ## Why this costs no new connectivity assumption
 *
 * §13 already **MUST**s a merchant reporting consumption to the Ledger at least
 * every 60 seconds. A status list rides that same schedule: fetch it on the
 * heartbeat the merchant is already required to make, and revocation latency
 * drops from an hour to a minute without the spend path ever touching the
 * network. Offline mode stays offline — the fetch is a background refresh, and
 * the hot path only reads a cached bitstring and checks its `exp`.
 *
 * This does **not** justify relaxing the one-hour `exp` cap. That cap also
 * bounds parallel-presentation loss (§13), which a status list does nothing
 * about.
 *
 * ## Three things that are easy to get wrong
 *
 * **The signature is verified before the payload is decompressed.** A status
 * list is a compressed blob fetched over a network. `gunzip` on unauthenticated
 * input is a memory-exhaustion primitive — a few KB expanding to gigabytes — so
 * the order here is normative in the same way §9.2's is: authenticate, then
 * parse. The declared `bits` then caps the inflated size, so even a validly
 * signed list cannot expand past what it claims to be.
 *
 * **A list without an `exp` is not a revocation mechanism.** Anyone who can
 * answer the fetch — a cache, a proxy, an attacker on the path — can serve
 * yesterday's list forever, and revocation silently stops propagating. `exp` is
 * mandatory here and a verifier refuses a stale list rather than falling back to
 * it.
 *
 * **`seq` must never go backwards.** `exp` alone does not stop a *rollback*: an
 * older list that has not yet expired is a perfectly valid document, and serving
 * it un-revokes everything revoked since. A cache that has seen sequence *n*
 * MUST refuse *n − 1*, which turns rollback from an attack into a fetch that
 * fails. It must equally **accept** *n* — see `minSeq`, where refusing an equal
 * `seq` turns a root with nothing revoked into a five-minute outage.
 *
 * ## One list per root, at a URI nobody declares
 *
 * The list covering a chain lives at `{ledger}/v1/status/{root_jti}` and that is
 * derived, never carried in the mandate. An issuer who could name its own status
 * URI could point it somewhere it controls and answer "not revoked" forever;
 * with the URI derived from two claims the chain has already agreed on — every
 * link `MUST` share one `ledger` (§7), and the root `jti` is the head of the
 * path — there is nothing left to lie about.
 *
 * Per-root rather than one list per Ledger also makes index allocation
 * tractable: the indices in one list are handed out under a single principal,
 * so nothing needs a global allocator. It discloses nothing extra either — a
 * merchant fetching `/v1/status/{root}` already holds the root `jti`, because it
 * just verified the chain that contains it.
 */

export const STATUS_TYP = 'application/agent-status+jwt';

/**
 * 131,072 bits = 16 KiB, which gzips to a few dozen bytes while empty.
 *
 * Taken from W3C Bitstring Status List so the underlying bitstring is
 * byte-compatible with one, *not* for that specification's herd-privacy
 * argument, which does not apply to a per-root list — the merchant already knows
 * which root it is asking about.
 *
 * What a fixed size does buy is an unambiguous out-of-range rule. `bits` is in
 * the signed claims, so an index at or beyond it is a malformed mandate rather
 * than an ambiguity between "index from the future" and "stale cache".
 */
export const DEFAULT_STATUS_LIST_BITS = 131_072;

/** A list larger than this is refused before allocation, not after. */
export const MAX_STATUS_LIST_BITS = 8 * 1024 * 1024; // 1 MiB of bitstring

/**
 * Coarse bound on the compact JWS before anything parses it.
 *
 * Derived rather than picked, because the obvious round number turns out not to
 * be obviously big enough. An incompressible bitstring at `MAX_STATUS_LIST_BITS`
 * is 1 MiB, which gzip leaves at ~1 MiB, base64url inflates by 4/3 to ~1.4 MiB,
 * and the JWS's own base64url of the JSON wrapping it inflates by 4/3 again to
 * ~1.87 MiB. A flat 2 MiB would have been an 89% cap masquerading as headroom,
 * and it would only have failed on a deployment with a million revoked mandates.
 *
 * Doubled anyway, deliberately. This gate exists to stop the process touching
 * something absurd, not to be exact — and it is measured against a length that
 * also includes `iss` and `sub`, so a deployment with a long ledger URL should
 * not be the thing that discovers where the line is. The **precise** bound is
 * the per-list check further down, which is derived from the signed `bits` and
 * runs after the signature.
 */
export const MAX_STATUS_JWS_BYTES = 2 * (Math.ceil((MAX_STATUS_LIST_BITS / 8) * (4 / 3) ** 2) + 8192);

/**
 * Five minutes, against §13's 60-second reporting heartbeat.
 *
 * The lifetime is the revocation bound — a revoked mandate keeps working at an
 * offline merchant until the list that omits it expires — so shorter is
 * strictly safer, and the floor is set by how often the merchant refreshes.
 * Equal to the refresh interval would mean every merchant runs permanently on
 * the edge of stale and a single failed fetch stops payments; 5× gives four
 * consecutive failures of headroom before anything is refused. A deployment
 * that refreshes faster should set this lower and get a tighter bound for it.
 */
export const DEFAULT_STATUS_TTL_SECONDS = 300;

export interface StatusListClaims {
  v: string;
  typ: 'status';
  /** The Ledger, matching the `ledger` claim every link in the chain agrees on. */
  iss: string;
  /** The root `jti` whose subtree this list covers. */
  sub: string;
  /**
   * Monotonic publication counter. A consumer MUST refuse a list whose `seq` is
   * below one it has already accepted for the same `sub`; see the rollback note
   * above.
   */
  seq: number;
  iat: number;
  /** Mandatory. A list with no expiry can be pinned by whoever answers the fetch. */
  exp: number;
  /** Size of the bitstring in bits. An index at or beyond this is out of range. */
  bits: number;
  /** Only `gzip` is defined for `am/1`. */
  enc: 'gzip';
  /** base64url(gzip(bitstring)). */
  list: string;
}

/**
 * Bit *i* is byte `i >> 3`, most significant bit first — the W3C Bitstring
 * Status List convention, kept so the decompressed bytes are the same bytes.
 */
function bitAt(bytes: Uint8Array, idx: number): boolean {
  const byte = bytes[idx >> 3];
  return byte !== undefined && (byte & (0x80 >> (idx & 7))) !== 0;
}

function setBit(bytes: Uint8Array, idx: number): void {
  bytes[idx >> 3] = (bytes[idx >> 3] ?? 0) | (0x80 >> (idx & 7));
}

/** The URI a chain's status list lives at. Derived, never declared. */
export function statusListUri(ledger: string, rootJti: string): string {
  return `${ledger.replace(/\/+$/, '')}/v1/status/${encodeURIComponent(rootJti)}`;
}

/**
 * A verified, in-date status list, ready to answer questions about one root.
 *
 * Only constructed by `verifyStatusList`, so holding one is proof the signature
 * checked out — there is no path that produces this object from bytes nobody
 * authenticated.
 */
export class StatusList {
  private constructor(
    readonly claims: StatusListClaims,
    private readonly bytes: Uint8Array,
  ) {}

  /** @internal — `verifyStatusList` and `buildStatusList` are the doors in. */
  static of(claims: StatusListClaims, bytes: Uint8Array): StatusList {
    return new StatusList(claims, bytes);
  }

  get root(): string {
    return this.claims.sub;
  }
  get seq(): number {
    return this.claims.seq;
  }
  get expiresAt(): number {
    return this.claims.exp;
  }
  get bits(): number {
    return this.claims.bits;
  }

  /**
   * Out of range is `true`, not `false`.
   *
   * An index the list does not cover is one this list cannot vouch for, and the
   * only safe reading of "I cannot tell you whether this is revoked" on a
   * revocation check is the one that refuses. The caller that wants to
   * distinguish the two cases has `bits` to compare against.
   */
  isRevoked(idx: number): boolean {
    if (!Number.isInteger(idx) || idx < 0 || idx >= this.claims.bits) return true;
    return bitAt(this.bytes, idx);
  }

  /** Whether this list is still within its own validity, given a clock. */
  fresh(now: number, graceSeconds = 0): boolean {
    return now <= this.claims.exp + graceSeconds;
  }
}

export interface BuildStatusListOptions {
  /** The Ledger URL; becomes `iss`. */
  ledger: string;
  /** The root `jti`; becomes `sub`. */
  root: string;
  /** Indices to mark revoked. Anything out of range is an error, not a no-op. */
  revoked: Iterable<number>;
  seq: number;
  iat: number;
  /** How long consumers may serve this list. Shorter is a tighter revocation bound. */
  ttlSeconds: number;
  bits?: number;
}

export function buildStatusList(opts: BuildStatusListOptions): StatusListClaims {
  const bits = opts.bits ?? DEFAULT_STATUS_LIST_BITS;
  if (!Number.isInteger(bits) || bits <= 0 || bits % 8 !== 0 || bits > MAX_STATUS_LIST_BITS) {
    throw new Error(`status list size must be a positive multiple of 8 up to ${MAX_STATUS_LIST_BITS}`);
  }

  const bytes = new Uint8Array(bits / 8);
  for (const idx of opts.revoked) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= bits) {
      throw new Error(`status index ${idx} is outside a ${bits}-bit list`);
    }
    setBit(bytes, idx);
  }

  return {
    v: PROTOCOL_VERSION,
    typ: 'status',
    iss: opts.ledger,
    sub: opts.root,
    seq: opts.seq,
    iat: opts.iat,
    exp: opts.iat + opts.ttlSeconds,
    bits,
    enc: 'gzip',
    list: gzipSync(bytes, { level: 9 }).toString('base64url'),
  };
}

export function signStatusList(claims: StatusListClaims, key: AgentKey): string {
  const header = { alg: 'EdDSA', typ: STATUS_TYP };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const sig = cryptoSign(null, Buffer.from(signingInput, 'ascii'), key.privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

function parseClaims(payload: Record<string, unknown>): StatusListClaims | null {
  const { v, typ, iss, sub, seq, iat, exp, bits, enc, list, ...rest } = payload;
  if (Object.keys(rest).length > 0) return null; // unknown claims fail closed, as §7 does
  if (v !== PROTOCOL_VERSION || typ !== 'status') return null;
  if (typeof iss !== 'string' || iss.length === 0) return null;
  if (typeof sub !== 'string' || sub.length === 0) return null;
  if (!Number.isInteger(seq) || (seq as number) < 0) return null;
  if (!Number.isInteger(iat) || !Number.isInteger(exp)) return null;
  if (!Number.isInteger(bits)) return null;
  const n = bits as number;
  if (n <= 0 || n % 8 !== 0 || n > MAX_STATUS_LIST_BITS) return null;
  if (enc !== 'gzip') return null;
  if (typeof list !== 'string' || list.length === 0) return null;
  return {
    v,
    typ,
    iss,
    sub,
    seq: seq as number,
    iat: iat as number,
    exp: exp as number,
    bits: n,
    enc,
    list,
  };
}

export interface VerifyStatusListOptions {
  /** The Ledger's public key. The list is signed by the same key that signs spend tokens. */
  ledgerJwk: Ed25519Jwk;
  now: number;
  /** Expected `iss`. Omitted skips the check, which a merchant should not do. */
  ledger?: string;
  /** Expected `sub`. Omitted skips the check, which a merchant should not do. */
  root?: string;
  /**
   * Lowest `seq` still acceptable for this root — in practice, the highest one
   * already seen. Anything **below** it is a rollback and is refused.
   *
   * Strictly below, not at-or-below, and the difference is a self-inflicted
   * outage. `seq` counts revocations (see `publishStatusList`), so a root with
   * nothing revoked publishes the same `seq` forever. Refusing an equal `seq`
   * would mean every one of those successful refreshes was discarded, the
   * cached list's `exp` never advanced, and five minutes later the merchant
   * refused every mandate under a root where nothing had happened at all.
   *
   * Accepting an equal `seq` is safe because `seq` is a function of the list's
   * content: two lists under one root that agree on it agree on every bit, so
   * there is nothing for an attacker to choose between.
   */
  minSeq?: number;
  /** Tolerance past `exp`. Defaults to 0 — a stale list is refused, not stretched. */
  graceSeconds?: number;
  skewSeconds?: number;
}

export type StatusListVerifyResult =
  | { ok: true; list: StatusList }
  | { ok: false; code: ErrorCode; detail: string };

/**
 * Verify and open a published status list.
 *
 * Order is load-bearing: size cap, parse, claim shape, **signature**, freshness,
 * then decompress. Nothing untrusted is inflated, and the `bits` the signature
 * covers is what caps the inflation.
 */
export function verifyStatusList(jws: string, opts: VerifyStatusListOptions): StatusListVerifyResult {
  if (typeof jws !== 'string' || jws.length > MAX_STATUS_JWS_BYTES) {
    return { ok: false, code: 'status_unknown', detail: 'status list is missing or implausibly large' };
  }

  const parsed: ParsedJws | null = parseCompactJws(jws);
  if (parsed === null) return { ok: false, code: 'status_unknown', detail: 'unparseable status list' };
  if (parsed.header.typ !== STATUS_TYP) {
    return { ok: false, code: 'status_unknown', detail: `unexpected typ ${parsed.header.typ}` };
  }

  const claims = parseClaims(parsed.payload);
  if (claims === null) return { ok: false, code: 'status_unknown', detail: 'malformed status claims' };

  // Signature first. Everything below this line acts on authenticated input;
  // everything above it only inspects lengths and JSON shape.
  if (!verifyJwsSignature(parsed, opts.ledgerJwk)) {
    return { ok: false, code: 'status_unknown', detail: 'status list signature does not verify' };
  }

  if (opts.ledger !== undefined && claims.iss !== opts.ledger) {
    return { ok: false, code: 'status_unknown', detail: `status list issued by ${claims.iss}` };
  }
  if (opts.root !== undefined && claims.sub !== opts.root) {
    return { ok: false, code: 'status_unknown', detail: `status list covers ${claims.sub}` };
  }
  if (opts.minSeq !== undefined && claims.seq < opts.minSeq) {
    return {
      ok: false,
      code: 'status_unknown',
      detail: `status list seq ${claims.seq} is older than ${opts.minSeq}`,
    };
  }

  const skew = opts.skewSeconds ?? 60;
  if (opts.now + skew < claims.iat) {
    return { ok: false, code: 'status_unknown', detail: 'status list is not yet valid' };
  }
  if (opts.now > claims.exp + (opts.graceSeconds ?? 0)) {
    return { ok: false, code: 'status_unknown', detail: 'status list has expired' };
  }

  const expectedBytes = claims.bits / 8;
  // Even authenticated, a list may not inflate past what it declares. gzip can
  // expand incompressible input very slightly, so the encoded form gets a little
  // headroom; the decompressed form gets none.
  if (Buffer.byteLength(claims.list, 'utf8') > Math.ceil((expectedBytes + 1024) * 1.34)) {
    return { ok: false, code: 'status_unknown', detail: 'encoded status list exceeds its declared size' };
  }

  let bytes: Buffer;
  try {
    bytes = gunzipSync(Buffer.from(claims.list, 'base64url'), { maxOutputLength: expectedBytes });
  } catch {
    return { ok: false, code: 'status_unknown', detail: 'status list did not decompress' };
  }
  if (bytes.length !== expectedBytes) {
    return {
      ok: false,
      code: 'status_unknown',
      detail: `status list is ${bytes.length} bytes, declares ${expectedBytes}`,
    };
  }

  return { ok: true, list: StatusList.of(claims, new Uint8Array(bytes)) };
}

/**
 * What a verifier consults. Synchronous by design at the call site that matters:
 * an offline merchant must answer from a cache, not from a fetch.
 *
 * Returning `null` means "cannot say", which every caller treats as a refusal.
 */
export type StatusSource = (uri: string) => StatusList | null | Promise<StatusList | null>;

export interface StatusListCacheConfig {
  ledgerJwk: Ed25519Jwk;
  /** Fetch the compact JWS at a URI. Only ever called off the spend path. */
  fetch: (uri: string) => Promise<string>;
  clock: () => number;
  /** Serve a list this long past its `exp` before refusing. Defaults to 0. */
  graceSeconds?: number;
  /** Reported to `onStale` when a refresh has not succeeded for this long. */
  staleAlertSeconds?: number;
  onStale?: (uri: string, ageSeconds: number, detail: string) => void;
}

interface CacheEntry {
  list: StatusList | null;
  /** Highest `seq` ever accepted for this URI, kept even if the list expires. */
  seq: number;
  lastOk: number | null;
  lastError: string | null;
}

/**
 * The merchant side: refresh in the background, answer from memory.
 *
 * This is what keeps offline mode offline. `get` never awaits anything and never
 * touches the network; `refresh` is called on the §13 heartbeat the merchant
 * already owes the Ledger.
 *
 * A refresh that fails does not evict what is cached — the previous list stays
 * until its own `exp`, at which point `get` starts returning `null` and the
 * verifier starts refusing. Failing closed is the only setting under which the
 * revocation claim is true: an attacker who can break the fetch would otherwise
 * un-revoke every mandate by causing an outage.
 */
export class StatusListCache {
  private readonly entries = new Map<string, CacheEntry>();

  constructor(private readonly cfg: StatusListCacheConfig) {}

  /** Off the hot path. Returns whether the cache now holds a usable list. */
  async refresh(uri: string, expect?: { ledger: string; root: string }): Promise<boolean> {
    const entry = this.entries.get(uri) ?? { list: null, seq: -1, lastOk: null, lastError: null };
    this.entries.set(uri, entry);

    let jws: string;
    try {
      jws = await this.cfg.fetch(uri);
    } catch (err) {
      entry.lastError = err instanceof Error ? err.message : String(err);
      this.alert(uri, entry);
      return entry.list !== null;
    }

    const verified = verifyStatusList(jws, {
      ledgerJwk: this.cfg.ledgerJwk,
      now: this.cfg.clock(),
      minSeq: entry.seq < 0 ? undefined : entry.seq,
      ...(expect !== undefined ? { ledger: expect.ledger, root: expect.root } : {}),
    });
    if (!verified.ok) {
      entry.lastError = verified.detail;
      this.alert(uri, entry);
      return entry.list !== null;
    }

    entry.list = verified.list;
    entry.seq = verified.list.seq;
    entry.lastOk = this.cfg.clock();
    entry.lastError = null;
    return true;
  }

  /** The spend path. No I/O, no promise, no fallback to a stale list. */
  get(uri: string): StatusList | null {
    const entry = this.entries.get(uri);
    if (entry?.list == null) return null;
    return entry.list.fresh(this.cfg.clock(), this.cfg.graceSeconds ?? 0) ? entry.list : null;
  }

  /** `StatusSource`, bound. Pass straight to `verifyChain`. */
  source(): StatusSource {
    return (uri) => this.get(uri);
  }

  /** For the operator: what each cached list knows and how old it is. */
  state(): Array<{ uri: string; seq: number; expiresAt: number | null; lastOk: number | null; lastError: string | null }> {
    return [...this.entries].map(([uri, e]) => ({
      uri,
      seq: e.seq,
      expiresAt: e.list?.expiresAt ?? null,
      lastOk: e.lastOk,
      lastError: e.lastError,
    }));
  }

  private alert(uri: string, entry: CacheEntry): void {
    const threshold = this.cfg.staleAlertSeconds;
    if (threshold === undefined || this.cfg.onStale === undefined) return;
    const age = entry.lastOk === null ? Number.POSITIVE_INFINITY : this.cfg.clock() - entry.lastOk;
    if (age >= threshold) this.cfg.onStale(uri, age, entry.lastError ?? 'unknown');
  }
}
