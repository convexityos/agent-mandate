import type {
  IdempotencyRecord,
  MandateNode,
  Reservation,
  ReservationQuery,
  SpendEvent,
  StepUpApproval,
  StepUpQuery,
} from '../store.js';

/**
 * Row ↔ domain conversion shared by the SQLite and Postgres stores.
 *
 * Both dialects store the same logical rows and differ only where they must:
 * SQLite has no arbitrary-precision numeric and no concurrent writers, Postgres
 * has both. Keeping the codec common is what stops "the SQLite store passed" and
 * "the Postgres store passed" from meaning two different things.
 *
 * ## Money never goes through SQL arithmetic
 *
 * Scaled amounts are read, modified in `BigInt`, and written back whole, under a
 * row lock — the ledger does the arithmetic, the database stores the result. So
 * every amount column here is an exact integer string on the way in and out, and
 * no dialect's numeric tower can round one. `money.ts` guarantees binary float
 * never touches an amount; this is where that guarantee reaches the disk.
 *
 * The single exception is `task_total`, which Postgres increments in SQL. That
 * column is `NUMERIC` — arbitrary-precision decimal, not float — so the addition
 * is exact. See `postgres.ts` for why it is done that way.
 */

/** Tag used to round-trip a `BigInt` through JSON. */
const BIGINT_TAG = '$bigint';

/**
 * `JSON.stringify` throws on a `BigInt` rather than mangling one, so an untagged
 * encoder would fail loudly rather than silently — but it would still fail.
 * `Reservation.amountScaled` is a `BigInt`, and `directive.intent` is
 * rail-specific `Record<string, unknown>` that may hold more of them, so the
 * codec tags them generically instead of enumerating fields it cannot know.
 */
export function encodeJson(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) =>
    typeof v === 'bigint' ? { [BIGINT_TAG]: v.toString() } : v,
  );
}

export function decodeJson<T>(text: string): T {
  return JSON.parse(text, (_k, v: unknown) => {
    if (typeof v === 'object' && v !== null && BIGINT_TAG in (v as Record<string, unknown>)) {
      const raw = (v as Record<string, unknown>)[BIGINT_TAG];
      if (typeof raw === 'string') return BigInt(raw);
    }
    return v;
  }) as T;
}

/** SQLite returns 0/1, Postgres returns booleans. */
export function truthy(v: unknown): boolean {
  return v === true || v === 1 || v === '1' || v === 't';
}

/** Postgres hands back `BIGINT` as a string; SQLite hands back a number. */
export function num(v: unknown): number {
  return typeof v === 'number' ? v : Number(v as string);
}

/** Amount columns arrive as exact integer strings from both dialects. */
export function big(v: unknown): bigint {
  return typeof v === 'bigint' ? v : BigInt(v as string | number);
}

export type Row = Record<string, unknown>;

export function nodeToRow(n: MandateNode): Row {
  return {
    jti: n.jti,
    parent: n.parent,
    root: n.root,
    issuer: n.issuer,
    token_hash: n.tokenHash,
    budget_scaled: n.budgetScaled === null ? null : n.budgetScaled.toString(),
    currency: n.currency,
    spent_scaled: n.spentScaled.toString(),
    rate: n.rate === null ? null : encodeJson(n.rate),
    rate_events: encodeJson(n.rateEvents),
    revoked: n.revoked,
    status_idx: n.statusIdx,
    exp: n.exp,
  };
}

export function rowToNode(r: Row): MandateNode {
  return {
    jti: r['jti'] as string,
    parent: (r['parent'] as string | null) ?? null,
    root: r['root'] as string,
    issuer: (r['issuer'] as string | null) ?? '',
    tokenHash: r['token_hash'] as string,
    budgetScaled: r['budget_scaled'] === null ? null : big(r['budget_scaled']),
    currency: (r['currency'] as string | null) ?? null,
    spentScaled: big(r['spent_scaled']),
    rate: r['rate'] === null ? null : decodeJson(r['rate'] as string),
    rateEvents: decodeJson(r['rate_events'] as string),
    revoked: truthy(r['revoked']),
    // Absent (an older row) and NULL (minted without `st`) mean the same thing:
    // not listed, therefore not revocable offline.
    statusIdx: r['status_idx'] == null ? null : num(r['status_idx']),
    exp: num(r['exp']),
  };
}

/**
 * The reservation keeps its indexed query columns and carries the rest as a
 * JSON document.
 *
 * Normalizing the whole shape would mean a schema that tracks `Directive`, whose
 * `intent` is deliberately rail-defined and open — the store would need a
 * migration every time a rail is added. The four columns broken out are exactly
 * the four `ReservationQuery` filters on, so every query the ledger issues is
 * indexable and nothing else needs to be legible to SQL.
 */
export function reservationToRow(r: Reservation): Row {
  return {
    id: r.id,
    root: r.root,
    status: r.status,
    created_at: r.createdAt,
    expires_at: r.expiresAt,
    has_directive: r.directive !== undefined,
    escalated: r.escalated !== undefined,
    doc: encodeJson(r),
  };
}

export function rowToReservation(r: Row): Reservation {
  return decodeJson<Reservation>(r['doc'] as string);
}

export function stepUpToRow(a: StepUpApproval): Row {
  return {
    handle: a.handle,
    root: a.root,
    resource: a.resource,
    max_amount_scaled: a.maxAmountScaled.toString(),
    currency: a.currency,
    expires_at: a.expiresAt,
    used: a.used,
    state: a.state,
    requested_at: a.requestedAt,
    agent: a.agent,
    task_id: a.taskId,
    // The signed decision is kept whole rather than shredded into columns: it is
    // evidence, and evidence that has been reassembled from parts is no longer
    // verifiable against the signature that made it evidence.
    decision: a.decision === undefined ? null : encodeJson(a.decision),
  };
}

export function rowToStepUp(r: Row): StepUpApproval {
  const decision = r['decision'];
  return {
    handle: r['handle'] as string,
    root: r['root'] as string,
    resource: r['resource'] as string,
    maxAmountScaled: big(r['max_amount_scaled']),
    currency: r['currency'] as string,
    expiresAt: num(r['expires_at']),
    used: truthy(r['used']),
    state: r['state'] as StepUpApproval['state'],
    requestedAt: num(r['requested_at']),
    agent: r['agent'] as string,
    taskId: (r['task_id'] as string | null) ?? null,
    ...(decision === null || decision === undefined
      ? {}
      : { decision: decodeJson<NonNullable<StepUpApproval['decision']>>(decision as string) }),
  };
}

/** `StepUpQuery` as a `WHERE` clause; the twin of `matchesStepUpQuery`. */
export function stepUpWhere(
  q: StepUpQuery,
  ph: (i: number) => string,
): { sql: string; params: unknown[] } {
  const clauses: string[] = [];
  const params: unknown[] = [];
  const bind = (v: unknown): string => {
    params.push(v);
    return ph(params.length);
  };

  if (q.state !== undefined) {
    if (q.state.length === 0) return { sql: '1 = 0', params: [] };
    clauses.push(`state IN (${q.state.map(bind).join(', ')})`);
  }
  if (q.root !== undefined) clauses.push(`root = ${bind(q.root)}`);
  if (q.unused !== undefined) clauses.push(`used = ${bind(!q.unused)}`);
  if (q.notExpiredAt !== undefined) clauses.push(`expires_at >= ${bind(q.notExpiredAt)}`);

  return { sql: clauses.length === 0 ? '1 = 1' : clauses.join(' AND '), params };
}

export function idempotentToRow(rec: IdempotencyRecord): Row {
  return {
    key: rec.key,
    request_hash: rec.requestHash,
    // The recorded response is stored whole. It contains a minted spend token
    // and a BigInt or two, and a replay has to return the same answer byte for
    // byte or it is not idempotent.
    response: encodeJson(rec.response),
    created_at: rec.createdAt,
    expires_at: rec.expiresAt,
  };
}

export function rowToIdempotent(r: Row): IdempotencyRecord {
  return {
    key: r['key'] as string,
    requestHash: r['request_hash'] as string,
    response: decodeJson(r['response'] as string),
    createdAt: num(r['created_at']),
    expiresAt: num(r['expires_at']),
  };
}

export function rowToSpendEvent(r: Row): SpendEvent {
  return { ts: num(r['ts']), amountScaled: big(r['amount_scaled']) };
}

/**
 * `ReservationQuery` as a `WHERE` clause.
 *
 * Kept beside `matchesQuery` in `store.ts` on purpose: those two must agree, and
 * the store conformance suite runs the same queries through both to check that
 * they do.
 */
export function reservationWhere(
  q: ReservationQuery,
  ph: (i: number) => string,
): { sql: string; params: unknown[] } {
  const clauses: string[] = [];
  const params: unknown[] = [];
  const bind = (v: unknown): string => {
    params.push(v);
    return ph(params.length);
  };

  if (q.status !== undefined) {
    // An empty status list matches nothing, which is what `[].includes(x)` does
    // in `matchesQuery`. `IN ()` is a syntax error, so it is spelled out.
    if (q.status.length === 0) return { sql: '1 = 0', params: [] };
    clauses.push(`status IN (${q.status.map(bind).join(', ')})`);
  }
  if (q.hasDirective !== undefined) clauses.push(`has_directive = ${bind(q.hasDirective)}`);
  if (q.escalated !== undefined) clauses.push(`escalated = ${bind(q.escalated)}`);
  if (q.expiresBefore !== undefined) clauses.push(`expires_at < ${bind(q.expiresBefore)}`);

  return { sql: clauses.length === 0 ? '1 = 1' : clauses.join(' AND '), params };
}
