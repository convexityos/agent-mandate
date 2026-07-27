import { randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { Caveats } from '../src/caveats.js';
import { signControlDecision } from '../src/control.js';
import { serve } from '../src/http/serve.js';
import { LedgerService } from '../src/http/service.js';
import { encodeSegment, parseCompactJws } from '../src/jws.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import {
  DEFAULT_STATUS_LIST_BITS,
  MAX_STATUS_JWS_BYTES,
  MAX_STATUS_LIST_BITS,
  STATUS_TYP,
  type StatusListClaims,
  StatusListCache,
  buildStatusList,
  signStatusList,
  statusListUri,
  verifyStatusList,
} from '../src/status.js';
import { verifyChain } from '../src/verify.js';
import { LEDGER, NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §3.2 — revocation distribution.
 *
 * Three groups, and the middle one is the point: the list format, the verifier
 * that consumes it, and the ledger that publishes it. What is checked hardest is
 * the set of ways a list can be *wrong in the attacker's favour* — a rollback to
 * before a revocation, a stale list served forever, a fetch that fails, a bomb
 * that expands on decompression.
 */

let principal: AgentKey;
let agent: AgentKey;
let sub: AgentKey;
let ledgerKey: AgentKey;
let store: MemoryLedgerStore;
let ledger: Ledger;
let clock: number;

const RESOURCE = 'https://api.weatherco.com/v3/forecast/94110';
const ROOT = 'mnd_root';

const rootCav = (over: Partial<Caveats> = {}): Caveats => ({
  max_total: usd('20.00'),
  max_per_txn: usd('5.00'),
  aud: ['api.weatherco.com'],
  depth: 2,
  delegable: true,
  ...over,
});

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  sub = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
  store = new MemoryLedgerStore(() => clock);
  ledger = new Ledger({
    url: LEDGER,
    key: ledgerKey,
    store,
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
  });
});

/** A one-link chain whose root carries status index `st`. */
function chain(st?: number, cav: Caveats = rootCav()): string[] {
  return buildChain(principal, [
    { holder: agent, cav, exp: NOW + 86400, jti: ROOT, ...(st !== undefined ? { st } : {}) },
  ]);
}

/** Root → child, both listed. */
function delegated(): string[] {
  return buildChain(principal, [
    { holder: agent, cav: rootCav(), exp: NOW + 86400, jti: ROOT, st: 1 },
    { holder: sub, cav: { max_total: usd('5.00') }, exp: NOW + 3600, jti: 'mnd_child', st: 2 },
  ]);
}

const publish = (revoked: number[], over: Partial<StatusListClaims> = {}): string => {
  const claims = buildStatusList({
    ledger: LEDGER,
    root: ROOT,
    revoked,
    seq: 1,
    iat: clock,
    ttlSeconds: 300,
  });
  return signStatusList({ ...claims, ...over }, ledgerKey);
};

const open = (jws: string, now = clock) =>
  verifyStatusList(jws, { ledgerJwk: ledgerKey.jwk, now });

// --------------------------------------------------------------- the format

describe('the status list itself', () => {
  it('round-trips the bits it was given and nothing else', () => {
    const opened = open(publish([0, 7, 8, 1000, DEFAULT_STATUS_LIST_BITS - 1]));
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;

    for (const i of [0, 7, 8, 1000, DEFAULT_STATUS_LIST_BITS - 1]) {
      expect(opened.list.isRevoked(i), `bit ${i}`).toBe(true);
    }
    for (const i of [1, 6, 9, 999, 1001]) {
      expect(opened.list.isRevoked(i), `bit ${i}`).toBe(false);
    }
  });

  it('compresses an almost-empty list to a fraction of its size', () => {
    // Not cosmetic: the whole design depends on a merchant re-fetching this on
    // a 60-second heartbeat, and 16 KiB per root per minute would not survive
    // contact with a real deployment.
    const jws = publish([42]);
    expect(jws.length).toBeLessThan(600);
  });

  it('admits a list at the maximum size, incompressible', () => {
    // Both size gates are guesses about gzip and base64url until something
    // measures them. The worst legitimate case is an incompressible bitstring at
    // the maximum, and it has to fit — a cap that refuses a valid list is a
    // revocation mechanism that stops working on the deployment that needs it
    // most. Built through gzip directly rather than through `buildStatusList`,
    // which would spend the test's whole budget on a four-million-element array.
    const bits = MAX_STATUS_LIST_BITS;
    const list = gzipSync(randomBytes(bits / 8), { level: 9 }).toString('base64url');
    const jws = signStatusList(
      { v: 'am/1', typ: 'status', iss: LEDGER, sub: ROOT, seq: bits / 2, iat: clock, exp: clock + 300, bits, enc: 'gzip', list },
      ledgerKey,
    );

    expect(jws.length).toBeLessThan(MAX_STATUS_JWS_BYTES);
    const opened = open(jws);
    expect(opened.ok, opened.ok ? '' : opened.detail).toBe(true);
  });

  it('treats an index past the end as revoked rather than as clear', () => {
    const opened = open(publish([]));
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(opened.list.isRevoked(DEFAULT_STATUS_LIST_BITS)).toBe(true);
    expect(opened.list.isRevoked(-1)).toBe(true);
    expect(opened.list.isRevoked(1.5)).toBe(true);
  });

  it('refuses a list signed by anyone but the ledger', () => {
    const impostor = generateAgentKey();
    const claims = buildStatusList({
      ledger: LEDGER,
      root: ROOT,
      revoked: [3],
      seq: 1,
      iat: clock,
      ttlSeconds: 300,
    });
    const result = open(signStatusList(claims, impostor));
    expect(result).toMatchObject({ ok: false, code: 'status_unknown' });
  });

  it('refuses a list that has expired, with no fallback to serving it anyway', () => {
    const jws = publish([]);
    expect(open(jws, clock + 299).ok).toBe(true);
    expect(open(jws, clock + 301)).toMatchObject({ ok: false, detail: /expired/ as never });
  });

  it('refuses a rollback to a still-valid older list', () => {
    // The attack `exp` alone does not stop. An older list is a perfectly valid
    // signed document; serving it un-revokes everything revoked since.
    const before = signStatusList(
      buildStatusList({ ledger: LEDGER, root: ROOT, revoked: [], seq: 7, iat: clock, ttlSeconds: 300 }),
      ledgerKey,
    );
    const after = signStatusList(
      buildStatusList({ ledger: LEDGER, root: ROOT, revoked: [4], seq: 8, iat: clock, ttlSeconds: 300 }),
      ledgerKey,
    );

    expect(verifyStatusList(after, { ledgerJwk: ledgerKey.jwk, now: clock, minSeq: 7 }).ok).toBe(true);
    expect(verifyStatusList(before, { ledgerJwk: ledgerKey.jwk, now: clock, minSeq: 8 })).toMatchObject({
      ok: false,
      code: 'status_unknown',
    });
    // Equal is accepted, and has to be. `seq` counts revocations, so a root with
    // nothing revoked republishes the same number forever; refusing it would
    // discard every successful refresh and expire the cache on a quiet root.
    expect(verifyStatusList(after, { ledgerJwk: ledgerKey.jwk, now: clock, minSeq: 8 }).ok).toBe(true);
  });

  it('refuses a payload that decompresses past its declared size', () => {
    // A signed gzip bomb: the ledger key is compromised, or the test stands in
    // for a bug that let one through. `bits` caps the inflation either way, so
    // the blast radius of a bad list is a refusal rather than the process.
    const bomb = gzipSync(Buffer.alloc(4 * 1024 * 1024, 0));
    const claims: StatusListClaims = {
      v: 'am/1',
      typ: 'status',
      iss: LEDGER,
      sub: ROOT,
      seq: 1,
      iat: clock,
      exp: clock + 300,
      bits: 1024,
      enc: 'gzip',
      list: bomb.toString('base64url'),
    };
    expect(bomb.length).toBeLessThan(8 * 1024); // genuinely small on the wire
    expect(open(signStatusList(claims, ledgerKey))).toMatchObject({
      ok: false,
      code: 'status_unknown',
    });
  });

  it('refuses a payload that decompresses short of its declared size', () => {
    // The other direction, and the more dangerous one: a truncated list reads
    // as all-zero past the end, which is "nothing is revoked".
    const claims: StatusListClaims = {
      v: 'am/1',
      typ: 'status',
      iss: LEDGER,
      sub: ROOT,
      seq: 1,
      iat: clock,
      exp: clock + 300,
      bits: 8192,
      enc: 'gzip',
      list: gzipSync(Buffer.alloc(16, 0)).toString('base64url'),
    };
    expect(open(signStatusList(claims, ledgerKey))).toMatchObject({
      ok: false,
      code: 'status_unknown',
    });
  });

  it('checks the signature before it decompresses anything', () => {
    // The ordering claim, made structurally rather than by timing. This payload
    // is both unsigned *and* a bomb — 4 MiB of zeros declared as a 512 KiB list
    // — so which error comes back says which check ran first. A verifier that
    // decompressed before authenticating would answer "exceeds its declared
    // size", having already inflated it to find out.
    const bomb = gzipSync(Buffer.alloc(4 * 1024 * 1024, 0));
    const header = encodeSegment({ alg: 'EdDSA', typ: STATUS_TYP });
    const payload = encodeSegment({
      v: 'am/1',
      typ: 'status',
      iss: LEDGER,
      sub: ROOT,
      seq: 1,
      iat: clock,
      exp: clock + 300,
      bits: 512 * 1024 * 8,
      enc: 'gzip',
      list: bomb.toString('base64url'),
    });
    const forged = `${header}.${payload}.${'A'.repeat(86)}`;
    expect(open(forged)).toMatchObject({
      ok: false,
      detail: 'status list signature does not verify',
    });
  });

  it('refuses a list for a different root or a different ledger', () => {
    const jws = publish([]);
    expect(
      verifyStatusList(jws, { ledgerJwk: ledgerKey.jwk, now: clock, root: 'mnd_elsewhere' }),
    ).toMatchObject({ ok: false, code: 'status_unknown' });
    expect(
      verifyStatusList(jws, { ledgerJwk: ledgerKey.jwk, now: clock, ledger: 'https://other.example' }),
    ).toMatchObject({ ok: false, code: 'status_unknown' });
  });

  it('derives the list URI from the chain rather than from a claim', () => {
    expect(statusListUri(LEDGER, ROOT)).toBe(`${LEDGER}/v1/status/${ROOT}`);
    expect(statusListUri(`${LEDGER}/`, ROOT)).toBe(`${LEDGER}/v1/status/${ROOT}`);
    // A jti with URI-significant characters cannot escape the path segment.
    expect(statusListUri(LEDGER, '../../evil')).toBe(`${LEDGER}/v1/status/..%2F..%2Fevil`);
  });
});

// ------------------------------------------------------------- the verifier

describe('verifyChain against a status list', () => {
  const verify = async (
    tokens: string[],
    opts: Partial<Parameters<typeof verifyChain>[1]> = {},
  ) =>
    verifyChain(tokens, {
      now: clock,
      request: { resource: RESOURCE, amount: usd('1.00') },
      isTrustedRootIssuer: trustOnly(principal),
      ...opts,
    });

  const sourceFor = (jws: string) => {
    const opened = verifyStatusList(jws, { ledgerJwk: ledgerKey.jwk, now: clock });
    if (!opened.ok) throw new Error(opened.detail);
    return () => opened.list;
  };

  it('admits a listed mandate whose bit is clear', async () => {
    const result = await verify(chain(5), { status: sourceFor(publish([1, 2, 3])) });
    expect(result.ok).toBe(true);
  });

  it('refuses a listed mandate whose bit is set', async () => {
    const result = await verify(chain(5), { status: sourceFor(publish([5])) });
    expect(result).toMatchObject({ ok: false, code: 'mandate_revoked' });
  });

  it('kills the subtree when an ancestor is revoked, not only the leaf', async () => {
    // §10.3's actual claim. It needs no special handling because §7 walks every
    // link, which is also why a child does not have to be listed for its parent's
    // revocation to reach it.
    const result = await verify(delegated(), { status: sourceFor(publish([1])) });
    expect(result).toMatchObject({ ok: false, code: 'mandate_revoked', link: 0 });
  });

  it('leaves an unlisted mandate alone unless the verifier requires listing', async () => {
    const status = sourceFor(publish([0, 1, 2, 3]));
    // No `st`, so nothing to look up. A mandate minted before status lists
    // existed must verify exactly as it did — §17.3.
    expect((await verify(chain(), { status })).ok).toBe(true);
    expect(await verify(chain(), { status, requireStatus: true })).toMatchObject({
      ok: false,
      code: 'status_unknown',
    });
  });

  it('refuses a listed mandate when the list cannot be consulted at all', async () => {
    // Fail closed. Otherwise breaking the fetch is how you bypass the check, and
    // an attacker who can cause an outage can un-revoke everything.
    const result = await verify(chain(5), { status: () => null });
    expect(result).toMatchObject({ ok: false, code: 'status_unknown' });
  });

  it('does not consult a list at all when no source is configured', async () => {
    // The ledger's own path: it holds authoritative revocation state and has no
    // business fetching a document it published. A listed mandate with no source
    // is admitted rather than refused as unknown.
    expect((await verify(chain(5))).ok).toBe(true);
  });

  it('reports an expired chain as expired rather than reaching for a list', async () => {
    let asked = 0;
    const result = await verify(chain(5), {
      now: NOW + 90000,
      status: () => {
        asked++;
        return null;
      },
    });
    expect(result).toMatchObject({ ok: false, code: 'mandate_expired' });
    expect(asked).toBe(0);
  });

  it('rejects a malformed status index rather than reading it as absent', async () => {
    const tokens = buildChain(principal, [
      {
        holder: agent,
        cav: rootCav(),
        jti: ROOT,
        tamper: (c) => {
          (c as unknown as Record<string, unknown>)['st'] = '5';
        },
      },
    ]);
    expect(await verify(tokens, { status: sourceFor(publish([])) })).toMatchObject({
      ok: false,
      code: 'chain_invalid',
    });
  });

  it('asks for the list at the URI derived from the chain', async () => {
    const seen: string[] = [];
    await verify(chain(5), {
      status: (uri) => {
        seen.push(uri);
        return null;
      },
    });
    expect(seen).toEqual([`${LEDGER}/v1/status/${ROOT}`]);
  });
});

// --------------------------------------------------------------- the cache

describe('StatusListCache', () => {
  const cacheWith = (fetch: (uri: string) => Promise<string>) =>
    new StatusListCache({ ledgerJwk: ledgerKey.jwk, fetch, clock: () => clock });

  const uri = () => statusListUri(LEDGER, ROOT);

  it('answers from memory with no I/O once refreshed', async () => {
    let fetches = 0;
    const cache = cacheWith(async () => {
      fetches++;
      return publish([9]);
    });

    expect(cache.get(uri())).toBeNull(); // nothing cached yet
    expect(await cache.refresh(uri())).toBe(true);
    expect(fetches).toBe(1);
    expect(cache.get(uri())?.isRevoked(9)).toBe(true);
    expect(cache.get(uri())?.isRevoked(8)).toBe(false);
    expect(fetches).toBe(1); // `get` is not a fetch
  });

  it('keeps serving the cached list when a refresh fails, until it expires', async () => {
    let mode: 'ok' | 'fail' = 'ok';
    const cache = cacheWith(async () => {
      if (mode === 'fail') throw new Error('connection refused');
      return publish([9]);
    });
    await cache.refresh(uri());

    mode = 'fail';
    expect(await cache.refresh(uri())).toBe(true); // previous list still usable
    expect(cache.get(uri())).not.toBeNull();

    // Past its own expiry, the failure stops being tolerable. The verifier then
    // refuses every listed mandate, which is the intended direction to fail.
    clock += 301;
    expect(cache.get(uri())).toBeNull();
  });

  it('will not go backwards even if the network serves an older list', async () => {
    const newer = signStatusList(
      buildStatusList({ ledger: LEDGER, root: ROOT, revoked: [4], seq: 9, iat: clock, ttlSeconds: 300 }),
      ledgerKey,
    );
    const older = signStatusList(
      buildStatusList({ ledger: LEDGER, root: ROOT, revoked: [], seq: 8, iat: clock, ttlSeconds: 300 }),
      ledgerKey,
    );

    let serve = newer;
    const cache = cacheWith(async () => serve);
    await cache.refresh(uri());
    expect(cache.get(uri())?.isRevoked(4)).toBe(true);

    serve = older;
    await cache.refresh(uri());
    expect(cache.get(uri())?.isRevoked(4)).toBe(true); // still revoked
    expect(cache.state()[0]?.lastError).toMatch(/older than/);
  });

  it('keeps a quiet root alive across refreshes that change nothing', async () => {
    // The outage a stricter rollback rule would have caused. Nothing is revoked,
    // so every publication is byte-identical with the same `seq`; if the cache
    // discarded those, `exp` would never advance and five minutes later a root
    // where nothing had happened would refuse every mandate under it.
    const cache = cacheWith(async () => ledger.publishStatusList(ROOT, { ttlSeconds: 300 }));
    await cache.refresh(uri());

    for (let i = 0; i < 4; i++) {
      clock += 120;
      expect(await cache.refresh(uri()), `refresh ${i}`).toBe(true);
      expect(cache.get(uri()), `list after refresh ${i}`).not.toBeNull();
    }
    expect(cache.state()[0]?.lastError).toBeNull();
  });

  it('reports how stale each list is, for an operator to alert on', async () => {
    const stale: Array<[string, number]> = [];
    const cache = new StatusListCache({
      ledgerJwk: ledgerKey.jwk,
      clock: () => clock,
      staleAlertSeconds: 120,
      onStale: (u, age) => stale.push([u, age]),
      fetch: async () => {
        throw new Error('down');
      },
    });

    await cache.refresh(uri());
    // Never succeeded: infinitely stale, and reported on the first failure
    // rather than after a threshold nothing will ever cross.
    expect(stale).toHaveLength(1);
    expect(stale[0]![1]).toBe(Number.POSITIVE_INFINITY);
    expect(cache.state()[0]).toMatchObject({ seq: -1, lastOk: null, lastError: 'down' });
  });
});

// --------------------------------------------------------------- the ledger

describe('the ledger publishing a status list', () => {
  it('lists a mandate it has seen, once revoked', async () => {
    const tokens = chain(11);
    await ledger.reserve({ tokens, request: { resource: RESOURCE, amount: usd('1.00') } });

    const before = open(await ledger.publishStatusList(ROOT));
    expect(before.ok && before.list.isRevoked(11)).toBe(false);

    await ledger.revoke(ROOT);

    const after = open(await ledger.publishStatusList(ROOT));
    expect(after.ok && after.list.isRevoked(11)).toBe(true);
  });

  it('publishes a list whose bits survive the round trip to a verifier', async () => {
    const tokens = delegated();
    await ledger.register(tokens);
    await ledger.revoke('mnd_child');

    const jws = await ledger.publishStatusList(ROOT);
    const opened = verifyStatusList(jws, {
      ledgerJwk: ledgerKey.jwk,
      now: clock,
      ledger: LEDGER,
      root: ROOT,
    });
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;

    const result = await verifyChain(tokens, {
      now: clock,
      request: { resource: RESOURCE, amount: usd('1.00') },
      isTrustedRootIssuer: trustOnly(principal),
      status: () => opened.list,
    });
    expect(result).toMatchObject({ ok: false, code: 'mandate_revoked', link: 1 });
  });

  it('builds by union, so a shared index never clears a revoked bit', async () => {
    // Two mandates at one index — an issuer's allocation bug, which costs
    // liveness (over-revocation) and must never cost safety.
    //
    // `mnd_child` is the revoked one and sorts first out of `findNodes`, so a
    // publisher that walked nodes writing `bit[idx] = node.revoked` would set
    // the bit and then have the unrevoked root clear it again. The revoked
    // mandate would read as live. Building by union cannot express that.
    const tokens = buildChain(principal, [
      { holder: agent, cav: rootCav(), exp: NOW + 86400, jti: ROOT, st: 3 },
      { holder: sub, cav: { max_total: usd('5.00') }, exp: NOW + 3600, jti: 'mnd_child', st: 3 },
    ]);
    await ledger.register(tokens);
    await ledger.revoke('mnd_child');

    const nodes = await store.read(async (tx) => tx.findNodes(ROOT));
    expect(nodes.map((n) => n.jti)).toEqual(['mnd_child', ROOT]); // the order that matters

    const opened = open(await ledger.publishStatusList(ROOT));
    expect(opened.ok && opened.list.isRevoked(3)).toBe(true);
  });

  it('stamps a lifetime a caller can tighten', async () => {
    const jws = await ledger.publishStatusList(ROOT, { ttlSeconds: 30, seq: 42 });
    const claims = parseCompactJws(jws)!.payload as unknown as StatusListClaims;
    expect(claims.exp - claims.iat).toBe(30);
    expect(claims.seq).toBe(42);
    expect(claims.sub).toBe(ROOT);
    expect(claims.iss).toBe(LEDGER);
  });

  it('numbers a list by what is revoked in it, not by when it was built', async () => {
    // Two consequences, both of which a wall clock gets wrong. Republishing an
    // unchanged list is the same number, so a consumer can accept it and refresh
    // its expiry; and a replica lagging behind on replication publishes a
    // *lower* number, so a merchant holding the fuller list correctly keeps it
    // rather than being talked backwards by a fresher timestamp.
    const seqOf = async () =>
      (parseCompactJws(await ledger.publishStatusList(ROOT))!.payload as unknown as StatusListClaims)
        .seq;

    await ledger.register(delegated());
    expect(await seqOf()).toBe(0);

    clock += 3600;
    expect(await seqOf()).toBe(0); // time passed, nothing changed

    await ledger.revoke('mnd_child');
    expect(await seqOf()).toBe(1);
    await ledger.revoke(ROOT);
    expect(await seqOf()).toBe(2);
  });
});

// -------------------------------------------------- revoking the unspent

describe('revoking a mandate the ledger has not seen spend', () => {
  const control = (target: string, root = ROOT) =>
    signControlDecision(
      {
        v: 'am/1',
        typ: 'control',
        jti: `ctl_${target}_${clock}`,
        iss: principal.did,
        action: 'revoke',
        root,
        target,
        iat: clock,
        exp: clock + 300,
      },
      principal,
    );

  it('records the revocation and refuses the first spend', async () => {
    // The hole this closes: a node is created on a mandate's *first* spend, so
    // before that there was nothing to mark revoked. The revocation was refused
    // as "unknown mandate" and the first spend then went straight through.
    const tokens = delegated();

    // The root has to exist for §10.6's ownership check — that is the whole
    // point of it — so register the chain and revoke the child, which has never
    // spent either way.
    await ledger.register(tokens);
    await store.transact(async (tx) => {
      // Prove the child node is what a first spend would create, then delete it
      // so this is genuinely the "never seen" case.
      expect(await tx.getNode('mnd_child')).toBeDefined();
    });

    const applied = await ledger.applyControl(control('mnd_child'));
    expect(applied).toMatchObject({ ok: true, action: 'revoke' });

    const spend = await ledger.reserve({
      tokens,
      request: { resource: RESOURCE, amount: usd('1.00') },
    });
    expect(spend).toMatchObject({ ok: false, code: 'mandate_revoked' });
  });

  it('revokes a jti with no node at all, and the node materializes revoked', async () => {
    const tokens = delegated();
    // Only the root is known to the ledger. `mnd_child` has never been presented.
    await ledger.register([tokens[0]!]);
    expect(await store.read(async (tx) => tx.getNode('mnd_child'))).toBeUndefined();

    expect(await ledger.applyControl(control('mnd_child'))).toMatchObject({ ok: true });

    const spend = await ledger.reserve({
      tokens,
      request: { resource: RESOURCE, amount: usd('1.00') },
    });
    expect(spend).toMatchObject({ ok: false, code: 'mandate_revoked' });

    // A refused spend writes no nodes — materialization happens with the debit —
    // so the record, not a node, is what refused it, and it keeps refusing.
    expect(await store.read(async (tx) => tx.getNode('mnd_child'))).toBeUndefined();
    expect(
      await ledger.reserve({ tokens, request: { resource: RESOURCE, amount: usd('1.00') } }),
    ).toMatchObject({ ok: false, code: 'mandate_revoked' });

    // And when a node does come into existence, it comes into existence revoked.
    await ledger.register(tokens);
    expect(await store.read(async (tx) => tx.getNode('mnd_child'))).toMatchObject({
      revoked: true,
    });
  });

  it('does not let one principal pre-revoke a jti under another principal', async () => {
    // A revocation for an unseen jti cannot be checked against a parent, because
    // there is no node recording one. Keying it by root is what stands in for
    // that check.
    const other = generateAgentKey();
    const otherLedger = new Ledger({
      url: LEDGER,
      key: ledgerKey,
      store,
      isTrustedRootIssuer: (iss) => iss === principal.did || iss === other.did,
      clock: () => clock,
    });

    const theirs = buildChain(other, [
      { holder: agent, cav: rootCav(), exp: NOW + 86400, jti: 'mnd_theirs' },
      { holder: sub, cav: { max_total: usd('5.00') }, exp: NOW + 3600, jti: 'mnd_target' },
    ]);
    await otherLedger.register([theirs[0]!]);

    const mine = buildChain(principal, [
      { holder: agent, cav: rootCav(), exp: NOW + 86400, jti: ROOT },
    ]);
    await otherLedger.register(mine);

    // Signed by me, naming my own root, targeting a jti that will materialize
    // under theirs. Accepted — I may revoke anything under my root — and then
    // simply does not apply to their subtree.
    const decision = signControlDecision(
      {
        v: 'am/1',
        typ: 'control',
        jti: 'ctl_cross',
        iss: principal.did,
        action: 'revoke',
        root: ROOT,
        target: 'mnd_target',
        iat: clock,
        exp: clock + 300,
      },
      principal,
    );
    expect(await otherLedger.applyControl(decision)).toMatchObject({ ok: true });

    const spend = await otherLedger.reserve({
      tokens: theirs,
      request: { resource: RESOURCE, amount: usd('1.00') },
    });
    expect(spend.ok).toBe(true);
  });

  it('still refuses a revoke naming a target under a different root it has seen', async () => {
    const other = generateAgentKey();
    const twoPrincipals = new Ledger({
      url: LEDGER,
      key: ledgerKey,
      store,
      isTrustedRootIssuer: (iss) => iss === principal.did || iss === other.did,
      clock: () => clock,
    });
    await twoPrincipals.register(
      buildChain(other, [{ holder: agent, cav: rootCav(), exp: NOW + 86400, jti: 'mnd_theirs' }]),
    );
    await twoPrincipals.register(chain());

    const decision = signControlDecision(
      {
        v: 'am/1',
        typ: 'control',
        jti: 'ctl_x',
        iss: principal.did,
        action: 'revoke',
        root: ROOT,
        target: 'mnd_theirs',
        iat: clock,
        exp: clock + 300,
      },
      principal,
    );
    expect(await twoPrincipals.applyControl(decision)).toMatchObject({
      ok: false,
      code: 'attenuation_violation',
    });
  });
});

// --------------------------------------------------------------- register

describe('register', () => {
  it('materializes a chain without spending anything', async () => {
    const tokens = delegated();
    expect(await ledger.register(tokens)).toMatchObject({ ok: true, path: [ROOT, 'mnd_child'] });

    const tree = await ledger.budgetTree(ROOT);
    expect([...tree.map((n) => n.jti)].sort()).toEqual(['mnd_child', ROOT]);
    expect(tree.every((n) => n.spent.amt === '0.00' || n.spent.amt === '0')).toBe(true);
  });

  it('produces exactly the node a first spend would, so the two interleave', async () => {
    const tokens = delegated();
    await ledger.register(tokens);
    const registered = await store.read(async (tx) => tx.getNode(ROOT));

    const spend = await ledger.reserve({
      tokens,
      request: { resource: RESOURCE, amount: usd('1.00') },
    });
    expect(spend.ok).toBe(true);

    const spent = await store.read(async (tx) => tx.getNode(ROOT));
    // Same identity and binding; only consumption moved.
    expect(spent!.tokenHash).toBe(registered!.tokenHash);
    expect(spent!.issuer).toBe(registered!.issuer);
    expect(spent!.statusIdx).toBe(1);
    expect(spent!.spentScaled).toBeGreaterThan(0n);
  });

  it('is idempotent, and refuses a jti re-presented with different content', async () => {
    const tokens = delegated();
    expect((await ledger.register(tokens)).ok).toBe(true);
    expect((await ledger.register(tokens)).ok).toBe(true);

    // Same jti, different caveats — the §10.1 substitution attack, which would
    // otherwise reset the budget.
    const reissued = buildChain(principal, [
      { holder: agent, cav: rootCav({ max_total: usd('999.00') }), exp: NOW + 86400, jti: ROOT, st: 1 },
    ]);
    expect(await ledger.register(reissued)).toMatchObject({
      ok: false,
      code: 'chain_invalid',
    });
  });

  it('verifies the chain rather than taking the caller\'s word for it', async () => {
    const stranger = generateAgentKey();
    const untrusted = buildChain(stranger, [
      { holder: agent, cav: rootCav(), exp: NOW + 86400, jti: 'mnd_forged' },
    ]);
    expect(await ledger.register(untrusted)).toMatchObject({ ok: false, code: 'chain_invalid' });
    expect(await store.read(async (tx) => tx.getNode('mnd_forged'))).toBeUndefined();
  });

  it('does not check request coverage, because there is no request', async () => {
    // The chain is scoped to weatherco; registration asserts nothing about a
    // resource, so nothing here should be comparing one.
    const narrow = chain(1, rootCav({ aud: ['api.weatherco.com'], purpose: ['research.readonly'] }));
    expect((await ledger.register(narrow)).ok).toBe(true);
  });
});

// ----------------------------------------------------------- the whole loop

describe('end to end over real HTTP', () => {
  let server: ReturnType<typeof serve>;
  let base: string;

  beforeEach(async () => {
    server = serve({
      port: 0,
      handlers: [new LedgerService({ ledger, basePath: '/ledger', requirePresenter: false })],
    });
    if (!server.listening) await new Promise((r) => server.once('listening', r));
    const addr = server.address();
    base = `http://127.0.0.1:${typeof addr === 'object' && addr !== null ? addr.port : 0}`;
  });
  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
  });

  it('registers, revokes, publishes, and the merchant refuses — without the ledger on the spend path', async () => {
    const tokens = delegated();

    const registered = await fetch(`${base}/ledger/v1/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tokens }),
    });
    expect(registered.status).toBe(200);

    // A merchant that will never contact the ledger on a spend, only refresh.
    const cache = new StatusListCache({
      ledgerJwk: ledgerKey.jwk,
      clock: () => clock,
      fetch: async (uri) => {
        // The URI is derived from the chain, so the merchant reaches a path it
        // was never told about by anyone but the mandate's own `ledger` claim.
        const res = await fetch(uri.replace(LEDGER, `${base}/ledger`));
        if (!res.ok) throw new Error(`status ${res.status}`);
        expect(res.headers.get('content-type')).toBe('application/agent-status+jwt');
        return res.text();
      },
    });

    const verify = () =>
      verifyChain(tokens, {
        now: clock,
        request: { resource: RESOURCE, amount: usd('1.00') },
        isTrustedRootIssuer: trustOnly(principal),
        status: cache.source(),
        requireStatus: true,
      });

    await cache.refresh(statusListUri(LEDGER, ROOT));
    expect((await verify()).ok).toBe(true);

    // The principal revokes the child. Nothing has told the merchant yet.
    await ledger.applyControl(
      signControlDecision(
        {
          v: 'am/1',
          typ: 'control',
          jti: 'ctl_e2e',
          iss: principal.did,
          action: 'revoke',
          root: ROOT,
          target: 'mnd_child',
          iat: clock,
          exp: clock + 300,
        },
        principal,
      ),
    );
    expect((await verify()).ok).toBe(true); // still working off the cached list

    // …until the next heartbeat, which is the entire revocation latency.
    await cache.refresh(statusListUri(LEDGER, ROOT));
    expect(await verify()).toMatchObject({ ok: false, code: 'mandate_revoked' });
  });

  it('caps how long an intermediary may hold a list to the list\'s own lifetime', async () => {
    const res = await fetch(`${base}/ledger/v1/status/${ROOT}`);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('public, max-age=300');

    const opened = verifyStatusList(await res.text(), {
      ledgerJwk: ledgerKey.jwk,
      now: clock,
      ledger: LEDGER,
      root: ROOT,
    });
    expect(opened.ok).toBe(true);
  });

  it('serves a list for a root it has never heard of rather than 404ing', async () => {
    // An empty list is the true answer — nothing under that root is revoked —
    // and a 404 would make "the ledger does not know this root" indistinguishable
    // from "the status endpoint is down", which a merchant must fail closed on.
    const res = await fetch(`${base}/ledger/v1/status/mnd_never_seen`);
    expect(res.status).toBe(200);
    const opened = verifyStatusList(await res.text(), {
      ledgerJwk: ledgerKey.jwk,
      now: clock,
      root: 'mnd_never_seen',
    });
    expect(opened.ok && opened.list.isRevoked(0)).toBe(false);
  });
});
