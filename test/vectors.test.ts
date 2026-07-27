import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  type Caveats,
  meetCaveats,
  narrows,
  validateCaveats,
  BOTTOM,
} from '../src/caveats.js';
import { agentKeyFromSeed } from '../src/sign.js';
import { canonicalizeUri, hostSetContains, uriSetContains } from '../src/uri.js';
import { verifyChain } from '../src/verify.js';
import type { RequestContext } from '../src/types.js';
import {
  type CaveatVector,
  type ChainVector,
  type UriVector,
  buildVectors,
} from './vectors.build.js';

/**
 * §3.1 — run the published conformance vectors against this implementation.
 *
 * The expectations in `vectors.build.ts` are written by hand from the spec, not
 * recorded from what this code does. So this file is not a tautology: it is the
 * check that the reference implementation and the specification agree, and a
 * failure here means one of the two is wrong rather than that a snapshot needs
 * updating.
 *
 * It also verifies the committed `vectors/*.json` match what the generator
 * produces. Vectors are a published artifact; if the files on disk can drift
 * from the generator, the thing third parties test against is not the thing this
 * suite tests.
 */

const VECTORS_DIR = fileURLToPath(new URL('../vectors/', import.meta.url));
const built = buildVectors();

describe('the committed vectors match the generator', () => {
  for (const name of Object.keys(built) as Array<keyof typeof built>) {
    it(`vectors/${name} is up to date`, () => {
      const path = `${VECTORS_DIR}${name}`;
      expect(existsSync(path), `${name} is missing — run: npm run vectors`).toBe(true);
      const onDisk: unknown = JSON.parse(readFileSync(path, 'utf8'));
      expect(onDisk, `${name} is stale — run: npm run vectors`).toEqual(built[name]);
    });
  }
});

const load = <T>(file: string): T[] =>
  (JSON.parse(readFileSync(`${VECTORS_DIR}${file}`, 'utf8')) as { vectors: T[] }).vectors;

describe('§7 chain vectors', () => {
  for (const v of load<ChainVector>('chain.json')) {
    it(`${v.id} — ${v.title}`, async () => {
      const trusted = new Set(v.trustedRootIssuers);
      const result = await verifyChain(v.tokens, {
        now: v.now,
        request: v.request as unknown as RequestContext,
        isTrustedRootIssuer: (iss) => trusted.has(iss),
        ...(v.presenterJkt !== undefined ? { presenterJkt: v.presenterJkt } : {}),
        ...(v.maxDepth !== undefined ? { maxDepth: v.maxDepth } : {}),
      });

      expect(result.ok, `${v.id}: ${result.ok ? 'accepted' : result.detail}`).toBe(v.expect.ok);
      if (!v.expect.ok) {
        expect(result.ok === false && result.code, v.why).toBe(v.expect.code);
        return;
      }
      // An expected `effective` is checked when the vector states one. Several
      // positive vectors do not, because what they pin is acceptance rather than
      // the exact fold.
      if (result.ok && v.expect.effective !== undefined) {
        expect(result.effective, v.why).toEqual(v.expect.effective);
      }
    });
  }
});

describe('§6 lattice vectors', () => {
  for (const v of load<CaveatVector>('caveats.json')) {
    it(`${v.id} — ${v.title}`, () => {
      if (v.op === 'narrows') {
        const r = narrows(v.child as Caveats, v.parent as Caveats);
        const want = v.expect as { ok: boolean; code?: string };
        expect(r.ok, v.why).toBe(want.ok);
        if (!want.ok) expect(r.ok === false && r.code).toBe(want.code);
        return;
      }

      if (v.op === 'validate') {
        const r = validateCaveats(v.value);
        const want = v.expect as { ok: boolean; code?: string };
        expect(r.ok, v.why).toBe(want.ok);
        if (!want.ok) expect(r.ok === false && r.code).toBe(want.code);
        return;
      }

      const met = meetCaveats(v.a as Caveats, v.b as Caveats);
      if ('bottom' in v.expect) {
        // ⊥ is a symbol and has no JSON spelling, so the vector says `bottom:
        // true` and the runner checks for the sentinel rather than a value.
        const values = Object.values(met as Record<string, unknown>);
        expect(values.includes(BOTTOM), v.why).toBe(true);
        return;
      }
      expect(met, v.why).toEqual((v.expect as { result: Caveats }).result);

      // A meet must be commutative, and every vector is a free opportunity to
      // check it — non-commutativity is the defect these were written after.
      expect(meetCaveats(v.b as Caveats, v.a as Caveats)).toEqual(met);
    });
  }
});

describe('§6.4 URI vectors', () => {
  for (const v of load<UriVector>('uri.json')) {
    it(`${v.id} — ${v.title}`, () => {
      if (v.op === 'canonicalize') {
        expect(canonicalizeUri(v.input!), v.why).toBe((v.expect as { output: string | null }).output);
        return;
      }
      const contains = v.op === 'uriSetContains' ? uriSetContains : hostSetContains;
      expect(contains(v.parent!, v.child!), v.why).toBe((v.expect as { result: boolean }).result);
    });
  }
});

/**
 * The first thing a third-party implementation does is derive the keys, and it
 * is the step most likely to be subtly wrong on both sides.
 *
 * Nothing else in this file would catch a bad `seedHex`: the tokens were signed
 * with the in-memory keys, so `verifyChain` succeeds whatever `keys.json`
 * claims. This closes that loop by going the other way — seed to key to
 * signature — exactly as a consumer of the published files must.
 */
describe('the published keys regenerate from their published seeds', () => {
  interface PublishedKey {
    name: string;
    seedHex: string;
    did: string;
    jwk: { kty: string; crv: string; x: string };
    jkt: string;
  }
  const published = (
    JSON.parse(readFileSync(`${VECTORS_DIR}keys.json`, 'utf8')) as { keys: PublishedKey[] }
  ).keys;

  it('derives the same did and jkt from seedHex alone', () => {
    expect(published.length).toBeGreaterThan(3);
    for (const k of published) {
      const seed = Uint8Array.from(Buffer.from(k.seedHex, 'hex'));
      expect(seed.length, `${k.name} seed must be 32 bytes`).toBe(32);
      const derived = agentKeyFromSeed(seed);
      expect(derived.did, `${k.name} did`).toBe(k.did);
      expect(derived.jkt, `${k.name} jkt`).toBe(k.jkt);
      expect(derived.jwk.x, `${k.name} public key`).toBe(k.jwk.x);
    }
  });

  it('verifies a chain vector signature with a key rebuilt from the published seed', () => {
    const principal = published.find((k) => k.name === 'principal')!;
    const derived = agentKeyFromSeed(Uint8Array.from(Buffer.from(principal.seedHex, 'hex')));

    // Raw Ed25519 over the JWS signing input, using only the published seed —
    // no chain logic, no trust list, just the signature a third party checks
    // first.
    const root = load<ChainVector>('chain.json').find(
      (v) => v.id === 'chain/root-only-accepted',
    )!;
    const [header, payload, signature] = root.tokens[0]!.split('.');
    const ok = cryptoVerify(
      null,
      Buffer.from(`${header}.${payload}`, 'ascii'),
      createPublicKey({ key: derived.jwk as never, format: 'jwk' }),
      Buffer.from(signature!, 'base64url'),
    );
    expect(ok).toBe(true);
  });
});

describe('the vectors themselves', () => {
  it('every vector has a stable id, a spec reference and a reason', () => {
    const all = [
      ...load<ChainVector>('chain.json'),
      ...load<CaveatVector>('caveats.json'),
      ...load<UriVector>('uri.json'),
    ];
    const ids = new Set<string>();
    for (const v of all) {
      expect(v.id).toMatch(/^(chain|caveats|uri)\/[a-z0-9-]+$/);
      expect(ids.has(v.id), `duplicate id ${v.id}`).toBe(false);
      ids.add(v.id);
      expect(v.spec).toMatch(/^§/);
      // `why` is what makes a failing vector actionable in another language. A
      // vector that only says what it expects tells an implementer nothing about
      // which of their assumptions is wrong.
      expect(v.why.length, `${v.id} needs a why`).toBeGreaterThan(40);
    }
    expect(all.length).toBeGreaterThan(35);
  });

  it('covers both outcomes, so a verifier that always refuses cannot pass', () => {
    const chain = load<ChainVector>('chain.json');
    const accepted = chain.filter((v) => v.expect.ok);
    const refused = chain.filter((v) => !v.expect.ok);
    expect(accepted.length).toBeGreaterThan(3);
    expect(refused.length).toBeGreaterThan(15);
  });
});
