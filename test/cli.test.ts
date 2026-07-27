import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { run } from '../src/cli/index.js';
import { agentKeyFromSeed } from '../src/sign.js';

/**
 * §1.4 — `am`.
 *
 * The last describe is the one that justifies the command existing: `am inspect`
 * has to make the §7 non-transitivity defect *visible*, not merely detectable.
 * A verifier already detects it; what took property tests to find was seeing it.
 */

const seed = (n: number) => Buffer.from(new Uint8Array(32).fill(n)).toString('hex');
const KEY = {
  principal: agentKeyFromSeed(new Uint8Array(32).fill(1)),
  agentA: agentKeyFromSeed(new Uint8Array(32).fill(2)),
  agentB: agentKeyFromSeed(new Uint8Array(32).fill(3)),
  agentC: agentKeyFromSeed(new Uint8Array(32).fill(4)),
};

let dir: string;

interface Run {
  code: number;
  out: string;
  err: string;
}

async function am(...argv: string[]): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(argv, (s) => out.push(s), (s) => err.push(s));
  return { code, out: out.join('\n'), err: err.join('\n') };
}

const ROOT_CAV = JSON.stringify({
  max_total: { cur: 'USD', amt: '100.00' },
  max_per_txn: { cur: 'USD', amt: '1.00' },
  aud: ['*.weatherco.com'],
  settle: 'escrow_schema',
  depth: 3,
});

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'am-cli-'));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const file = (name: string) => join(dir, name);
const write = (name: string, body: string) => {
  writeFileSync(file(name), body);
  return file(name);
};

describe('keygen', () => {
  it('writes a private JWK that is not world-readable', async () => {
    const path = file('k.jwk');
    const r = await am('keygen', '--out', path);
    expect(r.code).toBe(0);

    const jwk = JSON.parse(readFileSync(path, 'utf8')) as { kty: string; crv: string; d: string };
    expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
    expect(typeof jwk.d).toBe('string');
    expect(r.out).toContain('keep it out of version control');

    // 0600. Windows does not honour the mode bit, so this asserts only where it
    // means something rather than pretending it is portable.
    if (process.platform !== 'win32') {
      expect(statSync(path).mode & 0o077).toBe(0);
    }
  });

  it('prints to stdout when no --out is given', async () => {
    const r = await am('keygen');
    expect(JSON.parse(r.out)).toMatchObject({ kty: 'OKP' });
  });
});

describe('mint and attenuate', () => {
  it('issues a root and then a narrower link', async () => {
    const root = await am(
      'mint', '--seed', seed(1), '--sub', KEY.agentA.did, '--jti', 'mnd_root',
      '--cav', ROOT_CAV, '--now', '1800000000',
    );
    expect(root.code).toBe(0);
    const chain1 = JSON.parse(root.out) as string[];
    expect(chain1).toHaveLength(1);

    const path1 = write('chain1.json', root.out);
    const child = await am(
      'attenuate', '--seed', seed(2), '--sub', KEY.agentB.did, '--jti', 'mnd_a',
      '--chain', path1, '--cav', '{"max_total":{"cur":"USD","amt":"10.00"}}',
      '--now', '1800000000',
    );
    expect(child.code).toBe(0);
    expect(JSON.parse(child.out)).toHaveLength(2);
  });

  /**
   * §7 step 2: a link is signed by the holder of the link above it. Catching
   * this at issuance is worth more than catching it at verification, because
   * the person who can fix it is the one running this command.
   */
  it('refuses to attenuate with a key that does not hold the last link', async () => {
    const path1 = file('chain1.json');
    const r = await am(
      'attenuate', '--seed', seed(4), '--sub', KEY.agentC.did,
      '--chain', path1, '--cav', '{}',
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain('must be signed by the holder of the link above it');
  });

  it('rejects an unregistered caveat and says which are registered', async () => {
    const r = await am(
      'mint', '--seed', seed(1), '--sub', KEY.agentA.did,
      '--cav', '{"max_totl":{"cur":"USD","amt":"1.00"}}',
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain('unregistered caveat');
    expect(r.err).toContain('max_total');
  });

  it('rejects a subject that is not a did:key', async () => {
    const r = await am('mint', '--seed', seed(1), '--sub', 'did:web:acme.example', '--cav', '{}');
    expect(r.code).toBe(2);
    expect(r.err).toContain('not a did:key');
  });
});

describe('verify', () => {
  const resource = 'https://api.weatherco.com/v3/forecast/94110';

  it('admits a covered request and prints the fold', async () => {
    const r = await am(
      'verify', '--chain', file('chain1.json'), '--trust', KEY.principal.did,
      '--resource', resource, '--amount', '0.50 USD', '--now', '1800000010',
    );
    expect(r.code).toBe(0);
    expect(r.out).toContain('admitted');
    expect(r.out).toContain('max_per_txn 1.00 USD');
    expect(r.out).toContain('settle escrow_schema');
  });

  it('exits non-zero with the §15 code on refusal', async () => {
    const r = await am(
      'verify', '--chain', file('chain1.json'), '--trust', KEY.principal.did,
      '--resource', resource, '--amount', '5.00 USD', '--now', '1800000010',
    );
    expect(r.code).toBe(1);
    expect(r.out).toContain('amount_exceeds_cap');
  });

  it('refuses an untrusted root', async () => {
    const r = await am(
      'verify', '--chain', file('chain1.json'), '--trust', KEY.agentC.did,
      '--resource', resource, '--amount', '0.50 USD', '--now', '1800000010',
    );
    expect(r.code).toBe(1);
  });

  it('emits machine-readable output under --json', async () => {
    const r = await am(
      'verify', '--chain', file('chain1.json'), '--trust', KEY.principal.did,
      '--resource', resource, '--amount', '0.50 USD', '--now', '1800000010', '--json',
    );
    expect(JSON.parse(r.out)).toMatchObject({ ok: true });
  });

  it('explains a malformed amount rather than guessing', async () => {
    const r = await am(
      'verify', '--chain', file('chain1.json'), '--trust', KEY.principal.did,
      '--resource', resource, '--amount', 'twenty quid',
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain('1.00 USD');
  });
});

describe('replay', () => {
  it('drains the budget and then refuses, naming the binding mandate', async () => {
    const spends = write(
      'spends.json',
      JSON.stringify(
        Array.from({ length: 12 }, (_, i) => ({
          resource: `https://api.weatherco.com/v3/forecast/${94110 + i}`,
          amount: { cur: 'USD', amt: '1.00' },
        })),
      ),
    );

    // chain2 caps the child at 10.00 under a root of 100.00.
    const chain2 = write(
      'chain2.json',
      (
        await am(
          'attenuate', '--seed', seed(2), '--sub', KEY.agentB.did, '--jti', 'mnd_a',
          '--chain', file('chain1.json'), '--cav', '{"max_total":{"cur":"USD","amt":"10.00"}}',
          '--now', '1800000000',
        )
      ).out,
    );

    const r = await am(
      'replay', '--chain', chain2, '--trust', KEY.principal.did,
      '--spends', spends, '--now', '1800000010',
    );

    expect(r.code).toBe(1); // not everything was admitted
    expect(r.out).toContain('10/12 admitted');
    expect(r.out).toContain('budget_exhausted');
    // The binding constraint is the child's 10.00, not the root's 100.00.
    // Printing the root's would put "90 USD left" directly above
    // "budget_exhausted" and read as a contradiction.
    expect(r.out).toContain('mnd_a has 0 USD left');
    expect(r.out).not.toContain('90 USD left');
  });

  it('reports per-spend outcomes under --json', async () => {
    const spends = write(
      'one.json',
      JSON.stringify([
        {
          resource: 'https://api.weatherco.com/v3/forecast/94110',
          amount: { cur: 'USD', amt: '0.50' },
        },
      ]),
    );
    const r = await am(
      'replay', '--chain', file('chain1.json'), '--trust', KEY.principal.did,
      '--spends', spends, '--now', '1800000010', '--json',
    );
    const parsed = JSON.parse(r.out) as { spends: Array<Record<string, unknown>> };
    expect(parsed.spends[0]).toMatchObject({ ok: true });
    expect(parsed.spends[0]!['binding']).toMatchObject({ jti: 'mnd_root' });
  });
});

/**
 * The reason §1.4 was on the roadmap at all.
 *
 * The defect: a middle link that omits a caveat is ⊤ on that dimension, so a
 * grandchild can re-declare what its grandparent forbade while every
 * parent-child check passes. It took property tests to find. It should take
 * about four seconds to see.
 */
describe('inspect shows the grandchild escape', () => {
  let chain3: string;

  beforeAll(async () => {
    const c2 = (
      await am(
        'attenuate', '--seed', seed(2), '--sub', KEY.agentB.did, '--jti', 'mnd_a',
        '--chain', file('chain1.json'),
        // Omits `settle` — this is the link that makes the escape possible.
        '--cav', '{"max_total":{"cur":"USD","amt":"10.00"}}', '--now', '1800000000',
      )
    ).out;
    const p2 = write('c2.json', c2);
    chain3 = write(
      'c3.json',
      (
        await am(
          'attenuate', '--seed', seed(3), '--sub', KEY.agentC.did, '--jti', 'mnd_b',
          '--chain', p2,
          // Re-declares what the grandparent forbade.
          '--cav', '{"settle":"immediate"}', '--now', '1800000000',
        )
      ).out,
    );
  });

  it('prints the accumulated meet beside every link', async () => {
    const r = await am('inspect', '--chain', chain3);

    // The middle link declares only max_total, and the meet beside it still
    // shows the grandparent's settle. That juxtaposition is the whole point.
    expect(r.out).toContain('mnd_a');
    expect(r.out).toContain('inherits');
    expect(r.out).toMatch(/declares\s+max_total 10\.00 USD/);

    // The offending link declares `immediate` while the meet above says
    // `escrow_schema`.
    expect(r.out).toMatch(/declares\s+settle immediate/);
    expect(r.out).toContain('attenuation_violation against the accumulated meet');
    expect(r.out).toContain('settle immediate is looser than parent escrow_schema');
    expect(r.out).toContain('comparing each link against the meet of everything above it');
    expect(r.out).toContain('chain does not attenuate');
    expect(r.code).toBe(1);
  });

  it('is clean on a chain that genuinely attenuates', async () => {
    const r = await am('inspect', '--chain', file('c2.json'));
    expect(r.code).toBe(0);
    expect(r.out).toContain('every link narrows the accumulated meet');
    expect(r.out).not.toContain('attenuation_violation');
  });

  it('needs no request context, unlike verify', async () => {
    // A chain that would fail §8 coverage still has a fold worth reading, so
    // inspect takes no resource or amount at all.
    const r = await am('inspect', '--chain', file('chain1.json'));
    expect(r.code).toBe(0);
    expect(r.out).toContain('[0] mnd_root');
  });

  it('reports each link under --json', async () => {
    const r = await am('inspect', '--chain', chain3, '--json');
    const parsed = JSON.parse(r.out) as {
      links: Array<{ jti: string; narrows: boolean; meet: Record<string, unknown>; code?: string }>;
    };
    expect(parsed.links.map((l) => l.jti)).toEqual(['mnd_root', 'mnd_a', 'mnd_b']);
    expect(parsed.links[1]!.meet['settle']).toBe('escrow_schema');
    expect(parsed.links[2]).toMatchObject({ narrows: false, code: 'attenuation_violation' });
  });
});

describe('argument handling', () => {
  it('prints usage for help and for an unknown command', async () => {
    expect((await am('help')).out).toContain('am inspect');
    const unknown = await am('frobnicate');
    expect(unknown.code).toBe(2);
    expect(unknown.err).toContain('unknown command');
  });

  it('explains a missing chain rather than reading an empty stdin forever', async () => {
    const r = await am('inspect', '--chain', join(dir, 'nope.json'));
    expect(r.code).toBe(1);
  });

  it('rejects a chain that is not an array of strings', async () => {
    const bad = write('bad.json', '{"not":"an array"}');
    const r = await am('inspect', '--chain', bad);
    expect(r.code).toBe(2);
    expect(r.err).toContain('JSON array of compact JWS strings');
  });
});
