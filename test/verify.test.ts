import { beforeAll, describe, expect, it } from 'vitest';

import type { AgentKey } from '../src/sign.js';
import { LEDGER, NOW, buildChain, generateAgentKey, trustOnly, usd } from './helpers.js';
import { type VerifyResult, verifyChain } from '../src/verify.js';

let principal: AgentKey;
let agentA: AgentKey;
let agentC: AgentKey;
let stranger: AgentKey;

beforeAll(() => {
  principal = generateAgentKey();
  agentA = generateAgentKey();
  agentC = generateAgentKey();
  stranger = generateAgentKey();
});

const baseRequest = {
  resource: 'https://api.weatherco.com/v3/forecast/94110',
  amount: usd('0.02'),
  purpose: 'research.readonly',
  taskId: 'tsk_01',
};

function verify(tokens: string[], overrides: Partial<Parameters<typeof verifyChain>[1]> = {}) {
  return verifyChain(tokens, {
    now: NOW + 10,
    request: baseRequest,
    // The value `buildChain` mints, so the §7 step 3 identity check is live for
    // every test here rather than opted out of by default.
    ledger: LEDGER,
    isTrustedRootIssuer: trustOnly(principal),
    ...overrides,
  });
}

const expectFail = (r: VerifyResult, code: string) => {
  expect(r.ok).toBe(false);
  if (r.ok === false) expect(r.code).toBe(code);
};

/** Spec Appendix A, end to end. */
function appendixAChain() {
  return buildChain(principal, [
    {
      holder: agentA,
      exp: NOW + 86400,
      cav: {
        max_total: usd('50.00'),
        max_per_txn: usd('2.00'),
        aud: ['*.datavendor.io', 'api.weatherco.com'],
        purpose: ['research.readonly'],
        depth: 2,
        delegable: true,
      },
    },
    {
      holder: agentC,
      exp: NOW + 3600,
      cav: {
        max_total: usd('10.00'),
        max_per_txn: usd('0.50'),
        aud: ['api.weatherco.com'],
        resources: ['https://api.weatherco.com/v3/forecast/*'],
        purpose: ['research.readonly'],
        task: 'tsk_01',
        rate: { n: 200, per: 'PT1H' },
        depth: 0,
        delegable: false,
      },
    },
  ]);
}

describe('verifyChain — happy path', () => {
  it('accepts the Appendix A delegation and folds the effective authority', async () => {
    const r = await verify(appendixAChain());
    expect(r.ok).toBe(true);
    if (!r.ok) return;

    expect(r.effective.max_total).toEqual(usd('10.00'));
    expect(r.effective.max_per_txn).toEqual(usd('0.50'));
    expect(r.effective.aud).toEqual(['api.weatherco.com']);
    expect(r.effective.delegable).toBe(false);
    expect(r.window.exp).toBe(NOW + 3600);
    expect(r.chainHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.leaf.sub).toBe(agentC.did);
  });

  it('accepts a single root mandate', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, cav: { max_per_txn: usd('1.00'), aud: ['api.weatherco.com'] } },
    ]);
    expect((await verify(chain)).ok).toBe(true);
  });

  it('binds the presenter key to the leaf cnf.jkt', async () => {
    const chain = appendixAChain();
    expect((await verify(chain, { presenterJkt: agentC.jkt })).ok).toBe(true);
    expectFail(await verify(chain, { presenterJkt: agentA.jkt }), 'pop_failed');
  });
});

describe('verifyChain — attenuation', () => {
  it('rejects a child that widens its parent', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, cav: { max_total: usd('10.00') } },
      { holder: agentC, cav: { max_total: usd('50.00') } },
    ]);
    expectFail(await verify(chain), 'attenuation_violation');
  });

  it('rejects delegation from a sealed mandate', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, cav: { delegable: false } },
      { holder: agentC, cav: {} },
    ]);
    expectFail(await verify(chain), 'attenuation_violation');
  });

  it('consumes one depth per hop, and omission inherits rather than resetting', async () => {
    const deep = buildChain(principal, [
      { holder: agentA, cav: { depth: 1 } },
      { holder: agentC, cav: {} },
      { holder: stranger, cav: {} },
    ]);
    expectFail(await verify(deep), 'depth_exceeded');

    const okChain = buildChain(principal, [
      { holder: agentA, cav: { depth: 1 } },
      { holder: agentC, cav: {} },
    ]);
    const r = await verify(okChain);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.effective.depth).toBe(0);
  });

  it('re-applies a caveat the child omitted', async () => {
    // agentC's link says nothing about resources; the root's restriction must survive.
    const chain = buildChain(principal, [
      { holder: agentA, cav: { resources: ['https://api.weatherco.com/v9/*'] } },
      { holder: agentC, cav: { max_per_txn: usd('1.00') } },
    ]);
    expectFail(await verify(chain), 'resource_not_covered');
  });

  it('blocks the grandchild escape that pairwise checking would allow', async () => {
    // The root requires escrow. The middle link omits `settle` entirely, which
    // is legal (it narrows nothing). A verifier comparing each link only
    // against its immediate parent would then accept the grandchild declaring
    // `settle: immediate`, because its parent is ⊤ on that dimension — and the
    // principal's escrow requirement would evaporate two hops down.
    const chain = buildChain(principal, [
      { holder: agentA, cav: { settle: 'escrow_schema' } },
      { holder: agentC, cav: {} },
      { holder: stranger, cav: { settle: 'immediate' } },
    ]);
    const r = await verify(chain);
    expectFail(r, 'attenuation_violation');
    if (!r.ok) expect(r.link).toBe(2);
  });

  it('blocks the same escape on resources', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, cav: { resources: ['https://api.weatherco.com/v3/forecast/*'] } },
      { holder: agentC, cav: {} },
      { holder: stranger, cav: { resources: ['https://api.weatherco.com/*'] } },
    ]);
    expectFail(await verify(chain), 'attenuation_violation');
  });

  it('rejects an unregistered caveat key anywhere in the chain', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, cav: { max_total: usd('1.00') } },
      { holder: agentC, cav: { maxTotal: usd('999.00') } as never },
    ]);
    expectFail(await verify(chain), 'unknown_caveat');
  });

  it('narrows the validity window structurally', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, exp: NOW + 100, cav: {} },
      { holder: agentC, exp: NOW + 5000, cav: {} },
    ]);
    expectFail(await verify(chain), 'attenuation_violation');
  });
});

describe('verifyChain — structure and signatures', () => {
  it('rejects an untrusted root issuer', async () => {
    const chain = buildChain(stranger, [{ holder: agentA, cav: {} }]);
    expectFail(await verify(chain), 'chain_invalid');
  });

  it('rejects a link signed by anyone but the parent holder', async () => {
    const good = buildChain(principal, [
      { holder: agentA, cav: {} },
      { holder: agentC, cav: {} },
    ]);
    const forged = buildChain(principal, [{ holder: agentA, cav: {} }]);
    // Splice a link signed by `stranger` rather than by agentA.
    const rogue = buildChain(stranger, [
      { holder: agentC, cav: {}, jti: 'mnd_1' },
    ]);
    expect(good.length).toBe(2);
    expectFail(await verify([forged[0]!, rogue[0]!]), 'chain_invalid');
  });

  it('rejects a tampered payload', async () => {
    const chain = appendixAChain();
    const [h, p, s] = chain[1]!.split('.') as [string, string, string];
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    (claims['cav'] as Record<string, unknown>)['max_per_txn'] = usd('999.00');
    const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${s}`;
    expectFail(await verify([chain[0]!, tampered]), 'chain_invalid');
  });

  it('rejects alg:none and unsigned tokens', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ v: 'am/1', typ: 'mandate' })).toString(
      'base64url',
    );
    expectFail(await verify([`${header}.${payload}.AA`]), 'chain_invalid');
  });

  it('rejects unknown top-level claims', async () => {
    const chain = buildChain(principal, [
      {
        holder: agentA,
        cav: {},
        tamper: (c) => {
          (c as unknown as Record<string, unknown>)['admin'] = true;
        },
      },
    ]);
    expectFail(await verify(chain), 'chain_invalid');
  });

  it('rejects links that disagree on the ledger', async () => {
    const chain = buildChain(principal, [
      { holder: agentA, cav: {} },
      {
        holder: agentC,
        cav: {},
        tamper: (c) => {
          c.ledger = 'https://other-ledger.example.com';
        },
      },
    ]);
    expectFail(await verify(chain), 'chain_invalid');
  });

  it('enforces MAX_DEPTH', async () => {
    const keys = [agentA, agentC, stranger, generateAgentKey(), generateAgentKey()];
    const chain = buildChain(
      principal,
      keys.map((holder) => ({ holder, cav: {} })),
    );
    expectFail(await verify(chain), 'chain_invalid');
  });
});

describe('verifyChain — request coverage', () => {
  const chainFor = (cav: Record<string, unknown>) =>
    buildChain(principal, [{ holder: agentA, cav: cav as never }]);

  it('rejects a resource outside the grant, including via traversal', async () => {
    const chain = chainFor({ resources: ['https://api.weatherco.com/v3/forecast/*'] });
    expect((await verify(chain)).ok).toBe(true);
    expectFail(
      await verify(chain, {
        request: { ...baseRequest, resource: 'https://api.weatherco.com/v3/forecast/../../admin' },
      }),
      'resource_not_covered',
    );
    expectFail(
      await verify(chain, {
        request: {
          ...baseRequest,
          resource: 'https://api.weatherco.com/v3/forecast/%2E%2E/%2E%2E/admin',
        },
      }),
      'resource_not_covered',
    );
  });

  it('rejects a host outside aud', async () => {
    const chain = chainFor({ aud: ['*.datavendor.io'] });
    expectFail(await verify(chain), 'audience_mismatch');
  });

  it('rejects a missing or ungranted purpose', async () => {
    const chain = chainFor({ purpose: ['research.readonly'] });
    expectFail(
      await verify(chain, { request: { ...baseRequest, purpose: 'write' } }),
      'purpose_not_covered',
    );
    expectFail(
      await verify(chain, { request: { resource: baseRequest.resource, amount: usd('0.02') } }),
      'purpose_not_covered',
    );
  });

  it('rejects a call whose blast radius exceeds the granted effect', async () => {
    const chain = chainFor({ effect: 'read' });

    expectFail(
      await verify(chain, { request: { ...baseRequest, effect: 'write' } }),
      'effect_not_permitted',
    );
    expectFail(
      await verify(chain, { request: { ...baseRequest, effect: 'irreversible' } }),
      'effect_not_permitted',
    );

    // An undeclared effect is ⊤, so any mandate that bounds effect rejects it.
    // A caller that will not classify the call does not get the benefit of the
    // doubt.
    expectFail(await verify(chain, { request: baseRequest }), 'effect_not_permitted');

    expect((await verify(chain, { request: { ...baseRequest, effect: 'read' } })).ok).toBe(true);
  });

  it('leaves requests untouched when no link constrains effect', async () => {
    // The additive guarantee (§17.3): a mandate issued before `effect` existed
    // must verify exactly as it did, whatever the request now declares.
    const chain = chainFor({});
    expect((await verify(chain, { request: baseRequest })).ok).toBe(true);
    expect(
      (await verify(chain, { request: { ...baseRequest, effect: 'irreversible' } })).ok,
    ).toBe(true);
  });

  it('pins the task when the grant does', async () => {
    const chain = chainFor({ task: 'tsk_01' });
    expect((await verify(chain)).ok).toBe(true);
    expectFail(
      await verify(chain, { request: { ...baseRequest, taskId: 'tsk_02' } }),
      'purpose_not_covered',
    );
  });

  it('enforces the per-transaction cap and rejects cross-currency requests', async () => {
    const chain = chainFor({ max_per_txn: usd('0.50') });
    expectFail(
      await verify(chain, { request: { ...baseRequest, amount: usd('0.51') } }),
      'amount_exceeds_cap',
    );
    expectFail(
      await verify(chain, {
        request: { ...baseRequest, amount: { cur: 'EUR', amt: '0.01' } },
      }),
      'currency_mismatch',
    );
  });

  it('honours sub-cent precision exactly', async () => {
    const chain = chainFor({ max_per_txn: usd('0.000001') });
    expect(
      (await verify(chain, { request: { ...baseRequest, amount: usd('0.000001') } })).ok,
    ).toBe(true);
    expectFail(
      await verify(chain, { request: { ...baseRequest, amount: usd('0.000002') } }),
      'amount_exceeds_cap',
    );
  });
});

describe('verifyChain — time', () => {
  it('rejects an expired chain outside the skew tolerance', async () => {
    const chain = appendixAChain();
    expect((await verify(chain, { now: NOW + 3600 + 59 })).ok).toBe(true);
    expectFail(await verify(chain, { now: NOW + 3600 + 61 }), 'mandate_expired');
  });

  it('rejects a not-yet-valid chain', async () => {
    const chain = buildChain(principal, [{ holder: agentA, nbf: NOW + 1000, cav: {} }]);
    expectFail(await verify(chain, { now: NOW }), 'mandate_expired');
  });
});
