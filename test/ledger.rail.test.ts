import { beforeEach, describe, expect, it } from 'vitest';

import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import type { PayResult, RailStatus, SettlementRail } from '../src/rail/rail.js';
import { NullRail, X402Rail } from '../src/rail/x402.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';
import {
  BASE_CAIP2,
  FUNDING_SPREADS,
  FixtureSigner,
  LIVE,
  NFT_OWNER,
  USDC_BASE,
  fixtureTransport,
  urlFor,
} from './fixtures/x402.js';

const RESOURCE = urlFor(FUNDING_SPREADS);

let principal: AgentKey;
let agent: AgentKey;
let ledgerKey: AgentKey;
let clock: number;
let ids = 0;

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  ledgerKey = generateAgentKey();
  clock = NOW + 10;
  ids = 0;
});

function makeLedger(rail?: SettlementRail) {
  return new Ledger({
    url: 'https://ledger.example.com',
    key: ledgerKey,
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    idFactory: (p) => `${p}_${String(++ids).padStart(6, '0')}`,
    breakers: { novelMerchant: 'off' },
    ...(rail !== undefined ? { rail } : {}),
  });
}

function chain() {
  return buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: usd('1.00'),
        max_per_txn: usd('0.50'),
        aud: [LIVE.host],
      },
    },
  ]);
}

/** 0.001 USDC = 1000 atomic units, the storefront's captured price. */
const req = { resource: RESOURCE, amount: usd('0.001') };

/** A rail whose outcome the test dictates, for exercising the failure taxonomy. */
class ScriptedRail implements SettlementRail {
  readonly name = 'scripted';
  payCalls = 0;
  statusCalls = 0;
  constructor(
    private readonly payResult: PayResult,
    private readonly statusResult: RailStatus = { state: 'unknown', detail: 'still out' },
  ) {}
  async pay(): Promise<PayResult> {
    this.payCalls++;
    return this.payResult;
  }
  async status(): Promise<RailStatus> {
    this.statusCalls++;
    return this.statusResult;
  }
}

describe('ledger with no rail', () => {
  it('keeps books and settles nothing', async () => {
    const ledger = makeLedger();
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');
    const s = await ledger.settle(r.spendId);
    expect(s.ok && s.status).toBe('settled');
    expect((await ledger.reservation(r.spendId))?.railRef).toBeUndefined();
    expect(await ledger.reconcile()).toEqual([]);
  });
});

describe('ledger with a rail', () => {
  it('pays on settle and records the reference', async () => {
    const rail = new NullRail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');

    const s = await ledger.settle(r.spendId);
    expect(s.ok && s.status).toBe('settled');
    expect(rail.paid).toEqual([{ id: r.spendId, amount: usd('0.001') }]);

    const stored = await ledger.reservation(r.spendId);
    expect(stored?.railRef).toBe(`null:${r.spendId}`);
    expect(stored?.railName).toBe('null');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
  });

  it('refunds when the rail terminally declines', async () => {
    const rail = new ScriptedRail({ ok: false, terminal: true, detail: 'price moved' });
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');

    const s = await ledger.settle(r.spendId);
    expect(s.ok && s.status).toBe('refunded');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('1');
    expect((await ledger.reservation(r.spendId))?.refundReason).toContain('price moved');
  });

  it('holds an indeterminate settlement rather than guessing', async () => {
    // Refunding on a timeout is how you pay a merchant AND hand the money back
    // to the agent. The budget stays debited until the rail is asked.
    const rail = new ScriptedRail({ ok: false, terminal: false, detail: 'ETIMEDOUT' });
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');

    const s = await ledger.settle(r.spendId);
    expect(s.ok).toBe(false);
    if (!s.ok) expect(s.detail).toContain('indeterminate');

    const stored = await ledger.reservation(r.spendId);
    expect(stored?.status).toBe('settling');
    expect(stored?.settlingSince).toBe(clock);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999'); // still debited
  });

  it('never pays twice for one reservation', async () => {
    const rail = new NullRail();
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');

    const [a, b] = await Promise.all([ledger.settle(r.spendId), ledger.settle(r.spendId)]);
    const outcomes = [a, b].map((x) => (x.ok ? x.status : x.code));
    expect(outcomes).toContain('settled');
    expect(outcomes).toContain('token_replayed');
    expect(rail.paid).toHaveLength(1);
  });

  it('does not sweep a reservation that is mid-settlement', async () => {
    const rail = new ScriptedRail({ ok: false, terminal: false, detail: 'ETIMEDOUT' });
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');
    await ledger.settle(r.spendId);

    clock += 10_000;
    expect(await ledger.sweepExpired()).toEqual([]);
    expect((await ledger.reservation(r.spendId))?.status).toBe('settling');
  });
});

describe('reconcile', () => {
  it('settles a stuck reservation the rail confirms was paid', async () => {
    const rail = new ScriptedRail(
      { ok: false, terminal: false, detail: 'ETIMEDOUT' },
      { state: 'paid', ref: '0xlanded' },
    );
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');
    await ledger.settle(r.spendId);

    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'settled' }]);
    const stored = await ledger.reservation(r.spendId);
    expect(stored?.status).toBe('settled');
    expect(stored?.railRef).toBe('0xlanded');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
  });

  it('refunds a stuck reservation the rail confirms was not paid', async () => {
    const rail = new ScriptedRail(
      { ok: false, terminal: false, detail: 'ETIMEDOUT' },
      { state: 'not_paid' },
    );
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');
    await ledger.settle(r.spendId);

    expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'refunded' }]);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('1');
  });

  it('leaves it alone while the rail is still unsure, and is safe to re-run', async () => {
    const rail = new ScriptedRail({ ok: false, terminal: false, detail: 'ETIMEDOUT' });
    const ledger = makeLedger(rail);
    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');
    await ledger.settle(r.spendId);

    for (let i = 0; i < 3; i++) {
      expect(await ledger.reconcile()).toEqual([{ spendId: r.spendId, outcome: 'still_unknown' }]);
    }
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');
    expect(rail.statusCalls).toBe(3);
  });
});

function liveRail(t: ReturnType<typeof fixtureTransport>) {
  return new X402Rail({
    signer: new FixtureSigner(),
    transport: t.transport,
    network: BASE_CAIP2,
    asset: USDC_BASE,
    assetDecimals: 6,
    clock: () => clock,
  });
}

describe('end to end against the captured storefront', () => {
  it('reserves under a mandate and settles on-rail', async () => {
    const t = fixtureTransport();
    const ledger = makeLedger(liveRail(t));

    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error(`reserve failed: ${r.detail}`);

    const s = await ledger.settle(r.spendId, { respHash: 'sha256:body' });
    expect(s.ok && s.status).toBe('settled');
    if (s.ok) {
      expect(s.receipt.claims.resp_hash).toBe('sha256:body');
      expect(s.receipt.claims.rail).toBe('x402');
      expect(s.receipt.claims.rail_ref).toMatch(/^eip3009:/);
    }

    expect((await ledger.reservation(r.spendId))?.railRef).toMatch(/^eip3009:/);
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('0.999');

    // The merchant saw an ordinary x402 client — no mandate, no chain, nothing
    // to implement on its side.
    const payment = t.payments[0] as { scheme: string; network: string };
    expect(payment.scheme).toBe('exact');
    expect(payment.network).toBe(BASE_CAIP2);
    expect(JSON.stringify(t.payments)).not.toContain('mnd_root');
  });

  it('refunds the budget when the storefront prices differently than reserved', async () => {
    // /nft/owner is captured at 3000 atomic units; the reservation is for 1000.
    const t = fixtureTransport({ path: NFT_OWNER });
    const ledger = makeLedger(liveRail(t));

    const r = await ledger.reserve({ tokens: chain(), request: req });
    if (!r.ok) throw new Error('reserve failed');

    const s = await ledger.settle(r.spendId);
    expect(s.ok && s.status).toBe('refunded');
    expect((await ledger.remaining('mnd_root'))?.amt).toBe('1');
  });
});
