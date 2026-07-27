import { describe, expect, it } from 'vitest';

import { fromAtomicUnits, toAtomicUnits } from '../src/rail/rail.js';
import {
  PAYMENT_SIGNATURE_HEADER,
  X402Rail,
  amountOf,
  chainIdFromCaip2,
  nonceFor,
  parseX402Challenge,
  refFor,
} from '../src/rail/x402.js';
import type { Reservation } from '../src/ledger/store.js';
import { toScaled } from '../src/money.js';
import {
  BASE_CAIP2,
  BASE_CHAIN_ID,
  BUY_PACK,
  FUNDING_SPREADS,
  FixtureSigner,
  LIVE,
  PAY_TO,
  USDC_BASE,
  captureFor,
  fixtureTransport,
  urlFor,
} from './fixtures/x402.js';

const NOW = 1770001240;

function reservation(over: Partial<Reservation> = {}): Reservation {
  const amount = over.amount ?? { cur: 'USD', amt: '0.001' };
  return {
    id: 'spn_000001',
    path: ['mnd_root'],
    root: 'mnd_root',
    agent: 'did:key:z6MkAgent',
    taskId: 'tsk_01',
    merchant: LIVE.host,
    resource: urlFor(FUNDING_SPREADS),
    amount,
    amountScaled: toScaled(amount),
    settle: 'immediate',
    schema: null,
    chainHash: 'sha256:abc',
    status: 'settling',
    createdAt: NOW,
    expiresAt: NOW + 60,
    ...over,
  };
}

function makeRail(t = fixtureTransport(), signer = new FixtureSigner(), extra = {}) {
  const rail = new X402Rail({
    signer,
    transport: t.transport,
    network: BASE_CAIP2,
    asset: USDC_BASE,
    assetDecimals: 6,
    clock: () => NOW,
    ...extra,
  });
  return { rail, t, signer };
}

describe('the live capture', () => {
  it('is x402 v2, CAIP-2, with the challenge in a header and an empty body', () => {
    const c = captureFor(FUNDING_SPREADS);
    expect(c.status).toBe(402);
    expect(c.decoded.x402Version).toBe(2);
    expect(c.decoded.accepts[0]!.network).toBe(BASE_CAIP2);
    expect(c.decoded.accepts[0]!.amount).toBe('1000'); // 0.001 USDC
    expect(c.decoded.accepts[0]!.payTo).toBe(PAY_TO);
    expect(c.decoded.accepts[0]!.asset).toBe(USDC_BASE);
  });

  it('carries the real EIP-712 domain name, which is "USD Coin" not "USDC"', () => {
    // Signing over the wrong domain name produces a signature that looks valid
    // and that the token contract will not accept.
    expect(captureFor(FUNDING_SPREADS).decoded.accepts[0]!.extra).toEqual({
      name: 'USD Coin',
      version: '2',
    });
  });

  it('prices span four orders of magnitude in one storefront', () => {
    // 0.001 to 24.00 USDC. This is the argument for `step_up`: an agent
    // browsing this catalog is one parse away from a four-figure transfer.
    expect(captureFor(FUNDING_SPREADS).decoded.accepts[0]!.amount).toBe('1000');
    expect(captureFor(BUY_PACK).decoded.accepts[0]!.amount).toBe('24000000');
  });
});

describe('challenge parsing', () => {
  it('reads the v2 base64 PAYMENT-REQUIRED header off a real capture', () => {
    const c = captureFor(FUNDING_SPREADS);
    const parsed = parseX402Challenge({
      status: 402,
      headers: { 'PAYMENT-REQUIRED': c.paymentRequiredHeader },
      body: {},
    })!;
    expect(parsed.x402Version).toBe(2);
    expect(amountOf(parsed.accepts[0]!)).toBe('1000');
    expect(typeof parsed.resource).toBe('object');
  });

  it('is case-insensitive about the header name', () => {
    const c = captureFor(FUNDING_SPREADS);
    expect(
      parseX402Challenge({ status: 402, headers: { 'payment-required': c.paymentRequiredHeader } }),
    ).not.toBeNull();
  });

  it('still reads the v1 body form', () => {
    const parsed = parseX402Challenge({
      status: 402,
      headers: {},
      body: {
        x402Version: 1,
        accepts: [{ scheme: 'exact', network: 'base', maxAmountRequired: '1000', asset: 'a', payTo: 'b' }],
      },
    })!;
    expect(amountOf(parsed.accepts[0]!)).toBe('1000');
  });

  it('rejects anything that is not a challenge', () => {
    expect(parseX402Challenge({ status: 402, headers: {}, body: { accepts: [] } })).toBeNull();
    expect(parseX402Challenge({ status: 402, headers: {}, body: { x402Version: 2 } })).toBeNull();
    expect(parseX402Challenge({ status: 402, headers: {}, body: {} })).toBeNull();
    expect(
      parseX402Challenge({ status: 402, headers: { 'PAYMENT-REQUIRED': 'not-base64-json' } }),
    ).toBeNull();
  });
});

describe('CAIP-2', () => {
  it('derives the EIP-712 chainId from the network identifier', () => {
    expect(chainIdFromCaip2('eip155:8453')).toBe(BASE_CHAIN_ID);
    expect(chainIdFromCaip2('eip155:1')).toBe(1);
    expect(chainIdFromCaip2('base')).toBeNull();
    expect(chainIdFromCaip2('solana:mainnet')).toBeNull();
  });
});

describe('atomic unit conversion', () => {
  it('converts exactly at the asset precision', () => {
    expect(toAtomicUnits({ cur: 'USD', amt: '0.001' }, 6)).toBe(1000n);
    expect(toAtomicUnits({ cur: 'USD', amt: '24' }, 6)).toBe(24_000_000n);
    expect(toAtomicUnits({ cur: 'USD', amt: '0.000001' }, 6)).toBe(1n);
    expect(toAtomicUnits({ cur: 'USD', amt: '0.001000000' }, 6)).toBe(1000n);
  });

  it('refuses to round away precision the rail cannot carry', () => {
    // Our amounts carry 9 decimals; USDC carries 6. Truncating 0.0000005 to zero
    // atomic units means the merchant serves the request for free and nothing
    // reports a problem — so this is an error, not a rounding decision.
    expect(toAtomicUnits({ cur: 'USD', amt: '0.0000005' }, 6)).toBeNull();
    expect(toAtomicUnits({ cur: 'USD', amt: '0.000000001' }, 6)).toBeNull();
  });

  it('round-trips', () => {
    expect(fromAtomicUnits(1000n, 6, 'USDC')).toEqual({ cur: 'USDC', amt: '0.001' });
    expect(fromAtomicUnits(24_000_000n, 6, 'USDC')).toEqual({ cur: 'USDC', amt: '24' });
  });
});

describe('X402Rail.pay against the captured challenge', () => {
  it('pays with a PAYMENT-SIGNATURE header and the real EIP-712 domain', async () => {
    const { rail, t, signer } = makeRail();
    const r = await rail.pay(reservation());

    expect(r.ok).toBe(true);
    expect(t.payments).toHaveLength(1);

    const payment = t.payments[0] as {
      x402Version: number;
      scheme: string;
      network: string;
      payload: { authorization: { to: string; value: string; nonce: string } };
    };
    expect(payment.x402Version).toBe(2);
    expect(payment.scheme).toBe('exact');
    expect(payment.network).toBe(BASE_CAIP2);
    expect(payment.payload.authorization.to).toBe(PAY_TO);
    expect(payment.payload.authorization.value).toBe('1000');

    expect(signer.signed[0]?.domain).toEqual({
      name: 'USD Coin',
      version: '2',
      chainId: BASE_CHAIN_ID,
      verifyingContract: USDC_BASE,
    });
  });

  it('sends payment in PAYMENT-SIGNATURE, not X-PAYMENT', async () => {
    let seen: Record<string, string> = {};
    const t = fixtureTransport({
      onPaid: (req) => {
        seen = req.headers;
        return { status: 200, headers: {} };
      },
    });
    await makeRail(t).rail.pay(reservation());
    expect(Object.keys(seen)).toEqual([PAYMENT_SIGNATURE_HEADER]);
  });

  it('derives the nonce from the spendId, not from randomness', async () => {
    expect(nonceFor('spn_000001')).toBe(nonceFor('spn_000001'));
    expect(nonceFor('spn_000001')).not.toBe(nonceFor('spn_000002'));
    expect(nonceFor('spn_000001')).toMatch(/^0x[0-9a-f]{64}$/);

    const { rail, t } = makeRail();
    await rail.pay(reservation());
    const auth = (t.payments[0] as { payload: { authorization: { nonce: string } } }).payload
      .authorization;
    expect(auth.nonce).toBe(nonceFor('spn_000001'));
  });

  it('falls back to the EIP-3009 identifier when no settlement header is declared', async () => {
    // This storefront returns no settlement receipt. (from, nonce) uniquely
    // identifies the authorization and is checkable on-chain via
    // authorizationState(), so it is a real reconciliation key, not a placeholder.
    const { rail, signer } = makeRail();
    const r = await rail.pay(reservation());
    expect(r).toEqual({ ok: true, ref: refFor(signer.address, 'spn_000001') });
    if (r.ok) expect(r.ref).toMatch(/^eip3009:0x[0-9a-f]{40}:0x[0-9a-f]{64}$/);
  });

  it('prefers a transaction hash when the merchant does declare one', async () => {
    const t = fixtureTransport({
      onPaid: () => ({
        status: 200,
        headers: {
          'PAYMENT-RESPONSE': Buffer.from(
            JSON.stringify({ success: true, transaction: '0xdeadbeef' }),
          ).toString('base64'),
        },
      }),
    });
    const { rail } = makeRail(t, new FixtureSigner(), { settlementHeader: 'PAYMENT-RESPONSE' });
    expect(await rail.pay(reservation())).toEqual({ ok: true, ref: '0xdeadbeef' });
  });

  it('bounds the authorization by the merchant maxTimeoutSeconds', async () => {
    const { rail, signer } = makeRail();
    await rail.pay(reservation());
    const auth = signer.signed[0]!.authorization;
    expect(Number(auth.validAfter)).toBeLessThanOrEqual(NOW);
    expect(Number(auth.validBefore)).toBe(NOW + 300);
  });

  it('is idempotent for a given spendId', async () => {
    const { rail, t } = makeRail();
    const first = await rail.pay(reservation());
    expect(await rail.pay(reservation())).toEqual(first);
    expect(t.payments).toHaveLength(1);
  });

  it('still handles a v1 body-form merchant', async () => {
    const { rail, t } = makeRail(fixtureTransport({ v1Body: true }), new FixtureSigner(), {
      network: 'base',
      chainId: BASE_CHAIN_ID,
    });
    const r = await rail.pay(reservation());
    expect(r.ok).toBe(true);
    expect((t.payments[0] as { x402Version: number }).x402Version).toBe(1);
  });
});

describe('X402Rail failure taxonomy', () => {
  const terminal = (r: Awaited<ReturnType<X402Rail['pay']>>) => !r.ok && r.terminal;
  const indeterminate = (r: Awaited<ReturnType<X402Rail['pay']>>) => !r.ok && !r.terminal;

  it('treats an amount mismatch in either direction as terminal', async () => {
    const { rail } = makeRail();
    // The capture prices this at 1000 atomic units.
    expect(terminal(await rail.pay(reservation({ amount: { cur: 'USD', amt: '0.002' } })))).toBe(true);
    const { rail: r2 } = makeRail();
    expect(terminal(await r2.pay(reservation({ amount: { cur: 'USD', amt: '0.0005' } })))).toBe(true);
  });

  it('treats an unsupported network as terminal', async () => {
    const { rail } = makeRail(fixtureTransport(), new FixtureSigner(), { network: 'eip155:1' });
    const r = await rail.pay(reservation());
    expect(terminal(r)).toBe(true);
    if (!r.ok) expect(r.detail).toContain('eip155:1');
  });

  it('treats sub-precision amounts as terminal, not as free', async () => {
    const { rail } = makeRail();
    const r = await rail.pay(reservation({ amount: { cur: 'USD', amt: '0.0000005' } }));
    expect(terminal(r)).toBe(true);
    if (!r.ok) expect(r.detail).toContain('precision');
  });

  it('treats a merchant rejection as terminal', async () => {
    const { rail } = makeRail(fixtureTransport({ onPaid: () => ({ status: 402, headers: {} }) }));
    expect(terminal(await rail.pay(reservation()))).toBe(true);
  });

  it('treats a 5xx after payment as INDETERMINATE', async () => {
    // The authorization is signed and may already be on-chain. Calling this
    // terminal refunds an agent for a transfer that landed.
    const { rail } = makeRail(fixtureTransport({ onPaid: () => ({ status: 503, headers: {} }) }));
    expect(indeterminate(await rail.pay(reservation()))).toBe(true);
  });

  it('treats a transport throw after payment as indeterminate', async () => {
    const { rail } = makeRail(
      fixtureTransport({
        onPaid: () => {
          throw new Error('ETIMEDOUT');
        },
      }),
    );
    expect(indeterminate(await rail.pay(reservation()))).toBe(true);
  });

  it('treats a missing DECLARED settlement header as indeterminate', async () => {
    const { rail } = makeRail(
      fixtureTransport({ onPaid: () => ({ status: 200, headers: {} }) }),
      new FixtureSigner(),
      { settlementHeader: 'PAYMENT-RESPONSE' },
    );
    const r = await rail.pay(reservation());
    expect(indeterminate(r)).toBe(true);
    if (!r.ok) expect(r.detail).toContain('PAYMENT-RESPONSE');
  });

  it('does not cache indeterminate outcomes', async () => {
    let calls = 0;
    const { rail } = makeRail(
      fixtureTransport({
        onPaid: () => {
          calls++;
          return calls === 1 ? { status: 503, headers: {} } : { status: 200, headers: {} };
        },
      }),
    );
    expect(indeterminate(await rail.pay(reservation()))).toBe(true);
    // Reconciliation must be free to ask again.
    expect((await rail.pay(reservation())).ok).toBe(true);
  });

  it('treats a failing unpaid probe as indeterminate', async () => {
    const { rail } = makeRail(fixtureTransport({ challengeThrows: true }));
    expect(indeterminate(await rail.pay(reservation()))).toBe(true);
  });

  it('treats a signer failure as terminal', async () => {
    const { rail } = makeRail(fixtureTransport(), new FixtureSigner(true));
    expect(terminal(await rail.pay(reservation()))).toBe(true);
  });

  it('treats an unparseable challenge as terminal', async () => {
    const { rail } = makeRail(fixtureTransport({ challengeHeader: 'bm90LWpzb24=' }));
    expect(terminal(await rail.pay(reservation()))).toBe(true);
  });
});
