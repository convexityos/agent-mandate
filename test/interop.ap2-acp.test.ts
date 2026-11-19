import { describe, expect, it } from 'vitest';

import {
  AcpRail,
  type AcpCheckoutSession,
  type AcpDelegatedAllowance,
  type AcpHttpRequest,
  type AcpHttpResponse,
  type Ap2CartMandate,
  type Ap2IntentMandate,
  Ledger,
  MemoryLedgerStore,
  acpIdempotencyKeyFor,
  ap2MoneyToMoney,
  generateAgentKey,
  issueMandateFromAcpAllowance,
  issueMandateFromAp2Cart,
  issueMandateFromAp2Intent,
  mandateClaimsFromAcpAllowance,
  mandateClaimsFromAp2Cart,
  mandateClaimsFromAp2Intent,
  signMandate,
  toAp2PaymentMandate,
  verifyChain,
} from '../src/index.js';
import { PROTOCOL_VERSION } from '../src/types.js';

const NOW = 1_780_000_000;
const EXP_ISO = new Date((NOW + 3600) * 1000).toISOString();
const PAST_ISO = new Date((NOW - 60) * 1000).toISOString();
const LEDGER_URL = 'https://ledger.example';

function makeLedger(
  principalDid: string,
  rail?: AcpRail,
): { ledger: Ledger; store: MemoryLedgerStore; ledgerKey: ReturnType<typeof generateAgentKey> } {
  const ledgerKey = generateAgentKey();
  const store = new MemoryLedgerStore(() => NOW);
  const ledger = new Ledger({
    url: LEDGER_URL,
    key: ledgerKey,
    isTrustedRootIssuer: (did) => did === principalDid,
    store,
    clock: () => NOW,
    breakers: { novelMerchant: 'off' },
    ...(rail !== undefined ? { rail } : {}),
  });
  return { ledger, store, ledgerKey };
}

describe('AP2 interop adapter', () => {
  it('parses AP2 money strictly and rejects float drift, negatives, and >9 decimals', () => {
    expect(ap2MoneyToMoney({ currency: 'usd', value: '12.50' })).toEqual({
      ok: true,
      money: { cur: 'USD', amt: '12.50' },
    });
    expect(ap2MoneyToMoney({ currency: 'EUR', value: 19.95 })).toEqual({
      ok: true,
      money: { cur: 'EUR', amt: '19.95' },
    });
    expect(ap2MoneyToMoney({ currency: 'USD', value: -1 }).ok).toBe(false);
    expect(ap2MoneyToMoney({ currency: 'USD', value: Number.NaN }).ok).toBe(false);
    expect(ap2MoneyToMoney({ currency: 'USD', value: '0.0000000001' }).ok).toBe(false);
    expect(ap2MoneyToMoney({ currency: 'USD', value: 1e-12 }).ok).toBe(false);
  });

  it('refuses to mint an unbounded mandate when AP2 IntentMandate omits a cap', () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const intent: Ap2IntentMandate = {
      user_cart_confirmation_required: false,
      natural_language_description: 'Buy office supplies',
      intent_expiry: EXP_ISO,
    };
    const res = mandateClaimsFromAp2Intent(intent, {
      issuer: principal.did,
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe('chain_invalid');
  });

  it('maps AP2 IntentMandate into a verifiable, sub-delegatable am/1 root mandate', async () => {
    const principal = generateAgentKey();
    const orchestrator = generateAgentKey();
    const worker = generateAgentKey();

    const intent: Ap2IntentMandate = {
      user_cart_confirmation_required: false,
      natural_language_description: 'Purchase weather forecasts up to $25',
      merchants: ['https://shop.example/api/v1'],
      intent_expiry: EXP_ISO,
      max_amount: { currency: 'USD', value: '25.00' },
    };

    const issued = issueMandateFromAp2Intent(intent, principal, {
      subject: orchestrator.did,
      subjectJkt: orchestrator.jkt,
      ledger: LEDGER_URL,
      now: NOW,
      maxTotal: { cur: 'USD', amt: '20.00' },
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    expect(issued.claims.cav.max_total).toEqual({ cur: 'USD', amt: '20.00' });
    expect(issued.claims.cav.aud).toEqual(['shop.example']);
    expect(issued.claims.cav.resources).toEqual(['https://shop.example/api/v1/*']);

    // Sub-delegate $5 to a worker subagent and verify the full chain.
    const child = signMandate(
      {
        v: PROTOCOL_VERSION,
        typ: 'mandate',
        jti: 'mnd_worker_1',
        iss: orchestrator.did,
        sub: worker.did,
        par: issued.claims.jti,
        iat: NOW,
        nbf: NOW,
        exp: NOW + 1800,
        cnf: { jkt: worker.jkt },
        ledger: LEDGER_URL,
        cav: {
          max_total: { cur: 'USD', amt: '5.00' },
          max_per_txn: { cur: 'USD', amt: '5.00' },
        },
      },
      orchestrator,
    );

    const verified = await verifyChain([issued.token, child], {
      isTrustedRootIssuer: (did) => did === principal.did,
      ledger: LEDGER_URL,
      now: NOW,
      request: {
        resource: 'https://shop.example/api/v1/forecast',
        amount: { cur: 'USD', amt: '2.50' },
        taskId: issued.claims.cav.task,
      },
    });
    expect(verified.ok).toBe(true);

    const { ledger } = makeLedger(principal.did);
    const reserved = await ledger.reserve({
      tokens: [issued.token, child],
      request: {
        resource: 'https://shop.example/api/v1/forecast',
        amount: { cur: 'USD', amt: '2.50' },
        taskId: issued.claims.cav.task,
      },
    });
    expect(reserved.ok).toBe(true);
  });

  it('enforces step-up in Ledger when AP2 IntentMandate requires user cart confirmation', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();

    const intent: Ap2IntentMandate = {
      user_cart_confirmation_required: true,
      natural_language_description: 'Buy flight ticket',
      merchants: ['air.example'],
      intent_expiry: EXP_ISO,
      max_amount: { currency: 'USD', value: '500.00' },
    };

    const issued = issueMandateFromAp2Intent(intent, principal, {
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    expect(issued.claims.cav.step_up).toEqual({ over: { cur: 'USD', amt: '0' } });

    const { ledger } = makeLedger(principal.did);
    const reserved = await ledger.reserve({
      tokens: [issued.token],
      request: {
        resource: 'https://air.example/checkout',
        amount: { cur: 'USD', amt: '100.00' },
        taskId: issued.claims.cav.task,
      },
    });
    expect(reserved.ok).toBe(false);
    if (!reserved.ok) {
      expect(reserved.code).toBe('step_up_required');
    }
  });

  it('refuses immediate settlement when AP2 IntentMandate requires refundability', () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const intent: Ap2IntentMandate = {
      user_cart_confirmation_required: false,
      natural_language_description: 'Book refundable hotel',
      requires_refundability: true,
      intent_expiry: EXP_ISO,
      max_amount: { currency: 'USD', value: '300.00' },
    };

    const downgraded = mandateClaimsFromAp2Intent(intent, {
      issuer: principal.did,
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
      refundableSettle: 'immediate',
    });
    expect(downgraded.ok).toBe(false);
    if (!downgraded.ok) expect(downgraded.code).toBe('attenuation_violation');

    const defaulted = mandateClaimsFromAp2Intent(intent, {
      issuer: principal.did,
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
    });
    expect(defaulted.ok).toBe(true);
    if (defaulted.ok) expect(defaulted.claims.cav.settle).toBe('escrow_human');
  });

  it('rejects expired or timezone-ambiguous AP2 expiries and wildcard merchants', () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const baseOpts = {
      issuer: principal.did,
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
    };

    const expired = mandateClaimsFromAp2Intent(
      {
        user_cart_confirmation_required: false,
        natural_language_description: 'Expired',
        intent_expiry: PAST_ISO,
        max_amount: { currency: 'USD', value: '10' },
      },
      baseOpts,
    );
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.code).toBe('mandate_expired');

    const noTz = mandateClaimsFromAp2Intent(
      {
        user_cart_confirmation_required: false,
        natural_language_description: 'No timezone',
        intent_expiry: '2026-12-01T00:00:00',
        max_amount: { currency: 'USD', value: '10' },
      },
      baseOpts,
    );
    expect(noTz.ok).toBe(false);

    const wildcard = mandateClaimsFromAp2Intent(
      {
        user_cart_confirmation_required: false,
        natural_language_description: 'Wildcard',
        merchants: ['*.shop.example'],
        intent_expiry: EXP_ISO,
        max_amount: { currency: 'USD', value: '10' },
      },
      baseOpts,
    );
    expect(wildcard.ok).toBe(false);
  });

  it('pins AP2 CartMandate to exact total, enforces merchant_authorization and parent intent, and exports PaymentMandate', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();

    const parentIntent: Ap2IntentMandate = {
      user_cart_confirmation_required: true,
      natural_language_description: 'Buy running shoes under $150',
      merchants: ['shoes.example'],
      intent_expiry: EXP_ISO,
      max_amount: { currency: 'USD', value: '150.00' },
    };

    const cart: Ap2CartMandate = {
      contents: {
        id: 'cart_01',
        user_cart_confirmation_required: true,
        merchant_name: 'shoes.example',
        merchant_url: 'https://shoes.example/checkout/cart_01',
        cart_expiry: new Date((NOW + 1800) * 1000).toISOString(),
        payment_request: {
          details: {
            id: 'order_01',
            total: { label: 'Total', amount: { currency: 'USD', value: '120.00' } },
            display_items: [{ label: 'Shoes', amount: { currency: 'USD', value: '120.00' } }],
          },
        },
      },
      merchant_authorization: 'eyJhbGciOiJFZERTQSJ9.payload.sig',
    };

    // Missing merchant_authorization fails closed by default.
    const noAuth = mandateClaimsFromAp2Cart(
      { contents: cart.contents },
      {
        issuer: principal.did,
        subject: agent.did,
        subjectJkt: agent.jkt,
        ledger: LEDGER_URL,
        now: NOW,
      },
    );
    expect(noAuth.ok).toBe(false);

    // Cart exceeding parent intent cap fails closed.
    const overpricedCart: Ap2CartMandate = {
      ...cart,
      contents: {
        ...cart.contents,
        payment_request: {
          details: {
            id: 'order_02',
            total: { label: 'Total', amount: { currency: 'USD', value: '200.00' } },
          },
        },
      },
    };
    const overCap = mandateClaimsFromAp2Cart(overpricedCart, {
      issuer: principal.did,
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
      parentIntent,
    });
    expect(overCap.ok).toBe(false);
    if (!overCap.ok) expect(overCap.code).toBe('attenuation_violation');

    // Valid user-confirmed cart settles through Ledger and exports to AP2 PaymentMandate.
    const issued = issueMandateFromAp2Cart(cart, principal, {
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
      parentIntent,
      userConfirmed: true,
      verifyMerchantAuthorization: (c) => c.merchant_authorization === cart.merchant_authorization,
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    expect(issued.claims.cav.rate).toEqual({ n: 1, per: 'PT24H' });
    expect(issued.claims.cav.delegable).toBe(false);

    const { ledger } = makeLedger(principal.did);
    const reserved = await ledger.reserve({
      tokens: [issued.token],
      request: {
        resource: 'https://shoes.example/checkout/cart_01',
        amount: { cur: 'USD', amt: '120.00' },
        taskId: 'ap2cart:cart_01',
      },
    });
    expect(reserved.ok).toBe(true);
    if (!reserved.ok) return;

    const settled = await ledger.settle(reserved.spendId, {
      respHash: 'sha256:' + 'a'.repeat(64),
      respBytes: 512,
    });
    expect(settled.ok).toBe(true);
    if (!settled.ok) return;

    const pm = toAp2PaymentMandate({
      receipt: settled.receipt,
      paymentDetailsId: 'order_01',
      methodName: 'https://agentmandate.org/am1',
      merchantAgent: 'shoes.example',
    });
    expect(pm.payment_mandate_contents.payment_details_total.amount).toEqual({
      currency: 'USD',
      value: '120.00',
    });
    expect(pm.am1_provenance.spend_id).toBe(reserved.spendId);
    expect(pm.am1_provenance.root_jti).toBe(issued.claims.jti);
    expect(pm.am1_provenance.receipt_sig).toBe(settled.receipt.sigs.ledger);
  });
});

describe('ACP interop adapter and AcpRail', () => {
  it('maps ACP DelegatedPayment allowance onto a verifiable root am/1 mandate and rejects invalid inputs', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const allowance: AcpDelegatedAllowance = {
      reason: 'one_time',
      max_amount: 4995,
      currency: 'usd',
      checkout_session_id: 'cs_live_123',
      merchant_id: 'merch_acme',
      expires_at: NOW + 900,
    };

    const issued = issueMandateFromAcpAllowance(allowance, principal, {
      subject: agent.did,
      subjectJkt: agent.jkt,
      ledger: LEDGER_URL,
      now: NOW,
      merchantResource: 'https://merchant.example/acp/checkout_sessions/cs_live_123',
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    expect(issued.claims.cav.max_total).toEqual({ cur: 'USD', amt: '49.95' });
    expect(issued.claims.cav.task).toBe('acp:cs_live_123');
    expect(issued.claims.cav.rate).toEqual({ n: 1, per: 'PT24H' });

    const verified = await verifyChain([issued.token], {
      isTrustedRootIssuer: (did) => did === principal.did,
      ledger: LEDGER_URL,
      now: NOW,
      request: {
        resource: 'https://merchant.example/acp/checkout_sessions/cs_live_123',
        amount: { cur: 'USD', amt: '49.95' },
        taskId: 'acp:cs_live_123',
      },
    });
    expect(verified.ok).toBe(true);

    // Non-integer minor units rejected.
    const fractional = mandateClaimsFromAcpAllowance(
      { ...allowance, max_amount: 49.95 },
      {
        issuer: principal.did,
        subject: agent.did,
        subjectJkt: agent.jkt,
        ledger: LEDGER_URL,
        now: NOW,
      },
    );
    expect(fractional.ok).toBe(false);

    // Expired allowance rejected.
    const expired = mandateClaimsFromAcpAllowance(
      { ...allowance, expires_at: NOW - 10 },
      {
        issuer: principal.did,
        subject: agent.did,
        subjectJkt: agent.jkt,
        ledger: LEDGER_URL,
        now: NOW,
      },
    );
    expect(expired.ok).toBe(false);
    if (!expired.ok) expect(expired.code).toBe('mandate_expired');
  });

  it('settles an ACP checkout session end-to-end with deterministic Idempotency-Key', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const calls: AcpHttpRequest[] = [];

    const session: AcpCheckoutSession = {
      id: 'cs_ok_1',
      status: 'ready_for_payment',
      currency: 'usd',
      totals: [{ type: 'total', display_text: 'Total', amount: 2550 }],
    };

    const rail = new AcpRail({
      checkoutBaseUrl: 'https://merchant.example/acp',
      paymentTokenFor: () => 'spt_tok_123',
      transport: async (req): Promise<AcpHttpResponse> => {
        calls.push(req);
        if (req.method === 'GET') {
          return { status: 200, body: session };
        }
        return {
          status: 200,
          body: {
            ...session,
            status: 'completed',
            order: { id: 'ord_999', checkout_session_id: 'cs_ok_1' },
          },
        };
      },
    });

    const issued = issueMandateFromAcpAllowance(
      {
        reason: 'one_time',
        max_amount: 2550,
        currency: 'USD',
        checkout_session_id: 'cs_ok_1',
        merchant_id: 'merch_1',
        expires_at: NOW + 600,
      },
      principal,
      {
        subject: agent.did,
        subjectJkt: agent.jkt,
        ledger: LEDGER_URL,
        now: NOW,
        merchantResource: 'https://merchant.example/acp/checkout_sessions/cs_ok_1',
      },
    );
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const { ledger } = makeLedger(principal.did, rail);
    const reserved = await ledger.reserve({
      tokens: [issued.token],
      request: {
        resource: 'https://merchant.example/acp/checkout_sessions/cs_ok_1',
        amount: { cur: 'USD', amt: '25.50' },
        taskId: 'acp:cs_ok_1',
      },
    });
    expect(reserved.ok).toBe(true);
    if (!reserved.ok) return;

    const settled = await ledger.settle(reserved.spendId, {
      respHash: 'sha256:' + 'b'.repeat(64),
      respBytes: 256,
    });
    expect(settled.ok).toBe(true);
    if (!settled.ok) return;
    expect(settled.status).toBe('settled');

    const stored = await ledger.reservation(reserved.spendId);
    expect(stored?.railRef).toBe('ord_999');
    expect(stored?.railName).toBe('acp');

    expect(calls).toHaveLength(2);
    expect(calls[0]?.method).toBe('GET');
    expect(calls[1]?.method).toBe('POST');
    expect(calls[1]?.headers['Idempotency-Key']).toBe(acpIdempotencyKeyFor(reserved.spendId));
  });

  it('refuses ACP completion when merchant reprices the checkout session total', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    let postCalled = false;

    const rail = new AcpRail({
      checkoutBaseUrl: 'https://merchant.example/acp',
      paymentTokenFor: () => 'spt_tok_reprice',
      transport: async (req): Promise<AcpHttpResponse> => {
        if (req.method === 'POST') postCalled = true;
        return {
          status: 200,
          body: {
            id: 'cs_reprice',
            status: 'ready_for_payment',
            currency: 'usd',
            // Repriced from 1000 ($10.00) to 9900 ($99.00)
            totals: [{ type: 'total', display_text: 'Total', amount: 9900 }],
          } satisfies AcpCheckoutSession,
        };
      },
    });

    const issued = issueMandateFromAcpAllowance(
      {
        reason: 'one_time',
        max_amount: 1000,
        currency: 'USD',
        checkout_session_id: 'cs_reprice',
        merchant_id: 'merch_1',
        expires_at: NOW + 600,
      },
      principal,
      {
        subject: agent.did,
        subjectJkt: agent.jkt,
        ledger: LEDGER_URL,
        now: NOW,
        merchantResource: 'https://merchant.example/acp/checkout_sessions/cs_reprice',
      },
    );
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const { ledger } = makeLedger(principal.did, rail);
    const reserved = await ledger.reserve({
      tokens: [issued.token],
      request: {
        resource: 'https://merchant.example/acp/checkout_sessions/cs_reprice',
        amount: { cur: 'USD', amt: '10.00' },
        taskId: 'acp:cs_reprice',
      },
    });
    expect(reserved.ok).toBe(true);
    if (!reserved.ok) return;

    const settled = await ledger.settle(reserved.spendId, {
      respHash: 'sha256:' + 'c'.repeat(64),
      respBytes: 128,
    });
    expect(postCalled).toBe(false);
    expect(settled.ok).toBe(true);
    if (settled.ok) expect(settled.status).toBe('refunded');

    // Budget was credited back because completion never ran.
    expect((await ledger.remaining(issued.claims.jti))?.amt).toBe('10');
  });

  it('rejects sub-minor-unit amounts in AcpRail without rounding', async () => {
    const rail = new AcpRail({
      checkoutBaseUrl: 'https://merchant.example/acp',
      paymentTokenFor: () => 'spt_tok_prec',
      transport: async () => {
        throw new Error('transport must not be called for sub-cent amount');
      },
    });

    const res = await rail.pay({
      id: 'spn_prec',
      path: ['mnd_1'],
      root: 'mnd_1',
      agent: 'did:key:z6MkTest',
      taskId: 'acp:cs_prec',
      merchant: 'merchant.example',
      resource: 'https://merchant.example/acp/checkout_sessions/cs_prec',
      amount: { cur: 'USD', amt: '1.005' },
      amountScaled: 1_005_000_000n,
      settle: 'immediate',
      schema: null,
      chainHash: 'sha256:' + '0'.repeat(64),
      status: 'reserved',
      createdAt: NOW,
      expiresAt: NOW + 60,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.terminal).toBe(true);
  });

  it('holds indeterminate ACP 5xx completion in settling and reconciles via session status', async () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    let sessionStatus: AcpCheckoutSession['status'] = 'ready_for_payment';

    const rail = new AcpRail({
      checkoutBaseUrl: 'https://merchant.example/acp',
      paymentTokenFor: () => 'spt_tok_500',
      transport: async (req): Promise<AcpHttpResponse> => {
        if (req.method === 'GET') {
          return {
            status: 200,
            body: {
              id: 'cs_flaky',
              status: sessionStatus,
              currency: 'usd',
              totals: [{ type: 'total', display_text: 'Total', amount: 1500 }],
              ...(sessionStatus === 'completed'
                ? { order: { id: 'ord_reconciled', checkout_session_id: 'cs_flaky' } }
                : {}),
            } satisfies AcpCheckoutSession,
          };
        }
        // Server actually processed payment, then crashed with 503 before replying.
        sessionStatus = 'completed';
        return { status: 503, body: { error: 'upstream timeout' } };
      },
    });

    const issued = issueMandateFromAcpAllowance(
      {
        reason: 'one_time',
        max_amount: 1500,
        currency: 'USD',
        checkout_session_id: 'cs_flaky',
        merchant_id: 'merch_1',
        expires_at: NOW + 600,
      },
      principal,
      {
        subject: agent.did,
        subjectJkt: agent.jkt,
        ledger: LEDGER_URL,
        now: NOW,
        merchantResource: 'https://merchant.example/acp/checkout_sessions/cs_flaky',
      },
    );
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const { ledger } = makeLedger(principal.did, rail);
    const reserved = await ledger.reserve({
      tokens: [issued.token],
      request: {
        resource: 'https://merchant.example/acp/checkout_sessions/cs_flaky',
        amount: { cur: 'USD', amt: '15.00' },
        taskId: 'acp:cs_flaky',
      },
    });
    expect(reserved.ok).toBe(true);
    if (!reserved.ok) return;

    const settled = await ledger.settle(reserved.spendId, {
      respHash: 'sha256:' + 'd'.repeat(64),
      respBytes: 64,
    });
    expect(settled.ok).toBe(false);

    // Reservation stays in settling and budget MUST remain debited.
    const midRec = await ledger.reservation(reserved.spendId);
    expect(midRec?.status).toBe('settling');
    expect((await ledger.remaining(issued.claims.jti))?.amt).toBe('0');

    // Reconciliation asks GET /checkout_sessions/cs_flaky and settles cleanly.
    const report = await ledger.reconcile();
    expect(report).toEqual([{ spendId: reserved.spendId, outcome: 'settled' }]);
    const finalRec = await ledger.reservation(reserved.spendId);
    expect(finalRec?.status).toBe('settled');
    expect(finalRec?.railRef).toBe('ord_reconciled');
  });
});
