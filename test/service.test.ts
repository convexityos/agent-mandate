import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { signControlDecision } from '../src/control.js';
import { type ApprovalRequest, type ApprovalResponse } from '../src/http/approval.js';
import { serve } from '../src/http/serve.js';
import { LedgerService } from '../src/http/service.js';
import { type AuditEvent, Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { toScaled } from '../src/money.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §1.2 — the ledger as a service.
 *
 * Most of this file is about one sentence from the roadmap: *a retried mint that
 * debits twice is the whole failure class this project exists to prevent.*
 */

let principal: AgentKey;
let agent: AgentKey;
let clock: number;
let ledger: Ledger;
let audit: AuditEvent[];

const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  clock = NOW + 10;
  audit = [];
  ledger = new Ledger({
    url: 'https://ledger.example.com',
    key: generateAgentKey(),
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
    audit: { record: (e) => void audit.push(e) },
  });
});

const chain = (over: Record<string, unknown> = {}) =>
  buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: { max_total: usd('10.00'), max_per_txn: usd('5.00'), aud: [HOST], ...over },
    },
  ]);

/** Presenter resolution is a transport concern; here it is simply the leaf key. */
const service = (over: Record<string, unknown> = {}) =>
  new LedgerService({
    ledger,
    basePath: '/ledger',
    resolvePresenter: () => agent.jkt,
    ...over,
  });

const mint = (
  svc: LedgerService,
  key: string | null,
  body: Record<string, unknown> = {},
): Promise<ApprovalResponse> =>
  svc.handle({
    method: 'POST',
    path: '/ledger/v1/mint',
    ...(key !== null ? { headers: { 'Idempotency-Key': key } } : {}),
    body: {
      tokens: chain(),
      request: { resource: RESOURCE, amount: usd('1.00'), taskId: 'tsk_01' },
      ...body,
    },
  });

const remaining = async () => toScaled((await ledger.remaining('mnd_root'))!);

describe('idempotent mint', () => {
  it('debits once however many times the same request arrives', async () => {
    const svc = service();

    const first = await mint(svc, 'key-1');
    expect(first.status).toBe(201);

    for (let i = 0; i < 4; i++) {
      const replay = await mint(svc, 'key-1');
      expect(replay.status).toBe(201);
      // Byte-for-byte the same answer, including the minted spend token. A
      // replay that returned a *new* token would be a second reservation
      // wearing the first one's clothes.
      expect(replay.body).toEqual(first.body);
    }

    expect(await remaining()).toBe(toScaled(usd('9.00')));
  });

  it('debits once when the same key arrives concurrently', async () => {
    const svc = service();
    const all = await Promise.all(
      Array.from({ length: 8 }, () => mint(svc, 'key-concurrent')),
    );

    expect(all.every((r) => r.status === 201)).toBe(true);
    const ids = new Set(all.map((r) => (r.body as { spendId: string }).spendId));
    expect(ids.size).toBe(1);
    expect(await remaining()).toBe(toScaled(usd('9.00')));
  });

  it('debits twice for two different keys, because those are two spends', async () => {
    const svc = service();
    await mint(svc, 'key-a');
    await mint(svc, 'key-b');
    expect(await remaining()).toBe(toScaled(usd('8.00')));
  });

  /**
   * Silently returning the first response would be worse than either debiting
   * or failing: the caller would believe a request went through that never did.
   */
  it('refuses a key reused for a different request', async () => {
    const svc = service();
    await mint(svc, 'key-1');

    const different = await svc.handle({
      method: 'POST',
      path: '/ledger/v1/mint',
      headers: { 'idempotency-key': 'key-1' },
      body: {
        tokens: chain(),
        request: { resource: RESOURCE, amount: usd('2.00'), taskId: 'tsk_01' },
      },
    });

    expect(different.status).toBe(400);
    expect((different.body as { detail: string }).detail).toContain('different request');
    // And the original debit is untouched.
    expect(await remaining()).toBe(toScaled(usd('9.00')));
  });

  it('replays a refusal rather than re-deciding it', async () => {
    const svc = service();
    // Over max_per_txn, so this is refused on the merits.
    const over = {
      tokens: chain(),
      request: { resource: RESOURCE, amount: usd('9.00'), taskId: 'tsk_01' },
    };
    const first = await svc.handle({
      method: 'POST',
      path: '/ledger/v1/mint',
      headers: { 'idempotency-key': 'key-refused' },
      body: over,
    });
    expect(first.status).toBe(403);

    const replay = await svc.handle({
      method: 'POST',
      path: '/ledger/v1/mint',
      headers: { 'idempotency-key': 'key-refused' },
      body: over,
    });
    expect(replay.status).toBe(403);
    expect(replay.body).toEqual(first.body);
  });

  it('returns the same step-up handle on replay rather than queueing twice', async () => {
    const svc = service();
    const body = {
      tokens: chain({ step_up: { over: usd('0.50') } }),
      request: { resource: RESOURCE, amount: usd('2.00'), taskId: 'tsk_01' },
    };
    const req: ApprovalRequest = {
      method: 'POST',
      path: '/ledger/v1/mint',
      headers: { 'idempotency-key': 'key-stepup' },
      body,
    };

    const first = await svc.handle(req);
    const second = await svc.handle(req);
    expect(first.status).toBe(403);
    expect(second.body).toEqual(first.body);
    expect(await ledger.pendingStepUps()).toHaveLength(1);
  });

  it('refuses a mint with no key rather than inventing one', async () => {
    // A key the server made up is not idempotency: the mechanism depends on the
    // client sending the same one on the retry.
    const res = await mint(service(), null);
    expect(res.status).toBe(400);
    expect((res.body as { detail: string }).detail).toContain('Idempotency-Key');

    const relaxed = await mint(service({ requireIdempotencyKey: false }), null);
    expect(relaxed.status).toBe(201);
  });
});

describe('proof of possession', () => {
  it('refuses a mint with no verified presenter by default', async () => {
    const res = await mint(new LedgerService({ ledger, basePath: '/ledger' }), 'key-1');
    expect(res.status).toBe(401);
    expect((res.body as { code: string }).code).toBe('pop_failed');
  });

  it('refuses a presenter that is not the leaf holder', async () => {
    const svc = service({ resolvePresenter: () => generateAgentKey().jkt });
    const res = await mint(svc, 'key-1');
    expect(res.status).toBe(401);
  });

  it('can be turned off, but only deliberately', async () => {
    const svc = new LedgerService({
      ledger,
      basePath: '/ledger',
      requirePresenter: false,
    });
    expect((await mint(svc, 'key-1')).status).toBe(201);
  });
});

describe('the rest of the surface', () => {
  it('settles, reads back and issues a receipt', async () => {
    const svc = service();
    const minted = await mint(svc, 'key-1');
    const spendId = (minted.body as { spendId: string }).spendId;

    const settled = await svc.handle({
      method: 'POST',
      path: `/ledger/v1/spends/${spendId}/settle`,
      body: {},
    });
    expect(settled.status).toBe(200);

    const read = await svc.handle({ method: 'GET', path: `/ledger/v1/spends/${spendId}` });
    expect((read.body as { status: string }).status).toBe('settled');

    const receipt = await svc.handle({
      method: 'GET',
      path: `/ledger/v1/spends/${spendId}/receipt`,
    });
    expect(receipt.status).toBe(200);
    expect((receipt.body as { claims: { spend: string } }).claims.spend).toBe(spendId);

    expect((await svc.handle({ method: 'GET', path: '/ledger/v1/spends/spn_nope' })).status).toBe(
      404,
    );
  });

  it('refunds and credits the path back', async () => {
    const svc = service();
    const spendId = ((await mint(svc, 'key-1')).body as { spendId: string }).spendId;

    const refunded = await svc.handle({
      method: 'POST',
      path: `/ledger/v1/spends/${spendId}/refund`,
      body: { reason: 'merchant never served' },
    });
    expect(refunded.status).toBe(200);
    expect(await remaining()).toBe(toScaled(usd('10.00')));
  });

  it('applies a signed control decision and refuses an unsigned one', async () => {
    const svc = service();
    await mint(svc, 'key-1');

    const decision = signControlDecision(
      {
        v: 'am/1',
        typ: 'control',
        jti: 'ctl_1',
        iss: principal.did,
        action: 'kill',
        root: 'mnd_root',
        iat: clock,
        exp: clock + 300,
      },
      principal,
    );

    expect(
      (await svc.handle({ method: 'POST', path: '/ledger/v1/control', body: { decision } }))
        .status,
    ).toBe(200);
    expect(
      (
        await svc.handle({
          method: 'POST',
          path: '/ledger/v1/control',
          body: { decision: 'nope' },
        })
      ).status,
    ).toBe(400);
  });

  it('answers healthz and exposes the number worth paging on', async () => {
    const svc = service();
    expect((await svc.handle({ method: 'GET', path: '/ledger/healthz' })).status).toBe(200);

    const metrics = await svc.handle({ method: 'GET', path: '/ledger/metrics' });
    expect(metrics.headers['content-type']).toContain('text/plain');
    const text = metrics.body as string;
    expect(text).toContain('am_settling_outstanding 0');
    expect(text).toContain('am_stepups_pending 0');
    expect(text).toContain('# TYPE am_settling_outstanding gauge');
  });

  it('404s and 405s the obvious wrong turns', async () => {
    const svc = service();
    expect((await svc.handle({ method: 'GET', path: '/ledger/v1/nope' })).status).toBe(404);
    expect((await svc.handle({ method: 'GET', path: '/ledger/v1/mint' })).status).toBe(405);
    expect(
      (await svc.handle({ method: 'DELETE', path: '/ledger/v1/spends/x/settle' })).status,
    ).toBe(405);
  });

  it('rejects a malformed mint body before touching the ledger', async () => {
    const svc = service();
    const res = await svc.handle({
      method: 'POST',
      path: '/ledger/v1/mint',
      headers: { 'idempotency-key': 'k' },
      body: { tokens: 'not-an-array', request: {} },
    });
    expect(res.status).toBe(400);
    expect(audit).toHaveLength(0);
  });
});

describe('the audit log', () => {
  it('records every state transition, keyed by spendId', async () => {
    const svc = service();
    const spendId = ((await mint(svc, 'key-1')).body as { spendId: string }).spendId;
    await svc.handle({ method: 'POST', path: `/ledger/v1/spends/${spendId}/settle`, body: {} });

    const events = audit.filter((e) => e.spendId === spendId);
    expect(events.map((e) => e.event)).toEqual(['reserve.ok', 'settle.settled']);
    expect(events[0]).toMatchObject({
      root: 'mnd_root',
      agent: agent.did,
      amount: { cur: 'USD', amt: '1.00' },
      resource: RESOURCE,
      taskId: 'tsk_01',
    });
    expect(events[0]!.at).toBe(clock);
  });

  it('records refusals with their §15 code', async () => {
    const svc = service();
    await svc.handle({
      method: 'POST',
      path: '/ledger/v1/mint',
      headers: { 'idempotency-key': 'k' },
      body: {
        tokens: chain(),
        request: { resource: RESOURCE, amount: usd('9.00') },
      },
    });
    // `rejected` rather than `denied`: this one never reached the ledger's
    // state, because §7 coverage refused it before any transaction opened.
    expect(audit.map((e) => [e.event, e.code])).toEqual([
      ['reserve.rejected', 'amount_exceeds_cap'],
    ]);
  });

  it('records a step-up as a question rather than a denial', async () => {
    const svc = service();
    await svc.handle({
      method: 'POST',
      path: '/ledger/v1/mint',
      headers: { 'idempotency-key': 'k' },
      body: {
        tokens: chain({ step_up: { over: usd('0.50') } }),
        request: { resource: RESOURCE, amount: usd('2.00') },
      },
    });
    const e = audit[0]!;
    expect(e.event).toBe('reserve.step_up');
    expect(e['handle']).toMatch(/^stp_/);
  });

  it('survives a sink that throws', async () => {
    ledger = new Ledger({
      url: 'https://ledger.example.com',
      key: generateAgentKey(),
      store: new MemoryLedgerStore(() => clock),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
      breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
      audit: {
        record: () => {
          throw new Error('log pipeline is down');
        },
      },
    });
    // A failing log must not turn a completed spend into an error the caller
    // retries — which, with idempotency, would at least be safe, but would
    // still be a lie about what happened.
    expect((await mint(service(), 'key-1')).status).toBe(201);
    expect(await remaining()).toBe(toScaled(usd('9.00')));
  });
});

describe('over real HTTP', () => {
  let server: ReturnType<typeof serve>;
  let base: string;

  beforeEach(async () => {
    // Port 0: the OS assigns a free one. A fixed port makes each test race the
    // previous test's socket still winding down, which fails as a refused
    // connection rather than as anything informative.
    server = serve({ port: 0, handlers: [service()] });
    if (!server.listening) await new Promise((r) => server.once('listening', r));
    const addr = server.address();
    base = `http://127.0.0.1:${typeof addr === 'object' && addr !== null ? addr.port : 0}`;
  });
  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
  });

  it('mints, replays and settles across the wire', async () => {
    const body = JSON.stringify({
      tokens: chain(),
      request: { resource: RESOURCE, amount: usd('1.00'), taskId: 'tsk_01' },
    });
    const post = (path: string, payload: string, key?: string) =>
      fetch(`${base}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(key !== undefined ? { 'Idempotency-Key': key } : {}),
        },
        body: payload,
      });

    const first = await post('/ledger/v1/mint', body, 'wire-1');
    expect(first.status).toBe(201);
    const minted = (await first.json()) as { spendId: string };

    const replay = await post('/ledger/v1/mint', body, 'wire-1');
    expect(((await replay.json()) as { spendId: string }).spendId).toBe(minted.spendId);
    expect(await remaining()).toBe(toScaled(usd('9.00')));

    const settled = await post(`/ledger/v1/spends/${minted.spendId}/settle`, '{}');
    expect(settled.status).toBe(200);

    const metrics = await fetch(`${base}/ledger/metrics`);
    expect(await metrics.text()).toContain('am_settling_outstanding 0');
  });

  it('refuses a body that is not JSON, and one that is too large', async () => {
    const notJson = await fetch(`${base}/ledger/v1/mint`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{oops',
    });
    expect(notJson.status).toBe(400);

    const huge = await fetch(`${base}/ledger/v1/mint`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pad: 'x'.repeat(400_000) }),
    });
    expect(huge.status).toBe(413);
  });
});
