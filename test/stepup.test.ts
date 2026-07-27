import { beforeEach, describe, expect, it } from 'vitest';

import { ApprovalService } from '../src/http/approval.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { McpMandateGateway, type UpstreamServer } from '../src/mcp/gateway.js';
import type { JsonRpcResponse } from '../src/mcp/jsonrpc.js';
import { toScaled } from '../src/money.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { type StepUpDecisionClaims, signStepUpDecision, verifyStepUpDecision } from '../src/stepup.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

/**
 * §10.5 end to end: an agent blocked, a human asked, a signature, a spend.
 *
 * The unit-level state machine is covered in `ledger.test.ts`. This is the loop
 * as a deployment assembles it — approval surface, gateway, and the one
 * property that matters at every layer: the party asking cannot be the party
 * answering.
 */

let principal: AgentKey;
let agent: AgentKey;
let clock: number;
let ledger: Ledger;
let notified: string[];

const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;

beforeEach(() => {
  principal = generateAgentKey();
  agent = generateAgentKey();
  clock = NOW + 10;
  notified = [];
  ledger = new Ledger({
    url: 'https://ledger.example.com',
    key: generateAgentKey(),
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
    approver: { requested: (n) => void notified.push(n.handle) },
  });
});

const chain = () =>
  buildChain(principal, [
    {
      holder: agent,
      exp: NOW + 86400,
      jti: 'mnd_root',
      cav: {
        max_total: usd('100.00'),
        max_per_txn: usd('50.00'),
        aud: [HOST],
        step_up: { over: usd('1.00') },
      },
    },
  ]);

const decisionFor = (
  over: Partial<StepUpDecisionClaims> & { handle: string },
  signer: AgentKey = principal,
) =>
  signStepUpDecision(
    {
      v: 'am/1',
      typ: 'approval',
      iss: signer.did,
      verdict: 'approve',
      root: 'mnd_root',
      res: RESOURCE,
      amt: usd('5.00'),
      iat: clock,
      exp: clock + 900,
      ...over,
    },
    signer,
  );

describe('the signed decision itself', () => {
  it('verifies only for a trusted root issuer', async () => {
    const jws = decisionFor({ handle: 'stp_1' });

    const good = await verifyStepUpDecision(jws, {
      now: clock,
      isTrustedRootIssuer: trustOnly(principal),
    });
    expect(good.ok).toBe(true);

    const wrongPrincipal = await verifyStepUpDecision(jws, {
      now: clock,
      isTrustedRootIssuer: trustOnly(agent),
    });
    expect(wrongPrincipal.ok).toBe(false);
    if (!wrongPrincipal.ok) expect(wrongPrincipal.code).toBe('pop_failed');
  });

  it('rejects a decision whose payload was edited after signing', async () => {
    const jws = decisionFor({ handle: 'stp_1', amt: usd('5.00') });
    const [header, payload, sig] = jws.split('.');

    const tampered = JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8'));
    tampered.amt = { cur: 'USD', amt: '5000.00' };
    const forged = `${header}.${Buffer.from(JSON.stringify(tampered)).toString('base64url')}.${sig}`;

    const r = await verifyStepUpDecision(forged, {
      now: clock,
      isTrustedRootIssuer: trustOnly(principal),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('pop_failed');
  });

  it('expires', async () => {
    const jws = decisionFor({ handle: 'stp_1', iat: clock, exp: clock + 60 });
    const r = await verifyStepUpDecision(jws, {
      now: clock + 200,
      isTrustedRootIssuer: trustOnly(principal),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('token_expired');
  });
});

describe('the approval service', () => {
  const service = () => new ApprovalService({ ledger, basePath: '/step-ups' });

  async function blockOne(): Promise<string> {
    const r = await ledger.reserve({
      tokens: chain(),
      request: { resource: RESOURCE, amount: usd('5.00'), taskId: 'tsk_01' },
    });
    if (r.ok) throw new Error('expected a step-up');
    return r.stepUpHandle!;
  }

  it('lists the queue in money a human can read', async () => {
    const handle = await blockOne();
    const res = await service().handle({ method: 'GET', path: '/step-ups' });

    expect(res.status).toBe(200);
    const { stepUps } = res.body as { stepUps: Array<Record<string, unknown>> };
    expect(stepUps).toHaveLength(1);
    expect(stepUps[0]).toMatchObject({
      handle,
      // Not 5000000000 — a step-up nobody can read is a step-up nobody reads.
      amount: { cur: 'USD', amt: '5' },
      agent: agent.did,
      taskId: 'tsk_01',
      state: 'pending',
      resource: RESOURCE,
    });
  });

  it('accepts a signed approval and reports the new state', async () => {
    const handle = await blockOne();
    const res = await service().handle({
      method: 'POST',
      path: `/step-ups/${handle}`,
      body: { decision: decisionFor({ handle }) },
    });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ handle, state: 'approved', decision: { by: principal.did } });
  });

  /**
   * The endpoint carries no auth of its own by design — the authority is the
   * signature inside the decision. This is what makes that safe.
   */
  it('refuses a decision signed by the agent, however it is submitted', async () => {
    const handle = await blockOne();
    const res = await service().handle({
      method: 'POST',
      path: `/step-ups/${handle}`,
      body: { decision: decisionFor({ handle, iss: agent.did }, agent) },
    });

    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ code: 'pop_failed' });
    expect((await ledger.stepUp(handle))!.state).toBe('pending');
  });

  it('will not let the path redirect a signed decision onto another request', async () => {
    const handle = await blockOne();
    const res = await service().handle({
      method: 'POST',
      path: '/step-ups/stp_somebody_else',
      body: { decision: decisionFor({ handle }) },
    });

    expect(res.status).toBe(400);
    // And crucially the real request is untouched — the mismatch is caught
    // before the decision is applied, not after.
    expect((await ledger.stepUp(handle))!.state).toBe('pending');
  });

  it('answers sensibly for unknown handles and bad bodies', async () => {
    expect((await service().handle({ method: 'GET', path: '/step-ups/nope' })).status).toBe(404);
    expect(
      (await service().handle({ method: 'POST', path: '/step-ups/x', body: {} })).status,
    ).toBe(400);
    expect((await service().handle({ method: 'DELETE', path: '/step-ups' })).status).toBe(405);
  });
});

describe('the whole loop, through the gateway', () => {
  class Upstream implements UpstreamServer {
    calls = 0;
    async request(method: string): Promise<JsonRpcResponse> {
      if (method === 'tools/list') {
        return { jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'buy_report' }] } };
      }
      this.calls++;
      return { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'delivered' }] } };
    }
  }

  it('blocks, asks a human, and completes on the retry after approval', async () => {
    const upstream = new Upstream();
    const gateway = new McpMandateGateway({
      ledger,
      tokens: buildChain(principal, [
        {
          holder: agent,
          exp: NOW + 86400,
          jti: 'mnd_root',
          cav: {
            max_total: usd('100.00'),
            max_per_txn: usd('50.00'),
            aud: ['reports'],
            resources: ['mcp://reports/*'],
            step_up: { over: usd('1.00') },
          },
        },
      ]),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => clock,
      approvalBaseUrl: 'https://ledger.internal/step-ups',
      upstreams: [
        {
          name: 'reports',
          server: upstream,
          tools: { buy_report: { price: usd('5.00'), effect: 'write' } },
        },
      ],
    });

    // 1. The agent tries. It is stopped, and told where a human can answer.
    const first = await gateway.callTool('reports__buy_report', { id: 'q3' });
    expect(first!.outcome.disposition).toBe('awaiting_approval');
    expect(upstream.calls).toBe(0);

    const handle = first!.outcome.stepUpHandle!;
    const data = (first!.response as { error: { data: Record<string, unknown> } }).error.data;
    expect(data['stepUpUrl']).toBe(`https://ledger.internal/step-ups/${handle}`);
    expect(data['retryable']).toBe(true);
    expect(notified).toEqual([handle]);

    // 2. Retrying without an approval gets nowhere, and does not re-ask.
    const second = await gateway.callTool('reports__buy_report', { id: 'q3' });
    expect(second!.outcome.disposition).toBe('awaiting_approval');
    expect(upstream.calls).toBe(0);
    expect(await ledger.pendingStepUps()).toHaveLength(1);

    // 3. A human signs, through the same HTTP surface a console would use.
    const service = new ApprovalService({ ledger, basePath: '/step-ups' });
    const approved = await service.handle({
      method: 'POST',
      path: `/step-ups/${handle}`,
      body: {
        decision: decisionFor({
          handle,
          res: 'mcp://reports/buy_report',
          amt: usd('5.00'),
          reason: 'q3 report, agreed',
        }),
      },
    });
    expect(approved.status).toBe(200);

    // 4. The retry now goes through, and the money moves exactly once.
    const third = await gateway.callTool('reports__buy_report', { id: 'q3' });
    expect(third!.outcome.disposition).toBe('settled');
    expect(upstream.calls).toBe(1);
    expect(toScaled((await ledger.remaining('mnd_root'))!)).toBe(
      toScaled(usd('100.00')) - toScaled(usd('5.00')),
    );

    // 5. And the approval is spent: a second call asks again.
    const fourth = await gateway.callTool('reports__buy_report', { id: 'q3' });
    expect(fourth!.outcome.disposition).toBe('awaiting_approval');
    expect(upstream.calls).toBe(1);
  });
});
