import { beforeEach, describe, expect, it } from 'vitest';

import { buildPayment } from '../src/http/headers.js';
import {
  buildSignatureBase,
  signRequest,
  verifyRequestSignature,
  type SignableRequest,
} from '../src/http/signature.js';
import { type AgentKey, generateAgentKey } from '../src/sign.js';
import { int, str } from '../src/http/sfv.js';

let agent: AgentKey;
const NOW = 1770001240;

beforeEach(() => {
  agent = generateAgentKey();
});

const baseReq = (): SignableRequest => ({
  method: 'GET',
  url: 'https://api.weatherco.com/v3/forecast/94110',
  headers: { [ 'Payment' ]: buildPayment('token-abc') },
});

function signed(req = baseReq(), created = NOW) {
  const sigs = signRequest(req, { key: agent, created });
  return { ...req, headers: { ...req.headers, ...sigs } };
}

describe('RFC 9421 signature base', () => {
  it('has the shape the RFC specifies', () => {
    const params = new Map([
      ['created', int(NOW)],
      ['keyid', str(agent.did)],
    ]);
    const base = buildSignatureBase(baseReq(), ['@method', '@target-uri', 'payment'], params)!;
    const lines = base.split('\n');
    expect(lines[0]).toBe('"@method": GET');
    expect(lines[1]).toBe('"@target-uri": https://api.weatherco.com/v3/forecast/94110');
    expect(lines[2]).toBe(`"payment": ${buildPayment('token-abc')}`);
    expect(lines[3]).toMatch(/^"@signature-params": \("@method" "@target-uri" "payment"\);created=/);
    expect(base.endsWith('\n')).toBe(false);
  });

  it('refuses to sign when a covered component is absent', () => {
    expect(() =>
      signRequest({ method: 'GET', url: 'https://a.test/', headers: {} }, { key: agent, created: NOW }),
    ).toThrow();
  });
});

describe('verifyRequestSignature', () => {
  it('accepts a well-formed signature and returns the key thumbprint', () => {
    const r = verifyRequestSignature(signed(), { now: NOW });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.keyid).toBe(agent.did);
      expect(r.jkt).toBe(agent.jkt);
      expect(r.covered).toEqual(['@method', '@target-uri', 'payment']);
    }
  });

  it('rejects a signature that does not cover the payment header', () => {
    // A signature over @method alone verifies cryptographically and proves
    // nothing about what is being paid for.
    const req = baseReq();
    const sigs = signRequest(req, { key: agent, created: NOW, components: ['@method'] });
    const r = verifyRequestSignature(
      { ...req, headers: { ...req.headers, ...sigs } },
      { now: NOW },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toContain('does not cover');
  });

  it('rejects a signature lifted onto a different URL', () => {
    const s = signed();
    const moved = { ...s, url: 'https://api.weatherco.com/v3/premium/expensive' };
    expect(verifyRequestSignature(moved, { now: NOW }).ok).toBe(false);
  });

  it('rejects a signature lifted onto a different method', () => {
    expect(verifyRequestSignature({ ...signed(), method: 'POST' }, { now: NOW }).ok).toBe(false);
  });

  it('rejects a swapped payment token', () => {
    const s = signed();
    const tampered = {
      ...s,
      headers: { ...s.headers, Payment: buildPayment('token-someone-elses') },
    };
    expect(verifyRequestSignature(tampered, { now: NOW }).ok).toBe(false);
  });

  it('rejects a stale or future-dated signature', () => {
    const s = signed();
    expect(verifyRequestSignature(s, { now: NOW + 61 }).ok).toBe(false);
    expect(verifyRequestSignature(s, { now: NOW - 61 }).ok).toBe(false);
    expect(verifyRequestSignature(s, { now: NOW + 59 }).ok).toBe(true);
  });

  it('honours an explicit expires parameter', () => {
    const req = baseReq();
    const sigs = signRequest(req, { key: agent, created: NOW, expires: NOW + 5 });
    const s = { ...req, headers: { ...req.headers, ...sigs } };
    expect(verifyRequestSignature(s, { now: NOW + 4 }).ok).toBe(true);
    expect(verifyRequestSignature(s, { now: NOW + 6 }).ok).toBe(false);
  });

  it('rejects a signature made by a key other than the one keyid names', () => {
    const impostor = generateAgentKey();
    const req = baseReq();
    // Signed by `impostor`, but claiming to be `agent`.
    const sigs = signRequest(req, { key: impostor, created: NOW, keyid: agent.did });
    const r = verifyRequestSignature({ ...req, headers: { ...req.headers, ...sigs } }, { now: NOW });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detail).toContain('verification failed');
  });

  it('rejects missing, malformed, and unresolvable signatures', () => {
    expect(verifyRequestSignature(baseReq(), { now: NOW }).ok).toBe(false);
    expect(
      verifyRequestSignature(
        { ...baseReq(), headers: { 'Signature-Input': 'garbage', Signature: 'garbage' } },
        { now: NOW },
      ).ok,
    ).toBe(false);

    const req = baseReq();
    const sigs = signRequest(req, { key: agent, created: NOW, keyid: 'did:key:zNotAKey' });
    expect(
      verifyRequestSignature({ ...req, headers: { ...req.headers, ...sigs } }, { now: NOW }).ok,
    ).toBe(false);
  });
});
