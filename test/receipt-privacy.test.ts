import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  Ledger,
  MemoryLedgerStore,
  MIN_RECEIPT_SALT_BYTES,
  assertReceiptSalt,
  blindedPathTag,
  blindedPrincipalTag,
  generateAgentKey,
  receiptMatchesNode,
  rollupReceiptsByNode,
  saltedPathTag,
  verifyReceiptPath,
  verifyReceiptSignature,
  type Receipt,
  type ReceiptPathPrivacyConfig,
} from '../src/index.js';
import { LedgerService } from '../src/http/service.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';

const LEDGER_URL = 'https://ledger.example.com';
const HOST = 'api.weatherco.com';
const RESOURCE = `https://${HOST}/v3/forecast/94110`;
const SALT = 'secret-org-rollup-salt-0123456789abcdef';
const WRONG_SALT = 'different-org-salt-9876543210fedcba';

function setupTree(privacy?: ReceiptPathPrivacyConfig) {
  const principal = generateAgentKey();
  const teamLead = generateAgentKey();
  const subAgentA = generateAgentKey();
  const subAgentB = generateAgentKey();
  const ledgerKey = generateAgentKey();
  const clock = NOW + 10;

  const ledger = new Ledger({
    url: LEDGER_URL,
    key: ledgerKey,
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: trustOnly(principal),
    clock: () => clock,
    breakers: { novelMerchant: 'off' },
    ...(privacy !== undefined ? { receiptPathPrivacy: privacy } : {}),
  });

  const chainEngA = buildChain(principal, [
    {
      holder: teamLead,
      exp: NOW + 86400,
      jti: 'mnd_acme_root',
      cav: { max_total: usd('100.00'), max_per_txn: usd('10.00'), aud: [HOST] },
    },
    {
      holder: subAgentA,
      exp: NOW + 3600,
      jti: 'mnd_eng_dept',
      cav: { max_total: usd('50.00'), max_per_txn: usd('5.00'), aud: [HOST] },
    },
    {
      holder: subAgentA,
      exp: NOW + 1800,
      jti: 'mnd_eng_research_bot',
      cav: { max_total: usd('10.00'), max_per_txn: usd('1.00'), aud: [HOST] },
    },
  ]);

  const chainSalesB = buildChain(principal, [
    {
      holder: teamLead,
      exp: NOW + 86400,
      jti: 'mnd_acme_root',
      cav: { max_total: usd('100.00'), max_per_txn: usd('10.00'), aud: [HOST] },
    },
    {
      holder: subAgentB,
      exp: NOW + 3600,
      jti: 'mnd_sales_dept',
      cav: { max_total: usd('40.00'), max_per_txn: usd('5.00'), aud: [HOST] },
    },
  ]);

  return { ledger, ledgerKey, subAgentA, subAgentB, chainEngA, chainSalesB };
}

async function spendAndSettle(
  ledger: Ledger,
  tokens: string[],
  presenterJkt: string,
  amt = '0.25',
): Promise<Receipt> {
  const res = await ledger.reserve({
    tokens,
    presenterJkt,
    request: { resource: RESOURCE, amount: usd(amt) },
  });
  if (!res.ok) throw new Error(`reserve failed: ${res.code} ${res.detail}`);
  const settled = await ledger.settle(res.spendId, { respHash: 'sha256:cafe', respBytes: 64 });
  if (!settled.ok) throw new Error(`settle failed: ${settled.detail}`);
  return settled.receipt;
}

describe('receipt path salt hygiene', () => {
  it('rejects a receipt privacy salt shorter than 16 bytes', () => {
    expect(() => assertReceiptSalt('')).toThrow();
    expect(() => assertReceiptSalt('too-short')).toThrow();
    expect(() => assertReceiptSalt(Buffer.alloc(MIN_RECEIPT_SALT_BYTES - 1))).toThrow();
    expect(assertReceiptSalt(randomBytes(MIN_RECEIPT_SALT_BYTES)).byteLength).toBe(
      MIN_RECEIPT_SALT_BYTES,
    );

    expect(() => setupTree({ mode: 'salted', salt: 'weak' })).toThrow(/at least 16 bytes/);
    expect(() => setupTree({ mode: 'blinded', salt: 'short' })).toThrow(/at least 16 bytes/);
  });
});

describe('plain receipt mode (default)', () => {
  it('keeps cleartext path and omits path_mode by default for backwards compatibility', async () => {
    const { ledger, ledgerKey, subAgentA, chainEngA } = setupTree();
    const receipt = await spendAndSettle(ledger, chainEngA, subAgentA.jkt);

    expect(receipt.claims.path_mode).toBeUndefined();
    expect(receipt.claims.principal).toBe('mnd_acme_root');
    expect(receipt.claims.path).toEqual(['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot']);
    expect(verifyReceiptSignature(receipt.claims, receipt.sigs.ledger, ledgerKey.jwk)).toBe(true);
    expect(
      verifyReceiptPath(receipt.claims, ['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot']),
    ).toBe(true);
    expect(receiptMatchesNode(receipt.claims, 'mnd_eng_dept')).toBe(true);
  });
});

describe('salted receipt path privacy (indexed rollup without cleartext JTIs)', () => {
  it('hides cleartext mandate JTIs and principal while preserving indexed subtree rollup', async () => {
    const { ledger, ledgerKey, subAgentA, subAgentB, chainEngA, chainSalesB } = setupTree({
      mode: 'salted',
      salt: SALT,
    });

    const rEng1 = await spendAndSettle(ledger, chainEngA, subAgentA.jkt, '0.25');
    const rEng2 = await spendAndSettle(ledger, chainEngA, subAgentA.jkt, '0.50');
    const rSales = await spendAndSettle(ledger, chainSalesB, subAgentB.jkt, '0.75');

    for (const r of [rEng1, rEng2, rSales]) {
      expect(r.claims.path_mode).toBe('salted');
      expect(verifyReceiptSignature(r.claims, r.sigs.ledger, ledgerKey.jwk)).toBe(true);
      // No cleartext mandate identifiers anywhere in path or principal.
      const serialized = JSON.stringify(r.claims);
      expect(serialized).not.toContain('mnd_acme_root');
      expect(serialized).not.toContain('mnd_eng_dept');
      expect(serialized).not.toContain('mnd_eng_research_bot');
      expect(serialized).not.toContain('mnd_sales_dept');
      for (const entry of r.claims.path) {
        expect(entry).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
      }
      expect(r.claims.principal).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    }

    // O(1) indexed rollup works with a pre-computed subtree tag without sharing the master salt.
    const engTag = saltedPathTag('mnd_eng_dept', SALT);
    const rootTag = saltedPathTag('mnd_acme_root', SALT);
    const all = [rEng1, rEng2, rSales];
    expect(all.filter((r) => r.claims.path.includes(engTag))).toHaveLength(2);
    expect(all.filter((r) => r.claims.path.includes(rootTag))).toHaveLength(3);

    // Helper rollup and disclosure verification agree.
    expect(rollupReceiptsByNode(all, 'mnd_eng_dept', SALT)).toHaveLength(2);
    expect(rollupReceiptsByNode(all, 'mnd_sales_dept', SALT)).toHaveLength(1);
    expect(rollupReceiptsByNode(all, 'mnd_eng_dept', WRONG_SALT)).toHaveLength(0);
    expect(
      verifyReceiptPath(
        rEng1.claims,
        ['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot'],
        SALT,
      ),
    ).toBe(true);
    expect(
      verifyReceiptPath(
        rEng1.claims,
        ['mnd_acme_root', 'mnd_sales_dept', 'mnd_eng_research_bot'],
        SALT,
      ),
    ).toBe(false);
    expect(
      verifyReceiptPath(
        rEng1.claims,
        ['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot'],
        WRONG_SALT,
      ),
    ).toBe(false);
    expect(
      verifyReceiptPath(rEng1.claims, ['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot']),
    ).toBe(false);
  });
});

describe('blinded receipt path privacy (unlinkable across spends)', () => {
  it('produces unlinkable path and principal tags across spends under the same subtree while allowing salted audit', async () => {
    const { ledger, ledgerKey, subAgentA, subAgentB, chainEngA, chainSalesB } = setupTree({
      mode: 'blinded',
      salt: SALT,
    });

    const rEng1 = await spendAndSettle(ledger, chainEngA, subAgentA.jkt, '0.25');
    const rEng2 = await spendAndSettle(ledger, chainEngA, subAgentA.jkt, '0.50');
    const rSales = await spendAndSettle(ledger, chainSalesB, subAgentB.jkt, '0.75');

    expect(rEng1.claims.path_mode).toBe('blinded');
    expect(verifyReceiptSignature(rEng1.claims, rEng1.sigs.ledger, ledgerKey.jwk)).toBe(true);
    expect(verifyReceiptSignature(rEng2.claims, rEng2.sigs.ledger, ledgerKey.jwk)).toBe(true);

    // Two spends under the exact same chain produce zero overlapping tags,
    // preventing cross-receipt org-chart clustering by external readers.
    expect(rEng1.claims.principal).not.toBe(rEng2.claims.principal);
    for (let i = 0; i < rEng1.claims.path.length; i++) {
      expect(rEng1.claims.path[i]).not.toBe(rEng2.claims.path[i]);
    }
    expect(rEng1.claims.principal).toBe(
      blindedPrincipalTag(rEng1.claims.spend, 'mnd_acme_root', SALT),
    );
    expect(rEng1.claims.path[1]).toBe(blindedPathTag(rEng1.claims.spend, 'mnd_eng_dept', SALT));

    // Audited rollup and path disclosure still verify cleanly with the salt.
    const all = [rEng1, rEng2, rSales];
    expect(rollupReceiptsByNode(all, 'mnd_acme_root', SALT)).toHaveLength(3);
    expect(rollupReceiptsByNode(all, 'mnd_eng_dept', SALT)).toHaveLength(2);
    expect(rollupReceiptsByNode(all, 'mnd_sales_dept', SALT)).toHaveLength(1);
    expect(rollupReceiptsByNode(all, 'mnd_eng_dept', WRONG_SALT)).toHaveLength(0);

    expect(
      verifyReceiptPath(
        rEng1.claims,
        ['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot'],
        SALT,
      ),
    ).toBe(true);
    expect(
      verifyReceiptPath(
        rEng1.claims,
        ['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot'],
        WRONG_SALT,
      ),
    ).toBe(false);
  });

  it('serves privacy-protected receipts through LedgerService GET /v1/spends/:id/receipt', async () => {
    const { ledger, ledgerKey, subAgentA, chainEngA } = setupTree({
      mode: 'salted',
      salt: SALT,
    });
    const service = new LedgerService({ ledger });
    const settled = await spendAndSettle(ledger, chainEngA, subAgentA.jkt);

    const res = await service.handle({
      method: 'GET',
      path: `/v1/spends/${settled.claims.spend}/receipt`,
      headers: {},
    });
    expect(res.status).toBe(200);
    const body = res.body as Receipt;
    expect(body.claims.path_mode).toBe('salted');
    expect(JSON.stringify(body.claims)).not.toContain('mnd_acme_root');
    expect(verifyReceiptSignature(body.claims, body.sigs.ledger, ledgerKey.jwk)).toBe(true);
    expect(
      verifyReceiptPath(
        body.claims,
        ['mnd_acme_root', 'mnd_eng_dept', 'mnd_eng_research_bot'],
        SALT,
      ),
    ).toBe(true);
  });
});
