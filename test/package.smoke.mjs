import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function sanitizedEnv() {
  const env = { ...process.env };
  for (const key of ['GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN', 'NODE_AUTH_TOKEN']) {
    delete env[key];
  }
  return env;
}

function runNpm(args, opts) {
  const npmExec = process.env.npm_execpath;
  if (npmExec && /\.(c|m)?js$/i.test(npmExec)) {
    return execFileSync(process.execPath, [npmExec, ...args], opts);
  }
  if (process.platform === 'win32') {
    return execFileSync('cmd.exe', ['/d', '/s', '/c', 'npm', ...args], opts);
  }
  return execFileSync('npm', args, opts);
}

const env = sanitizedEnv();
const tmpRoot = mkdtempSync(join(tmpdir(), 'vitna-mandate-smoke-'));
const packDir = join(tmpRoot, 'pack');
const sandboxDir = join(tmpRoot, 'sandbox');

try {
  mkdirSync(packDir, { recursive: true });
  mkdirSync(sandboxDir, { recursive: true });

  runNpm(['pack', '--pack-destination', packDir], {
    cwd: REPO_ROOT,
    env,
    stdio: 'pipe',
  });

  const tarballs = readdirSync(packDir).filter((name) => /^vitna-mandate-.*\.tgz$/.test(name));
  assert.equal(tarballs.length, 1, `expected exactly one vitna-mandate tarball, got: ${tarballs.join(', ')}`);
  const tarballName = tarballs[0];
  const tarballRelFromSandbox = relative(sandboxDir, join(packDir, tarballName)).split('\\').join('/');

  writeFileSync(
    join(sandboxDir, 'package.json'),
    JSON.stringify({ name: 'vitna-mandate-sandbox', private: true, type: 'module' }, null, 2) + '\n',
    'utf8',
  );

  runNpm(['install', '--no-audit', '--no-fund', tarballRelFromSandbox], {
    cwd: sandboxDir,
    env,
    stdio: 'pipe',
  });

  const pkgRoot = join(sandboxDir, 'node_modules', '@vitna', 'mandate');
  const expectedFiles = [
    'LICENSE',
    'README.md',
    'package.json',
    'dist/src/index.js',
    'dist/src/index.d.ts',
    'bin/am.mjs',
    'bin/am-hook.mjs',
    'vectors/index.json',
    'vectors/chain.json',
    'vectors/caveats.json',
    'vectors/uri.json',
    'vectors/keys.json',
    'spec/agent-mandate-v1.md',
  ];
  for (const rel of expectedFiles) {
    assert.equal(existsSync(join(pkgRoot, rel)), true, `missing packaged file: ${rel}`);
  }
  assert.equal(existsSync(join(pkgRoot, 'dist/test')), false, 'dist/test must be excluded from published package');

  const pkgMeta = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8'));
  assert.equal(pkgMeta.name, '@vitna/mandate');
  assert.equal(pkgMeta.license, 'Apache-2.0');

  const verifyScript = `
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import {
  ANY_LEDGER,
  AcpRail,
  BOTTOM,
  agentKeyFromSeed,
  canonicalizeUri,
  generateAgentKey,
  hostSetContains,
  isQuoteHash,
  issueMandateFromAcpAllowance,
  issueMandateFromAp2Intent,
  mandateClaimsFromAcpAllowance,
  mandateClaimsFromAp2Intent,
  meetCaveats,
  narrows,
  quoteHashFromX402Response,
  quotesMatch,
  uriSetContains,
  validateCaveats,
  verifyChain,
} from '@vitna/mandate';
import { SqliteStore } from '@vitna/mandate/sqlite';
import * as ap2Sub from '@vitna/mandate/interop/ap2';
import * as acpSub from '@vitna/mandate/interop/acp';
import * as pgSub from '@vitna/mandate/postgres';
import * as migSub from '@vitna/mandate/migrations';
import * as mcpSub from '@vitna/mandate/mcp/gateway';

assert.equal(typeof ap2Sub.issueMandateFromAp2Intent, 'function');
assert.equal(typeof acpSub.AcpRail, 'function');
assert.equal(typeof pgSub.PostgresStore, 'function');
assert.equal(typeof migSub.runSqliteMigrations, 'function');
assert.equal(typeof mcpSub.McpMandateGateway, 'function');

const require = createRequire(import.meta.url);
const loadVectors = (file) =>
  JSON.parse(readFileSync(require.resolve('@vitna/mandate/vectors/' + file), 'utf8'));

const chainVectors = loadVectors('chain.json').vectors;
assert.equal(chainVectors.length > 20, true, 'chain.json must contain conformance vectors');
for (const v of chainVectors) {
  const trusted = new Set(v.trustedRootIssuers);
  const res = await verifyChain(v.tokens, {
    now: v.now,
    request: v.request,
    ledger: ANY_LEDGER,
    isTrustedRootIssuer: (iss) => trusted.has(iss),
    ...(v.presenterJkt !== undefined ? { presenterJkt: v.presenterJkt } : {}),
    ...(v.maxDepth !== undefined ? { maxDepth: v.maxDepth } : {}),
  });
  assert.equal(res.ok, v.expect.ok, v.id + ': unexpected ok verdict');
  if (!v.expect.ok) {
    assert.equal(res.code, v.expect.code, v.id + ': unexpected error code');
  } else if (v.expect.effective !== undefined) {
    assert.deepStrictEqual(res.effective, v.expect.effective, v.id + ': unexpected effective caveats');
  }
}

const caveatVectors = loadVectors('caveats.json').vectors;
assert.equal(caveatVectors.length > 0, true);
for (const v of caveatVectors) {
  if (v.op === 'narrows') {
    const r = narrows(v.child, v.parent);
    assert.equal(r.ok, v.expect.ok, v.id);
    if (!v.expect.ok) assert.equal(r.code, v.expect.code, v.id);
  } else if (v.op === 'validate') {
    const r = validateCaveats(v.value);
    assert.equal(r.ok, v.expect.ok, v.id);
    if (!v.expect.ok) assert.equal(r.code, v.expect.code, v.id);
  } else {
    const met = meetCaveats(v.a, v.b);
    if ('bottom' in v.expect) {
      assert.equal(Object.values(met).includes(BOTTOM), true, v.id + ': expected BOTTOM');
    } else {
      assert.deepStrictEqual(met, v.expect.result, v.id);
      assert.deepStrictEqual(meetCaveats(v.b, v.a), met, v.id + ': meet must commute');
    }
  }
}

const uriVectors = loadVectors('uri.json').vectors;
assert.equal(uriVectors.length > 0, true);
for (const v of uriVectors) {
  if (v.op === 'canonicalize') {
    assert.equal(canonicalizeUri(v.input), v.expect.output, v.id);
  } else {
    const fn = v.op === 'uriSetContains' ? uriSetContains : hostSetContains;
    assert.equal(fn(v.parent, v.child), v.expect.result, v.id);
  }
}

const publishedKeys = loadVectors('keys.json').keys;
assert.equal(publishedKeys.length > 3, true);
for (const k of publishedKeys) {
  const derived = agentKeyFromSeed(Uint8Array.from(Buffer.from(k.seedHex, 'hex')));
  assert.equal(derived.did, k.did, k.name + ' did');
  assert.equal(derived.jkt, k.jkt, k.name + ' jkt');
  assert.equal(derived.jwk.x, k.jwk.x, k.name + ' jwk.x');
}

const now = 1780000000;
const expIso = new Date((now + 3600) * 1000).toISOString();
const pastIso = new Date((now - 60) * 1000).toISOString();
const principal = generateAgentKey();
const agent = generateAgentKey();
const ledgerUrl = 'https://ledger.example';

const ap2NoCap = mandateClaimsFromAp2Intent(
  {
    user_cart_confirmation_required: false,
    natural_language_description: 'Missing budget',
    intent_expiry: expIso,
  },
  { issuer: principal.did, subject: agent.did, subjectJkt: agent.jkt, ledger: ledgerUrl, now },
);
assert.equal(ap2NoCap.ok, false);
assert.equal(ap2NoCap.code, 'chain_invalid');

const ap2Expired = mandateClaimsFromAp2Intent(
  {
    user_cart_confirmation_required: false,
    natural_language_description: 'Expired intent',
    intent_expiry: pastIso,
    max_amount: { currency: 'USD', value: '10.00' },
  },
  { issuer: principal.did, subject: agent.did, subjectJkt: agent.jkt, ledger: ledgerUrl, now },
);
assert.equal(ap2Expired.ok, false);
assert.equal(ap2Expired.code, 'mandate_expired');

const ap2Valid = issueMandateFromAp2Intent(
  {
    user_cart_confirmation_required: true,
    natural_language_description: 'Weather forecast order',
    merchants: ['https://shop.example/api/v1'],
    intent_expiry: expIso,
    max_amount: { currency: 'USD', value: '25.00' },
  },
  principal,
  { subject: agent.did, subjectJkt: agent.jkt, ledger: ledgerUrl, now },
);
assert.equal(ap2Valid.ok, true);
assert.deepStrictEqual(ap2Valid.claims.cav.step_up, { over: { cur: 'USD', amt: '0' } });
const ap2WrongTask = await verifyChain([ap2Valid.token], {
  now,
  request: {
    resource: 'https://shop.example/api/v1/order',
    amount: { cur: 'USD', amt: '10.00' },
  },
  ledger: ledgerUrl,
  isTrustedRootIssuer: (iss) => iss === principal.did,
  presenterJkt: agent.jkt,
});
assert.equal(ap2WrongTask.ok, false);
assert.equal(ap2WrongTask.code, 'purpose_not_covered');

const ap2Verify = await verifyChain([ap2Valid.token], {
  now,
  request: {
    resource: 'https://shop.example/api/v1/order',
    amount: { cur: 'USD', amt: '10.00' },
    taskId: ap2Valid.claims.cav.task,
  },
  ledger: ledgerUrl,
  isTrustedRootIssuer: (iss) => iss === principal.did,
  presenterJkt: agent.jkt,
});
assert.equal(ap2Verify.ok, true, ap2Verify.ok ? '' : ap2Verify.code + ': ' + ap2Verify.detail);

const acpZero = mandateClaimsFromAcpAllowance(
  {
    reason: 'one_time',
    max_amount: 0,
    currency: 'USD',
    checkout_session_id: 'cs_zero',
    merchant_id: 'merch_1',
    expires_at: now + 3600,
  },
  { issuer: principal.did, subject: agent.did, subjectJkt: agent.jkt, ledger: ledgerUrl, now },
);
assert.equal(acpZero.ok, false);
assert.equal(acpZero.code, 'chain_invalid');

const acpUnknownCur = mandateClaimsFromAcpAllowance(
  {
    reason: 'one_time',
    max_amount: 500,
    currency: 'XYZ',
    checkout_session_id: 'cs_cur',
    merchant_id: 'merch_1',
    expires_at: now + 3600,
  },
  { issuer: principal.did, subject: agent.did, subjectJkt: agent.jkt, ledger: ledgerUrl, now },
);
assert.equal(acpUnknownCur.ok, false);
assert.equal(acpUnknownCur.code, 'currency_mismatch');

const acpValid = issueMandateFromAcpAllowance(
  {
    reason: 'one_time',
    max_amount: 2500,
    currency: 'usd',
    checkout_session_id: 'cs_test_1',
    merchant_id: 'merch_1',
    expires_at: now + 3600,
  },
  principal,
  {
    subject: agent.did,
    subjectJkt: agent.jkt,
    ledger: ledgerUrl,
    now,
    merchantResource: 'https://merchant.example/acp/checkout_sessions/cs_test_1',
  },
);
assert.equal(acpValid.ok, true);
assert.deepStrictEqual(acpValid.claims.cav.max_total, { cur: 'USD', amt: '25' });
const acpVerify = await verifyChain([acpValid.token], {
  now,
  request: {
    resource: 'https://merchant.example/acp/checkout_sessions/cs_test_1',
    amount: { cur: 'USD', amt: '25.00' },
    taskId: acpValid.claims.cav.task,
  },
  ledger: ledgerUrl,
  isTrustedRootIssuer: (iss) => iss === principal.did,
  presenterJkt: agent.jkt,
});
assert.equal(acpVerify.ok, true, acpVerify.ok ? '' : acpVerify.code + ': ' + acpVerify.detail);

const rail = new AcpRail({
  checkoutBaseUrl: 'https://merchant.example/acp',
  paymentTokenFor: () => 'spt_test',
  transport: async (req) => {
    assert.equal(req.method, 'GET');
    return {
      status: 200,
      body: {
        id: 'cs_test_1',
        status: 'ready_for_payment',
        currency: 'USD',
        totals: [{ type: 'total', display_text: 'Total', amount: 3000 }],
      },
    };
  },
});
const payMismatch = await rail.pay({
  id: 'sp_test_1',
  chainHash: 'sha256:0000',
  path: [acpValid.claims.jti],
  agent: agent.did,
  principal: principal.did,
  taskId: 'acp:cs_test_1',
  merchant: 'merchant.example',
  resource: 'https://merchant.example/acp/checkout_sessions/cs_test_1',
  amount: { cur: 'USD', amt: '25.00' },
  status: 'reserved',
  reservedAt: now,
  expiresAt: now + 60,
});
assert.equal(payMismatch.ok, false);
assert.equal(payMismatch.terminal, true);

const uri = 'https://api.example.com/v1/resource';
const payload1 = Buffer.from(
  JSON.stringify({ x402Version: 2, accepts: [{ payTo: '0x1111', amount: '10000' }] }),
  'utf8',
).toString('base64');
const payload2 = Buffer.from(
  JSON.stringify({ x402Version: 2, accepts: [{ payTo: '0x2222', amount: '10000' }] }),
  'utf8',
).toString('base64');
const h1 = quoteHashFromX402Response(uri, { status: 402, headers: { 'PAYMENT-REQUIRED': payload1 } });
const h2 = quoteHashFromX402Response(uri, { status: 402, headers: { 'PAYMENT-REQUIRED': payload2 } });
assert.equal(isQuoteHash(h1), true);
assert.equal(quotesMatch(h1, h1), true);
assert.equal(quotesMatch(h1, h2), false);

const store = new SqliteStore({ location: ':memory:' });
store.close();

const totalVectors = chainVectors.length + caveatVectors.length + uriVectors.length;
console.log(
  JSON.stringify({
    ok: true,
    vectors: totalVectors,
    keys: publishedKeys.length,
    checks: ['ap2', 'acp', 'x402', 'sqlite', 'exports'],
  }),
);
`;

  writeFileSync(join(sandboxDir, 'verify-sandbox.mjs'), verifyScript, 'utf8');
  const scriptOut = execFileSync(process.execPath, [join(sandboxDir, 'verify-sandbox.mjs')], {
    cwd: sandboxDir,
    env,
    encoding: 'utf8',
  });

  const helpOut = execFileSync(process.execPath, [join(pkgRoot, 'bin', 'am.mjs'), '--help'], {
    cwd: sandboxDir,
    env,
    encoding: 'utf8',
  });
  assert.match(helpOut, /Agent Mandate Protocol/);

  const summary = JSON.parse(scriptOut.trim());
  assert.equal(summary.ok, true);
  console.log(
    `@vitna/mandate pack smoke passed (${summary.vectors} vectors, ${summary.keys} keys, CLI + AP2/ACP/x402/SQLite)`,
  );
} finally {
  rmSync(tmpRoot, { recursive: true, force: true });
}
