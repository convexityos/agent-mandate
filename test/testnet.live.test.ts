import { describe, expect, it } from 'vitest';

import { executeDirective } from '../src/agent/directive.js';
import { LocalEip3009Signer } from '../src/agent/signer.js';
import { NobleEip712Verifier, bytesToHex, domainSeparator } from '../src/chain/eip712.js';
import { EthCallChainReader, jsonRpcTransport } from '../src/chain/ethcall.js';
import { BASE_MAINNET, BASE_SEPOLIA, domainFor } from '../src/chain/networks.js';
import { Ledger } from '../src/ledger/ledger.js';
import { MemoryLedgerStore } from '../src/ledger/store.js';
import { X402NonCustodialRail, type X402Intent } from '../src/rail/x402-noncustodial.js';
import { generateAgentKey } from '../src/sign.js';
import { NOW, buildChain, trustOnly, usd } from './helpers.js';
import { secp256k1 } from '@noble/curves/secp256k1';

/**
 * Full non-custodial flow against **Base Sepolia**, opt-in via LIVE_RPC=1.
 *
 * Everything on the wire here is read-only. The run generates a fresh ephemeral
 * key, produces a genuine EIP-3009 signature, and then deliberately does not
 * broadcast it — signing and submitting are separate steps precisely so this is
 * possible. The final assertion is that the authorization is still unused
 * on-chain, which is the machine-checkable statement that nothing was spent.
 */

const LIVE = process.env['LIVE_RPC'] === '1';
const RPC = process.env['BASE_SEPOLIA_RPC_URL'] ?? BASE_SEPOLIA.defaultRpcUrl;
const USDC = BASE_SEPOLIA.assets['USDC']!;

describe.skipIf(!LIVE)('Base Sepolia, read-only', () => {
  const transport = jsonRpcTransport({ url: RPC, timeoutMs: 20_000 });

  it('is the chain we think it is', async () => {
    const res = await fetch(RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
    });
    const body = (await res.json()) as { result: string };
    expect(Number(BigInt(body.result))).toBe(BASE_SEPOLIA.chainId);
  });

  it('agrees with the contract on DOMAIN_SEPARATOR', async () => {
    const onChain = await transport({ to: USDC.address, data: '0x3644e515' });
    expect(bytesToHex(domainSeparator(domainFor(BASE_SEPOLIA, 'USDC')!))).toBe(onChain);
  });

  it('signs as "USDC" here and "USD Coin" on mainnet', async () => {
    // The trap is inverted between networks, so a single hard-coded constant is
    // wrong on one of them — silently, because the signature stays well-formed
    // and the token contract simply refuses it.
    expect(USDC.domainName).toBe('USDC');
    expect(BASE_MAINNET.assets['USDC']!.domainName).toBe('USD Coin');

    const onChain = await transport({ to: USDC.address, data: '0x3644e515' });
    const wrong = domainSeparator({
      ...domainFor(BASE_SEPOLIA, 'USDC')!,
      name: 'USD Coin', // the mainnet answer, on the testnet contract
    });
    expect(bytesToHex(wrong)).not.toBe(onChain);
  });
});

describe.skipIf(!LIVE)('end-to-end on Base Sepolia, nothing broadcast', () => {
  it('reserves, issues a directive, signs it, and leaves it unspent', async () => {
    const transport = jsonRpcTransport({ url: RPC, timeoutMs: 20_000 });
    const chain = new EthCallChainReader(transport);

    // Ephemeral key, generated here, never persisted, never funded.
    const priv = secp256k1.utils.randomPrivateKey();
    const signer = new LocalEip3009Signer({
      privateKey: priv,
      policy: {
        maxPerTransfer: 10_000n, // 0.01 USDC
        allowedAssets: [USDC.address],
        allowedChainIds: [BASE_SEPOLIA.chainId],
        maxValidityWindowSeconds: 3600,
      },
    });

    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const ledgerKey = generateAgentKey();
    const now = Math.floor(Date.now() / 1000);

    const ledger = new Ledger({
      url: 'https://ledger.optera.one',
      key: ledgerKey,
      store: new MemoryLedgerStore(() => now),
      isTrustedRootIssuer: trustOnly(principal),
      clock: () => now,
      breakers: { novelMerchant: 'off' },
      nonCustodialRail: new X402NonCustodialRail({
        payer: signer.address,
        verifier: new NobleEip712Verifier(),
        chain,
        network: BASE_SEPOLIA.caip2,
        asset: USDC.address,
        clock: () => now,
      }),
    });

    // A merchant quote for the testnet asset. In production this arrives in the
    // merchant's own 402; the ledger pins whatever the agent forwards.
    const quote = {
      rail: {
        x402Version: 2,
        accepts: [
          {
            scheme: 'exact',
            network: BASE_SEPOLIA.caip2,
            amount: '1000',
            asset: USDC.address,
            payTo: '0x000000000000000000000000000000000000c0De',
            maxTimeoutSeconds: 300,
            extra: { name: USDC.domainName, version: USDC.domainVersion },
          },
        ],
      },
    };

    const tokens = buildChain(principal, [
      {
        holder: agent,
        nbf: now - 60,
        exp: now + 86400,
        jti: 'mnd_testnet_root',
        cav: {
          max_total: usd('1.00'),
          max_per_txn: usd('0.01'),
          aud: ['merchant.testnet.example'],
          payer: signer.address,
        },
      },
    ]);

    const reserved = await ledger.reserve({
      tokens,
      request: {
        resource: 'https://merchant.testnet.example/data',
        amount: usd('0.001'),
      },
      quote,
    });
    expect(reserved.ok).toBe(true);
    if (!reserved.ok) return;

    const intent = reserved.directive!.intent as X402Intent;
    expect(intent.domain.chainId).toBe(BASE_SEPOLIA.chainId);
    expect(intent.domain.name).toBe('USDC');
    expect(intent.authorization.value).toBe('1000');
    expect(intent.authorization.from).toBe(signer.address);

    // Sign for real.
    const executed = executeDirective(reserved.directiveJws!, {
      signer,
      ledgerJwk: ledgerKey.jwk,
      ledgerUrl: 'https://ledger.optera.one',
      now,
      jkt: agent.jkt,
    });
    expect(executed.ok).toBe(true);
    if (!executed.ok) return;

    // The ledger accepts it: recovery lands on the payer it named.
    const reportResult = await ledger.report(reserved.spendId, executed.report);
    expect(reportResult.ok).toBe(false); // accepted, awaiting the oracle
    expect((await ledger.reservation(reserved.spendId))?.reported?.ok).toBe(true);

    // The oracle, read live from Base Sepolia, says the authorization has not
    // been consumed — because it was never broadcast. This is the assertion
    // that no value moved.
    const used = await chain.authorizationState(
      USDC.address,
      signer.address,
      intent.authorization.nonce,
    );
    expect(used).toBe(false);

    // And the ledger draws the correct conclusion: unknown, not settled.
    expect(await ledger.reconcile()).toEqual([
      { spendId: reserved.spendId, outcome: 'still_unknown' },
    ]);

    // eslint-disable-next-line no-console
    console.log(
      [
        '',
        '  Base Sepolia dry run',
        `    payer          ${signer.address}`,
        `    asset          ${USDC.address} (${USDC.domainName} v${USDC.domainVersion})`,
        `    nonce          ${intent.authorization.nonce}`,
        `    signature      ${executed.signed.signature.slice(0, 26)}…`,
        `    recovered      ${new NobleEip712Verifier().recover(intent.domain, intent.authorization, executed.signed.signature)}`,
        `    on-chain used  ${used}   <- nothing was broadcast`,
        '',
      ].join('\n'),
    );
  }, 30_000);
});
