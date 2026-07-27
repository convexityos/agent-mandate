import { describe, expect, it } from 'vitest';

import {
  bytesToHex,
  domainSeparator,
  hexToBytes,
  keccak256,
  utf8,
} from '../src/chain/eip712.js';
import { EthCallChainReader, jsonRpcTransport } from '../src/chain/ethcall.js';
import type { Eip712Domain } from '../src/rail/x402.js';
import { USDC_BASE } from './fixtures/x402.js';

/**
 * Live read-only checks against Base mainnet.
 *
 * Opt-in via LIVE_RPC=1 so CI never depends on a public endpoint being up. Every
 * call here is an `eth_call` — no key, no transaction, nothing spent. Running it
 * costs a few HTTP requests and validates the one thing unit tests structurally
 * cannot: that this encoder talks to the real contract.
 */

const LIVE = process.env['LIVE_RPC'] === '1';
const RPC_URL = process.env['BASE_RPC_URL'] ?? 'https://mainnet.base.org';
const BASE_CHAIN_ID = 8453;

const selector = (sig: string) => bytesToHex(keccak256(utf8(sig)).slice(0, 4));

function decodeAbiString(returnData: string): string {
  const b = hexToBytes(returnData);
  if (b === null || b.length < 64) throw new Error(`not an ABI string: ${returnData}`);
  const length = Number(BigInt(bytesToHex(b.slice(32, 64))));
  return new TextDecoder().decode(b.slice(64, 64 + length));
}

describe.skipIf(!LIVE)('Base mainnet, read-only', () => {
  const transport = jsonRpcTransport({ url: RPC_URL, timeoutMs: 20_000 });

  const call = (data: string) => transport({ to: USDC_BASE, data });

  it('reaches the RPC and reports the expected chain', async () => {
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
    });
    const body = (await res.json()) as { result: string };
    expect(Number(BigInt(body.result))).toBe(BASE_CHAIN_ID);
  });

  it('reads the EIP-712 domain fields the live 402 capture claimed', async () => {
    // The storefront's challenge advertises {name:"USD Coin", version:"2"}.
    // This is the contract itself confirming it.
    expect(decodeAbiString(await call(selector('name()')))).toBe('USD Coin');
    expect(decodeAbiString(await call(selector('version()')))).toBe('2');
  });

  it('agrees with the contract on DOMAIN_SEPARATOR', async () => {
    // The strongest check available without spending anything: if our locally
    // computed separator matches the deployed contract's, then the typehash,
    // the string hashing, the word packing and the field order are all correct
    // for real — not merely self-consistent.
    const domain: Eip712Domain = {
      name: 'USD Coin',
      version: '2',
      chainId: BASE_CHAIN_ID,
      verifyingContract: USDC_BASE,
    };
    const onChain = await call(selector('DOMAIN_SEPARATOR()'));
    expect(bytesToHex(domainSeparator(domain))).toBe(onChain);
  });

  it('proves the domain check has teeth', async () => {
    const onChain = await call(selector('DOMAIN_SEPARATOR()'));
    // "USDC" is the plausible-looking wrong answer; it is not what the contract
    // signs over, and this is what a signature made against it would fail on.
    expect(
      bytesToHex(
        domainSeparator({
          name: 'USDC',
          version: '2',
          chainId: BASE_CHAIN_ID,
          verifyingContract: USDC_BASE,
        }),
      ),
    ).not.toBe(onChain);
  });

  it('reads authorizationState for an unused nonce', async () => {
    const reader = new EthCallChainReader(transport);
    const used = await reader.authorizationState(
      USDC_BASE,
      '0x1111111111111111111111111111111111111111',
      `0x${'ab'.repeat(32)}`,
    );
    expect(used).toBe(false);
  });

  it('throws rather than decoding false when the token address is wrong', async () => {
    // An eth_call to a non-contract returns "0x". Decoding that as "not
    // consumed" would refund every payment ever made.
    const reader = new EthCallChainReader(transport);
    await expect(
      reader.authorizationState(
        '0x000000000000000000000000000000000000dEaD',
        '0x1111111111111111111111111111111111111111',
        `0x${'ab'.repeat(32)}`,
      ),
    ).rejects.toThrow();
  });
});
