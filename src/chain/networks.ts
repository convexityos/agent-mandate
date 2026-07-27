import type { Eip712Domain } from '../rail/x402.js';

/**
 * Verified per-network settlement config.
 *
 * Every value here was read from the deployed contract, not from documentation
 * — see test/chain.live.test.ts, which re-reads them.
 *
 * The EIP-712 domain `name` is the reason this file exists. Base **mainnet**
 * USDC signs as `"USD Coin"`; Base **Sepolia** USDC signs as `"USDC"`. The trap
 * is inverted between the two networks, so any hard-coded default is wrong on
 * one of them, and the failure is silent: the signature is well-formed and the
 * token contract simply refuses it. Adapters should always prefer the domain
 * advertised in the merchant's challenge; this table is the fallback for when
 * one is not supplied, and the per-network correctness that a single constant
 * cannot provide.
 */

export interface NetworkAsset {
  symbol: string;
  address: string;
  decimals: number;
  /** EIP-712 domain name as the contract reports it. NOT the symbol. */
  domainName: string;
  domainVersion: string;
}

export interface NetworkConfig {
  /** CAIP-2 identifier, as x402 v2 uses. */
  caip2: string;
  chainId: number;
  name: string;
  testnet: boolean;
  defaultRpcUrl: string;
  assets: Record<string, NetworkAsset>;
}

export const BASE_MAINNET: NetworkConfig = {
  caip2: 'eip155:8453',
  chainId: 8453,
  name: 'Base',
  testnet: false,
  defaultRpcUrl: 'https://mainnet.base.org',
  assets: {
    USDC: {
      symbol: 'USDC',
      address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      decimals: 6,
      domainName: 'USD Coin',
      domainVersion: '2',
    },
  },
};

export const BASE_SEPOLIA: NetworkConfig = {
  caip2: 'eip155:84532',
  chainId: 84532,
  name: 'Base Sepolia',
  testnet: true,
  defaultRpcUrl: 'https://sepolia.base.org',
  assets: {
    USDC: {
      symbol: 'USDC',
      address: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
      decimals: 6,
      // Not a typo, and not the same as mainnet. Read from the contract.
      domainName: 'USDC',
      domainVersion: '2',
    },
  },
};

export const NETWORKS: Record<string, NetworkConfig> = {
  [BASE_MAINNET.caip2]: BASE_MAINNET,
  [BASE_SEPOLIA.caip2]: BASE_SEPOLIA,
};

export function networkFor(caip2: string): NetworkConfig | null {
  return NETWORKS[caip2] ?? null;
}

export function domainFor(network: NetworkConfig, symbol: string): Eip712Domain | null {
  const asset = network.assets[symbol];
  if (asset === undefined) return null;
  return {
    name: asset.domainName,
    version: asset.domainVersion,
    chainId: network.chainId,
    verifyingContract: asset.address,
  };
}
