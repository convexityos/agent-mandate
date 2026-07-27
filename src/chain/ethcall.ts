import type { ChainReader } from '../rail/x402-noncustodial.js';
import { bytesToHex, hexToBytes, keccak256, utf8, word } from './eip712.js';

/**
 * `ChainReader` over JSON-RPC `eth_call` (§12.4.5).
 *
 * `authorizationState(address,bytes32)` is standard ERC-3009. It answers "has
 * this authorization been consumed?" without trusting the agent, the merchant,
 * or a facilitator — which is the entire basis of non-custodial confirmation.
 *
 * The transport is injected. A ledger that reconciles money should not have a
 * hard-coded RPC URL, and tests should not need a network.
 */

export const AUTHORIZATION_STATE_SIGNATURE = 'authorizationState(address,bytes32)';

/** First 4 bytes of keccak256 of the signature — derived, never hard-coded. */
export const AUTHORIZATION_STATE_SELECTOR = keccak256(utf8(AUTHORIZATION_STATE_SIGNATURE)).slice(
  0,
  4,
);

export interface EthCallRequest {
  to: string;
  data: string;
  /** Defaults to "latest". */
  block?: string;
}

/** Returns the 0x-prefixed return data, or throws. */
export type EthCallTransport = (req: EthCallRequest) => Promise<string>;

export interface JsonRpcOptions {
  url: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

interface JsonRpcResponse {
  result?: unknown;
  error?: { code?: number; message?: string };
}

export function jsonRpcTransport(opts: JsonRpcOptions): EthCallTransport {
  const doFetch = opts.fetchImpl ?? fetch;
  let id = 0;

  return async ({ to, data, block }) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
    try {
      const res = await doFetch(opts.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...opts.headers },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: ++id,
          method: 'eth_call',
          params: [{ to, data }, block ?? 'latest'],
        }),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
      const body = (await res.json()) as JsonRpcResponse;
      if (body.error !== undefined) {
        throw new Error(`RPC error ${body.error.code ?? '?'}: ${body.error.message ?? 'unknown'}`);
      }
      if (typeof body.result !== 'string') throw new Error('RPC returned no result');
      return body.result;
    } finally {
      clearTimeout(timer);
    }
  };
}

export function encodeAuthorizationState(from: string, nonce: string): string {
  const fromBytes = hexToBytes(from);
  if (fromBytes === null || fromBytes.length !== 20) throw new Error(`not an address: ${from}`);
  const nonceBytes = hexToBytes(nonce);
  if (nonceBytes === null || nonceBytes.length !== 32) throw new Error(`not a bytes32: ${nonce}`);

  const out = new Uint8Array(4 + 32 + 32);
  out.set(AUTHORIZATION_STATE_SELECTOR, 0);
  out.set(word(fromBytes), 4);
  out.set(nonceBytes, 36);
  return bytesToHex(out);
}

/**
 * Decode a single ABI `bool`.
 *
 * Empty return data is NOT false. It is what an `eth_call` to a non-contract
 * address returns, so treating it as "not consumed" would let a
 * misconfigured token address quietly refund every payment ever made. It throws
 * instead, which the rail reports as `unknown` rather than `not_paid`.
 */
export function decodeBool(returnData: string): boolean {
  const bytes = hexToBytes(returnData);
  if (bytes === null || bytes.length !== 32) {
    throw new Error(`expected one ABI word, got ${returnData.length > 66 ? 'more' : returnData}`);
  }
  for (let i = 0; i < 31; i++) {
    if (bytes[i] !== 0) throw new Error('malformed bool: high bytes set');
  }
  const last = bytes[31]!;
  if (last !== 0 && last !== 1) throw new Error(`malformed bool: 0x${last.toString(16)}`);
  return last === 1;
}

export class EthCallChainReader implements ChainReader {
  constructor(
    private readonly transport: EthCallTransport,
    private readonly block: string = 'latest',
  ) {}

  async authorizationState(token: string, from: string, nonce: string): Promise<boolean> {
    const data = encodeAuthorizationState(from, nonce);
    return decodeBool(await this.transport({ to: token, data, block: this.block }));
  }
}
