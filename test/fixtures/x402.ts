import { readFileSync } from 'node:fs';

import type {
  Eip3009Authorization,
  Eip3009Signer,
  Eip712Domain,
  X402HttpRequest,
  X402HttpResponse,
  X402Transport,
} from '../../src/rail/x402.js';
import { PAYMENT_REQUIRED_HEADER, PAYMENT_SIGNATURE_HEADER } from '../../src/rail/x402.js';

/**
 * Fixtures replayed from a live capture of the Fabler Labs x402 storefront
 * (test/fixtures/x402-live.json, captured 2026-07-27). The `PAYMENT-REQUIRED`
 * header values are byte-exact, so the tests parse exactly what the merchant
 * sent rather than what we assumed it would send — which is how the v1/v2
 * divergences got caught in the first place.
 *
 * Nothing here touches a network or a chain: the transport is a function and the
 * signer is deterministic.
 */

interface LiveCapture {
  capturedAt: string;
  host: string;
  endpoints: Record<
    string,
    {
      status: number;
      paymentRequiredHeader: string;
      decoded: {
        x402Version: number;
        accepts: Array<{
          scheme: string;
          network: string;
          amount: string;
          asset: string;
          payTo: string;
          maxTimeoutSeconds?: number;
          extra?: { name?: string; version?: string };
        }>;
      };
    }
  >;
}

export const LIVE: LiveCapture = JSON.parse(
  readFileSync(new URL('./x402-live.json', import.meta.url), 'utf8'),
) as LiveCapture;

export const BASE_CAIP2 = 'eip155:8453';
export const BASE_CHAIN_ID = 8453;
export const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const PAY_TO = '0x65E3E64935eA709bDf1119E1fC991299c04c0154';

export const FUNDING_SPREADS = '/market/funding-spreads';
export const NFT_OWNER = '/nft/owner';
export const BUY_PACK = '/buy/pack';

export const urlFor = (path: string) => `https://${LIVE.host}${path}`;
export const captureFor = (path: string) => LIVE.endpoints[path]!;

export class FixtureSigner implements Eip3009Signer {
  readonly address = '0x1111111111111111111111111111111111111111';
  readonly signed: Array<{ domain: Eip712Domain; authorization: Eip3009Authorization }> = [];
  constructor(private readonly fail = false) {}

  async signTransferAuthorization(
    domain: Eip712Domain,
    authorization: Eip3009Authorization,
  ): Promise<string> {
    if (this.fail) throw new Error('signer unavailable');
    this.signed.push({ domain, authorization });
    // Deterministic stand-in; a real signer produces a 65-byte secp256k1 sig.
    return `0xsig-${authorization.nonce.slice(2, 18)}`;
  }
}

export interface FixtureTransportOptions {
  /** Which captured endpoint to serve. Defaults to the funding-spreads capture. */
  path?: string;
  /** Override the captured `PAYMENT-REQUIRED` header verbatim. */
  challengeHeader?: string;
  /** Serve the v1 shape instead: challenge in the body, `maxAmountRequired`. */
  v1Body?: boolean;
  onPaid?: (req: X402HttpRequest, attempt: number) => X402HttpResponse | Promise<X402HttpResponse>;
  challengeThrows?: boolean;
}

export interface FixtureTransport {
  transport: X402Transport;
  /** Every payment header the ledger sent, decoded. */
  payments: Array<Record<string, unknown>>;
  challengeCalls: number;
}

export function fixtureTransport(opts: FixtureTransportOptions = {}): FixtureTransport {
  const capture = captureFor(opts.path ?? FUNDING_SPREADS);

  const state: FixtureTransport = {
    payments: [],
    challengeCalls: 0,
    transport: async (req: X402HttpRequest) => {
      const payment = req.headers[PAYMENT_SIGNATURE_HEADER] ?? req.headers['X-PAYMENT'];

      if (payment === undefined) {
        state.challengeCalls++;
        if (opts.challengeThrows === true) throw new Error('ECONNRESET');

        if (opts.v1Body === true) {
          const a = capture.decoded.accepts[0]!;
          return {
            status: 402,
            headers: { 'Content-Type': 'application/json' },
            body: {
              x402Version: 1,
              error: 'X-PAYMENT header is required',
              accepts: [
                {
                  scheme: a.scheme,
                  network: 'base',
                  maxAmountRequired: a.amount,
                  resource: urlFor(opts.path ?? FUNDING_SPREADS),
                  payTo: a.payTo,
                  asset: a.asset,
                  maxTimeoutSeconds: a.maxTimeoutSeconds,
                  extra: a.extra,
                },
              ],
            },
          };
        }

        return {
          status: 402,
          headers: {
            'Content-Type': 'application/json',
            [PAYMENT_REQUIRED_HEADER]: opts.challengeHeader ?? capture.paymentRequiredHeader,
          },
          // v2 bodies are always empty; the challenge is in the header.
          body: {},
        };
      }

      state.payments.push(
        JSON.parse(Buffer.from(payment, 'base64').toString('utf8')) as Record<string, unknown>,
      );
      const attempt = state.payments.length;

      if (opts.onPaid !== undefined) return opts.onPaid(req, attempt);

      // The storefront declares no settlement-receipt header, so a plain 2xx is
      // what a successful payment actually looks like.
      return { status: 200, headers: {}, body: { ok: true } };
    },
  };
  return state;
}
