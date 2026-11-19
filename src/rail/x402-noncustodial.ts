import type { Reservation } from '../ledger/store.js';
import {
  quoteHashForX402Challenge,
  quoteHashFromX402Response,
  quotesMatch,
  type X402ChallengeLikeResponse,
} from '../quote.js';
import { canonicalJson } from '../receipt.js';
import { toAtomicUnits } from './rail.js';
import type { RailStatus } from './rail.js';
import {
  type Directive,
  type NonCustodialRail,
  type PrepareResult,
  type ProofVerdict,
  type RailCapabilities,
} from './noncustodial.js';
import {
  type Eip3009Authorization,
  type Eip712Domain,
  type X402Accepts,
  type X402Challenge,
  amountOf,
  chainIdFromCaip2,
  nonceFor,
  parseX402Challenge,
  refFor,
} from './x402.js';

/**
 * Non-custodial x402 (§12.4) over EIP-3009.
 *
 * This rail gets the two strong properties:
 *
 *   - **trustless oracle** — `authorizationState(from, nonce)` on the token
 *     contract answers "did this execute?" without trusting the agent, the
 *     merchant, or a facilitator. The Ledger can ask because it chose the nonce.
 *   - **hard expiry** — past `validBefore` the signature is permanently
 *     unusable, so an unconfirmed payment is decidably a non-payment.
 *
 * Both fall out of the deterministic nonce from §12.2.2. Idempotency was the
 * visible reason for it; this is the load-bearing one.
 */

/** Verification only — recovers an address, never touches a private key. */
export interface Eip712Verifier {
  recover(
    domain: Eip712Domain,
    authorization: Eip3009Authorization,
    signature: string,
  ): string | null;
}

/** Read-only chain access. `authorizationState` is ERC-3009 standard. */
export interface ChainReader {
  authorizationState(token: string, from: string, nonce: string): Promise<boolean>;
}

export interface X402NonCustodialConfig {
  /** The agent's own funding address. The Ledger never holds its key. */
  payer: string;
  verifier: Eip712Verifier;
  chain: ChainReader;
  network: string;
  asset: string;
  assetDecimals?: number;
  chainId?: number;
  clock: () => number;
  authorizationTtlSeconds?: number;
  scheme?: string;
}

export interface X402Intent extends Record<string, unknown> {
  rail: 'x402';
  scheme: string;
  network: string;
  domain: Eip712Domain;
  authorization: Eip3009Authorization;
  /** Cryptographic digest of the bound 402 challenge when supplied at reserve time. */
  quoteHash?: string;
}

function parseQuotedX402(
  resource: string,
  quote: unknown,
): { challenge: X402Challenge; quoteHash: string } | null {
  if (typeof quote === 'string' && quote.length > 0) {
    try {
      const parsed = JSON.parse(Buffer.from(quote, 'base64').toString('utf8')) as unknown;
      if (
        typeof parsed === 'object' &&
        parsed !== null &&
        Array.isArray((parsed as Record<string, unknown>)['accepts']) &&
        typeof (parsed as Record<string, unknown>)['x402Version'] === 'number'
      ) {
        return {
          challenge: parsed as X402Challenge,
          quoteHash: quoteHashForX402Challenge(resource, quote),
        };
      }
    } catch {
      return null;
    }
    return null;
  }

  if (typeof quote !== 'object' || quote === null) return null;
  const obj = quote as Record<string, unknown>;

  if (obj['status'] === 402 && typeof obj['headers'] === 'object' && obj['headers'] !== null) {
    const res = obj as unknown as X402ChallengeLikeResponse;
    const challenge = parseX402Challenge({
      status: res.status,
      headers: Object.fromEntries(
        Object.entries(res.headers).map(([k, v]) => [k, Array.isArray(v) ? v[0] : v]),
      ),
      body: res.body,
    });
    const hash = quoteHashFromX402Response(resource, res);
    if (challenge !== null && hash !== null) {
      return { challenge, quoteHash: hash };
    }
    return null;
  }

  if (Array.isArray(obj['accepts'])) {
    const challenge = obj as unknown as X402Challenge;
    return {
      challenge,
      quoteHash: quoteHashForX402Challenge(resource, canonicalJson(challenge)),
    };
  }

  return null;
}

export class X402NonCustodialRail implements NonCustodialRail {
  readonly name = 'x402-noncustodial';

  readonly capabilities: RailCapabilities;

  constructor(private readonly cfg: X402NonCustodialConfig) {
    this.capabilities = {
      trustlessOracle: true,
      hardExpiry: true,
      decimals: cfg.assetDecimals ?? 6,
      reversible: false,
    };
  }

  get payer(): string {
    return this.cfg.payer;
  }

  /**
   * `quote` is the merchant's x402 challenge, forwarded by the agent verbatim
   * as a decoded `X402Challenge`, raw base64 `PAYMENT-REQUIRED` header string,
   * or full 402 response.
   */
  prepare(r: Reservation, quote: unknown): PrepareResult {
    const parsed = parseQuotedX402(r.resource, quote);
    if (parsed === null) {
      return { ok: false, terminal: true, detail: 'no x402 challenge supplied' };
    }
    const { challenge, quoteHash: observedHash } = parsed;

    if (r.quoteHash !== undefined && !quotesMatch(r.quoteHash, observedHash)) {
      return {
        ok: false,
        terminal: true,
        detail: `x402 challenge digest mismatch: reserved ${r.quoteHash}, supplied ${observedHash}`,
      };
    }

    const accepts = challenge.accepts.find(
      (a: X402Accepts) =>
        a.scheme === (this.cfg.scheme ?? 'exact') &&
        a.network === this.cfg.network &&
        a.asset.toLowerCase() === this.cfg.asset.toLowerCase(),
    );
    if (accepts === undefined) {
      return {
        ok: false,
        terminal: true,
        detail: `no ${this.cfg.network} / ${this.cfg.asset} option in the challenge`,
      };
    }

    const requiredRaw = amountOf(accepts);
    if (requiredRaw === null) return { ok: false, terminal: true, detail: 'challenge states no amount' };
    let required: bigint;
    try {
      required = BigInt(requiredRaw);
    } catch {
      return { ok: false, terminal: true, detail: `malformed amount "${requiredRaw}"` };
    }

    const value = toAtomicUnits(r.amount, this.capabilities.decimals);
    if (value === null) {
      return {
        ok: false,
        terminal: true,
        detail: `${r.amount.amt} ${r.amount.cur} needs more precision than ${this.capabilities.decimals} decimals`,
      };
    }
    if (value !== required) {
      return {
        ok: false,
        terminal: true,
        detail: `reserved ${value} atomic units, merchant requires ${required} — price moved`,
      };
    }

    const chainId = this.cfg.chainId ?? chainIdFromCaip2(accepts.network);
    if (chainId === null) {
      return {
        ok: false,
        terminal: true,
        detail: `cannot derive an EIP-712 chainId from "${accepts.network}"`,
      };
    }

    const now = this.cfg.clock();
    const validBefore = now + (this.cfg.authorizationTtlSeconds ?? accepts.maxTimeoutSeconds ?? 600);

    const intent: X402Intent = {
      rail: 'x402',
      scheme: accepts.scheme,
      network: accepts.network,
      domain: {
        // From the challenge, never hard-coded: Base USDC signs as "USD Coin",
        // and the wrong name yields a valid-looking, unusable signature.
        name: accepts.extra?.name ?? 'USD Coin',
        version: accepts.extra?.version ?? '2',
        chainId,
        verifyingContract: accepts.asset,
      },
      authorization: {
        from: this.cfg.payer,
        to: accepts.payTo,
        value: value.toString(),
        validAfter: String(now - 60),
        validBefore: String(validBefore),
        // The LEDGER chooses the nonce. This is what makes confirm() possible.
        nonce: nonceFor(r.id),
      },
      ...(r.quoteHash !== undefined ? { quoteHash: r.quoteHash } : {}),
    };

    return {
      ok: true,
      prepared: {
        intent,
        payer: this.cfg.payer,
        expiresAt: validBefore,
        // Past validBefore the signature can never execute, so the negative
        // answer is final the instant the deadline passes.
        decidableAt: validBefore,
      },
    };
  }

  verifyProof(directive: Directive, proof: unknown): ProofVerdict {
    const signature = (proof as { signature?: unknown })?.signature;
    if (typeof signature !== 'string' || signature === '') {
      return { ok: false, detail: 'proof carries no signature' };
    }

    const intent = directive.intent as X402Intent;
    const recovered = this.cfg.verifier.recover(intent.domain, intent.authorization, signature);
    if (recovered === null) return { ok: false, detail: 'signature did not recover' };

    // Catching a mis-signed authorization here rather than at reconcile time
    // makes the failure attributable to one agent and one directive, instead of
    // surfacing later as an unexplained hole in the budget.
    if (recovered.toLowerCase() !== directive.payer.toLowerCase()) {
      return { ok: false, detail: `signed by ${recovered}, expected ${directive.payer}` };
    }

    return { ok: true, ref: refFor(directive.payer, directive.jti) };
  }

  async confirm(directive: Directive): Promise<RailStatus> {
    const intent = directive.intent as X402Intent;
    let used: boolean;
    try {
      used = await this.cfg.chain.authorizationState(
        intent.domain.verifyingContract,
        intent.authorization.from,
        intent.authorization.nonce,
      );
    } catch (e) {
      return { state: 'unknown', detail: `chain read failed: ${String(e)}` };
    }

    if (used) return { state: 'paid', ref: refFor(directive.payer, directive.jti) };

    // Unconsumed and still live: genuinely unknown, not "no".
    if (this.cfg.clock() < directive.decidableAt) {
      return { state: 'unknown', detail: 'authorization still executable' };
    }
    return { state: 'not_paid' };
  }
}
