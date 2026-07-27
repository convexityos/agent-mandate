import { secp256k1 } from '@noble/curves/secp256k1';

import {
  bytesToHex,
  hexToBytes,
  keccak256,
  toChecksumAddress,
  transferWithAuthorizationDigest,
} from '../chain/eip712.js';
import type { Eip3009Authorization, Eip3009Signer, Eip712Domain } from '../rail/x402.js';

/**
 * The agent-side signer — the only component in this repository that can move
 * money, and therefore the only one written defensively against its own caller.
 *
 * In non-custodial mode the Ledger authorizes and the agent executes. That
 * split is worthless if the agent signs whatever the Ledger sends: a
 * compromised, buggy, or merely misconfigured Ledger would then have exactly the
 * custodial power the design set out to remove. **This signer is the principal's
 * last line of defence, so it re-derives everything and enforces its own
 * limits.**
 *
 * Three rules it will not bend:
 *
 *  1. **It never signs an opaque digest.** The interface takes a structured
 *     domain and authorization and computes the hash itself. A signer that
 *     accepts a pre-computed hash can be handed the hash of an entirely
 *     different transaction — a `transfer(attacker, balance)` — and will
 *     cheerfully authorize it.
 *  2. **Policy is mandatory.** There is no default-open construction, because a
 *     signer with no limits is a hot wallet with extra steps.
 *  3. **A nonce binds to one set of parameters, permanently.** Re-signing the
 *     same nonce with a different destination is refused even if policy would
 *     otherwise allow it.
 */

export class PolicyViolation extends Error {
  constructor(
    readonly rule: string,
    detail: string,
  ) {
    super(`signer policy: ${rule} — ${detail}`);
    this.name = 'PolicyViolation';
  }
}

export interface SignerPolicy {
  /** Hard ceiling per authorization, in the asset's atomic units. Required. */
  maxPerTransfer: bigint;
  /** EIP-712 `verifyingContract` values this signer will sign for. Required. */
  allowedAssets: readonly string[];
  /** Chain ids this signer will sign for. Required. */
  allowedChainIds: readonly number[];
  /** Optional destination allowlist. Absent means any destination. */
  allowedRecipients?: readonly string[];
  /** Cumulative ceiling across the signer's lifetime. Absent means unbounded. */
  maxTotal?: bigint;
  /**
   * Longest `validBefore - validAfter` accepted. A long window is a signature
   * that stays spendable long after the task that justified it has finished.
   */
  maxValidityWindowSeconds?: number;
}

export interface SignedAuthorization {
  signature: string;
  digest: string;
  address: string;
  domain: Eip712Domain;
  authorization: Eip3009Authorization;
}

export interface LocalSignerOptions {
  /** 32-byte secp256k1 private key, as hex or raw bytes. */
  privateKey: string | Uint8Array;
  policy: SignerPolicy;
  clock?: () => number;
  /** Audit hook. Called after a successful signature; never receives key material. */
  onSign?: (event: Omit<SignedAuthorization, 'signature'> & { signature: string }) => void;
  /** Called when a request is refused, so refusals are observable rather than silent. */
  onRefuse?: (rule: string, detail: string) => void;
}

const lower = (s: string) => s.toLowerCase();

export class LocalEip3009Signer implements Eip3009Signer {
  readonly address: string;

  /** Truly private: `#` fields are not reachable from outside the class. */
  readonly #key: Uint8Array;
  readonly #policy: SignerPolicy;
  readonly #clock: () => number;
  readonly #allowedAssets: Set<string>;
  readonly #allowedChains: Set<number>;
  readonly #allowedRecipients: Set<string> | null;
  /** nonce → digest, so one nonce can never authorize two different transfers. */
  readonly #seen = new Map<string, { digest: string; signature: string }>();
  #spent = 0n;

  constructor(private readonly opts: LocalSignerOptions) {
    const key =
      typeof opts.privateKey === 'string' ? hexToBytes(opts.privateKey) : opts.privateKey;
    if (key === null || key.length !== 32) {
      throw new Error('privateKey must be 32 bytes');
    }
    if (!secp256k1.utils.isValidPrivateKey(key)) {
      throw new Error('privateKey is not a valid secp256k1 scalar');
    }
    if (opts.policy.maxPerTransfer <= 0n) {
      throw new Error('policy.maxPerTransfer must be positive');
    }
    if (opts.policy.allowedAssets.length === 0 || opts.policy.allowedChainIds.length === 0) {
      throw new Error('policy must allowlist at least one asset and one chain');
    }

    this.#key = Uint8Array.from(key);
    this.#policy = opts.policy;
    this.#clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
    this.#allowedAssets = new Set(opts.policy.allowedAssets.map(lower));
    this.#allowedChains = new Set(opts.policy.allowedChainIds);
    this.#allowedRecipients =
      opts.policy.allowedRecipients === undefined
        ? null
        : new Set(opts.policy.allowedRecipients.map(lower));

    const pub = secp256k1.getPublicKey(this.#key, false).slice(1);
    this.address = toChecksumAddress(bytesToHex(keccak256(pub).slice(12)));
  }

  /** Remaining cumulative allowance, or null when uncapped. */
  get remaining(): bigint | null {
    return this.#policy.maxTotal === undefined ? null : this.#policy.maxTotal - this.#spent;
  }

  /**
   * What this signer would do, without doing it. Lets an agent runtime log or
   * surface an authorization for approval before any signature exists.
   */
  inspect(
    domain: Eip712Domain,
    authorization: Eip3009Authorization,
  ): { ok: true; digest: string } | { ok: false; rule: string; detail: string } {
    try {
      this.#check(domain, authorization);
      return {
        ok: true,
        digest: bytesToHex(transferWithAuthorizationDigest(domain, authorization)),
      };
    } catch (e) {
      const v = e as PolicyViolation;
      return { ok: false, rule: v.rule ?? 'malformed', detail: v.message };
    }
  }

  async signTransferAuthorization(
    domain: Eip712Domain,
    authorization: Eip3009Authorization,
  ): Promise<string> {
    return this.sign(domain, authorization).signature;
  }

  sign(domain: Eip712Domain, authorization: Eip3009Authorization): SignedAuthorization {
    try {
      this.#check(domain, authorization);
    } catch (e) {
      const v = e as PolicyViolation;
      this.opts.onRefuse?.(v.rule ?? 'malformed', v.message);
      throw e;
    }

    // Computed here, from structured fields. Never supplied by the caller.
    const digestBytes = transferWithAuthorizationDigest(domain, authorization);
    const digest = bytesToHex(digestBytes);

    const prior = this.#seen.get(lower(authorization.nonce));
    if (prior !== undefined) {
      // Same nonce, same transfer: hand back the identical signature rather than
      // producing a second one. Idempotent by construction.
      return {
        signature: prior.signature,
        digest,
        address: this.address,
        domain,
        authorization,
      };
    }

    const sig = secp256k1.sign(digestBytes, this.#key); // canonical low-s by default
    const signature = `${bytesToHex(sig.toCompactRawBytes())}${(sig.recovery + 27)
      .toString(16)
      .padStart(2, '0')}`;

    this.#seen.set(lower(authorization.nonce), { digest, signature });
    this.#spent += BigInt(authorization.value);

    const result: SignedAuthorization = {
      signature,
      digest,
      address: this.address,
      domain,
      authorization,
    };
    this.opts.onSign?.(result);
    return result;
  }

  #check(domain: Eip712Domain, a: Eip3009Authorization): void {
    if (lower(a.from) !== lower(this.address)) {
      throw new PolicyViolation('from', `authorization funds ${a.from}, this signer is ${this.address}`);
    }
    if (!this.#allowedChains.has(domain.chainId)) {
      throw new PolicyViolation('chain', `chainId ${domain.chainId} is not allowlisted`);
    }
    if (!this.#allowedAssets.has(lower(domain.verifyingContract))) {
      throw new PolicyViolation('asset', `${domain.verifyingContract} is not allowlisted`);
    }
    if (this.#allowedRecipients !== null && !this.#allowedRecipients.has(lower(a.to))) {
      throw new PolicyViolation('recipient', `${a.to} is not allowlisted`);
    }

    if (!/^\d+$/.test(a.value)) throw new PolicyViolation('value', `"${a.value}" is not a uint`);
    const value = BigInt(a.value);
    if (value <= 0n) throw new PolicyViolation('value', 'refusing to sign a zero-value transfer');
    if (value > this.#policy.maxPerTransfer) {
      throw new PolicyViolation(
        'maxPerTransfer',
        `${value} exceeds the per-transfer ceiling of ${this.#policy.maxPerTransfer}`,
      );
    }
    if (this.#policy.maxTotal !== undefined && this.#spent + value > this.#policy.maxTotal) {
      throw new PolicyViolation(
        'maxTotal',
        `${value} would take cumulative spend to ${this.#spent + value}, over ${this.#policy.maxTotal}`,
      );
    }

    const validAfter = Number(a.validAfter);
    const validBefore = Number(a.validBefore);
    if (!Number.isFinite(validAfter) || !Number.isFinite(validBefore)) {
      throw new PolicyViolation('validity', 'validAfter/validBefore are not numeric');
    }
    const now = this.#clock();
    if (validBefore <= now) {
      throw new PolicyViolation('validity', 'authorization has already expired');
    }
    if (validAfter > now) {
      throw new PolicyViolation('validity', 'authorization is not yet valid');
    }
    const window = validBefore - validAfter;
    const maxWindow = this.#policy.maxValidityWindowSeconds;
    if (maxWindow !== undefined && window > maxWindow) {
      throw new PolicyViolation('validity', `${window}s window exceeds the ${maxWindow}s maximum`);
    }

    const nonce = hexToBytes(a.nonce);
    if (nonce === null || nonce.length !== 32) {
      throw new PolicyViolation('nonce', `${a.nonce} is not a bytes32`);
    }

    // A nonce is single-use on-chain. Letting it authorize two different
    // transfers locally means one of them is a signature the principal never
    // intended and can no longer distinguish.
    const prior = this.#seen.get(lower(a.nonce));
    if (prior !== undefined) {
      const digest = bytesToHex(transferWithAuthorizationDigest(domain, a));
      if (prior.digest !== digest) {
        throw new PolicyViolation(
          'nonce',
          `${a.nonce} was already signed for a different transfer`,
        );
      }
    }
  }

  /** Key material must not reach a log, a crash dump, or a serialized error. */
  toJSON(): Record<string, unknown> {
    return { address: this.address, type: 'LocalEip3009Signer', privateKey: '[redacted]' };
  }

  // Deliberately tolerant of a detached receiver. This hook runs while someone
  // is debugging, often inside an error path; throwing here replaces the problem
  // they were investigating with a confusing one about inspection.
  [Symbol.for('nodejs.util.inspect.custom')](this: LocalEip3009Signer | undefined): string {
    return `LocalEip3009Signer<${this?.address ?? 'detached'}>`;
  }
}

/**
 * Reads a key from the environment so it never appears in source or argv.
 *
 * Still the weakest of the acceptable options: environment variables leak into
 * child processes, crash reporters and `/proc`. Anything holding real value
 * belongs behind a KMS or hardware signer implementing `Eip3009Signer` directly
 * — the interface exists so the key never has to be in this process at all.
 */
export function signerFromEnv(
  variable: string,
  policy: SignerPolicy,
  opts: Omit<LocalSignerOptions, 'privateKey' | 'policy'> = {},
): LocalEip3009Signer {
  const raw = process.env[variable];
  if (raw === undefined || raw === '') {
    throw new Error(`${variable} is not set`);
  }
  return new LocalEip3009Signer({ privateKey: raw.trim(), policy, ...opts });
}
