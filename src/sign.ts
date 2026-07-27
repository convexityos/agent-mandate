import {
  type KeyObject,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';

import { type Ed25519Jwk, didKeyFromEd25519, jwkThumbprint } from './didkey.js';
import { MANDATE_TYP, encodeSegment } from './jws.js';
import type { MandateClaims } from './types.js';

/**
 * Issuer-side helpers. Kept separate from the verifier so that a deployment can
 * ship the verifier without ever linking signing code — merchants verify, they
 * never issue.
 */

export interface AgentKey {
  privateKey: KeyObject;
  publicKey: Uint8Array;
  jwk: Ed25519Jwk;
  did: string;
  /** RFC 7638 thumbprint, for `cnf.jkt`. */
  jkt: string;
}

export function generateAgentKey(): AgentKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as unknown as Ed25519Jwk;
  const raw = Uint8Array.from(Buffer.from(jwk.x, 'base64url'));
  return {
    privateKey,
    publicKey: raw,
    jwk,
    did: didKeyFromEd25519(raw),
    jkt: jwkThumbprint(jwk),
  };
}

/**
 * PKCS#8 wrapper for a bare Ed25519 seed: SEQUENCE { version, AlgorithmIdentifier
 * { 1.3.101.112 }, OCTET STRING { OCTET STRING (32) } }. Fixed for every
 * Ed25519 key, so the whole DER is this prefix followed by the 32-byte seed.
 */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * A key derived from a fixed seed rather than from entropy.
 *
 * Exists for the conformance vectors (§3.1). A vector file is a published
 * artifact that a third-party implementation checks itself against, so the same
 * inputs must produce the same *bytes* — and `generateAgentKey` cannot, because
 * a fresh key means a fresh signature means a different file on every run.
 *
 * Not for production. A seed anyone can read is a key anyone can use, and every
 * seed this repository ships is in `vectors/keys.json` on purpose.
 */
export function agentKeyFromSeed(seed: Uint8Array): AgentKey {
  if (seed.length !== 32) throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' }) as unknown as Ed25519Jwk;
  const raw = Uint8Array.from(Buffer.from(jwk.x, 'base64url'));
  return {
    privateKey,
    publicKey: raw,
    jwk,
    did: didKeyFromEd25519(raw),
    jkt: jwkThumbprint(jwk),
  };
}

export function signMandate(claims: MandateClaims, signer: AgentKey, kid?: string): string {
  const header = {
    alg: 'EdDSA',
    typ: MANDATE_TYP,
    kid: kid ?? `${signer.did}#${signer.did.slice('did:key:'.length)}`,
  };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const sig = cryptoSign(null, Buffer.from(signingInput, 'ascii'), signer.privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}
