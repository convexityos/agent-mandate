import { type KeyObject, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

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
