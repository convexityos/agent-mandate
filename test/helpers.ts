import type { Caveats } from '../src/caveats.js';
import { type AgentKey, generateAgentKey, signMandate } from '../src/sign.js';
import type { MandateClaims } from '../src/types.js';

export const LEDGER = 'https://ledger.example.com';
export const NOW = 1770000000;

export interface LinkSpec {
  holder: AgentKey;
  cav: Caveats;
  exp?: number;
  nbf?: number;
  jti?: string;
  /** Mutate the claims after construction, to build deliberately invalid chains. */
  tamper?: (c: MandateClaims) => void;
}

export { generateAgentKey };

/**
 * Builds a chain where link 0 is signed by `issuer` and link i>0 is signed by
 * the holder of link i-1, which is the delegation rule the verifier enforces.
 */
export function buildChain(issuer: AgentKey, specs: LinkSpec[]): string[] {
  const tokens: string[] = [];
  let parentJti: string | null = null;
  let signer = issuer;

  for (let i = 0; i < specs.length; i++) {
    const s = specs[i]!;
    const jti = s.jti ?? `mnd_${i}`;
    const claims: MandateClaims = {
      v: 'am/1',
      typ: 'mandate',
      jti,
      iss: signer.did,
      sub: s.holder.did,
      par: parentJti,
      iat: NOW,
      nbf: s.nbf ?? NOW,
      exp: s.exp ?? NOW + 3600,
      cnf: { jkt: s.holder.jkt },
      ledger: LEDGER,
      cav: s.cav,
    };
    s.tamper?.(claims);
    tokens.push(signMandate(claims, signer, signer.did));
    parentJti = claims.jti;
    signer = s.holder;
  }
  return tokens;
}

export function trustOnly(key: AgentKey) {
  return (iss: string) => iss === key.did;
}

export function usd(amt: string) {
  return { cur: 'USD', amt };
}
