import type { Caveats } from './caveats.js';
import type { Money } from './money.js';

export const PROTOCOL_VERSION = 'am/1';
export const MAX_DEPTH = 4;
export const DEFAULT_SKEW_SECONDS = 60;

export interface MandateClaims {
  v: string;
  typ: 'mandate';
  jti: string;
  iss: string;
  sub: string;
  par: string | null;
  iat: number;
  nbf: number;
  exp: number;
  cnf: { jkt: string };
  ledger: string;
  cav: Caveats;
}

export interface RequestContext {
  /** Absolute URI of the resource being purchased. */
  resource: string;
  amount: Money;
  purpose?: string;
  taskId?: string;
  /**
   * §6.2 — the blast radius this call actually has, asserted by whatever is
   * enforcing. Absent means ⊤ (`irreversible`), the same convention the caveat
   * side uses: a caller that will not say what a call does is asking for the
   * broadest reading of it, and gets checked against that.
   */
  effect?: import('./caveats.js').Effect;
}

/** Effective window folded from the chain's top-level claims. */
export interface Window {
  nbf: number;
  exp: number;
}
