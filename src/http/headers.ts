import type { Settle } from '../caveats.js';
import type { Money } from '../money.js';
import { PROTOCOL_VERSION } from '../types.js';
import {
  type SfDictionary,
  asInt,
  asString,
  asStringList,
  inner,
  int,
  item,
  parseDictionary,
  serializeDictionary,
  str,
  tok,
} from './sfv.js';

/**
 * Spec §14 — the wire headers.
 *
 * All three are RFC 8941 Dictionaries rather than parameterized Items, because a
 * parameter value may not be an Inner List and `settle` needs to advertise more
 * than one mode.
 */

export const ACCEPT_PAYMENT = 'Accept-Payment';
export const PAYMENT = 'Payment';
export const PAYMENT_RECEIPT = 'Payment-Receipt';
export const SCHEME = 'agent-mandate';

export interface Challenge {
  scheme: string;
  v: number;
  ledger: string;
  quoteId: string;
  amount: Money;
  settle: Settle[];
  schema?: string;
  /** Unix seconds after which the quote is no longer honoured. */
  exp: number;
}

export function buildChallenge(c: Challenge): string {
  const d: SfDictionary = new Map();
  d.set('scheme', item(tok(c.scheme)));
  d.set('v', item(int(c.v)));
  d.set('ledger', item(str(c.ledger)));
  d.set('quote', item(str(c.quoteId)));
  d.set('amount', item(str(c.amount.amt)));
  d.set('currency', item(str(c.amount.cur)));
  d.set('settle', inner(c.settle.map((s) => item(tok(s)))));
  if (c.schema !== undefined) d.set('schema', item(str(c.schema)));
  d.set('exp', item(int(c.exp)));
  return serializeDictionary(d);
}

const SETTLE_MODES = new Set<string>(['immediate', 'escrow_schema', 'escrow_human']);

export function parseChallenge(header: string | undefined): Challenge | null {
  if (header === undefined) return null;
  const d = parseDictionary(header);
  if (d === null) return null;

  const scheme = asString(d.get('scheme'));
  const v = asInt(d.get('v'));
  const ledger = asString(d.get('ledger'));
  const quoteId = asString(d.get('quote'));
  const amt = asString(d.get('amount'));
  const cur = asString(d.get('currency'));
  const settleRaw = asStringList(d.get('settle'));
  const exp = asInt(d.get('exp'));
  const schema = asString(d.get('schema'));

  if (
    scheme !== SCHEME ||
    v === null ||
    ledger === null ||
    quoteId === null ||
    amt === null ||
    cur === null ||
    settleRaw === null ||
    exp === null
  ) {
    return null;
  }
  if (!settleRaw.every((s) => SETTLE_MODES.has(s))) return null;

  return {
    scheme,
    v,
    ledger,
    quoteId,
    amount: { cur, amt },
    settle: settleRaw as Settle[],
    ...(schema !== null ? { schema } : {}),
    exp,
  };
}

export function buildPayment(token: string): string {
  const d: SfDictionary = new Map();
  d.set('scheme', item(tok(SCHEME)));
  d.set('v', item(int(1)));
  d.set('token', item(str(token)));
  return serializeDictionary(d);
}

export function parsePayment(header: string | undefined): { token: string } | null {
  if (header === undefined) return null;
  const d = parseDictionary(header);
  if (d === null) return null;
  if (asString(d.get('scheme')) !== SCHEME) return null;
  if (asInt(d.get('v')) !== 1) return null;
  const token = asString(d.get('token'));
  return token === null ? null : { token };
}

export function buildReceiptHeader(receiptId: string, ledgerUrl: string): string {
  const d: SfDictionary = new Map();
  d.set('id', item(str(receiptId)));
  d.set('ledger', item(str(ledgerUrl)));
  return serializeDictionary(d);
}

export function parseReceiptHeader(
  header: string | undefined,
): { id: string; ledger: string } | null {
  if (header === undefined) return null;
  const d = parseDictionary(header);
  if (d === null) return null;
  const id = asString(d.get('id'));
  const ledger = asString(d.get('ledger'));
  return id === null || ledger === null ? null : { id, ledger };
}

// -------------------------------------------------------- §14.4 discovery doc

export interface AgentPaymentDoc {
  v: string[];
  ledgers: string[];
  settle: Settle[];
  signature: { algs: string[]; required_components: string[] };
  pricing?: { endpoint?: string; table?: Array<{ resource: string; amount: Money }> };
}

export const WELL_KNOWN_PATH = '/.well-known/agent-payment';

export function buildDiscoveryDoc(
  doc: Omit<AgentPaymentDoc, 'v'> & { v?: string[] },
): AgentPaymentDoc {
  return { v: doc.v ?? [PROTOCOL_VERSION], ...doc };
}
