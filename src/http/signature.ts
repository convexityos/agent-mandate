import { createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import { type Ed25519Jwk, jwkFromDidKey, jwkThumbprint } from '../didkey.js';
import type { AgentKey } from '../sign.js';
import {
  type SfParams,
  asBytes,
  asStringList,
  bytes as sfBytes,
  inner,
  int,
  item,
  parseDictionary,
  serializeDictionary,
  str,
} from './sfv.js';

/**
 * RFC 9421 HTTP Message Signatures, Ed25519 only.
 *
 * This is what makes proof-of-possession real. Everything upstream —
 * `cnf.jkt` on a mandate, `cnf.jkt` on a spend token — is a claim about which
 * key the holder must control. Without a signature over the actual request,
 * nothing ever checks that claim, and both artifacts degrade to bearer tokens.
 *
 * The same Ed25519 key serves here and as the agent's Web Bot Auth identity, so
 * a merchant that already verifies bot identity gets PoP for free.
 */

export const DEFAULT_LABEL = 'pay';
export const DEFAULT_COMPONENTS = ['@method', '@target-uri', 'payment'] as const;
/** How stale a `created` timestamp may be. Bounds the capture-and-replay window. */
export const DEFAULT_MAX_AGE_SECONDS = 60;

export interface SignableRequest {
  method: string;
  /** Absolute target URI, as the client sent it. */
  url: string;
  headers: Record<string, string | string[] | undefined>;
}

/**
 * Case-insensitive header lookup. HTTP field names are case-insensitive, and
 * they genuinely arrive in different cases: Node lowercases what it parses off
 * the wire, while a client assembling a request writes `Payment`. Matching
 * exactly makes a signature that verifies in one direction and not the other.
 */
export function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | null {
  const want = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== want) continue;
    const raw = headers[key];
    if (raw === undefined) continue;
    // RFC 9421 §2.1: strip OWS, join repeated fields with ", ".
    return (Array.isArray(raw) ? raw : [raw]).map((v) => String(v).trim()).join(', ');
  }
  return null;
}

function headerValue(req: SignableRequest, name: string): string | null {
  return getHeader(req.headers, name);
}

function componentValue(req: SignableRequest, id: string): string | null {
  switch (id) {
    case '@method':
      return req.method.toUpperCase();
    case '@target-uri':
      return req.url;
    default:
      if (id.startsWith('@')) return null; // unsupported derived component
      return headerValue(req, id);
  }
}

function signatureParamsValue(components: readonly string[], params: SfParams): string {
  const list = inner(
    components.map((c) => item(str(c))),
    params,
  );
  // Serialize as a one-entry dictionary and strip the key, which is exactly the
  // `Signature-Input` member value.
  return serializeDictionary(new Map([['x', list]])).slice(2);
}

/** RFC 9421 §2.5. Newline-joined, no trailing newline. */
export function buildSignatureBase(
  req: SignableRequest,
  components: readonly string[],
  params: SfParams,
): string | null {
  const lines: string[] = [];
  for (const c of components) {
    const v = componentValue(req, c);
    if (v === null) return null; // a covered component that is not present
    lines.push(`"${c.toLowerCase()}": ${v}`);
  }
  lines.push(`"@signature-params": ${signatureParamsValue(components, params)}`);
  return lines.join('\n');
}

export interface SignOptions {
  key: AgentKey;
  created: number;
  components?: readonly string[];
  label?: string;
  /** Defaults to the signer's `did:key`, which merchants can resolve offline. */
  keyid?: string;
  expires?: number;
  nonce?: string;
}

export function signRequest(
  req: SignableRequest,
  opts: SignOptions,
): { 'Signature-Input': string; Signature: string } {
  const components = opts.components ?? DEFAULT_COMPONENTS;
  const label = opts.label ?? DEFAULT_LABEL;

  const params: SfParams = new Map();
  params.set('created', int(opts.created));
  if (opts.expires !== undefined) params.set('expires', int(opts.expires));
  if (opts.nonce !== undefined) params.set('nonce', str(opts.nonce));
  params.set('keyid', str(opts.keyid ?? opts.key.did));
  params.set('alg', str('ed25519'));

  const base = buildSignatureBase(req, components, params);
  if (base === null) throw new Error('cannot sign: a covered component is missing');

  const sig = cryptoSign(null, Buffer.from(base, 'utf8'), opts.key.privateKey);

  return {
    'Signature-Input': serializeDictionary(
      new Map([[label, inner(components.map((c) => item(str(c))), params)]]),
    ),
    Signature: serializeDictionary(new Map([[label, item(sfBytes(sig))]])),
  };
}

export type SignatureVerifyResult =
  | { ok: true; keyid: string; jkt: string; covered: string[]; created: number }
  | { ok: false; detail: string };

export interface VerifySignatureOptions {
  now: number;
  /** Components that MUST appear in the covered list. */
  requiredComponents?: readonly string[];
  maxAgeSeconds?: number;
  label?: string;
  /** Defaults to resolving `keyid` as a did:key. */
  resolveKey?: (keyid: string) => Ed25519Jwk | null;
}

export function verifyRequestSignature(
  req: SignableRequest,
  opts: VerifySignatureOptions,
): SignatureVerifyResult {
  const required = opts.requiredComponents ?? DEFAULT_COMPONENTS;
  const maxAge = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  const resolve = opts.resolveKey ?? jwkFromDidKey;

  const rawInput = headerValue(req, 'signature-input');
  const rawSig = headerValue(req, 'signature');
  if (rawInput === null || rawSig === null) return { ok: false, detail: 'missing signature headers' };

  const inputDict = parseDictionary(rawInput);
  const sigDict = parseDictionary(rawSig);
  if (inputDict === null || sigDict === null) {
    return { ok: false, detail: 'malformed signature headers' };
  }

  const label = opts.label ?? [...inputDict.keys()][0];
  if (label === undefined) return { ok: false, detail: 'no signature present' };

  const inputMember = inputDict.get(label);
  const covered = asStringList(inputMember);
  const signature = asBytes(sigDict.get(label));
  if (covered === null || signature === null || inputMember === undefined) {
    return { ok: false, detail: `no usable signature labelled ${label}` };
  }

  // The covered set must include everything we require. Without this a signature
  // over "@method" alone verifies happily and proves nothing about the payment.
  const coveredLower = covered.map((c) => c.toLowerCase());
  for (const need of required) {
    if (!coveredLower.includes(need.toLowerCase())) {
      return { ok: false, detail: `signature does not cover ${need}` };
    }
  }

  const params = (inputMember as { params: SfParams }).params;
  const alg = params.get('alg');
  if (alg !== undefined && !(alg.t === 'string' && alg.v === 'ed25519')) {
    return { ok: false, detail: `unsupported alg ${String(alg.v)}` };
  }

  const createdP = params.get('created');
  if (createdP === undefined || createdP.t !== 'int') {
    return { ok: false, detail: 'missing created' };
  }
  const created = createdP.v;
  if (created > opts.now + maxAge) return { ok: false, detail: 'created is in the future' };
  if (created < opts.now - maxAge) return { ok: false, detail: 'signature is stale' };

  const expires = params.get('expires');
  if (expires !== undefined && expires.t === 'int' && expires.v < opts.now) {
    return { ok: false, detail: 'signature expired' };
  }

  const keyidP = params.get('keyid');
  if (keyidP === undefined || keyidP.t !== 'string') return { ok: false, detail: 'missing keyid' };
  const keyid = keyidP.v;

  const jwk = resolve(keyid);
  if (jwk === null) return { ok: false, detail: `unresolvable keyid ${keyid}` };

  const base = buildSignatureBase(req, covered, params);
  if (base === null) return { ok: false, detail: 'a covered component is absent from the request' };

  let valid = false;
  try {
    const key = createPublicKey({ key: jwk as never, format: 'jwk' });
    valid = cryptoVerify(null, Buffer.from(base, 'utf8'), key, signature);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, detail: 'signature verification failed' };

  return { ok: true, keyid, jkt: jwkThumbprint(jwk), covered: coveredLower, created };
}
