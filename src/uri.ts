/**
 * Spec §6.4 — canonicalization and pattern containment.
 *
 * The grammar is deliberately restricted:
 *
 *   pattern    = scheme "://" hostpat [ "/" pathprefix [ "*" ] ]
 *   hostpat    = host | "*." host          ; exactly one wildcard label
 *
 * Regular expressions are prohibited. Containment of arbitrary regular
 * expressions is not decidable in general, and if you cannot mechanically prove
 * a child narrows its parent you do not have attenuation, you have a vibe.
 *
 * We do not use the WHATWG URL parser here. It resolves dot-segments *before*
 * percent-decoding, so `%2E%2E%2F` survives normalization and re-expands to
 * `../` downstream. Order matters: decode unreserved, *then* resolve.
 */

const URI_RE = /^([a-zA-Z][a-zA-Z0-9+.\-]*):\/\/([^/?#]*)([^?#]*)(?:\?[^#]*)?(?:#.*)?$/;

const DEFAULT_PORTS: Readonly<Record<string, string>> = { http: '80', https: '443' };

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

export interface UriPattern {
  scheme: string;
  host: string;
  hostWildcard: boolean;
  path: string;
  pathWildcard: boolean;
}

export interface HostPattern {
  host: string;
  wildcard: boolean;
}

/** Percent-decode only unreserved characters; normalize remaining escapes to uppercase hex. */
function decodeUnreserved(s: string): string {
  return s.replace(/%[0-9A-Fa-f]{2}/g, (esc) => {
    const c = String.fromCharCode(parseInt(esc.slice(1), 16));
    return UNRESERVED.test(c) ? c : esc.toUpperCase();
  });
}

/** RFC 3986 §5.2.4 remove_dot_segments, preserving trailing-slash semantics. */
function removeDotSegments(path: string): string {
  const segs = path.split('/');
  const out: string[] = [];
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i]!;
    const isLast = i === segs.length - 1;
    if (seg === '.') {
      if (isLast) out.push('');
      continue;
    }
    if (seg === '..') {
      if (out.length > 1) out.pop();
      if (isLast) out.push('');
      continue;
    }
    out.push(seg);
  }
  const res = out.join('/');
  return res.startsWith('/') ? res : `/${res}`;
}

function normalizeHost(authority: string): string | null {
  // Userinfo is rejected outright: `https://evil.com@good.com/` is a classic
  // read-the-wrong-host confusion and has no legitimate use in a resource grant.
  if (authority.includes('@')) return null;
  if (authority.includes('[')) return null; // IPv6 literals unsupported in v1
  if (authority === '') return null;

  const colon = authority.lastIndexOf(':');
  let host = authority;
  let port: string | null = null;
  if (colon !== -1) {
    const maybePort = authority.slice(colon + 1);
    if (!/^\d*$/.test(maybePort)) return null;
    host = authority.slice(0, colon);
    port = maybePort === '' ? null : maybePort;
  }

  host = host.toLowerCase();
  if (host === '' || host.includes('..') || host.startsWith('.')) return null;
  if (host.endsWith('.')) host = host.slice(0, -1); // strip root label

  return port === null ? host : `${host}:${port}`;
}

/**
 * Canonical form: `scheme://host[:port]/path`.
 *
 * Query and fragment are dropped. Authority decisions are made on path prefix
 * only (§6.4), so admitting query strings into the canonical form would create
 * two spellings of the same grant without changing what it grants. Merchants
 * that need to price on query parameters must expose them as path segments.
 */
export function canonicalizeUri(raw: string): string | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  const m = URI_RE.exec(raw);
  if (!m) return null;

  const scheme = m[1]!.toLowerCase();
  const authority = m[2]!;
  const rawPath = m[3]!;

  let host = normalizeHost(authority);
  if (host === null) return null;

  const colon = host.lastIndexOf(':');
  if (colon !== -1) {
    const port = host.slice(colon + 1);
    if (DEFAULT_PORTS[scheme] === port) host = host.slice(0, colon);
  }

  const decoded = decodeUnreserved(rawPath === '' ? '/' : rawPath);
  const path = removeDotSegments(decoded);
  if (path.split('/').includes('..')) return null; // defensive; unreachable post-resolution

  return `${scheme}://${host}${path}`;
}

export function parseUriPattern(raw: string): UriPattern | null {
  if (typeof raw !== 'string') return null;

  let body = raw;
  let pathWildcard = false;
  if (body.endsWith('*')) {
    body = body.slice(0, -1);
    pathWildcard = true;
  }

  const m = URI_RE.exec(body);
  if (!m) return null;
  const scheme = m[1]!.toLowerCase();
  let authority = m[2]!;
  const rawPath = m[3]!;

  // After stripping the single trailing path wildcard, the only '*' the grammar
  // permits is a leading host label.
  let hostWildcard = false;
  if (authority.startsWith('*.')) {
    hostWildcard = true;
    authority = authority.slice(2);
  }
  if (authority.includes('*')) return null;
  if (rawPath.includes('*')) return null;

  let host = normalizeHost(authority);
  if (host === null) return null;
  const colon = host.lastIndexOf(':');
  if (colon !== -1 && DEFAULT_PORTS[scheme] === host.slice(colon + 1)) {
    host = host.slice(0, colon);
  }

  const decoded = decodeUnreserved(rawPath === '' ? '/' : rawPath);
  const path = removeDotSegments(decoded);
  if (path.split('/').includes('..')) return null;

  // A bare `https://host` grants the whole host.
  if (rawPath === '' || rawPath === '/') pathWildcard = true;

  return { scheme, host, hostWildcard, path, pathWildcard };
}

export function parseHostPattern(raw: string): HostPattern | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  let wildcard = false;
  let body = raw;
  if (body.startsWith('*.')) {
    wildcard = true;
    body = body.slice(2);
  }
  if (body.includes('*')) return null;
  const host = normalizeHost(body);
  if (host === null) return null;
  return { host, wildcard };
}

/** A wildcard label matches exactly one non-empty, dot-free label. */
export function hostMatches(p: HostPattern, host: string): boolean {
  const h = host.toLowerCase();
  if (!p.wildcard) return h === p.host;
  const suffix = `.${p.host}`;
  if (!h.endsWith(suffix)) return false;
  const label = h.slice(0, -suffix.length);
  return label.length > 0 && !label.includes('.');
}

export function hostPatternContains(parent: HostPattern, child: HostPattern): boolean {
  if (!parent.wildcard) return !child.wildcard && parent.host === child.host;
  // `*.x` matches exactly one extra label, so it cannot contain `*.y.x`
  // (which matches two). Wildcard-to-wildcard requires identical suffixes.
  if (child.wildcard) return child.host === parent.host;
  return hostMatches(parent, child.host);
}

export function uriMatches(p: UriPattern, canonicalUri: string): boolean {
  const m = /^([a-z0-9+.\-]+):\/\/([^/]+)(\/.*)$/.exec(canonicalUri);
  if (!m) return false;
  const [, scheme, host, path] = m as unknown as [string, string, string, string];
  if (scheme !== p.scheme) return false;
  if (!hostMatches({ host: p.host, wildcard: p.hostWildcard }, host)) return false;
  return p.pathWildcard ? path.startsWith(p.path) : path === p.path;
}

export function uriPatternContains(parent: UriPattern, child: UriPattern): boolean {
  if (parent.scheme !== child.scheme) return false;
  if (
    !hostPatternContains(
      { host: parent.host, wildcard: parent.hostWildcard },
      { host: child.host, wildcard: child.hostWildcard },
    )
  ) {
    return false;
  }
  if (parent.pathWildcard) return child.path.startsWith(parent.path);
  return !child.pathWildcard && child.path === parent.path;
}

/**
 * Set containment: every child pattern must be contained by *some single*
 * parent pattern.
 *
 * This is sound but incomplete — a child pattern covered by the union of two
 * parent patterns is rejected even though it grants nothing new. Incompleteness
 * costs an issuer an awkward error message; unsoundness costs the principal
 * their balance. We take the trade.
 */
export function uriSetContains(parentPatterns: string[], childPatterns: string[]): boolean {
  const parents: UriPattern[] = [];
  for (const p of parentPatterns) {
    const parsed = parseUriPattern(p);
    if (parsed === null) return false;
    parents.push(parsed);
  }
  for (const c of childPatterns) {
    const parsed = parseUriPattern(c);
    if (parsed === null) return false;
    if (!parents.some((p) => uriPatternContains(p, parsed))) return false;
  }
  return true;
}

export function hostSetContains(parentPatterns: string[], childPatterns: string[]): boolean {
  const parents: HostPattern[] = [];
  for (const p of parentPatterns) {
    const parsed = parseHostPattern(p);
    if (parsed === null) return false;
    parents.push(parsed);
  }
  for (const c of childPatterns) {
    const parsed = parseHostPattern(c);
    if (parsed === null) return false;
    if (!parents.some((p) => hostPatternContains(p, parsed))) return false;
  }
  return true;
}

export function hostOfUri(canonicalUri: string): string | null {
  const m = /^[a-z0-9+.\-]+:\/\/([^/]+)\//.exec(canonicalUri);
  return m ? m[1]! : null;
}
