import { describe, expect, it } from 'vitest';

import {
  canonicalizeUri,
  hostPatternContains,
  hostMatches,
  parseHostPattern,
  parseUriPattern,
  uriMatches,
  uriPatternContains,
  uriSetContains,
} from '../src/uri.js';

describe('canonicalizeUri', () => {
  it('lowercases scheme and host, strips default ports', () => {
    expect(canonicalizeUri('HTTPS://API.Example.COM:443/V3')).toBe('https://api.example.com/V3');
    expect(canonicalizeUri('http://x.test:80/a')).toBe('http://x.test/a');
    expect(canonicalizeUri('https://x.test:8443/a')).toBe('https://x.test:8443/a');
  });

  it('resolves dot segments', () => {
    expect(canonicalizeUri('https://x.test/v1/../../admin')).toBe('https://x.test/admin');
    expect(canonicalizeUri('https://x.test/a/./b')).toBe('https://x.test/a/b');
    expect(canonicalizeUri('https://x.test/a/b/..')).toBe('https://x.test/a/');
  });

  it('decodes percent-escaped dot segments BEFORE resolving them', () => {
    // The whole reason we do not use the WHATWG URL parser: it resolves first,
    // so %2E%2E survives normalization and re-expands downstream.
    expect(canonicalizeUri('https://x.test/v1/%2E%2E/%2E%2E/admin')).toBe('https://x.test/admin');
    expect(canonicalizeUri('https://x.test/v1/%2e%2e/admin')).toBe('https://x.test/admin');
  });

  it('rejects userinfo, IPv6 literals, and malformed input', () => {
    expect(canonicalizeUri('https://evil.test@good.test/a')).toBeNull();
    expect(canonicalizeUri('https://[::1]/a')).toBeNull();
    expect(canonicalizeUri('not a uri')).toBeNull();
    expect(canonicalizeUri('https:///a')).toBeNull();
  });

  it('drops query and fragment', () => {
    expect(canonicalizeUri('https://x.test/a?b=1#c')).toBe('https://x.test/a');
  });

  it('is idempotent', () => {
    for (const u of ['https://X.test/a/../b', 'http://y.test:80/', 'https://z.test/%7Euser']) {
      const once = canonicalizeUri(u)!;
      expect(canonicalizeUri(once)).toBe(once);
    }
  });
});

describe('host patterns', () => {
  const p = (s: string) => parseHostPattern(s)!;

  it('wildcard matches exactly one label', () => {
    expect(hostMatches(p('*.example.com'), 'api.example.com')).toBe(true);
    expect(hostMatches(p('*.example.com'), 'example.com')).toBe(false);
    expect(hostMatches(p('*.example.com'), 'a.b.example.com')).toBe(false);
  });

  it('containment', () => {
    expect(hostPatternContains(p('*.example.com'), p('api.example.com'))).toBe(true);
    expect(hostPatternContains(p('*.example.com'), p('*.example.com'))).toBe(true);
    // `*.x` matches one extra label; `*.y.x` matches two, so it is not contained.
    expect(hostPatternContains(p('*.example.com'), p('*.y.example.com'))).toBe(false);
    expect(hostPatternContains(p('api.example.com'), p('*.example.com'))).toBe(false);
    expect(hostPatternContains(p('api.example.com'), p('api.example.com'))).toBe(true);
  });

  it('rejects interior wildcards', () => {
    expect(parseHostPattern('a.*.example.com')).toBeNull();
    expect(parseHostPattern('*api.example.com')).toBeNull();
  });
});

describe('uri patterns', () => {
  const p = (s: string) => parseUriPattern(s)!;

  it('parses the wildcard forms', () => {
    expect(p('https://api.test/v3/forecast/*')).toMatchObject({
      scheme: 'https',
      host: 'api.test',
      hostWildcard: false,
      path: '/v3/forecast/',
      pathWildcard: true,
    });
    expect(p('https://api.test')).toMatchObject({ path: '/', pathWildcard: true });
    expect(p('https://*.test/a')).toMatchObject({ host: 'test', hostWildcard: true });
  });

  it('rejects regex-ish and multi-wildcard patterns', () => {
    expect(parseUriPattern('https://api.test/v[0-9]/*')).not.toBeNull(); // literal chars, no special meaning
    expect(uriMatches(p('https://api.test/v[0-9]/*'), 'https://api.test/v3/x')).toBe(false);
    expect(parseUriPattern('https://api.test/*/b*')).toBeNull();
    expect(parseUriPattern('https://*.*.test/a')).toBeNull();
  });

  it('prefix matching does not leak across sibling paths', () => {
    expect(uriMatches(p('https://api.test/v1/*'), 'https://api.test/v10/foo')).toBe(false);
    expect(uriMatches(p('https://api.test/v1/*'), 'https://api.test/v1/foo')).toBe(true);
  });

  it('exact-path parents contain only the identical child', () => {
    expect(uriPatternContains(p('https://api.test/a'), p('https://api.test/a'))).toBe(true);
    expect(uriPatternContains(p('https://api.test/a'), p('https://api.test/a*'))).toBe(false);
    expect(uriPatternContains(p('https://api.test/a*'), p('https://api.test/a/b'))).toBe(true);
  });

  it('set containment requires a single covering parent', () => {
    expect(
      uriSetContains(['https://api.test/v1/*'], ['https://api.test/v1/a', 'https://api.test/v1/b']),
    ).toBe(true);
    expect(uriSetContains(['https://api.test/v1/*'], ['https://api.test/v2/a'])).toBe(false);
    // Sound but incomplete: covered by the union, rejected anyway. Documented trade.
    expect(
      uriSetContains(['https://api.test/a*', 'https://api.test/b*'], ['https://api.test/*']),
    ).toBe(false);
  });
});
