import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  asInt,
  asString,
  asStringList,
  bool,
  bytes,
  inner,
  int,
  item,
  parseDictionary,
  serializeDictionary,
  str,
  tok,
  type SfDictionary,
  type SfMember,
} from '../src/http/sfv.js';
import { buildChallenge, parseChallenge, buildPayment, parsePayment } from '../src/http/headers.js';

describe('RFC 8941 dictionaries', () => {
  it('round-trips the shapes this protocol emits', () => {
    const entries: [string, SfMember][] = [
      ['scheme', item(tok('agent-mandate'))],
      ['v', item(int(1))],
      ['ledger', item(str('https://ledger.example.com'))],
      ['settle', inner([item(tok('immediate')), item(tok('escrow_schema'))])],
      ['flag', item(bool(true))],
      ['sig', item(bytes(Buffer.from('hello')))],
    ];
    const d: SfDictionary = new Map(entries);
    const s = serializeDictionary(d);
    expect(s).toContain('settle=(immediate escrow_schema)');
    expect(s).toContain('flag,'); // bare true

    const p = parseDictionary(s)!;
    expect(asString(p.get('scheme'))).toBe('agent-mandate');
    expect(asInt(p.get('v'))).toBe(1);
    expect(asStringList(p.get('settle'))).toEqual(['immediate', 'escrow_schema']);
    expect(serializeDictionary(p)).toBe(s);
  });

  it('escapes and recovers strings containing quotes and backslashes', () => {
    const s = serializeDictionary(new Map([['x', item(str('a"b\\c'))]]));
    expect(asString(parseDictionary(s)!.get('x'))).toBe('a"b\\c');
  });

  it('rejects malformed input rather than salvaging it', () => {
    for (const bad of [
      'a=',
      'a=1,',
      'a="unterminated',
      'a=(1 2',
      '=1',
      'a=1.5', // decimals are outside the supported subset
      'a=@nope',
      'a=:not_base64!:',
    ]) {
      expect(parseDictionary(bad)).toBeNull();
    }
  });

  it('parses an empty dictionary', () => {
    expect(parseDictionary('')?.size).toBe(0);
  });

  it('serialization is stable under re-parse', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.tuple(
            fc.stringMatching(/^[a-z][a-z0-9_-]{0,8}$/),
            fc.oneof(
              fc.integer({ min: -1000, max: 1000 }).map((n) => item(int(n))),
              fc.string({ minLength: 0, maxLength: 12 }).map((s) => item(str(s))),
              fc.boolean().map((b) => item(bool(b))),
            ),
          ),
          { minLength: 1, maxLength: 6 },
        ),
        (entries) => {
          const d: SfDictionary = new Map(entries);
          fc.pre(d.size === entries.length);
          const once = serializeDictionary(d);
          const reparsed = parseDictionary(once);
          expect(reparsed).not.toBeNull();
          expect(serializeDictionary(reparsed!)).toBe(once);
        },
      ),
      { numRuns: 500 },
    );
  });
});

describe('§14 headers', () => {
  it('round-trips a challenge', () => {
    const c = {
      scheme: 'agent-mandate',
      v: 1,
      ledger: 'https://ledger.example.com',
      quoteId: 'qt_abc',
      amount: { cur: 'USD', amt: '0.02' },
      settle: ['immediate' as const, 'escrow_schema' as const],
      schema: 'sha256:41bd',
      exp: 1770001294,
    };
    const parsed = parseChallenge(buildChallenge(c));
    expect(parsed).toEqual(c);
  });

  it('rejects a challenge advertising an unknown settlement mode', () => {
    const raw = buildChallenge({
      scheme: 'agent-mandate',
      v: 1,
      ledger: 'https://l.test',
      quoteId: 'q',
      amount: { cur: 'USD', amt: '1.00' },
      settle: ['immediate'],
      exp: 1,
    }).replace('(immediate)', '(immediate free_lunch)');
    expect(parseChallenge(raw)).toBeNull();
  });

  it('rejects a challenge from a different scheme', () => {
    expect(parseChallenge('scheme=x402, v=1')).toBeNull();
  });

  it('round-trips a payment header with a JWS in it', () => {
    const token = 'eyJhbGciOiJFZERTQSJ9.eyJhIjoxfQ.AAAA-_x';
    expect(parsePayment(buildPayment(token))?.token).toBe(token);
  });
});
