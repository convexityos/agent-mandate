/**
 * RFC 8941 Structured Field Values — the subset this protocol uses.
 *
 * Supported: Dictionaries, whose values are Tokens, Strings, Integers,
 * Booleans, Byte Sequences, or Inner Lists of those; parameters on both members
 * and inner-list items.
 *
 * Not supported: Decimals, Dates, Display Strings, and bare Lists. Parsing
 * rejects them rather than coercing — a header this protocol did not emit should
 * not silently become one it understands.
 */

export type SfBare =
  | { t: 'token'; v: string }
  | { t: 'string'; v: string }
  | { t: 'int'; v: number }
  | { t: 'bool'; v: boolean }
  | { t: 'bytes'; v: Buffer };

export interface SfInnerList {
  t: 'inner';
  v: SfItem[];
  params: SfParams;
}

export interface SfItem {
  value: SfBare;
  params: SfParams;
}

export type SfParams = Map<string, SfBare>;
export type SfMember = SfItem | SfInnerList;
export type SfDictionary = Map<string, SfMember>;

const TOKEN_RE = /^[a-zA-Z*][a-zA-Z0-9:/!#$%&'*+\-.^_`|~]*$/;
const KEY_RE = /^[a-z*][a-z0-9_\-.*]*$/;

export const tok = (v: string): SfBare => ({ t: 'token', v });
export const str = (v: string): SfBare => ({ t: 'string', v });
export const int = (v: number): SfBare => ({ t: 'int', v });
export const bool = (v: boolean): SfBare => ({ t: 'bool', v });
export const bytes = (v: Buffer): SfBare => ({ t: 'bytes', v });

export const item = (value: SfBare, params: SfParams = new Map()): SfItem => ({ value, params });
export const inner = (v: SfItem[], params: SfParams = new Map()): SfInnerList => ({
  t: 'inner',
  v,
  params,
});

// ---------------------------------------------------------------- serializing

function serializeBare(b: SfBare): string {
  switch (b.t) {
    case 'token':
      if (!TOKEN_RE.test(b.v)) throw new Error(`invalid token: ${b.v}`);
      return b.v;
    case 'string':
      return `"${b.v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
    case 'int':
      if (!Number.isInteger(b.v) || Math.abs(b.v) > 999_999_999_999_999) {
        throw new Error(`invalid integer: ${b.v}`);
      }
      return String(b.v);
    case 'bool':
      return b.v ? '?1' : '?0';
    case 'bytes':
      return `:${b.v.toString('base64')}:`;
  }
}

function serializeParams(p: SfParams): string {
  let out = '';
  for (const [k, v] of p) {
    if (!KEY_RE.test(k)) throw new Error(`invalid parameter key: ${k}`);
    out += v.t === 'bool' && v.v ? `;${k}` : `;${k}=${serializeBare(v)}`;
  }
  return out;
}

function serializeMember(m: SfMember): string {
  if ('t' in m && m.t === 'inner') {
    return `(${m.v.map((i) => serializeBare(i.value) + serializeParams(i.params)).join(' ')})${serializeParams(m.params)}`;
  }
  const i = m as SfItem;
  return serializeBare(i.value) + serializeParams(i.params);
}

export function serializeDictionary(dict: SfDictionary): string {
  const parts: string[] = [];
  for (const [k, m] of dict) {
    if (!KEY_RE.test(k)) throw new Error(`invalid dictionary key: ${k}`);
    // A true Boolean member is written bare, per RFC 8941 §4.1.2.
    if (!('t' in m) && (m as SfItem).value.t === 'bool' && (m as SfItem).value.v === true) {
      parts.push(k + serializeParams((m as SfItem).params));
    } else {
      parts.push(`${k}=${serializeMember(m)}`);
    }
  }
  return parts.join(', ');
}

// ------------------------------------------------------------------- parsing

class Cursor {
  constructor(
    readonly s: string,
    public i = 0,
  ) {}
  get eof(): boolean {
    return this.i >= this.s.length;
  }
  peek(): string | undefined {
    return this.s[this.i];
  }
  ws(): void {
    while (this.i < this.s.length && (this.s[this.i] === ' ' || this.s[this.i] === '\t')) this.i++;
  }
  sp(): void {
    while (this.s[this.i] === ' ') this.i++;
  }
}

function parseBare(c: Cursor): SfBare | null {
  const ch = c.peek();
  if (ch === undefined) return null;

  if (ch === '"') {
    c.i++;
    let out = '';
    while (!c.eof) {
      const x = c.s[c.i++]!;
      if (x === '\\') {
        const esc = c.s[c.i++];
        if (esc !== '"' && esc !== '\\') return null;
        out += esc;
      } else if (x === '"') {
        return str(out);
      } else if (x < ' ' || x > '~') {
        return null;
      } else {
        out += x;
      }
    }
    return null;
  }

  if (ch === '?') {
    c.i++;
    const x = c.s[c.i++];
    if (x === '0') return bool(false);
    if (x === '1') return bool(true);
    return null;
  }

  if (ch === ':') {
    c.i++;
    const end = c.s.indexOf(':', c.i);
    if (end === -1) return null;
    const b64 = c.s.slice(c.i, end);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return null;
    c.i = end + 1;
    return bytes(Buffer.from(b64, 'base64'));
  }

  if (ch === '-' || (ch >= '0' && ch <= '9')) {
    const start = c.i;
    if (ch === '-') c.i++;
    while (!c.eof && c.s[c.i]! >= '0' && c.s[c.i]! <= '9') c.i++;
    // Decimals are out of the supported subset; reject rather than truncate.
    if (c.s[c.i] === '.') return null;
    const raw = c.s.slice(start, c.i);
    if (raw === '' || raw === '-') return null;
    return int(Number(raw));
  }

  const start = c.i;
  while (!c.eof && TOKEN_RE.test(c.s.slice(start, c.i + 1))) c.i++;
  if (c.i === start) return null;
  return tok(c.s.slice(start, c.i));
}

function parseParams(c: Cursor): SfParams | null {
  const params: SfParams = new Map();
  while (c.s[c.i] === ';') {
    c.i++;
    c.sp();
    const start = c.i;
    while (!c.eof && KEY_RE.test(c.s.slice(start, c.i + 1))) c.i++;
    const key = c.s.slice(start, c.i);
    if (key === '') return null;
    if (c.s[c.i] === '=') {
      c.i++;
      const v = parseBare(c);
      if (v === null) return null;
      params.set(key, v);
    } else {
      params.set(key, bool(true));
    }
  }
  return params;
}

function parseMember(c: Cursor): SfMember | null {
  if (c.peek() === '(') {
    c.i++;
    const items: SfItem[] = [];
    for (;;) {
      c.sp();
      if (c.peek() === ')') {
        c.i++;
        break;
      }
      const v = parseBare(c);
      if (v === null) return null;
      const p = parseParams(c);
      if (p === null) return null;
      items.push({ value: v, params: p });
      if (c.peek() !== ' ' && c.peek() !== ')') return null;
    }
    const p = parseParams(c);
    return p === null ? null : inner(items, p);
  }
  const v = parseBare(c);
  if (v === null) return null;
  const p = parseParams(c);
  return p === null ? null : { value: v, params: p };
}

export function parseDictionary(input: string): SfDictionary | null {
  const c = new Cursor(input);
  const dict: SfDictionary = new Map();
  c.ws();
  if (c.eof) return dict;

  for (;;) {
    const start = c.i;
    while (!c.eof && KEY_RE.test(c.s.slice(start, c.i + 1))) c.i++;
    const key = c.s.slice(start, c.i);
    if (key === '') return null;

    if (c.peek() === '=') {
      c.i++;
      const m = parseMember(c);
      if (m === null) return null;
      dict.set(key, m);
    } else {
      const p = parseParams(c);
      if (p === null) return null;
      dict.set(key, { value: bool(true), params: p });
    }

    c.ws();
    if (c.eof) return dict;
    if (c.peek() !== ',') return null;
    c.i++;
    c.ws();
    if (c.eof) return null; // trailing comma
  }
}

// ------------------------------------------------------------------ accessors

export function asString(m: SfMember | undefined): string | null {
  if (m === undefined || 't' in m) return null;
  const v = (m as SfItem).value;
  return v.t === 'string' || v.t === 'token' ? String(v.v) : null;
}

export function asInt(m: SfMember | undefined): number | null {
  if (m === undefined || 't' in m) return null;
  const v = (m as SfItem).value;
  return v.t === 'int' ? v.v : null;
}

export function asBytes(m: SfMember | undefined): Buffer | null {
  if (m === undefined || 't' in m) return null;
  const v = (m as SfItem).value;
  return v.t === 'bytes' ? v.v : null;
}

export function asStringList(m: SfMember | undefined): string[] | null {
  if (m === undefined || !('t' in m) || m.t !== 'inner') return null;
  const out: string[] = [];
  for (const i of m.v) {
    if (i.value.t !== 'string' && i.value.t !== 'token') return null;
    out.push(String(i.value.v));
  }
  return out;
}
