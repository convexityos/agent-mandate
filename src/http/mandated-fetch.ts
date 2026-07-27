import type { Effect } from '../caveats.js';
import type { ErrorCode } from '../errors.js';
import type { Ledger } from '../ledger/ledger.js';
import type { Money } from '../money.js';
import type { AgentKey } from '../sign.js';
import { type PaidResponse, payAndRetry } from './client.js';
import type { Challenge } from './headers.js';
import { PROBLEM_CONTENT_TYPE, problem } from './problem.js';
import { type SignableRequest, signRequest, verifyRequestSignature } from './signature.js';

/**
 * §2.2 — `mandatedFetch`.
 *
 * [`payAndRetry`](./client.ts) has had the whole loop for as long as the HTTP
 * binding has existed. Nobody wants to assemble it. Merchant-side conformance is
 * five checks by design; agent-side should be one import.
 *
 * ```ts
 * const fetch = mandatedFetch({ tokens, key, mint: localMint(ledger) });
 * const res = await fetch('https://api.weatherco.com/v3/forecast/94110');
 * ```
 *
 * ## A refusal is a Response, not an exception
 *
 * When the mandate says no — budget exhausted, resource outside the grant, a
 * human needed — this returns a normal `Response` carrying RFC 9457 problem
 * details. It does not throw.
 *
 * That is the whole point of being drop-in. Code that already handles `fetch`
 * handles this, and an agent that wraps its calls in `try/catch` does not
 * silently convert "your principal said no" into a retry loop. A thrown
 * exception is one stray `catch` away from being swallowed, and the thing being
 * swallowed here is a spending control.
 *
 * Network failures still throw, because those are what `fetch` throws on and a
 * drop-in that changed that would be a different function.
 */

// ------------------------------------------------------------------- minting

export interface MintRequest {
  tokens: string[];
  resource: string;
  amount: Money;
  quote: { quoteId: string; schema?: string };
  presenterJkt: string;
  idempotencyKey: string;
  taskId?: string;
  purpose?: string;
  effect?: Effect;
}

export type MintResult =
  | { ok: true; token: string; spendId: string }
  | { ok: false; code: ErrorCode; detail: string; stepUpHandle?: string };

/** Where a spend token comes from. In-process or over the wire. */
export interface MintSource {
  mint(req: MintRequest): Promise<MintResult>;
}

/** Mint against a `Ledger` in this process. */
export function localMint(ledger: Ledger): MintSource {
  return {
    async mint(req) {
      const r = await ledger.reserve({
        tokens: req.tokens,
        presenterJkt: req.presenterJkt,
        idempotencyKey: req.idempotencyKey,
        quote: {
          quoteId: req.quote.quoteId,
          ...(req.quote.schema !== undefined ? { schema: req.quote.schema } : {}),
        },
        request: {
          resource: req.resource,
          amount: req.amount,
          ...(req.taskId !== undefined ? { taskId: req.taskId } : {}),
          ...(req.purpose !== undefined ? { purpose: req.purpose } : {}),
          ...(req.effect !== undefined ? { effect: req.effect } : {}),
        },
      });
      return r.ok
        ? { ok: true, token: r.token, spendId: r.spendId }
        : {
            ok: false,
            code: r.code,
            detail: r.detail,
            ...(r.stepUpHandle !== undefined ? { stepUpHandle: r.stepUpHandle } : {}),
          };
    },
  };
}

export interface RemoteMintOptions {
  /** Base URL of a `LedgerService`, e.g. `https://ledger.internal/ledger`. */
  url: string;
  /** Signs the mint request so the ledger can check §7 step 9. */
  key: AgentKey;
  fetch?: typeof fetch;
  clock?: () => number;
}

/**
 * Mint against a remote `LedgerService`.
 *
 * The request is signed with RFC 9421 so the ledger can resolve a presenter —
 * §7 step 9 binds the chain to the key that presents it, and a ledger that
 * accepted an unsigned mint would honour a chain from anyone who copied it.
 * Pair with `rfc9421Presenter()` on the service.
 */
export function remoteMint(opts: RemoteMintOptions): MintSource {
  const call = opts.fetch ?? globalThis.fetch;
  const clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
  const base = opts.url.replace(/\/$/, '');

  return {
    async mint(req) {
      const url = `${base}/v1/mint`;
      const body = JSON.stringify({
        tokens: req.tokens,
        request: {
          resource: req.resource,
          amount: req.amount,
          ...(req.taskId !== undefined ? { taskId: req.taskId } : {}),
          ...(req.purpose !== undefined ? { purpose: req.purpose } : {}),
          ...(req.effect !== undefined ? { effect: req.effect } : {}),
        },
        quote: req.quote,
      });

      const sigs = signRequest(
        { method: 'POST', url, headers: {} },
        { key: opts.key, created: clock(), components: ['@method', '@target-uri'] },
      );

      const res = await call(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'idempotency-key': req.idempotencyKey, ...sigs },
        body,
      });

      const payload = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (res.ok) {
        return {
          ok: true,
          token: payload['token'] as string,
          spendId: payload['spendId'] as string,
        };
      }
      return {
        ok: false,
        code: (payload['code'] as ErrorCode) ?? 'chain_invalid',
        detail: (payload['detail'] as string) ?? `ledger returned ${res.status}`,
        ...(typeof payload['stepUpHandle'] === 'string'
          ? { stepUpHandle: payload['stepUpHandle'] }
          : {}),
      };
    },
  };
}

/**
 * A `resolvePresenter` for `LedgerService` that verifies an RFC 9421 signature.
 *
 * Covers `@method` and `@target-uri` by default, which proves possession of the
 * key and nothing about the body. That is what §7 step 9 needs — the binding is
 * to `cnf.jkt`, and the chain in the body is self-authenticating — but a
 * deployment that wants the mint parameters covered too should require
 * `content-digest` here and have its client send one.
 */
export function rfc9421Presenter(
  options: { clock?: () => number; requiredComponents?: readonly string[] } = {},
): (req: { method: string; path: string; headers?: Record<string, string | string[] | undefined>; query?: Record<string, string | undefined> }) => string | null {
  const clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
  const required = options.requiredComponents ?? ['@method', '@target-uri'];

  return (req) => {
    const headers = req.headers ?? {};
    const host = (Array.isArray(headers['host']) ? headers['host'][0] : headers['host']) ?? 'localhost';
    const signable: SignableRequest = {
      method: req.method,
      // Reconstructed rather than taken from a header: `@target-uri` is what was
      // signed, and trusting a client-supplied absolute URL here would let a
      // signature made for one target be replayed against another.
      url: `http://${host}${req.path}`,
      headers,
    };
    const result = verifyRequestSignature(signable, { now: clock(), requiredComponents: required });
    return result.ok ? result.jkt : null;
  };
}

// --------------------------------------------------------------------- fetch

export interface MandatedFetchOptions {
  /** The mandate chain every call under this client spends against. */
  tokens: string[];
  /** Holder key for the chain's leaf. Signs the paid retry (§14). */
  key: AgentKey;
  mint: MintSource;
  /** Defaults to the global. Injectable so tests and proxies can wrap it. */
  fetch?: typeof fetch;
  clock?: () => number;
  taskId?: string;
  purpose?: string;
  effect?: Effect;
}

/** Set on every refusal this client synthesizes, so it is not mistaken for the merchant's. */
export const REFUSAL_HEADER = 'x-am-refusal';

/** The §15 code, when a response is a refusal by the mandate rather than by the merchant. */
export function refusalCode(res: Response): ErrorCode | null {
  return (res.headers.get(REFUSAL_HEADER) as ErrorCode | null) ?? null;
}

function refusal(code: ErrorCode, detail: string, extra: Record<string, unknown> = {}): Response {
  const p = problem(code, detail, extra);
  return new Response(JSON.stringify(p), {
    status: p.status,
    headers: { 'content-type': PROBLEM_CONTENT_TYPE, [REFUSAL_HEADER]: code },
  });
}

const headerRecord = (h: Headers): Record<string, string> => Object.fromEntries(h.entries());

/**
 * A drop-in `fetch` that pays for what it asks for.
 *
 * Handles 402 → present → mint → sign → retry, exactly once. A second 402 after
 * paying means the price moved or the token was rejected, and looping on that is
 * how an agent spends a budget on nothing.
 */
export function mandatedFetch(opts: MandatedFetchOptions): typeof fetch {
  const call = opts.fetch ?? globalThis.fetch;
  const clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));

  // Derived from `fetch` rather than written out: `RequestInfo` is a DOM type
  // and this package compiles without the DOM lib, so naming it directly would
  // tie the signature to a lib the library does not require.
  type FetchInput = Parameters<typeof fetch>[0];
  type FetchInit = Parameters<typeof fetch>[1];

  return async (input: FetchInput, init?: FetchInit): Promise<Response> => {
    const request = new Request(input as string, init);

    // Buffered up front because the retry has to send the same body, and a
    // stream can only be read once. A drop-in that lost the body on the paid
    // attempt would work for GETs and silently corrupt every POST.
    const body = request.method === 'GET' || request.method === 'HEAD'
      ? undefined
      : new Uint8Array(await request.clone().arrayBuffer());

    const url = request.url;
    const headers = headerRecord(request.headers);

    const signable: SignableRequest = { method: request.method, url, headers };

    let refused: Response | null = null;
    // Per call, not per client: `payAndRetry` reduces a response to status and
    // headers, and the caller still needs a real Response with an intact body,
    // so the last one is kept here to be rebuilt. At module scope this would be
    // shared between concurrent callers, which is a data race that returns one
    // agent's purchase to another.
    let latest: { status: number; headers: Headers; buffer: ArrayBuffer } | null = null;

    const result = await payAndRetry(signable, async (req) => {
      const res = await call(req.url, {
        method: req.method,
        headers: req.headers as Record<string, string>,
        ...(body !== undefined ? { body } : {}),
        // Whatever the caller asked for. A drop-in that quietly changed redirect
        // handling would be a different function.
        redirect: request.redirect,
      });
      // Read once here, replayed below: a body can only be consumed once, and
      // `payAndRetry` needs the status while the caller needs the bytes.
      const buffer = await res.arrayBuffer();
      latest = { status: res.status, headers: res.headers, buffer };
      return { status: res.status, headers: headerRecord(res.headers) } satisfies PaidResponse;
    }, {
      key: opts.key,
      clock,
      reserve: async (challenge: Challenge) => {
        const minted = await opts.mint.mint({
          tokens: opts.tokens,
          resource: url,
          amount: challenge.amount,
          quote: {
            quoteId: challenge.quoteId,
            ...(challenge.schema !== undefined ? { schema: challenge.schema } : {}),
          },
          presenterJkt: opts.key.jkt,
          // Derived from the quote, and deliberately not from anything the
          // caller supplies.
          //
          // This makes the *mint* idempotent, which is what protects against a
          // retried or duplicated mint request — the failure the ledger's
          // §9 machinery exists for.
          //
          // It cannot make a whole-`fetch` retry idempotent, and nothing here
          // could. A caller that gives up and calls again gets a fresh 402 with
          // a fresh `quoteId`, which is a genuinely different purchase against
          // a genuinely different quote; replaying the earlier mint would hand
          // back a token bound to a quote the merchant has moved on from. The
          // abandoned reservation is cleaned up by expiry (§12), not by replay.
          idempotencyKey: `quote:${challenge.ledger}:${challenge.quoteId}`,
          ...(opts.taskId !== undefined ? { taskId: opts.taskId } : {}),
          ...(opts.purpose !== undefined ? { purpose: opts.purpose } : {}),
          ...(opts.effect !== undefined ? { effect: opts.effect } : {}),
        });

        if (minted.ok) return { ok: true, token: minted.token };
        refused = refusal(minted.code, minted.detail, {
          resource: url,
          amount: challenge.amount,
          ...(minted.stepUpHandle !== undefined ? { stepUpHandle: minted.stepUpHandle } : {}),
        });
        return { ok: false, detail: minted.detail };
      },
    });

    if (refused !== null) return refused;

    if (!result.ok) {
      // Not a mandate refusal: the merchant's challenge was unusable, or it
      // still wanted payment after being paid. Reported as such rather than
      // dressed up as a policy decision.
      return refusal('chain_invalid', result.detail, { resource: url });
    }

    if (latest === null) return refusal('chain_invalid', 'no response from the merchant');
    const { status, headers: h, buffer } = latest as {
      status: number;
      headers: Headers;
      buffer: ArrayBuffer;
    };
    // 204 and 304 must not carry a body, and constructing a Response with one
    // throws rather than being ignored.
    const hasBody = status !== 204 && status !== 304;
    return new Response(hasBody ? buffer : null, { status, headers: h });
  };
}
