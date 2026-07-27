import { type IncomingMessage, type Server, type ServerResponse, createServer } from 'node:http';

import type { ApprovalRequest, ApprovalResponse } from './approval.js';

/**
 * A `node:http` binding for the framework-agnostic handlers.
 *
 * Everything in this directory takes a parsed request and returns a status,
 * headers and a body, so it drops into Express, Hono or a Worker unchanged. This
 * is the small amount of glue that makes the same objects a runnable daemon,
 * which the ledger needs to be and a library is not.
 */

/** Anything with the shared `handle` shape: the ledger, approvals, the console. */
export interface Handler {
  handle(req: ApprovalRequest): Promise<ApprovalResponse>;
}

export interface HttpServeOptions {
  port: number;
  host?: string;
  /**
   * Tried in order; the first that does not 404 wins. Mount points are the
   * handlers' own `basePath`, so this is a list rather than a router.
   */
  handlers: Handler[];
  /**
   * Cap on request body size. A ledger accepts mandate chains from whoever can
   * reach it, and an unbounded body is the cheapest denial of service there is.
   */
  maxBodyBytes?: number;
  onError?: (err: unknown) => void;
}

const DEFAULT_MAX_BODY = 256 * 1024;

async function readBody(req: IncomingMessage, limit: number): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    // Bail on the chunk that crosses the limit rather than after buffering the
    // whole thing, which would make the limit decorative.
    if (size > limit) return null;
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function serve(opts: HttpServeOptions): Server {
  const limit = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
        const raw = await readBody(req, limit);
        if (raw === null) {
          res.writeHead(413, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'request body too large' }));
          return;
        }

        let body: unknown;
        if (raw !== '') {
          try {
            body = JSON.parse(raw);
          } catch {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'body is not valid JSON' }));
            return;
          }
        }

        const parsed: ApprovalRequest = {
          method: req.method ?? 'GET',
          path: url.pathname,
          query: Object.fromEntries(url.searchParams),
          headers: req.headers,
          ...(body !== undefined ? { body } : {}),
        };

        for (const handler of opts.handlers) {
          const out = await handler.handle(parsed);
          if (out.status === 404) continue;
          res.writeHead(out.status, out.headers);
          res.end(typeof out.body === 'string' ? out.body : JSON.stringify(out.body));
          return;
        }

        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
      } catch (err) {
        opts.onError?.(err);
        // Never the exception text: this runs on attacker-reachable input, and
        // a stack trace in a 500 is a free map of the deployment.
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'internal error' }));
        } else {
          res.end();
        }
      }
    })();
  });

  server.listen(opts.port, opts.host ?? '127.0.0.1');
  return server;
}
