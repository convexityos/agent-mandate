/**
 * JSON-RPC 2.0, the subset MCP uses.
 *
 * Hand-rolled rather than taken from the MCP SDK for the same reason RFC 9421
 * and RFC 8941 are hand-rolled here: a gateway is mostly an opaque relay. It
 * inspects two methods and forwards everything else byte-for-byte, so almost
 * none of a client library's surface would be exercised, and the parts that
 * would be are a framer and five type guards.
 *
 * Forwarding unknown methods untouched is also what keeps the proxy honest as
 * the protocol grows: a message this file does not understand is not a message
 * it can silently mangle.
 */

export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: JsonRpcId;
  result: unknown;
}

export interface JsonRpcFailure {
  jsonrpc: '2.0';
  id: JsonRpcId;
  error: { code: number; message: string; data?: unknown };
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;
export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

/** JSON-RPC 2.0 §5.1. Application codes live at or above -32000. */
export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;

/**
 * Refusal by the mandate, as distinct from anything the upstream server did.
 *
 * A dedicated code so a client can tell "your budget said no" from "the tool
 * broke" without parsing prose. The `data` payload carries the `am/1` error code
 * so the two vocabularies stay linked.
 */
export const MANDATE_DENIED = -32001;

export function isRequest(m: JsonRpcMessage): m is JsonRpcRequest {
  return 'method' in m && 'id' in m;
}

export function isNotification(m: JsonRpcMessage): m is JsonRpcNotification {
  return 'method' in m && !('id' in m);
}

export function isResponse(m: JsonRpcMessage): m is JsonRpcResponse {
  return 'result' in m || 'error' in m;
}

/** Shallow structural check; deliberately not a schema validator. */
export function parseMessage(text: string): JsonRpcMessage | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const m = v as Record<string, unknown>;
  if (m['jsonrpc'] !== '2.0') return null;
  const hasMethod = typeof m['method'] === 'string';
  const hasOutcome = 'result' in m || 'error' in m;
  if (!hasMethod && !hasOutcome) return null;
  return v as JsonRpcMessage;
}

export function serializeMessage(m: JsonRpcMessage): string {
  // The stdio framing is newline-delimited, so a literal newline inside the
  // payload would split one message into two unparseable halves. `JSON.stringify`
  // escapes them in strings, and nothing else in JSON can produce one.
  return JSON.stringify(m);
}

export function errorResponse(
  id: JsonRpcId,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcFailure {
  return {
    jsonrpc: '2.0',
    id,
    error: { code, message, ...(data !== undefined ? { data } : {}) },
  };
}

/**
 * Reassembles newline-delimited messages from arbitrarily chunked input.
 *
 * A stdio pipe splits wherever it likes: mid-message, mid-multi-byte-character,
 * or several messages to a chunk. Decoding is done with a streaming decoder so a
 * UTF-8 sequence straddling a chunk boundary is held rather than replaced with
 * U+FFFD, which would corrupt the payload rather than fail it.
 */
export class LineFramer {
  private buffer = '';
  private readonly decoder = new TextDecoder('utf-8');

  push(chunk: Uint8Array | string): string[] {
    this.buffer +=
      typeof chunk === 'string' ? chunk : this.decoder.decode(chunk, { stream: true });

    const out: string[] = [];
    let nl = this.buffer.indexOf('\n');
    while (nl !== -1) {
      const line = this.buffer.slice(0, nl).replace(/\r$/, '');
      this.buffer = this.buffer.slice(nl + 1);
      if (line.trim() !== '') out.push(line);
      nl = this.buffer.indexOf('\n');
    }
    return out;
  }
}

export const encodeLine = (m: JsonRpcMessage): string => `${serializeMessage(m)}\n`;
