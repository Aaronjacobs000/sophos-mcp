/**
 * Request checks for the HTTP transport.
 *
 * The server is meant to be reached by MCP clients, on this machine or across
 * the network, so the Host header is not checked: a client on another machine
 * sends the server's own address or name there. What it must keep out is a web
 * page in someone's browser. A page can reach the server two ways: a cross-site
 * POST (a text/plain body with "application/json" in a parameter passes the
 * SDK's content-type check without a CORS preflight) and DNS rebinding (the
 * attacker's hostname re-resolves to the server, so the page can also read the
 * response). Browsers send an Origin header on every POST, and in both cases it
 * names the attacker's site, so refuseForeignOrigins answers a request only when
 * it has no Origin (MCP clients that are not browsers send none), a loopback
 * Origin, or one listed in MCP_ALLOWED_ORIGINS.
 *
 * requireBearerToken is the opt-in shared secret (MCP_HTTP_TOKEN) for a server
 * that other machines can reach.
 *
 * MAX_MCP_MESSAGE_BYTES is the /mcp body limit. It matches the SDK's stdio
 * message cap (STDIO_DEFAULT_MAX_BUFFER_SIZE), so a tool call that fits on one
 * transport fits on the other. refusePayloadTooLarge answers a body over it,
 * refuseMalformedJson a body that is not JSON, and refuseUnreadableBody every
 * other body parser error, all as JSON-RPC errors instead of Express's HTML
 * error page, which carries a stack trace.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { STATUS_CODES } from "node:http";
import type { ErrorRequestHandler, NextFunction, Request, RequestHandler, Response } from "express";

/** 10 MiB: the largest JSON-RPC message /mcp accepts, the same as stdio. */
export const MAX_MCP_MESSAGE_BYTES = 10 * 1024 * 1024;

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopbackOrigin(origin: string): boolean {
  try {
    return LOOPBACK_HOSTNAMES.has(new URL(origin).hostname);
  } catch {
    return false;
  }
}

function jsonRpcError(res: Response, status: number, message: string, code = -32000): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code, message }, id: null });
}

export function refuseForeignOrigins(allowedOrigins: string[]): RequestHandler {
  const allowed = new Set(allowedOrigins);
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;
    if (origin === undefined || isLoopbackOrigin(origin) || allowed.has(origin)) {
      next();
      return;
    }
    jsonRpcError(
      res,
      403,
      `Forbidden: browser requests from Origin "${origin}" are refused. Add it to MCP_ALLOWED_ORIGINS (comma separated) to allow it.`
    );
  };
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

export function requireBearerToken(token: string): RequestHandler {
  // Hashing both sides gives equal length buffers, so the compare is constant time
  const expected = sha256(token);
  return (req: Request, res: Response, next: NextFunction): void => {
    const presented = /^Bearer +(.+)$/i.exec(req.headers.authorization ?? "")?.[1];
    if (presented !== undefined && timingSafeEqual(sha256(presented), expected)) {
      next();
      return;
    }
    res.set("WWW-Authenticate", "Bearer");
    jsonRpcError(res, 401, "Unauthorized: send the MCP_HTTP_TOKEN value as an \"Authorization: Bearer <token>\" header.");
  };
}

/** Turns the body parser's 413 into a JSON-RPC error; other errors pass through. */
export const refusePayloadTooLarge: ErrorRequestHandler = (error, _req, res, next) => {
  if ((error as { type?: unknown })?.type !== "entity.too.large") {
    next(error);
    return;
  }
  jsonRpcError(
    res,
    413,
    `Payload Too Large: the request body is over the ${MAX_MCP_MESSAGE_BYTES} byte limit. For a large case file, use file_path.`
  );
};

/** Turns the body parser's JSON syntax error into a JSON-RPC parse error (-32700); other errors pass through. */
export const refuseMalformedJson: ErrorRequestHandler = (error, _req, res, next) => {
  if ((error as { type?: unknown })?.type !== "entity.parse.failed") {
    next(error);
    return;
  }
  // The SDK's wording for the same case when it parses the body itself
  jsonRpcError(res, 400, "Parse error: Invalid JSON", -32700);
};

/**
 * Answers every other body parser error as a JSON-RPC error with the parser's status: a body that does not
 * decompress (400), an unsupported Content-Encoding or charset (415). A status that is not a client error becomes
 * a 500 with no detail. Mounted last before the /mcp route, so it never passes an error on.
 */
export const refuseUnreadableBody: ErrorRequestHandler = (error, req, res, _next) => {
  const { status, type, encoding, charset } = (error ?? {}) as Record<string, unknown>;
  if (type === "encoding.unsupported") {
    jsonRpcError(res, 415, `Unsupported Media Type: Content-Encoding "${String(encoding)}" is not supported. Use gzip, deflate, br or none.`);
  } else if (type === "charset.unsupported") {
    jsonRpcError(res, 415, `Unsupported Media Type: charset "${String(charset)}" is not supported. Use UTF-8.`);
  } else if (typeof status === "number" && status >= 400 && status < 500) {
    const contentEncoding = req.headers["content-encoding"];
    const as = contentEncoding && contentEncoding !== "identity" ? ` as Content-Encoding "${contentEncoding}"` : "";
    jsonRpcError(res, status, `${STATUS_CODES[status] ?? "Bad Request"}: the request body could not be read${as}.`);
  } else {
    jsonRpcError(res, 500, "Internal error: the request body could not be read.", -32603);
  }
};

export function isLoopbackAddress(address: string): boolean {
  return address.startsWith("127.") || address === "::1" || address.toLowerCase().startsWith("::ffff:127.");
}

/** The one line printed when the listener is reachable from other machines and has no token. */
export function openListenerWarning(address: string, tokenSet: boolean): string | undefined {
  if (tokenSet || isLoopbackAddress(address)) return undefined;
  return `[sophos-mcp] WARNING: listening on ${address} with no MCP_HTTP_TOKEN. Anyone who can reach this port can use the tools with your Sophos credentials. Set MCP_HTTP_TOKEN, and put TLS in front (a reverse proxy or Tailscale).`;
}
