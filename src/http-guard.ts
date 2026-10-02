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
 */

import { createHash, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopbackOrigin(origin: string): boolean {
  try {
    return LOOPBACK_HOSTNAMES.has(new URL(origin).hostname);
  } catch {
    return false;
  }
}

function jsonRpcError(res: Response, status: number, message: string): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code: -32000, message }, id: null });
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

export function isLoopbackAddress(address: string): boolean {
  return address.startsWith("127.") || address === "::1" || address.toLowerCase().startsWith("::ffff:127.");
}

/** The one line printed when the listener is reachable from other machines and has no token. */
export function openListenerWarning(address: string, tokenSet: boolean): string | undefined {
  if (tokenSet || isLoopbackAddress(address)) return undefined;
  return `[sophos-mcp] WARNING: listening on ${address} with no MCP_HTTP_TOKEN. Anyone who can reach this port can use the tools with your Sophos credentials. Set MCP_HTTP_TOKEN, and put TLS in front (a reverse proxy or Tailscale).`;
}
