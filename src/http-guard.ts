/**
 * Keeps web pages away from the local HTTP transport.
 *
 * The server binds to 127.0.0.1 with no authentication, so the only callers it
 * should answer are local MCP clients. A browser can still reach it two ways:
 * a cross-site POST (a text/plain body with "application/json" in a parameter
 * passes the SDK's content-type check without a CORS preflight) and DNS
 * rebinding (the attacker's hostname re-resolves to 127.0.0.1, so the page can
 * also read the response). Both carry a foreign Origin, and rebinding carries
 * a foreign Host, so a request is refused unless its Host is a loopback name
 * and its Origin, when present, is one too. MCP clients that are not browsers
 * send no Origin.
 */

import type { NextFunction, Request, Response } from "express";

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopback(url: string): boolean {
  try {
    return LOOPBACK_HOSTNAMES.has(new URL(url).hostname);
  } catch {
    return false;
  }
}

export function localRequestsOnly(req: Request, res: Response, next: NextFunction): void {
  const host = req.headers.host;
  const origin = req.headers.origin;
  const hostOk = host !== undefined && isLoopback(`http://${host}`);
  const originOk = origin === undefined || isLoopback(origin);
  if (hostOk && originOk) {
    next();
    return;
  }
  res.status(403).json({
    jsonrpc: "2.0",
    error: {
      code: -32000,
      message: "Forbidden: this server only answers requests with a localhost Host and Origin",
    },
    id: null,
  });
}
