// The HTTP transport must answer MCP clients on this machine or across the
// network, and refuse what a web page can send: a cross-site POST or a
// DNS-rebinding request, both of which carry a foreign Origin. With
// MCP_HTTP_TOKEN set, /mcp also needs the bearer token. The app here is built
// the way runHTTP() in src/index.ts builds it, with one stub write tool on a
// fresh server per request, and requests go over a real socket so the headers
// are exactly what a client or browser would send.

import { test } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isLoopbackAddress, openListenerWarning, refuseForeignOrigins, requireBearerToken } from "../dist/http-guard.js";
import { parseAllowedOrigins } from "../dist/config/config.js";

async function startApp({ allowedOrigins = [], token } = {}) {
  let calls = 0;
  const createServer = () => {
    const server = new McpServer({ name: "test", version: "0.0.0" });
    server.registerTool("sophos_isolate_endpoint", { description: "stub", inputSchema: { id: z.string() } }, async ({ id }) => {
      calls++;
      return { content: [{ type: "text", text: `isolated ${id}` }] };
    });
    return server;
  };

  const app = express();
  app.use(refuseForeignOrigins(allowedOrigins));
  if (token) app.use("/mcp", requireBearerToken(token));
  app.use(express.json());
  app.post("/mcp", async (req, res) => {
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  app.get("/health", (_req, res) => {
    res.json({ status: "ok", server: "sophos-central-mcp-server" });
  });

  const listener = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => listener.on("listening", resolve));
  return { port: listener.address().port, calls: () => calls, close: () => listener.close() };
}

function send(port, { method = "POST", path = "/mcp", headers = {} } = {}) {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "sophos_isolate_endpoint", arguments: { id: "victim" } },
  });
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path, method, headers: { Accept: "application/json, text/event-stream", ...headers } },
      (res) => {
        let text = "";
        res.on("data", (chunk) => (text += chunk));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text }));
      }
    );
    req.on("error", reject);
    req.end(method === "POST" ? body : undefined);
  });
}

const post = (port, headers) => send(port, { headers });

test("a cross-site POST with a text/plain body is refused before any tool runs", async () => {
  const app = await startApp();
  try {
    const res = await post(app.port, {
      Host: `127.0.0.1:${app.port}`,
      Origin: "https://attacker.example",
      "Content-Type": "text/plain;charset=application/json",
    });
    assert.equal(res.status, 403);
    assert.match(JSON.parse(res.text).error.message, /MCP_ALLOWED_ORIGINS/);
    assert.equal(app.calls(), 0);
  } finally {
    app.close();
  }
});

test("a DNS-rebinding request is refused by its foreign Origin", async () => {
  const app = await startApp();
  try {
    const res = await post(app.port, {
      Host: `attacker.example:${app.port}`,
      Origin: `http://attacker.example:${app.port}`,
      "Content-Type": "application/json",
    });
    assert.equal(res.status, 403);
    assert.equal(app.calls(), 0);
  } finally {
    app.close();
  }
});

test("an opaque null Origin is refused", async () => {
  const app = await startApp();
  try {
    const res = await post(app.port, { Host: `127.0.0.1:${app.port}`, Origin: "null", "Content-Type": "application/json" });
    assert.equal(res.status, 403);
    assert.equal(app.calls(), 0);
  } finally {
    app.close();
  }
});

test("local MCP clients get through, with no Origin or a loopback one", async () => {
  const app = await startApp();
  try {
    for (const host of [`127.0.0.1:${app.port}`, `localhost:${app.port}`, `[::1]:${app.port}`]) {
      const res = await post(app.port, { Host: host, "Content-Type": "application/json" });
      assert.equal(res.status, 200, host);
    }
    for (const origin of ["http://localhost:6274", "http://127.0.0.1:6274", "http://[::1]:6274"]) {
      const res = await post(app.port, { Host: `localhost:${app.port}`, Origin: origin, "Content-Type": "application/json" });
      assert.equal(res.status, 200, origin);
    }
    assert.equal(app.calls(), 6);
  } finally {
    app.close();
  }
});

test("MCP clients on other machines get through whatever Host they send", async () => {
  const app = await startApp();
  try {
    for (const host of [`192.168.1.20:${app.port}`, `100.105.82.70:${app.port}`, `mcp.lan:${app.port}`, `[fd7a:115c:a1e0::1]:${app.port}`]) {
      const res = await post(app.port, { Host: host, "Content-Type": "application/json" });
      assert.equal(res.status, 200, host);
    }
    assert.equal(app.calls(), 4);
  } finally {
    app.close();
  }
});

test("an Origin listed in MCP_ALLOWED_ORIGINS gets through and no other does", async () => {
  const app = await startApp({ allowedOrigins: parseAllowedOrigins(" https://inspector.example.com, http://10.0.0.5:6274/ ,") });
  try {
    for (const origin of ["https://inspector.example.com", "http://10.0.0.5:6274"]) {
      const res = await post(app.port, { Host: `10.0.0.9:${app.port}`, Origin: origin, "Content-Type": "application/json" });
      assert.equal(res.status, 200, origin);
    }
    for (const origin of ["https://inspector.example.com:8443", "http://inspector.example.com", "http://10.0.0.5:6275", "https://attacker.example"]) {
      const res = await post(app.port, { Host: `10.0.0.9:${app.port}`, Origin: origin, "Content-Type": "application/json" });
      assert.equal(res.status, 403, origin);
    }
    assert.equal(app.calls(), 2);
  } finally {
    app.close();
  }
});

test("MCP_ALLOWED_ORIGINS entries are reduced to origins and bad ones are refused", () => {
  assert.deepEqual(parseAllowedOrigins(undefined), []);
  assert.deepEqual(parseAllowedOrigins(""), []);
  assert.deepEqual(parseAllowedOrigins("https://a.example/some/path,HTTP://B.example:80"), ["https://a.example", "http://b.example"]);
  for (const bad of ["not a url", "null", "file:///etc/passwd", "*"]) {
    assert.throws(() => parseAllowedOrigins(bad), /MCP_ALLOWED_ORIGINS/, bad);
  }
});

test("with a token set, /mcp needs the right bearer token and /health stays open", async () => {
  const token = "correct-horse-battery-staple";
  const app = await startApp({ token });
  try {
    const missing = await post(app.port, { "Content-Type": "application/json" });
    assert.equal(missing.status, 401);
    assert.equal(missing.headers["www-authenticate"], "Bearer");
    const body = JSON.parse(missing.text);
    assert.equal(body.jsonrpc, "2.0");
    assert.equal(body.error.code, -32000);
    assert.match(body.error.message, /MCP_HTTP_TOKEN/);
    assert.doesNotMatch(missing.text, new RegExp(token));

    for (const authorization of [`Bearer ${token}x`, "Bearer wrong", `Basic ${token}`, token, "Bearer "]) {
      const res = await post(app.port, { Authorization: authorization, "Content-Type": "application/json" });
      assert.equal(res.status, 401, authorization);
    }
    assert.equal(app.calls(), 0);

    const right = await post(app.port, { Host: `192.168.1.20:${app.port}`, Authorization: `Bearer ${token}`, "Content-Type": "application/json" });
    assert.equal(right.status, 200);
    const lowerScheme = await post(app.port, { Authorization: `bearer ${token}`, "Content-Type": "application/json" });
    assert.equal(lowerScheme.status, 200);
    assert.equal(app.calls(), 2);

    const health = await send(app.port, { method: "GET", path: "/health" });
    assert.equal(health.status, 200);
  } finally {
    app.close();
  }
});

test("the Origin check still applies when the token is right", async () => {
  const token = "correct-horse-battery-staple";
  const app = await startApp({ token });
  try {
    const res = await post(app.port, { Authorization: `Bearer ${token}`, Origin: "https://attacker.example", "Content-Type": "application/json" });
    assert.equal(res.status, 403);
    assert.equal(app.calls(), 0);
  } finally {
    app.close();
  }
});

test("with no token set, requests need no Authorization header and any sent is ignored", async () => {
  const app = await startApp();
  try {
    const none = await post(app.port, { "Content-Type": "application/json" });
    assert.equal(none.status, 200);
    const stray = await post(app.port, { Authorization: "Bearer anything", "Content-Type": "application/json" });
    assert.equal(stray.status, 200);
    assert.equal(app.calls(), 2);
  } finally {
    app.close();
  }
});

test("the open-listener warning fires only off loopback with no token", () => {
  for (const address of ["127.0.0.1", "127.0.1.1", "::1", "::ffff:127.0.0.1"]) {
    assert.equal(isLoopbackAddress(address), true, address);
    assert.equal(openListenerWarning(address, false), undefined, address);
  }
  for (const address of ["0.0.0.0", "::", "192.168.1.20", "100.105.82.70"]) {
    assert.equal(isLoopbackAddress(address), false, address);
    assert.match(openListenerWarning(address, false), /WARNING: listening on .* with no MCP_HTTP_TOKEN/, address);
    assert.equal(openListenerWarning(address, true), undefined, address);
  }
});
