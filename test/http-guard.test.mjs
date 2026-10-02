// The HTTP transport must refuse requests a web page can make: a cross-site
// POST with a foreign Origin and a DNS-rebinding request with a foreign Host.
// The app here is built the way runHTTP() in src/index.ts builds it, with one
// stub write tool on a fresh server per request, and requests go over a real
// socket so the headers are exactly what a browser would send.

import { test } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { localRequestsOnly } from "../dist/http-guard.js";

async function startApp() {
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
  app.use(localRequestsOnly);
  app.use(express.json());
  app.post("/mcp", async (req, res) => {
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const listener = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => listener.on("listening", resolve));
  return { port: listener.address().port, calls: () => calls, close: () => listener.close() };
}

function post(port, headers) {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "sophos_isolate_endpoint", arguments: { id: "victim" } },
  });
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path: "/mcp", method: "POST", headers: { Accept: "application/json, text/event-stream", ...headers } },
      (res) => {
        let text = "";
        res.on("data", (chunk) => (text += chunk));
        res.on("end", () => resolve({ status: res.statusCode, text }));
      }
    );
    req.on("error", reject);
    req.end(body);
  });
}

test("a cross-site POST with a text/plain body is refused before any tool runs", async () => {
  const app = await startApp();
  try {
    const res = await post(app.port, {
      Host: `127.0.0.1:${app.port}`,
      Origin: "https://attacker.example",
      "Content-Type": "text/plain;charset=application/json",
    });
    assert.equal(res.status, 403);
    assert.equal(app.calls(), 0);
  } finally {
    app.close();
  }
});

test("a DNS-rebinding request with a foreign Host is refused", async () => {
  const app = await startApp();
  try {
    const res = await post(app.port, {
      Host: `attacker.example:${app.port}`,
      Origin: `http://attacker.example:${app.port}`,
      "Content-Type": "application/json",
    });
    assert.equal(res.status, 403);
    const noOrigin = await post(app.port, { Host: `attacker.example:${app.port}`, "Content-Type": "application/json" });
    assert.equal(noOrigin.status, 403);
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

test("local MCP clients still get through", async () => {
  const app = await startApp();
  try {
    for (const host of [`127.0.0.1:${app.port}`, `localhost:${app.port}`, `[::1]:${app.port}`]) {
      const res = await post(app.port, { Host: host, "Content-Type": "application/json" });
      assert.equal(res.status, 200, host);
    }
    const browserOnLocalhost = await post(app.port, {
      Host: `localhost:${app.port}`,
      Origin: "http://localhost:6274",
      "Content-Type": "application/json",
    });
    assert.equal(browserOnLocalhost.status, 200);
    assert.equal(app.calls(), 4);
  } finally {
    app.close();
  }
});
