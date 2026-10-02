// Runs the built entry point in HTTP mode against an in-memory Sophos (see
// fake-sophos-fetch.mjs) and checks runHTTP() in src/index.ts: overlapping tool
// calls all succeed, and the Origin guard, the MCP_HTTP_TOKEN check and the
// listen address log are wired in.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const fakeSophos = new URL("./fake-sophos-fetch.mjs", import.meta.url).href;

async function freePort() {
  const probe = createServer().listen(0, "127.0.0.1");
  await new Promise((resolve) => probe.on("listening", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

async function startServer(extraEnv = {}) {
  const port = await freePort();
  const env = {
    ...process.env,
    SOPHOS_CLIENT_ID: "test-id",
    SOPHOS_CLIENT_SECRET: "test-secret",
    TRANSPORT: "http",
    PORT: String(port),
    FAKE_SOPHOS_DELAY_MS: "300",
  };
  for (const name of ["SOPHOS_FUSION_GRAPHQL_URL", "MCP_HTTP_HOST", "MCP_HTTP_TOKEN", "MCP_ALLOWED_ORIGINS"]) delete env[name];
  Object.assign(env, extraEnv);
  const child = spawn(process.execPath, ["--import", fakeSophos, entry], { env, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start: ${stderr}`)), 15_000);
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (stderr.includes("HTTP server listening")) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on("exit", (code) => reject(new Error(`server exited with ${code}: ${stderr}`)));
  });
  // Give the lines printed right after the listen line time to arrive
  await new Promise((resolve) => setTimeout(resolve, 100));
  return { port, stderr: () => stderr, stop: () => child.kill() };
}

function callTool(port, id, headers = {}) {
  return fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "sophos_list_endpoints", arguments: {} } }),
  });
}

test("overlapping tool calls over HTTP all succeed", async () => {
  const server = await startServer();
  try {
    const responses = await Promise.all([1, 2, 3, 4].map((id) => callTool(server.port, id)));
    for (const res of responses) {
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.result?.isError, undefined, JSON.stringify(body));
      assert.match(body.result.content[0].text, /"count": 0/);
    }
  } finally {
    server.stop();
  }
});

test("the HTTP entry point refuses a foreign Origin", async () => {
  const server = await startServer();
  try {
    const res = await callTool(server.port, 1, { Origin: "https://attacker.example" });
    assert.equal(res.status, 403);
  } finally {
    server.stop();
  }
});

test("the HTTP entry point listens on 127.0.0.1 by default, with no warning", async () => {
  const server = await startServer();
  try {
    assert.match(server.stderr(), new RegExp(`HTTP server listening on http://127\\.0\\.0\\.1:${server.port}/mcp`));
    assert.doesNotMatch(server.stderr(), /WARNING/);
  } finally {
    server.stop();
  }
});

test("the HTTP entry point enforces MCP_HTTP_TOKEN and never prints it", async () => {
  const token = "entry-point-test-token-5f1c";
  const server = await startServer({ MCP_HTTP_TOKEN: token });
  try {
    assert.equal((await callTool(server.port, 1)).status, 401);
    assert.equal((await callTool(server.port, 2, { Authorization: "Bearer wrong" })).status, 401);
    const right = await callTool(server.port, 3, { Authorization: `Bearer ${token}` });
    assert.equal(right.status, 200);
    assert.match((await right.json()).result.content[0].text, /"count": 0/);
    assert.equal((await fetch(`http://127.0.0.1:${server.port}/health`)).status, 200);
    assert.doesNotMatch(server.stderr(), new RegExp(token));
  } finally {
    server.stop();
  }
});
