// Runs the built entry point in HTTP mode against an in-memory Sophos (see
// fake-sophos-fetch.mjs) and checks runHTTP() in src/index.ts: overlapping tool
// calls all succeed, the Origin guard, the MCP_HTTP_TOKEN check and the listen
// address log are wired in, bodies are parsed only on /mcp after the token, up
// to the same 10 MiB message cap as stdio, a body over the cap, not valid
// JSON or otherwise refused by the parser gets a JSON-RPC error, and tool
// arguments are capped by element count (maxToolInputElements).

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

const MAX_MESSAGE_BYTES = 10 * 1024 * 1024; // the SDK's stdio cap, STDIO_DEFAULT_MAX_BUFFER_SIZE
const CASE_ID = "659240aa-797e-42cf-bb82-cca43c4e80d8";

function postMcp(port, body, headers = {}) {
  return fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body,
  });
}

function uploadBody(fileBytes) {
  const content_base64 = Buffer.alloc(fileBytes, 0x5a).toString("base64");
  const args = { case_id: CASE_ID, name: "evidence.bin", content_base64 };
  return JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "sophos_fusion_upload_case_file", arguments: args } });
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

test("the HTTP entry point parses request bodies only on /mcp, after the token check", async () => {
  const server = await startServer({ MCP_HTTP_TOKEN: "entry-point-test-token-9a2e" });
  try {
    // Not valid Brotli: a body parser that ran would fail decompressing it and answer 400
    const junk = { method: "POST", headers: { "Content-Type": "application/json", "Content-Encoding": "br" }, body: "not brotli" };
    const other = await fetch(`http://127.0.0.1:${server.port}/other`, junk);
    assert.equal(other.status, 404);
    assert.match(await other.text(), /Cannot POST \/other/);
    assert.equal((await fetch(`http://127.0.0.1:${server.port}/mcp`, junk)).status, 401);
  } finally {
    server.stop();
  }
});

test("an authenticated /mcp call carries a case file up to the stdio message cap", async () => {
  const token = "entry-point-test-token-3c7d";
  const server = await startServer({ MCP_HTTP_TOKEN: token });
  try {
    // 7.5 MiB less 1 KiB: the description's "about 7.5 MiB" for content_base64
    const fileBytes = 7.5 * 1024 * 1024 - 1024;
    const body = uploadBody(fileBytes);
    assert.ok(body.length > 100 * 1024 && body.length < MAX_MESSAGE_BYTES, `body is ${body.length} bytes`);
    const res = await postMcp(server.port, body, { Authorization: `Bearer ${token}` });
    assert.equal(res.status, 200);
    const result = (await res.json()).result;
    assert.equal(result.isError, undefined, result.content[0].text);
    const file = JSON.parse(result.content[0].text);
    assert.equal(file.upload_bytes, fileBytes);
    assert.equal(file.size, fileBytes);
    assert.equal(file.upload_status, "UPLOADED");
  } finally {
    server.stop();
  }
});

test("a /mcp body over the cap gets a JSON-RPC 413 and the server keeps serving", async () => {
  const token = "entry-point-test-token-8b41";
  const server = await startServer({ MCP_HTTP_TOKEN: token });
  try {
    const body = uploadBody(8 * 1024 * 1024);
    assert.ok(body.length > MAX_MESSAGE_BYTES);
    const res = await postMcp(server.port, body, { Authorization: `Bearer ${token}` });
    assert.equal(res.status, 413);
    assert.match(res.headers.get("content-type"), /application\/json/);
    const text = await res.text();
    assert.doesNotMatch(text, /PayloadTooLargeError|<html|node_modules/i);
    const { error } = JSON.parse(text);
    assert.equal(error.code, -32000);
    assert.match(error.message, new RegExp(`over the ${MAX_MESSAGE_BYTES} byte limit.*file_path`));
    const after = await callTool(server.port, 2, { Authorization: `Bearer ${token}` });
    assert.equal(after.status, 200);
    assert.match((await after.json()).result.content[0].text, /"count": 0/);
  } finally {
    server.stop();
  }
});

test("malformed JSON on /mcp gets a JSON-RPC parse error with no stack, and the server keeps serving", async () => {
  const token = "entry-point-test-token-d27f";
  const server = await startServer({ MCP_HTTP_TOKEN: token });
  try {
    const res = await postMcp(server.port, '{"jsonrpc":"2.0","id":1,', { Authorization: `Bearer ${token}` });
    assert.equal(res.status, 400);
    assert.match(res.headers.get("content-type"), /application\/json/);
    const text = await res.text();
    assert.doesNotMatch(text, /SyntaxError|<html|node_modules|JSON\.parse|body-parser|\/Users\/|\/home\//i);
    assert.deepEqual(JSON.parse(text), { jsonrpc: "2.0", error: { code: -32700, message: "Parse error: Invalid JSON" }, id: null });
    const after = await callTool(server.port, 2, { Authorization: `Bearer ${token}` });
    assert.equal(after.status, 200);
    assert.match((await after.json()).result.content[0].text, /"count": 0/);
  } finally {
    server.stop();
  }
});

test("every other body the /mcp parser rejects gets a JSON-RPC error with its status and no stack, and the server keeps serving", async () => {
  const token = "entry-point-test-token-6e03";
  const server = await startServer({ MCP_HTTP_TOKEN: token });
  try {
    const auth = { Authorization: `Bearer ${token}` };
    const valid = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    const unreadable = (encoding) => `Bad Request: the request body could not be read as Content-Encoding "${encoding}".`;
    const cases = [
      ["bad brotli", { "Content-Encoding": "br" }, "not brotli", 400, unreadable("br")],
      ["bad gzip", { "Content-Encoding": "gzip" }, "not gzip", 400, unreadable("gzip")],
      ["bad deflate", { "Content-Encoding": "deflate" }, "not deflate", 400, unreadable("deflate")],
      ["unknown Content-Encoding", { "Content-Encoding": "zstd" }, valid, 415, 'Unsupported Media Type: Content-Encoding "zstd" is not supported. Use gzip, deflate, br or none.'],
      ["non-UTF charset", { "Content-Type": "application/json; charset=latin1" }, valid, 415, 'Unsupported Media Type: charset "latin1" is not supported. Use UTF-8.'],
      ["unknown UTF charset", { "Content-Type": "application/json; charset=utf-99" }, valid, 415, 'Unsupported Media Type: charset "utf-99" is not supported. Use UTF-8.'],
    ];
    for (const [name, headers, body, status, message] of cases) {
      const res = await postMcp(server.port, body, { ...auth, ...headers });
      assert.equal(res.status, status, name);
      assert.match(res.headers.get("content-type"), /application\/json/, name);
      const text = await res.text();
      assert.doesNotMatch(text, /MediaTypeError|NodeError|zlib|<html|node_modules|body-parser|\/Users\/|\/home\//i, name);
      assert.deepEqual(JSON.parse(text), { jsonrpc: "2.0", error: { code: -32000, message }, id: null }, name);
    }
    const after = await callTool(server.port, 2, auth);
    assert.equal(after.status, 200);
    assert.match((await after.json()).result.content[0].text, /"count": 0/);
  } finally {
    server.stop();
  }
});

test("a tool call with more than 1,000,000 argument elements is refused before validation", async () => {
  const server = await startServer();
  try {
    const ids = `[${Array(1_000_001).fill("0").join(",")}]`;
    const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sophos_fusion_add_case_evidence","arguments":{"case_id":"${CASE_ID}","detection_ids":${ids}}}}`;
    const res = await postMcp(server.port, body);
    assert.equal(res.status, 200);
    const { result } = await res.json();
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /more than the maximum of 1000000 elements/);
  } finally {
    server.stop();
  }
});
