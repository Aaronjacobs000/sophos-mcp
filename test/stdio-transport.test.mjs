// Runs the built entry point on stdio against an in-memory Sophos (see
// fake-sophos-fetch.mjs) and pins what the README and the upload tool
// description say about the message cap: a message up to the SDK's 10 MiB cap
// (STDIO_DEFAULT_MAX_BUFFER_SIZE) is answered, and one over it makes the SDK's
// StdioServerTransport close itself, so the server exits without an answer.
// The SDK (1.32) has no option to refuse that message and keep reading. If an
// SDK update changes this, the second half fails: update the docs with it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const fakeSophos = new URL("./fake-sophos-fetch.mjs", import.meta.url).href;

const MAX_MESSAGE_BYTES = 10 * 1024 * 1024; // the SDK's stdio cap, STDIO_DEFAULT_MAX_BUFFER_SIZE
const CASE_ID = "659240aa-797e-42cf-bb82-cca43c4e80d8";

function startServer() {
  const env = { ...process.env, SOPHOS_CLIENT_ID: "test-id", SOPHOS_CLIENT_SECRET: "test-secret", TRANSPORT: "stdio" };
  for (const name of ["SOPHOS_FUSION_GRAPHQL_URL", "MCP_HTTP_HOST", "MCP_HTTP_TOKEN", "MCP_ALLOWED_ORIGINS"]) delete env[name];
  const child = spawn(process.execPath, ["--import", fakeSophos, entry], { env, stdio: ["pipe", "pipe", "pipe"] });
  // A write after the server has gone fails with EPIPE; the exit is what the test checks
  child.stdin.on("error", () => {});
  const responses = new Map();
  const waiters = new Map();
  let stdout = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
    let newline;
    while ((newline = stdout.indexOf("\n")) !== -1) {
      const message = JSON.parse(stdout.slice(0, newline));
      stdout = stdout.slice(newline + 1);
      responses.set(message.id, message);
      waiters.get(message.id)?.(message);
    }
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));
  const send = (message) => child.stdin.write(`${typeof message === "string" ? message : JSON.stringify(message)}\n`);
  const response = (id) =>
    responses.has(id)
      ? Promise.resolve(responses.get(id))
      : new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error(`no response for id ${id}: ${stderr}`)), 15_000);
          waiters.set(id, (message) => {
            clearTimeout(timer);
            resolve(message);
          });
        });
  return { send, response, responses, exited, stop: () => child.kill() };
}

function uploadCall(id, fileBytes) {
  const content_base64 = Buffer.alloc(fileBytes, 0x5a).toString("base64");
  const args = { case_id: CASE_ID, name: "evidence.bin", content_base64 };
  return JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "sophos_fusion_upload_case_file", arguments: args } });
}

test("a stdio message up to the 10 MiB cap is answered, and one over it ends the server unanswered", async () => {
  const server = startServer();
  try {
    server.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "stdio-test", version: "0" } } });
    assert.equal((await server.response(1)).result.serverInfo.name, "sophos-central-mcp-server");
    server.send({ jsonrpc: "2.0", method: "notifications/initialized" });

    // 7.5 MiB less 1 KiB: the description's "about 7.5 MiB" for content_base64
    const fits = uploadCall(2, 7.5 * 1024 * 1024 - 1024);
    assert.ok(fits.length < MAX_MESSAGE_BYTES, `message is ${fits.length} bytes`);
    server.send(fits);
    const { result } = await server.response(2);
    assert.equal(result.isError, undefined, result.content[0].text);
    assert.equal(JSON.parse(result.content[0].text).upload_status, "UPLOADED");

    const tooBig = uploadCall(3, 8 * 1024 * 1024);
    assert.ok(tooBig.length > MAX_MESSAGE_BYTES);
    server.send(tooBig);
    server.send({ jsonrpc: "2.0", id: 4, method: "tools/list" });
    const exit = await Promise.race([server.exited, new Promise((resolve) => setTimeout(() => resolve("still running"), 15_000))]);
    assert.deepEqual(exit, { code: 0, signal: null });
    assert.equal(server.responses.has(3), false);
    assert.equal(server.responses.has(4), false);
  } finally {
    server.stop();
  }
});
