/**
 * Read-only mode (SOPHOS_READ_ONLY), first half: the switch is off unless
 * set, a typo stops the server, the tool filter keeps exactly the classified
 * read tools, and the entry point wires both guards. The request guard with
 * the mode on is in read-only-guard.test.mjs, since turning it on lasts for
 * the process. fetch is stubbed; no network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { createServer as createNetServer } from "node:net";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadConfig, parseReadOnly } from "../dist/config/config.js";
import { READ_ONLY_EXCLUDED, READ_ONLY_TOOLS, registerReadToolsOnly } from "../dist/read-only.js";
import { guardedFetch, isReadOnlyMode } from "../dist/client/read-only-guard.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { FusionClient } from "../dist/client/fusion-client.js";

const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const fakeSophos = new URL("./fake-sophos-fetch.mjs", import.meta.url).href;

async function listTools({ readOnly }) {
  const indexSrc = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
  const modules = [...indexSrc.matchAll(/from\s+"\.\/tools\/([a-z0-9-]+)\.js"/g)].map((m) => m[1]);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  const counts = readOnly ? registerReadToolsOnly(server) : undefined;
  // Registration only reads the identity, as in tool-registration.test.mjs. A partner caller gets every tool.
  const stub = {
    getIdentity: () => ({ id: "00000000-0000-4000-8000-000000000000", idType: "partner", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Partner-ID", value: "00000000-0000-4000-8000-000000000000" }),
  };
  for (const mod of modules) {
    const exports = await import(`../dist/tools/${mod}.js`);
    for (const [name, register] of Object.entries(exports)) {
      if (/^register\w+Tools$/.test(name) && typeof register === "function") register(server, stub, stub, stub);
    }
  }
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  const tools = [];
  let cursor;
  do {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    tools.push(...page.tools);
    cursor = page.nextCursor;
  } while (cursor);
  await client.close();
  await server.close();
  return { tools, counts };
}

test("SOPHOS_READ_ONLY is off unless set, and a value it does not know stops the server", () => {
  for (const off of [undefined, "", "false", "0", "off", "no", " FALSE "]) assert.equal(parseReadOnly(off), false, String(off));
  for (const on of ["true", "1", "on", "yes", "TRUE", " On "]) assert.equal(parseReadOnly(on), true, on);
  for (const bad of ["ture", "readonly", "2", "y"]) assert.throws(() => parseReadOnly(bad), /Invalid SOPHOS_READ_ONLY value/, bad);

  const saved = { id: process.env.SOPHOS_CLIENT_ID, secret: process.env.SOPHOS_CLIENT_SECRET, ro: process.env.SOPHOS_READ_ONLY };
  try {
    process.env.SOPHOS_CLIENT_ID = "test-id";
    process.env.SOPHOS_CLIENT_SECRET = "test-secret";
    delete process.env.SOPHOS_READ_ONLY;
    assert.equal(loadConfig().readOnly, false);
    process.env.SOPHOS_READ_ONLY = "true";
    assert.equal(loadConfig().readOnly, true);
  } finally {
    for (const [key, name] of [["id", "SOPHOS_CLIENT_ID"], ["secret", "SOPHOS_CLIENT_SECRET"], ["ro", "SOPHOS_READ_ONLY"]]) {
      if (saved[key] === undefined) delete process.env[name];
      else process.env[name] = saved[key];
    }
  }
});

test("off by default: every tool is registered", async () => {
  const { tools } = await listTools({ readOnly: false });
  assert.equal(tools.length, 362);
  assert.ok(tools.some((t) => t.annotations.readOnlyHint === false), "write tools are registered");
});

test("read-only mode registers the 177 classified read tools and no write tool", async () => {
  const all = (await listTools({ readOnly: false })).tools;
  const { tools, counts } = await listTools({ readOnly: true });
  const names = new Set(tools.map((t) => t.name));

  assert.equal(tools.length, 177);
  assert.deepEqual(counts, { registered: 177, leftOut: 185 });
  for (const tool of tools) {
    assert.equal(tool.annotations?.readOnlyHint, true, `${tool.name} is annotated read-only`);
    assert.ok(READ_ONLY_TOOLS.has(tool.name), `${tool.name} is classified`);
  }
  for (const tool of all.filter((t) => t.annotations.readOnlyHint !== true)) {
    assert.ok(!names.has(tool.name), `write tool ${tool.name} is left out`);
  }
  for (const name of Object.keys(READ_ONLY_EXCLUDED)) assert.ok(!names.has(name), `${name} is left out`);
  assert.ok(names.has("sophos_get_helm_values"), "the Helm values download is a read");
  for (const name of ["sophos_isolate_endpoint", "sophos_wipe_mobile_device", "sophos_delete_endpoint", "sophos_fusion_update_case", "sophos_bulk_change_endpoint_group"]) {
    assert.ok(!names.has(name), `${name} is left out`);
  }
});

test("every tool annotated read-only is either classified as a read or excluded with a reason", async () => {
  const { tools } = await listTools({ readOnly: false });
  const annotatedRead = new Set(tools.filter((t) => t.annotations.readOnlyHint === true).map((t) => t.name));
  const classified = new Set([...READ_ONLY_TOOLS, ...Object.keys(READ_ONLY_EXCLUDED)]);
  assert.deepEqual([...annotatedRead].filter((n) => !classified.has(n)), [], "a new read tool must go in READ_ONLY_TOOLS or READ_ONLY_EXCLUDED");
  assert.deepEqual([...classified].filter((n) => !annotatedRead.has(n)), [], "every classified tool exists and is annotated read-only");
  for (const name of READ_ONLY_TOOLS) assert.equal(READ_ONLY_EXCLUDED[name], undefined, `${name} is not both read and excluded`);
  for (const reason of Object.values(READ_ONLY_EXCLUDED)) assert.doesNotMatch(reason, /[\u2013\u2014]/);
});

test("the filter leaves out an unclassified tool even when it is annotated read-only", () => {
  const server = new McpServer({ name: "test", version: "0.0.0" });
  const counts = registerReadToolsOnly(server);
  const config = { description: "x", inputSchema: {}, annotations: { readOnlyHint: true } };
  server.registerTool("sophos_some_new_read_tool", config, async () => ({ content: [] }));
  server.registerTool("sophos_list_endpoints", { ...config, annotations: { readOnlyHint: false } }, async () => ({ content: [] }));
  server.registerTool("sophos_list_alerts", config, async () => ({ content: [] }));
  assert.deepEqual(counts, { registered: 1, leftOut: 2 });
  assert.throws(() => server.tool("sophos_old_style", async () => ({ content: [] })), /registerTool only/);
});

test("off by default: the request guard sends a write through untouched", async () => {
  assert.equal(isReadOnlyMode(), false);
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method ?? "GET" });
    return new Response(JSON.stringify({ data: { ok: true } }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  try {
    const tenantResolver = { resolveApiHost: async () => "https://api-au01.central.sophos.com" };
    const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
    await client.tenantRequest("00000000-0000-4000-8000-000000000001", "/endpoint/v1/endpoints/x/isolation", { method: "POST", body: {} });
    await new FusionClient({ getToken: async () => "fake-token" }).query("t", "mutation M { m }");
    await guardedFetch("https://fake-upload.test/put", { method: "PUT", body: "x" });
    assert.deepEqual(calls.map((c) => c.method), ["POST", "POST", "PUT"]);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("every outbound request in src goes through guardedFetch", () => {
  const files = readdirSync(new URL("../src", import.meta.url), { recursive: true }).filter((f) => f.endsWith(".ts"));
  for (const file of files) {
    const text = readFileSync(new URL(`../src/${file}`, import.meta.url), "utf8");
    const raw = text.split("\n").filter((line) => /(?<![\w.])(?<!async )fetch\(|globalThis\.fetch\b/.test(line));
    if (file.replaceAll("\\", "/") === "client/read-only-guard.ts") {
      assert.equal(raw.length, 1, "the guard's own call to fetch");
    } else {
      assert.deepEqual(raw, [], `${file} calls fetch directly`);
    }
  }
});

async function freePort() {
  const probe = createNetServer().listen(0, "127.0.0.1");
  await new Promise((resolve) => probe.on("listening", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

function serverEnv(extra) {
  const env = { ...process.env, SOPHOS_CLIENT_ID: "test-id", SOPHOS_CLIENT_SECRET: "test-secret", TRANSPORT: "http" };
  for (const name of ["SOPHOS_FUSION_GRAPHQL_URL", "MCP_HTTP_HOST", "MCP_HTTP_TOKEN", "MCP_ALLOWED_ORIGINS", "SOPHOS_READ_ONLY"]) delete env[name];
  return Object.assign(env, extra);
}

async function rpc(port, id, method, params) {
  const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  assert.equal(res.status, 200);
  return res.json();
}

test("the entry point in read-only mode lists only read tools, answers a read and has no write tool", async () => {
  const port = await freePort();
  const child = spawn(process.execPath, ["--import", fakeSophos, entry], {
    env: serverEnv({ PORT: String(port), SOPHOS_READ_ONLY: "true" }),
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  try {
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
    // The fake whoami is a tenant caller, so the partner only tools are not registered at all
    const listed = await rpc(port, 1, "tools/list", {});
    const tools = listed.result.tools;
    assert.ok(tools.length > 100 && tools.length < 177, `${tools.length} tools`);
    for (const tool of tools) assert.ok(READ_ONLY_TOOLS.has(tool.name), `${tool.name} is a classified read tool`);
    assert.ok(!tools.some((t) => t.name === "sophos_isolate_endpoint"));
    assert.match(stderr, new RegExp(`Read-only mode: ${tools.length} read tools registered, \\d+ left out`));

    const read = await rpc(port, 2, "tools/call", { name: "sophos_list_endpoints", arguments: {} });
    assert.equal(read.result?.isError, undefined, JSON.stringify(read));
    assert.match(read.result.content[0].text, /"count": 0/);

    const write = await rpc(port, 3, "tools/call", {
      name: "sophos_isolate_endpoint",
      arguments: { endpoint_id: "659240aa-797e-42cf-bb82-cca43c4e80d8" },
    });
    assert.ok(write.error || write.result?.isError, JSON.stringify(write));
    assert.match(JSON.stringify(write), /not found/i);
  } finally {
    child.kill();
  }
});

test("a SOPHOS_READ_ONLY value the server does not know stops it before any request", () => {
  const noNetwork =
    "data:text/javascript,globalThis.fetch=async(u)=>{process.stderr.write('FETCH '+u+'\\n');throw new Error('network disabled in test')}";
  const run = spawnSync(process.execPath, ["--import", noNetwork, entry], {
    env: serverEnv({ TRANSPORT: "stdio", SOPHOS_READ_ONLY: "ture" }),
    encoding: "utf8",
    timeout: 20_000,
  });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /Invalid SOPHOS_READ_ONLY value "ture"/);
  assert.doesNotMatch(run.stderr, /FETCH /);
});
