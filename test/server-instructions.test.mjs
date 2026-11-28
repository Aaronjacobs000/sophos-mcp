/**
 * The instructions the server sends in its initialize result
 * (src/instructions.ts). For each caller type, with read-only mode off and
 * on, every tool the text names is registered the way src/index.ts registers
 * tools, every prefix it names starts a registered tool, and the text stays
 * under its cap and on the prose and naming rules. Then the built entry point,
 * run on stdio against the in-memory Sophos, sends the text. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { serverInstructions } from "../dist/instructions.js";
import { registerReadToolsOnly } from "../dist/read-only.js";

const MAX_WORDS = 150;
const CALLERS = ["partner", "organization", "tenant"];
// src/index.ts registers these two modules for partner and organization callers only
const MULTI_TENANT_MODULES = new Set(["tenants", "partner"]);

const indexSrc = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
const modules = [...indexSrc.matchAll(/from\s+"\.\/tools\/([a-z0-9-]+)\.js"/g)].map((m) => m[1]);

async function registeredTools(idType, readOnly) {
  const server = new McpServer({ name: "test", version: "0.0.0" });
  if (readOnly) registerReadToolsOnly(server);
  // Registration stores these and reads only the identity (health.ts registers
  // its multi-tenant tools for partner and organization callers)
  const stub = {
    getIdentity: () => ({ id: "00000000-0000-4000-8000-000000000000", idType, apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Partner-ID", value: "00000000-0000-4000-8000-000000000000" }),
  };
  for (const mod of modules) {
    if (idType === "tenant" && MULTI_TENANT_MODULES.has(mod)) continue;
    const exports = await import(`../dist/tools/${mod}.js`);
    for (const [name, register] of Object.entries(exports)) {
      if (/^register\w+Tools$/.test(name) && typeof register === "function") register(server, stub, stub, stub);
    }
  }
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  const names = [];
  let cursor;
  do {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    names.push(...page.tools.map((t) => t.name));
    cursor = page.nextCursor;
  } while (cursor);
  await client.close();
  await server.close();
  return names;
}

for (const idType of CALLERS) {
  for (const readOnly of [false, true]) {
    test(`every tool the instructions name is registered: ${idType} caller, read-only ${readOnly ? "on" : "off"}`, async () => {
      const text = serverInstructions({ idType, readOnly });
      const names = await registeredTools(idType, readOnly);
      assert.ok(names.length > 100, `${names.length} tools registered`);
      const registered = new Set(names);
      const mentioned = [...new Set(text.match(/\bsophos_[a-z0-9_]*/g))];
      assert.ok(mentioned.length > 0, "the text names tools");
      for (const name of mentioned) {
        if (name.endsWith("_")) {
          assert.ok(names.some((n) => n.startsWith(name)), `prefix ${name} starts a registered tool`);
        } else {
          assert.ok(registered.has(name), `${name} is registered`);
        }
      }
    });
  }
}

test("the instructions stay short, dash free and on the naming rules", () => {
  for (const idType of CALLERS) {
    for (const readOnly of [false, true]) {
      const text = serverInstructions({ idType, readOnly });
      const words = text.split(/\s+/).filter(Boolean).length;
      assert.ok(words <= MAX_WORDS, `${idType}, read-only ${readOnly}: ${words} words, cap ${MAX_WORDS}`);
      assert.doesNotMatch(text, /[\u2013\u2014]/, "no en or em dash");
      assert.doesNotMatch(text, /Sophos Taegis/);
      assert.doesNotMatch(text, /organis|authoris|behaviour|licence/i, "US spelling");
      assert.match(text, /Sophos Fusion \(formerly Sophos Central\)/);
    }
  }
  assert.match(serverInstructions({ idType: "partner", readOnly: false }), /partner credential/);
  assert.match(serverInstructions({ idType: "organization", readOnly: false }), /organization credential/);
  assert.match(serverInstructions({ idType: "tenant", readOnly: false }), /tenant credential/);
  assert.match(serverInstructions({ idType: "tenant", readOnly: true }), /Read-only mode is on/);
  assert.doesNotMatch(serverInstructions({ idType: "tenant", readOnly: false }), /read-only/i);
});

test("an unknown caller type gets the multi-tenant text, as src/index.ts registers the multi-tenant tools for it", () => {
  assert.equal(
    serverInstructions({ idType: "something-new", readOnly: false }),
    serverInstructions({ idType: "organization", readOnly: false })
  );
});

// The built entry point on stdio, against fake-sophos-fetch.mjs (a tenant credential)
async function initializeOverStdio(extraEnv) {
  const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
  const fakeSophos = new URL("./fake-sophos-fetch.mjs", import.meta.url).href;
  const env = { ...process.env, SOPHOS_CLIENT_ID: "test-id", SOPHOS_CLIENT_SECRET: "test-secret", TRANSPORT: "stdio", ...extraEnv };
  for (const name of ["SOPHOS_FUSION_GRAPHQL_URL", "MCP_HTTP_HOST", "MCP_HTTP_TOKEN", "MCP_ALLOWED_ORIGINS"]) delete env[name];
  if (!("SOPHOS_READ_ONLY" in extraEnv)) delete env.SOPHOS_READ_ONLY;
  const child = spawn(process.execPath, ["--import", fakeSophos, entry], { env, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));
  try {
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no initialize response: ${stderr}`)), 15_000);
      let stdout = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
        const newline = stdout.indexOf("\n");
        if (newline === -1) return;
        clearTimeout(timer);
        resolve(JSON.parse(stdout.slice(0, newline)).result);
      });
      child.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "instructions-test", version: "0" } },
        })}\n`
      );
    });
    return result;
  } finally {
    child.kill();
  }
}

test("the stdio server sends the instructions in its initialize result", async () => {
  const result = await initializeOverStdio({});
  assert.equal(result.serverInfo.name, "sophos-central-mcp-server");
  assert.equal(result.instructions, serverInstructions({ idType: "tenant", readOnly: false }));
});

test("with read-only mode on, the stdio server sends the read-only instructions", async () => {
  const result = await initializeOverStdio({ SOPHOS_READ_ONLY: "true" });
  assert.equal(result.instructions, serverInstructions({ idType: "tenant", readOnly: true }));
});
