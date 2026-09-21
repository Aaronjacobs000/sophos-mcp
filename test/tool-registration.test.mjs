/**
 * Registers every tool module the way src/index.ts does, connects a client
 * over an in-memory transport and lists the tools. No credentials and no
 * network: registration never calls Sophos. Proves the server still exposes
 * the 288 Classic tools plus the 12 Fusion case tools.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const FUSION_CASE_TOOLS = [
  "sophos_fusion_list_cases",
  "sophos_fusion_get_case",
  "sophos_fusion_get_case_evidence",
  "sophos_fusion_get_case_summary",
  "sophos_fusion_list_case_reference_data",
  "sophos_fusion_create_case",
  "sophos_fusion_update_case",
  "sophos_fusion_list_case_comments",
  "sophos_fusion_add_case_comment",
  "sophos_fusion_add_case_evidence",
  "sophos_fusion_remove_case_evidence",
  "sophos_fusion_create_case_link",
];

const CLASSIC_CASE_TOOLS = [
  "sophos_list_cases",
  "sophos_get_case",
  "sophos_create_case",
  "sophos_update_case",
  "sophos_delete_case",
  "sophos_list_case_detections",
  "sophos_get_case_detection",
  "sophos_list_case_impacted_entities",
  "sophos_get_case_mitre_summary",
];

async function listAllTools() {
  const indexSrc = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
  const modules = [...indexSrc.matchAll(/from\s+"\.\/tools\/([a-z0-9-]+)\.js"/g)].map((m) => m[1]);
  assert.ok(modules.length > 0, "tool modules found in src/index.ts");

  const server = new McpServer({ name: "test", version: "0.0.0" });
  // Registration stores these and only reads the identity (health.ts registers
  // its partner-only tools for partner callers). One stub fits every parameter.
  const stub = {
    getIdentity: () => ({
      id: "00000000-0000-4000-8000-000000000000",
      idType: "partner",
      apiHosts: { global: "https://api.central.sophos.com" },
    }),
    getIdHeader: () => ({ name: "X-Partner-ID", value: "00000000-0000-4000-8000-000000000000" }),
  };
  for (const mod of modules) {
    const exports = await import(`../dist/tools/${mod}.js`);
    const registrars = Object.entries(exports).filter(
      ([name, value]) => /^register\w+Tools$/.test(name) && typeof value === "function"
    );
    assert.ok(registrars.length > 0, `${mod} exports a register*Tools function`);
    for (const [, register] of registrars) register(server, stub, stub, stub);
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
  return { modules, tools };
}

test("tools/list exposes the 288 Classic tools plus the 12 Fusion case tools", async () => {
  const { modules, tools } = await listAllTools();
  const names = new Set(tools.map((t) => t.name));

  assert.ok(modules.includes("fusion-cases"), "fusion-cases is imported by src/index.ts");
  assert.equal(tools.length, 300);
  assert.equal(names.size, 300, "tool names are unique");

  for (const name of CLASSIC_CASE_TOOLS) assert.ok(names.has(name), `${name} still registered`);
  for (const name of FUSION_CASE_TOOLS) assert.ok(names.has(name), `${name} registered`);

  const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url), "utf8"));
  for (const tool of manifest.tools) {
    assert.ok(names.has(tool.name), `manifest tool ${tool.name} is registered`);
  }
});

test("every Fusion case tool has a schema, annotations and dash-free prose", async () => {
  const { tools } = await listAllTools();
  for (const tool of tools.filter((t) => t.name.startsWith("sophos_fusion_"))) {
    assert.equal(tool.inputSchema?.type, "object", `${tool.name} has an object input schema`);
    assert.ok(tool.inputSchema.properties, `${tool.name} declares properties`);
    assert.equal(typeof tool.annotations?.readOnlyHint, "boolean", `${tool.name} has readOnlyHint`);
    assert.ok(tool.description.length > 100, `${tool.name} has a description`);
    assert.doesNotMatch(tool.description, /[–—]/, `${tool.name} description has no en or em dash`);
  }
  const readOnly = tools.filter((t) => t.name.startsWith("sophos_fusion_") && t.annotations.readOnlyHint);
  assert.equal(readOnly.length, 6, "six Fusion case tools are read-only");
});
