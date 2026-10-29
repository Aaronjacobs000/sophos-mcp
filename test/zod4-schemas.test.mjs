/**
 * Input schemas on zod 4. Calls tools through their real handlers with fetch
 * (or the Fusion client) stubbed. ID arguments are checked for shape only
 * (z.guid), because Sophos IDs are not all RFC 4122 UUIDs: built-in role IDs,
 * some XDR query IDs and some Fusion reference data IDs carry other version
 * and variant digits (live tenants, 29/10/2026). Also a defaulted field, a
 * record schema and the length check that fails fast on an oversized array
 * (GHSA-mrhx-c7xc-m3w5). No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerAdminManagementTools } from "../dist/tools/admin-management.js";
import { registerEndpointTools } from "../dist/tools/endpoints.js";
import { registerPolicyTools } from "../dist/tools/policies.js";
import { registerFusionSearchTools } from "../dist/tools/fusion-search.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const ADMIN = "00000000-0000-4000-8000-0000000000a1";

// Real ID shapes from live tenants that RFC 4122 UUID checks refuse
const NON_RFC_IDS = {
  "built-in Super Admin role": "73757065-7261-646d-696e-5b302d39612d",
  "built-in partner role": "70617274-6e65-7273-7570-657261646d69",
  "XDR query, version digit 0": "0a77e773-ce9f-0768-a4a8-46e96feb7d9a",
  "Fusion case reference data": "6d7e8f9a-0b1c-2d3e-4f5a-6b7c8d9e0f1a",
};

/** Connects an MCP client to the registrars on a real SophosClient; fetch answers `answer(...)` or {}. */
async function harness(registrars, answer = () => ({})) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    calls.push({ method: init?.method ?? "GET", path: u.pathname, query: Object.fromEntries(u.searchParams), body });
    return new Response(JSON.stringify(answer() ?? {}), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  for (const register of registrars) register(server, client, tenantResolver);
  return connect(server, calls, () => (globalThis.fetch = realFetch));
}

async function connect(server, calls, restore = () => {}) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    async tool(name) {
      return (await mcp.listTools()).tools.find((t) => t.name === name);
    },
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = result.content.map((c) => c.text ?? "").join("\n");
      return { isError: Boolean(result.isError), text };
    },
    async close() {
      await mcp.close();
      await server.close();
      restore();
    },
  };
}

test("an ID argument accepts every 8-4-4-4-12 hex shape, including Sophos IDs that are not RFC 4122", async () => {
  const h = await harness([registerAdminManagementTools]);
  try {
    const advertised = (await h.tool("sophos_add_admin_role_assignment")).inputSchema.properties.role_id;
    assert.equal(advertised.format, "uuid");
    for (const [label, id] of Object.entries(NON_RFC_IDS)) {
      assert.equal(z.uuid().safeParse(id).success, false, `${label}: z.uuid() would refuse it`);
    }
    const ids = { ...NON_RFC_IDS, "upper case RFC 4122": "6F7A8B9C-0D1E-4F3A-8B5C-6D7E8F9A0B1C" };
    for (const [label, id] of Object.entries(ids)) {
      assert.match(id, new RegExp(advertised.pattern), `${label}: the advertised pattern accepts it`);
      h.calls.length = 0;
      const { isError, text } = await h.call("sophos_add_admin_role_assignment", { admin_id: ADMIN, role_id: id });
      assert.equal(isError, false, `${label}: ${text}`);
      assert.deepEqual(h.calls, [{ method: "POST", path: `/common/v1/admins/${ADMIN}/role-assignments`, query: {}, body: { roleId: id } }], label);
    }
  } finally {
    await h.close();
  }
});

test("an ID argument that is not 8-4-4-4-12 hex is refused before anything is sent", async () => {
  const h = await harness([registerAdminManagementTools]);
  try {
    for (const id of ["73757065-7261-646d-696e-5b302d39612", "superadmin", "1-598868", "CSE00001", ""]) {
      const { isError, text } = await h.call("sophos_add_admin_role_assignment", { admin_id: ADMIN, role_id: id });
      assert.equal(isError, true, id);
      assert.match(text, /^MCP error -32602: Input validation error/, id);
      assert.match(text, /role_id/, id);
    }
    assert.equal(h.calls.length, 0, "no request was sent");
  } finally {
    await h.close();
  }
});

test("a defaulted field is filled when omitted, kept when sent, and still range checked", async () => {
  const h = await harness([registerEndpointTools], () => ({ items: [], pages: {} }));
  try {
    const advertised = (await h.tool("sophos_list_endpoints")).inputSchema;
    assert.equal(advertised.properties.limit.default, 50);
    assert.ok(!(advertised.required ?? []).includes("limit"), "limit is not required");

    assert.equal((await h.call("sophos_list_endpoints", {})).isError, false);
    assert.equal(h.calls[0].query.pageSize, "50", "the default is sent when limit is omitted");
    assert.equal((await h.call("sophos_list_endpoints", { limit: 7 })).isError, false);
    assert.equal(h.calls[1].query.pageSize, "7", "a sent value replaces the default");

    for (const limit of [0, 101, 2.5]) {
      const { isError, text } = await h.call("sophos_list_endpoints", { limit });
      assert.equal(isError, true, String(limit));
      assert.match(text, /^MCP error -32602: Input validation error/, String(limit));
    }
    assert.equal(h.calls.length, 2, "no request for an out of range limit");
  } finally {
    await h.close();
  }
});

test("a record argument takes any JSON object and refuses anything else", async () => {
  const calls = [];
  const fusion = {
    query: async (tenantId, document, variables) => {
      calls.push(variables);
      return { data: { createSearch: { urn: "urn:sophos:search:1:x", status: "QUEUED", outcome: { success: "UNKNOWN", errors: [] } } }, warnings: [] };
    },
  };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFusionSearchTools(server, fusion, { resolveTenantId: (id) => id ?? TENANT });
  const stub = { resolveTenantId: (id) => id ?? TENANT };
  registerPolicyTools(server, {}, stub);
  const h = await connect(server, calls);
  try {
    for (const [tool, field] of [["sophos_fusion_create_search", "metadata"], ["sophos_create_policy", "settings"], ["sophos_update_policy", "settings"]]) {
      const advertised = (await h.tool(tool)).inputSchema.properties[field];
      assert.equal(advertised.type, "object", `${tool} ${field}`);
      assert.deepEqual(advertised.additionalProperties, {}, `${tool} ${field} takes any value per key`);
    }

    const metadata = { source: "mcp", nested: { list: [1, "two", null], flag: false } };
    const { isError } = await h.call("sophos_fusion_create_search", { query: "from process earliest=-1h", metadata });
    assert.equal(isError, false);
    assert.deepEqual(calls[0].input.metadata, metadata, "the object is passed through unchanged");

    for (const bad of ["source=mcp", [1, 2], 3]) {
      const { isError: refused, text } = await h.call("sophos_fusion_create_search", { query: "from process earliest=-1h", metadata: bad });
      assert.equal(refused, true, JSON.stringify(bad));
      assert.match(text, /^MCP error -32602: Input validation error[\s\S]*metadata/, JSON.stringify(bad));
    }
    assert.equal(calls.length, 1, "nothing sent for a non-object");
  } finally {
    await h.close();
  }
});

test("an oversized array is refused on its length alone, with one issue (GHSA-mrhx-c7xc-m3w5)", async () => {
  const h = await harness([registerEndpointTools]);
  try {
    const ids = new Array(200_000).fill("not-an-id");
    const { isError, text } = await h.call("sophos_bulk_scan_endpoints", { ids });
    assert.equal(isError, true);
    assert.match(text, /^MCP error -32602: Input validation error/);
    assert.match(text, /500/, "names the limit");
    assert.ok(text.length < 1000, `one issue, not one per element (${text.length} characters)`);
    assert.equal(h.calls.length, 0, "no request was sent");
  } finally {
    await h.close();
  }
});
