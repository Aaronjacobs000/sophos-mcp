/**
 * List mappers on records that lack fields a formatter used to assume.
 *
 * sophos_list_admins: an admin record has no top-level name. Live (02/11/2026)
 * /common/v1/admins items carry users[].name and profile { firstName,
 * lastName, email }, which sophos_get_admin returns as they are; the list
 * mapped a top-level name and reported null for every admin.
 *
 * sophos_list_endpoints: its fields parameter makes the API leave out every
 * object not named. fields "hostname,lastSeenAt" threw "Cannot read properties
 * of undefined (reading 'overall')", and naming health but not os threw on
 * 'platform'. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";

async function harness(module, registrar, answer) {
  const mod = await import(`../dist/tools/${module}.js`);
  const realFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    requests.push({ path: u.pathname, query: Object.fromEntries(u.searchParams) });
    return new Response(JSON.stringify(answer(u)), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const identity = { id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => identity,
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  mod[registrar](server, client, tenantResolver, { assertClassic: async () => [] });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    requests,
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = result.content.map((c) => c.text ?? "").join("\n");
      assert.ok(!result.isError, `${name} failed: ${text}`);
      return JSON.parse(text);
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

// Shaped like a live /common/v1/admins item (values invented).
const admin = (id, extra) => ({
  id,
  tenant: { id: TENANT },
  roleAssignments: [{ id: `ra-${id}`, roleId: "00000000-0000-4000-8000-0000000000r1" }],
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
  ...extra,
});

test("sophos_list_admins: name comes from users[].name and email from profile, as sophos_get_admin shows them", async () => {
  const h = await harness("directory", "registerDirectoryTools", () => ({
    items: [
      admin("a1", {
        users: [{ id: "u1", name: "Pat Example" }],
        profile: { firstName: "Pat", lastName: "Example", email: "pat@example.test" },
      }),
      admin("a2", { profile: { firstName: "Sam", lastName: "Sample", email: "sam@example.test" } }),
      admin("a3", {}),
    ],
    pages: { current: 1, size: 50, total: 1, items: 3, maxSize: 100 },
  }));
  try {
    const out = await h.call("sophos_list_admins", { tenant_id: TENANT, limit: 100 });
    assert.deepEqual(
      out.admins.map(({ id, name, email }) => ({ id, name, email })),
      [
        { id: "a1", name: "Pat Example", email: "pat@example.test" },
        { id: "a2", name: "Sam Sample", email: "sam@example.test" },
        { id: "a3", name: null, email: null },
      ]
    );
    assert.equal(out.admins[0].roles.length, 1);
  } finally {
    await h.close();
  }
});

const ENDPOINT_ID = "00000000-0000-4000-8000-0000000000e1";

test("sophos_list_endpoints: fields that leave out health and os return nulls, not an error", async () => {
  const h = await harness("endpoints", "registerEndpointTools", () => ({
    items: [{ id: ENDPOINT_ID, hostname: "HOST-1", lastSeenAt: "2026-11-01T00:00:00Z" }],
    pages: { size: 2, maxSize: 500 },
  }));
  try {
    const out = await h.call("sophos_list_endpoints", {
      tenant_id: TENANT,
      type: "computer",
      limit: 2,
      fields: "hostname,lastSeenAt",
    });
    assert.equal(h.requests[0].query.fields, "hostname,lastSeenAt");
    const [ep] = out.endpoints;
    assert.equal(ep.hostname, "HOST-1");
    assert.equal(ep.last_seen, "2026-11-01T00:00:00Z");
    assert.equal(ep.health, null);
    assert.equal(ep.threat_status, null);
    assert.equal(ep.os, null);
    assert.equal(ep.is_server, null);
  } finally {
    await h.close();
  }
});

test("sophos_list_endpoints: health without os, or os without health, maps what is there", async () => {
  const h = await harness("endpoints", "registerEndpointTools", () => ({
    items: [
      { id: ENDPOINT_ID, hostname: "HOST-1", health: { overall: "good" } },
      { id: ENDPOINT_ID, hostname: "HOST-2", os: { platform: "windows", name: "Windows 11", majorVersion: 10, minorVersion: 0, isServer: false } },
    ],
    pages: { size: 2, maxSize: 500 },
  }));
  try {
    const out = await h.call("sophos_list_endpoints", { tenant_id: TENANT, fields: "hostname,health,os" });
    assert.equal(out.endpoints[0].health, "good");
    assert.equal(out.endpoints[0].threat_status, null);
    assert.equal(out.endpoints[0].os, null);
    assert.equal(out.endpoints[1].health, null);
    assert.equal(out.endpoints[1].os, "windows Windows 11 10.0");
    assert.equal(out.endpoints[1].is_server, false);
  } finally {
    await h.close();
  }
});

test("sophos_get_endpoint: a record without health, os or tenant maps to nulls, not an error", async () => {
  const h = await harness("endpoints", "registerEndpointTools", () => ({ id: ENDPOINT_ID, hostname: "HOST-1", type: "computer" }));
  try {
    const out = await h.call("sophos_get_endpoint", { tenant_id: TENANT, endpoint_id: ENDPOINT_ID });
    assert.equal(out.tenant_id, null);
    assert.equal(out.services_status, null);
    assert.deepEqual(out.service_details, []);
    assert.equal(out.os_build, null);
  } finally {
    await h.close();
  }
});
