/**
 * sophos_list_endpoints last_seen_before and last_seen_after. Counting stale
 * devices used to mean paging every endpoint (2,814 computers, 24 minutes, on
 * one tenant). The Endpoint API filters by last seen time itself and, with
 * pageTotal=true, counts the filtered list, so one call at limit 1 is the
 * count. The accepted values are the ones measured live on 03/11/2026: a UTC
 * date, a UTC date-time ending in Z, or a negative duration of days, hours,
 * minutes and seconds of at most three digits each. Everything Sophos answers
 * 400 to, and a positive duration (the future), is refused before a request.
 * No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerEndpointTools } from "../dist/tools/endpoints.js";

const TENANT = "00000000-0000-4000-8000-000000000001";

async function harness(answer) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    calls.push({ path: u.pathname, query: Object.fromEntries(u.searchParams) });
    return new Response(JSON.stringify(answer(u)), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const tenantResolver = {
    resolveApiHost: async () => "https://api-au01.central.sophos.com",
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerEndpointTools(server, client, tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    mcp,
    async call(args) {
      const result = await mcp.callTool({ name: "sophos_list_endpoints", arguments: args });
      const text = result.content.map((c) => c.text ?? "").join("");
      return { isError: Boolean(result.isError), text, json: result.isError ? null : JSON.parse(text) };
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

const endpoint = (i, lastSeenAt) => ({ id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, hostname: `HOST-${i}`, type: "computer", lastSeenAt });

test("last_seen_before and last_seen_after are sent as lastSeenBefore and lastSeenAfter, and total is the filtered count", async () => {
  const h = await harness(() => ({ items: [endpoint(1, "2026-09-28T00:00:00Z")], pages: { size: 1, items: 412, total: 412, nextKey: "k1" } }));
  try {
    const out = await h.call({ tenant_id: TENANT, type: "computer", last_seen_before: "-P30D", limit: 1 });
    assert.equal(out.isError, false, out.text);
    assert.deepEqual(h.calls[0].query, { pageSize: "1", pageTotal: "true", type: "computer", lastSeenBefore: "-P30D" });
    assert.equal(out.json.total, 412, "one call at limit 1 is the stale count");

    await h.call({ tenant_id: TENANT, last_seen_after: "2026-10-01T00:00:00Z", last_seen_before: "-P7D" });
    assert.equal(h.calls[1].query.lastSeenAfter, "2026-10-01T00:00:00Z");
    assert.equal(h.calls[1].query.lastSeenBefore, "-P7D");

    await h.call({ tenant_id: TENANT });
    assert.equal("lastSeenBefore" in h.calls[2].query, false);
    assert.equal("lastSeenAfter" in h.calls[2].query, false);
  } finally {
    await h.close();
  }
});

test("every format Sophos accepted live is passed through unchanged", async () => {
  const accepted = [
    "-P30D", "-P0D", "-P999D", "-PT12H", "-PT999H", "-PT30M", "-PT45S", "-P1DT6H", "-P30DT0H", "-P1DT1H1M1S",
    "2026-10-01", "2026-10-01T00:00Z", "2026-10-01T00:00:00Z", "2026-10-01T00:00:00.1Z", "2026-10-01T00:00:00.123Z",
  ];
  const h = await harness(() => ({ items: [], pages: { size: 1, items: 0, total: 0 } }));
  try {
    for (const value of accepted) {
      for (const [arg, param] of [["last_seen_before", "lastSeenBefore"], ["last_seen_after", "lastSeenAfter"]]) {
        const out = await h.call({ tenant_id: TENANT, [arg]: value, limit: 1 });
        assert.equal(out.isError, false, `${arg} ${value}: ${out.text}`);
        assert.equal(h.calls.at(-1).query[param], value);
      }
    }
  } finally {
    await h.close();
  }
});

test("a value Sophos refuses, or a duration into the future, is refused before any request", async () => {
  const refused = [
    "P30D", // no minus: 30 days in the future, which would count every endpoint as stale
    "+P30D", "-P1W", "-P3M", "-P1Y", "-P1000D", "-PT1000H", "-P1.5D", "-PT1.5H", "-P", "-PT", "-P30DT", "-p30d",
    "2026-10-01T10:00:00+10:00", "2026-10-01T00:00:00", "2026-10-01T00:00:00.123456Z", "2026-10-1", "2026-13-01",
    "30 days", "",
  ];
  const h = await harness(() => ({ items: [], pages: {} }));
  try {
    for (const value of refused) {
      for (const arg of ["last_seen_before", "last_seen_after"]) {
        const out = await h.call({ tenant_id: TENANT, [arg]: value });
        assert.equal(out.isError, true, `${arg} ${JSON.stringify(value)} was accepted`);
        assert.match(out.text, /-P30D/, "the error shows a working value");
      }
    }
    assert.equal(h.calls.length, 0, "nothing reached Sophos");
  } finally {
    await h.close();
  }
});

test("the tool and argument descriptions say how to count stale devices", async () => {
  const h = await harness(() => ({}));
  try {
    const { tools } = await h.mcp.listTools();
    const tool = tools.find((t) => t.name === "sophos_list_endpoints");
    assert.match(tool.description, /Stale devices: count them in one call with last_seen_before "-P30D" and\s+limit 1, and read total/);
    assert.match(tool.description, /Do not page through every endpoint to count them/);
    const before = tool.inputSchema.properties.last_seen_before;
    const after = tool.inputSchema.properties.last_seen_after;
    assert.equal(before.type, "string");
    assert.match(before.description, /stale-device count use "-P30D" with limit 1 and read total/);
    assert.match(after.description, /"-P7D"/);
    assert.equal(tool.inputSchema.required?.includes("last_seen_before") ?? false, false);
  } finally {
    await h.close();
  }
});
