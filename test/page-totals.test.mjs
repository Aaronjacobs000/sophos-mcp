/**
 * Item and page totals on the REST list tools. A Sophos page object carries
 * `pages.total` (the number of pages) and `pages.items` (the number of items),
 * both only when the API sends them, and most APIs send them only for a request
 * with `pageTotal=true`. `total` must be the item count from `pages.items`, 0
 * when `pages.total` is 0, and otherwise null, never the length of the page;
 * `pages.total` is reported only as `total_pages`. Measured on a live tenant
 * (02/11/2026): /cases/v1/cases at pageSize 2 answered
 * `{ current: 1, size: 2, total: 3, items: 5 }` with two cases unasked, while
 * /endpoint/v1/policies at pageSize 2 answered `{ current: 1, size: 2 }` without
 * pageTotal and `{ total: 12, items: 23 }` with it, and /endpoint/v1/endpoints
 * carried the counts on a pageFromKey page too. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const ID = "00000000-0000-4000-8000-0000000000a1";
const noMigration = { assertClassic: async () => [] };

// One item shape that every list formatter accepts (cases, endpoints, allowed and blocked items).
const item = (id) => ({
  id,
  name: id,
  type: "computer",
  tenant: { id: TENANT },
  properties: {},
  health: { overall: "good", threats: { status: "good" } },
  os: { platform: "windows", name: "Windows 11", majorVersion: 10, minorVersion: 0, isServer: false },
});
const ITEMS = [item("one"), item("two")];

// Offset pages as the live API answers them: with both totals, with neither
// (no pageTotal=true), and with the page count alone.
const OFFSET = {
  both: { current: 1, size: 2, total: 3, items: 5, maxSize: 50 },
  neither: { current: 1, size: 2, maxSize: 50 },
  pagesOnly: { current: 1, size: 2, total: 3, maxSize: 50 },
};

// Every list tool that reports an item total from a REST page object.
// [module, registrar, tool, arguments, total field, total_pages field]
// The request path each one sends pageTotal on is the one that returns ITEMS.
const TOOLS = [
  ["cases", "registerCaseTools", "sophos_list_cases", {}],
  ["cases", "registerCaseTools", "sophos_list_case_detections", { case_id: "1-598868" }],
  ["cases", "registerCaseTools", "sophos_list_case_impacted_entities", { case_id: "1-598868" }],
  ["detections", "registerDetectionTools", "sophos_get_detections_results", { run_id: ID }],
  ["detections", "registerDetectionTools", "sophos_get_detection_groups_results", { run_id: ID }],
  ["live-discover", "registerLiveDiscoverTools", "sophos_list_live_discover_queries", {}],
  ["admin-management", "registerAdminManagementTools", "sophos_list_admin_role_assignments", { admin_id: ID }],
  ["admin-management", "registerAdminManagementTools", "sophos_list_permission_sets", {}],
  ["directory", "registerDirectoryTools", "sophos_list_users", {}],
  ["directory", "registerDirectoryTools", "sophos_list_admins", {}],
  ["directory", "registerDirectoryTools", "sophos_list_user_groups", {}],
  ["directory", "registerDirectoryTools", "sophos_list_user_group_members", { group_id: ID }],
  ["policies", "registerPolicyTools", "sophos_list_policies", {}],
  ["endpoint-migrations", "registerEndpointMigrationTools", "sophos_list_migrations", {}],
  ["endpoint-migrations", "registerEndpointMigrationTools", "sophos_list_migration_endpoints", { migration_id: ID }],
  ["groups", "registerGroupTools", "sophos_list_endpoint_groups", {}],
  ["groups", "registerGroupTools", "sophos_get_endpoint_group", { group_id: ID, include_endpoints: true }, "endpoints_total", "endpoints_total_pages"],
  ["exclusions", "registerExclusionTools", "sophos_list_exclusions", {}],
  ["exclusions", "registerExclusionTools", "sophos_list_allowed_items", {}],
  ["exclusions", "registerExclusionTools", "sophos_list_blocked_items", {}],
  ["partner", "registerPartnerTools", "sophos_list_partner_admins", {}],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_blocked_addresses", {}],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_local_sites", {}],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_detected_exploits", {}],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_exploit_mitigation_apps", {}],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_ips_exclusions", {}],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_isolation_exclusions", {}],
  ["firewall", "registerFirewallTools", "sophos_list_firewalls", {}],
  ["firewall", "registerFirewallTools", "sophos_list_firewall_groups", {}],
  ["xdr", "registerXdrTools", "sophos_list_xdr_query_runs", {}],
];

// The cases and detections results APIs take no pageTotal parameter (cases
// count unasked), and these two return the whole list with no page object.
const NO_PAGE_TOTAL_PARAM = new Set([
  "sophos_list_cases",
  "sophos_list_case_detections",
  "sophos_list_case_impacted_entities",
  "sophos_get_detections_results",
  "sophos_get_detection_groups_results",
]);
const WHOLE_LIST = new Set(["sophos_list_admin_role_assignments", "sophos_list_permission_sets"]);

/**
 * Registers one tools module on a real SophosClient that answers every GET with
 * `answer(path)`. `requests` records the path and query of each call.
 */
async function harness(module, registrar, answer) {
  const mod = await import(`../dist/tools/${module}.js`);
  const realFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    requests.push({ path: u.pathname, query: Object.fromEntries(u.searchParams) });
    return new Response(JSON.stringify(answer(u.pathname)), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  const identity = { id: TENANT, idType: "partner", apiHosts: { global: "https://api.central.sophos.com" } };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => identity,
    getIdHeader: () => ({ name: "X-Partner-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  mod[registrar](server, client, tenantResolver, noMigration);
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

async function totalsFor([module, registrar, tool, args], pages, items = ITEMS) {
  return (await callWith([module, registrar, tool, args], pages, items)).out;
}

/** Calls one tool against a single canned page; returns its output and the list request. */
async function callWith([module, registrar, tool, args], pages, items = ITEMS) {
  // sophos_get_endpoint_group reads the group, then its endpoints page.
  const h = await harness(module, registrar, (path) =>
    path === `/endpoint/v1/endpoint-groups/${ID}`
      ? { id: ID, name: "G", type: "computer" }
      : { items, ...(pages === undefined ? {} : { pages }) }
  );
  try {
    const out = await h.call(tool, { tenant_id: TENANT, ...args });
    const list = h.requests.filter((r) => r.path !== `/endpoint/v1/endpoint-groups/${ID}`);
    assert.equal(list.length, 1, `${tool} sends one list request`);
    return { out, request: list[0] };
  } finally {
    await h.close();
  }
}

for (const row of TOOLS) {
  const [, , tool, , totalField = "total", pagesField = "total_pages"] = row;

  test(`${tool}: ${totalField} is pages.items and ${pagesField} is pages.total`, async () => {
    const out = await totalsFor(row, OFFSET.both);
    assert.equal(out[totalField], 5, "item count from pages.items");
    assert.equal(out[pagesField], 3, "page count from pages.total");
  });

  if (WHOLE_LIST.has(tool)) {
    test(`${tool}: the API returns the whole list, so ${totalField} is its length`, async () => {
      const out = await totalsFor(row, undefined);
      assert.equal(out[totalField], ITEMS.length);
      assert.equal(out[pagesField], undefined);
    });
    continue;
  }

  test(`${tool}: ${totalField} is null, never the page length, when the API sends no item count`, async () => {
    const out = await totalsFor(row, OFFSET.neither);
    assert.equal(out[totalField], null);
    assert.equal(out[pagesField], undefined);
  });

  test(`${tool}: a page count alone never becomes ${totalField}`, async () => {
    const out = await totalsFor(row, OFFSET.pagesOnly);
    assert.equal(out[totalField], null);
    assert.equal(out[pagesField], 3);
  });

  test(`${tool}: no pages at all means ${totalField} is 0`, async () => {
    // /endpoint/v1/settings/blocked-items answered this for an empty list, pageTotal=true or not.
    const out = await totalsFor(row, { current: 1, total: 0, maxSize: 50 }, []);
    assert.equal(out[totalField], 0);
    assert.equal(out[pagesField], 0);
  });

  if (NO_PAGE_TOTAL_PARAM.has(tool)) {
    test(`${tool}: sends no pageTotal, which its API does not take`, async () => {
      const { request } = await callWith(row, OFFSET.both);
      assert.equal(request.query.pageTotal, undefined);
    });
  } else {
    test(`${tool}: asks for the counts with pageTotal=true`, async () => {
      const { request } = await callWith(row, OFFSET.both);
      assert.equal(request.query.pageTotal, "true");
    });
  }
}

// The endpoint list pages by key and reports the page length as `count`, so
// its `total` stays null when the API sends no item count.
const ENDPOINTS = ["endpoints", "registerEndpointTools", "sophos_list_endpoints", {}];

test("sophos_list_endpoints: total is pages.items and total_pages is pages.total", async () => {
  const out = await totalsFor(ENDPOINTS, { nextKey: "k", size: 2, total: 2, items: 4, maxSize: 500 });
  assert.equal(out.count, 2);
  assert.equal(out.total, 4);
  assert.equal(out.total_pages, 2);
});

test("sophos_list_endpoints: asks for the counts with pageTotal=true on the first page and on a cursor page", async () => {
  const first = await callWith(ENDPOINTS, { nextKey: "k", size: 2, total: 2, items: 4, maxSize: 500 });
  assert.equal(first.request.query.pageTotal, "true");
  const next = await callWith(["endpoints", "registerEndpointTools", "sophos_list_endpoints", { cursor: "k" }], {
    fromKey: "k", nextKey: "l", size: 2, total: 2, items: 4, maxSize: 500,
  });
  assert.equal(next.request.query.pageTotal, "true");
  assert.equal(next.request.query.pageFromKey, "k");
  assert.equal(next.out.total, 4);
});

test("sophos_list_admins: a tenant with no admins answers with no items key and reports total 0", async () => {
  // /common/v1/admins live (02/11/2026): no items key at all; with pageTotal=true the page says items 0.
  const h = await harness("directory", "registerDirectoryTools", () => ({
    pages: { current: 1, size: 50, total: 0, items: 0, maxSize: 100 },
  }));
  try {
    const out = await h.call("sophos_list_admins", { tenant_id: TENANT });
    assert.equal(h.requests[0].query.pageTotal, "true");
    assert.equal(out.total, 0);
    assert.deepEqual(out.admins, []);
  } finally {
    await h.close();
  }
});

test("sophos_list_endpoints: no item count means total is null, never the page count", async () => {
  const keyOnly = await totalsFor(ENDPOINTS, { nextKey: "k", size: 2, maxSize: 500 });
  assert.equal(keyOnly.total, null);
  assert.equal(keyOnly.total_pages, undefined);
  const pagesOnly = await totalsFor(ENDPOINTS, { nextKey: "k", size: 2, total: 2, maxSize: 500 });
  assert.equal(pagesOnly.total, null);
  assert.equal(pagesOnly.total_pages, 2);
});
