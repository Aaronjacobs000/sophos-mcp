/**
 * Every list tool's truncation notice says how to reach the items it left
 * out. In 0.10.8 a list tool with no paging arguments could only say "cannot
 * page" (sophos_list_tenants, for one), and a few paged tools did not pass
 * their paging arguments. Now:
 *
 * - tools whose Sophos API pages, and lists a tool builds itself (tenants,
 *   account health, gap analysis, billing summary), take paging arguments and
 *   give an exact next request; reading by it returns every item once, in order
 * - tools whose API returns the list whole give no next request but name the
 *   arguments that narrow the list (narrow_with), or say there are none
 *
 * No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { jsonResult } from "../dist/tools/helpers.js";
import { CHARACTER_LIMIT } from "../dist/config/config.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const ID = "00000000-0000-4000-8000-0000000000a1";

const textOf = (result) => result.content.map((c) => c.text ?? "").join("");
const uuid = (i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`;
// Item i carries a string whose length varies with i, so pages differ in size.
const blob = (i) => "x".repeat(300 + ((i * 397) % 900));
const bulky = (i) => ({ id: uuid(i), name: `item-${String(i).padStart(4, "0")}`, description: blob(i) });
const many = (count) => Array.from({ length: count }, (_, i) => bulky(i));

/** Registers one tools module, partner caller, fetch answered by answer(url, method, body). */
async function harness(module, registrar, answer, resolverExtras = {}) {
  const mod = await import(`../dist/tools/${module}.js`);
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    calls.push({ method, path: u.pathname, query: Object.fromEntries(u.searchParams), headers: init?.headers });
    return new Response(JSON.stringify(answer(u, method, body, init) ?? {}), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const identity = { id: TENANT, idType: "partner", apiHosts: { global: "https://api.central.sophos.com" } };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => identity,
    getIdHeader: () => ({ name: "X-Partner-ID", value: TENANT }),
    ...resolverExtras,
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  if (registrar === "registerTenantTools") mod[registrar](server, tenantResolver);
  else mod[registrar](server, client, tenantResolver, { assertClassic: async () => [] });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = textOf(result);
      assert.ok(!result.isError, `${name} failed: ${text}`);
      assert.ok(text.length <= CHARACTER_LIMIT, `${name} returned ${text.length} characters`);
      return JSON.parse(text);
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

// --- The notice for a list that cannot page ---

test("a Narrowing gives no next request and names the arguments that narrow the list", () => {
  const out = JSON.parse(textOf(jsonResult({ total: 200, roles: many(200) }, { narrow_with: ["type", "principal_type"], note: "sophos_get_role reads one role." })));
  assert.equal(out.truncated.field, "roles");
  assert.equal(out.truncated.next, null);
  assert.deepEqual(out.truncated.narrow_with, ["type", "principal_type"]);
  assert.equal(
    out.truncated.how,
    "This tool cannot page to the omitted items. Narrow the request with type or principal_type to see them. sophos_get_role reads one role."
  );
  const three = JSON.parse(textOf(jsonResult({ sets: many(200) }, { narrow_with: ["type", "product", "access"] })));
  assert.match(three.truncated.how, /Narrow the request with type, product, or access to see them\.$/);
  const none = JSON.parse(textOf(jsonResult({ items: many(200) }, { narrow_with: [] })));
  assert.deepEqual(none.truncated.narrow_with, []);
  assert.equal(none.truncated.how, "This tool cannot page to the omitted items and has no argument that narrows the list.");
});

// --- Tools whose API returns the whole list: the notice names the narrowing ---

const NARROWED = [
  ["directory", "registerDirectoryTools", "sophos_list_roles", { tenant_id: TENANT }, ["type", "principal_type"]],
  ["admin-management", "registerAdminManagementTools", "sophos_list_permission_sets", { tenant_id: TENANT }, ["type", "product", "access"]],
  ["admin-management", "registerAdminManagementTools", "sophos_list_admin_role_assignments", { tenant_id: TENANT, admin_id: ID }, []],
  ["partner", "registerPartnerTools", "sophos_list_partner_roles", {}, ["type", "principal_type"]],
  ["partner", "registerPartnerTools", "sophos_list_partner_permission_sets", {}, ["type", "product", "access"]],
  ["partner", "registerPartnerTools", "sophos_list_partner_admin_role_assignments", { admin_id: ID }, []],
  ["cloud-security", "registerCloudSecurityTools", "sophos_list_cloud_security_default_contents", { tenant_id: TENANT }, []],
  ["endpoint-migrations", "registerEndpointMigrationTools", "sophos_list_recommended_packages", { tenant_id: TENANT }, []],
  ["endpoint-migrations", "registerEndpointMigrationTools", "sophos_list_static_packages", { tenant_id: TENANT }, ["endpoint_type", "platform", "type"]],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_installer_downloads", { tenant_id: TENANT }, []],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_web_control_categories", { tenant_id: TENANT }, []],
  ["endpoint-settings", "registerEndpointSettingsTools", "sophos_list_exploit_mitigation_categories", { tenant_id: TENANT }, []],
  ["firewall", "registerFirewallTools", "sophos_search_threat_feed_indicators", { tenant_id: TENANT, firewall_id: ID, indicator_values: ["1.2.3.4"] }, ["indicator_values"]],
  ["licensing", "registerLicensingTools", "sophos_list_licenses", { tenant_id: TENANT }, []],
  ["xdr", "registerXdrTools", "sophos_list_xdr_query_categories", { tenant_id: TENANT }, []],
];

for (const [module, registrar, tool, args, narrowWith] of NARROWED) {
  test(`${tool}: an oversized list names ${narrowWith.length ? narrowWith.join(", ") : "no argument"} to narrow it`, async () => {
    const h = await harness(module, registrar, () => ({ items: many(300) }));
    try {
      const out = await h.call(tool, args);
      assert.ok(out.truncated, "the list does not fit");
      assert.equal(out.truncated.next, null);
      assert.deepEqual(out.truncated.narrow_with, narrowWith);
      for (const name of narrowWith) assert.match(out.truncated.how, new RegExp(name));
    } finally {
      await h.close();
    }
  });
}

test("sophos_list_wifi_mac_filters and the mailbox alias and delegate lists say nothing narrows them", async () => {
  const addresses = Array.from({ length: 400 }, (_, i) => `${blob(i)}-${i}@example.test`);
  const wifi = await harness("wifi", "registerWifiTools", () => ({ macAddresses: addresses }));
  try {
    const out = await wifi.call("sophos_list_wifi_mac_filters", { tenant_id: TENANT });
    assert.deepEqual(out.truncated.narrow_with, []);
  } finally {
    await wifi.close();
  }
  const email = await harness("email", "registerEmailTools", () => ({ id: ID, email: "a@example.test", aliases: addresses, delegates: addresses }));
  try {
    for (const tool of ["sophos_list_mailbox_aliases", "sophos_list_mailbox_delegates"]) {
      const out = await email.call(tool, { tenant_id: TENANT, mailbox_id: ID });
      assert.equal(out.truncated.next, null);
      assert.deepEqual(out.truncated.narrow_with, []);
    }
  } finally {
    await email.close();
  }
});

test("the permission set lists send type, product and access to Sophos", async () => {
  const common = await harness("admin-management", "registerAdminManagementTools", () => ({ items: [] }));
  try {
    await common.call("sophos_list_permission_sets", { tenant_id: TENANT, type: "product", product: "endpoint", access: "readOnly" });
    assert.equal(common.calls[0].path, "/common/v1/roles/permission-sets");
    assert.deepEqual(common.calls[0].query, { type: "product", product: "endpoint", access: "readOnly" });
    await common.call("sophos_list_permission_sets", { tenant_id: TENANT });
    assert.deepEqual(common.calls[1].query, {});
  } finally {
    await common.close();
  }
  const partner = await harness("partner", "registerPartnerTools", () => ({ items: [] }));
  try {
    await partner.call("sophos_list_partner_permission_sets", { type: "setting", access: "admin" });
    assert.equal(partner.calls[0].path, "/partner/v1/roles/permission-sets");
    assert.deepEqual(partner.calls[0].query, { type: "setting", access: "admin" });
  } finally {
    await partner.close();
  }
});

// --- Tools that gained paging: the request carries it and next reads everything ---

const ALL = many(260);

// page and pageSize select a slice of ALL.
const offsetApi = (u) => {
  const size = Number(u.searchParams.get("pageSize"));
  const current = Number(u.searchParams.get("page"));
  return { items: ALL.slice((current - 1) * size, current * size), pages: { current, size, total: Math.ceil(ALL.length / size), items: ALL.length } };
};

// pageFromKey is the index of the first item.
const keyApi = (u) => {
  const size = Number(u.searchParams.get("pageSize"));
  const from = Number(u.searchParams.get("pageFromKey") ?? 0);
  const end = Math.min(from + size, ALL.length);
  return { items: ALL.slice(from, end), pages: { size, items: ALL.length, ...(end < ALL.length ? { nextKey: String(end) } : {}) } };
};

/**
 * Reads a page-numbered tool to the end through its truncation notices: next
 * through next_through_page at the smaller size, then resume. Returns the IDs
 * in the order first seen and the number of truncated pages.
 */
async function readAllByPage(h, tool, args, sizeKey, { items = (out) => out.items, page = (out) => out.pages.current, totalPages = (out) => out.pages.total } = {}) {
  const ids = [];
  const pending = [];
  let truncations = 0;
  let request = { ...args };
  for (let calls = 1; calls <= 300; calls++) {
    const out = await h.call(tool, request);
    for (const item of items(out)) if (!ids.includes(item.id)) ids.push(item.id);
    if (out.truncated) {
      truncations++;
      assert.ok(out.truncated.next, `${tool} names the next request`);
      pending.push({ size: out.truncated.next[sizeKey], through: out.truncated.next_through_page, resume: out.truncated.resume });
      request = { ...request, ...out.truncated.next };
      continue;
    }
    if (page(out) >= totalPages(out)) return { ids, truncations };
    request = { ...request, page: page(out) + 1 };
    while (pending.length && request[sizeKey] === pending.at(-1).size && request.page > pending.at(-1).through) {
      const done = pending.pop();
      if (!done.resume) return { ids, truncations };
      request = { ...request, ...done.resume };
    }
  }
  assert.fail(`${tool} did not reach the end of the list`);
}

const PAGED = [
  ["mobile", "registerMobileTools", "sophos_list_mobile_os", { tenant_id: TENANT, page_size: 100 }, "/mobile/v1/operating-systems", "page_size"],
  ["mobile", "registerMobileTools", "sophos_list_mobile_device_properties", { tenant_id: TENANT, device_id: ID, page_size: 100 }, `/mobile/v1/devices/${ID}/properties`, "page_size"],
  ["mobile", "registerMobileTools", "sophos_get_mobile_device_compliance", { tenant_id: TENANT, device_id: ID, page_size: 100 }, `/mobile/v1/devices/${ID}/compliance-violations`, "page_size"],
  ["mobile", "registerMobileTools", "sophos_get_mobile_device_scans", { tenant_id: TENANT, device_id: ID, page_size: 100 }, `/mobile/v1/devices/${ID}/scan-results`, "page_size"],
  ["mobile", "registerMobileTools", "sophos_get_mobile_device_policies", { tenant_id: TENANT, device_id: ID, page_size: 100 }, `/mobile/v1/devices/${ID}/policies`, "page_size"],
  ["mobile", "registerMobileTools", "sophos_get_mobile_device_apps", { tenant_id: TENANT, device_id: ID, page_size: 100 }, `/mobile/v1/devices/${ID}/installed-apps`, "page_size"],
  ["firewall", "registerFirewallTools", "sophos_get_firewall_sync_status", { tenant_id: TENANT, group_id: ID, limit: 100 }, `/firewall/v1/firewall-groups/${ID}/firewalls/sync-status`, "limit"],
  ["web-filtering", "registerWebFilteringTools", "sophos_list_web_filtering_profiles", { tenant_id: TENANT, limit: 100 }, "/web-filters/v1/profiles", "limit"],
];

for (const [module, registrar, tool, args, path, sizeKey] of PAGED) {
  test(`${tool}: pages with page and ${sizeKey}, and every item arrives in order through the truncation notices`, async () => {
    const h = await harness(module, registrar, (u) => {
      assert.equal(u.pathname, path);
      return offsetApi(u);
    });
    try {
      const { ids, truncations } = await readAllByPage(h, tool, args, sizeKey);
      assert.ok(truncations > 0, "a page of 100 does not fit");
      assert.deepEqual(ids, ALL.map((item) => item.id));
      assert.deepEqual(
        { page: h.calls[0].query.page, pageSize: h.calls[0].query.pageSize, pageTotal: h.calls[0].query.pageTotal },
        { page: "1", pageSize: "100", pageTotal: "true" }
      );
    } finally {
      await h.close();
    }
  });
}

test("the S/MIME certificate lists pass their key paging, and next repeats at the size that fit", async () => {
  const paths = {
    sophos_list_smime_internal_users: "/email/v1/smime/users/internal",
    sophos_list_smime_external_users: "/email/v1/smime/users/external",
    sophos_list_smime_external_cas: "/email/v1/smime/cas/external",
  };
  for (const [tool, path] of Object.entries(paths)) {
    const h = await harness("email-smime", "registerEmailSmimeTools", (u) => {
      assert.equal(u.pathname, path);
      return keyApi(u);
    });
    try {
      const ids = [];
      let truncations = 0;
      let request = { tenant_id: TENANT, page_size: 200 };
      for (let calls = 0; calls < 100; calls++) {
        const out = await h.call(tool, request);
        for (const item of out.items) if (!ids.includes(item.id)) ids.push(item.id);
        if (out.truncated) {
          truncations++;
          assert.equal(out.truncated.next.page_size, out.truncated.returned);
          request = { tenant_id: TENANT, ...out.truncated.next };
          continue;
        }
        if (!out.pages.nextKey) break;
        request = { tenant_id: TENANT, page_from_key: out.pages.nextKey, page_size: 200 };
      }
      assert.ok(truncations > 0, `${tool}: a page of 200 does not fit`);
      assert.deepEqual(ids, ALL.map((item) => item.id), tool);
    } finally {
      await h.close();
    }
  }
});

/** Reads an offset-paged tool from offset 0 through its truncation notices. */
async function readAllByOffset(h, tool, args, field) {
  const ids = [];
  let truncations = 0;
  let request = { ...args };
  for (let calls = 1; calls <= 100; calls++) {
    const out = await h.call(tool, request);
    for (const item of out[field]) ids.push(item.id ?? item.tenant_id ?? item.accountId);
    if (!out.truncated) return { ids, truncations, last: out };
    truncations++;
    assert.equal(out.truncated.next.offset, (request.offset ?? 0) + out.truncated.returned);
    request = { ...request, ...out.truncated.next };
  }
  assert.fail(`${tool} did not reach the end of the list`);
}

test("sophos_list_tenants: offset and limit page the tenant list, and the notice's next reads all of it", async () => {
  const tenants = Array.from({ length: 300 }, (_, i) => ({
    id: uuid(i),
    name: `Tenant ${String(i).padStart(3, "0")} ${blob(i)}`,
    dataRegion: "au01",
    dataGeography: "AU",
    apiHost: HOST,
  }));
  const h = await harness("tenants", "registerTenantTools", () => ({}), { loadTenants: async () => tenants });
  try {
    const { ids, truncations } = await readAllByOffset(h, "sophos_list_tenants", {}, "tenants");
    assert.ok(truncations > 0, "300 tenants do not fit");
    assert.deepEqual(ids, tenants.map((t) => t.id));

    const slice = await h.call("sophos_list_tenants", { offset: 10, limit: 5 });
    assert.equal(slice.total, 300);
    assert.deepEqual(slice.tenants.map((t) => t.id), tenants.slice(10, 15).map((t) => t.id));

    const filtered = await h.call("sophos_list_tenants", { name_filter: "tenant 29", limit: 3 });
    assert.equal(filtered.total, 10, "Tenant 290 to 299");
    assert.deepEqual(filtered.tenants.map((t) => t.id), [uuid(290), uuid(291), uuid(292)]);
  } finally {
    await h.close();
  }
});

test("sophos_list_account_health and sophos_partner_gap_analysis page their ranking with offset", async () => {
  const tenants = Array.from({ length: 120 }, (_, i) => ({ id: uuid(i), name: `Tenant ${i}` }));
  // Tenant i scores 100 - (i % 60); the detail block makes the full list too big.
  const health = (i) => ({
    endpoint: {
      protection: { computer: { score: 100 - (i % 60), total: 10 }, server: { score: 100 - (i % 60), total: 2 } },
      detail: blob(i).repeat(2),
    },
  });
  const h = await harness(
    "health",
    "registerHealthTools",
    (u, method, body, init) => {
      const tenant = new Headers(init?.headers).get("X-Tenant-ID");
      return health(Number(tenant.slice(-12)));
    },
    { getCachedTenants: () => tenants }
  );
  try {
    const whole = await readAllByOffset(h, "sophos_list_account_health", {}, "tenants");
    assert.ok(whole.truncations > 0, "120 health blocks do not fit");
    assert.equal(whole.ids.length, 120);
    assert.equal(new Set(whole.ids).size, 120, "no tenant twice");

    const top = await h.call("sophos_list_account_health", { limit: 10 });
    const next = await h.call("sophos_list_account_health", { offset: 10, limit: 10 });
    assert.deepEqual([...top.tenants, ...next.tenants].map((t) => t.tenant_id), whole.ids.slice(0, 20));
    const scores = whole.ids.map((id) => 100 - (Number(id.slice(-12)) % 60));
    assert.deepEqual(scores, [...scores].sort((a, b) => a - b), "lowest score first");

    const gaps = await h.call("sophos_partner_gap_analysis", { protection_threshold: 99, limit: 5 });
    const gapsNext = await h.call("sophos_partner_gap_analysis", { protection_threshold: 99, offset: 5, limit: 5 });
    const gapsAll = await h.call("sophos_partner_gap_analysis", { protection_threshold: 99 });
    assert.deepEqual(
      [...gaps.tenants_with_gaps, ...gapsNext.tenants_with_gaps].map((t) => t.tenant_id),
      gapsAll.tenants_with_gaps.slice(0, 10).map((t) => t.tenant_id)
    );
    assert.equal(gapsNext.summary.total_tenants, 120, "the summary still covers every tenant");
  } finally {
    await h.close();
  }
});

test("sophos_get_billing_summary: offset pages the ranking, ranks continue, and the notice's next reads every customer", async () => {
  // Customer i bills 1000 - i, one line per product, 6 products each.
  const lines = [];
  for (let i = 0; i < 150; i++) {
    for (let p = 0; p < 6; p++) {
      lines.push({
        assignedAccountIdentifier: `Customer ${String(i).padStart(3, "0")}`,
        accountId: uuid(i),
        billableQuantity: 1,
        unitPrice: (1000 - i) / 6,
        productGroup: "User",
        productDescription: `Product ${p} ${"y".repeat(60)}`,
        productCode: `P${p}`,
      });
    }
  }
  const h = await harness("partner", "registerPartnerTools", (u) => {
    assert.equal(u.pathname, "/partner/v1/billing/usage/2026/10");
    return { items: lines, pages: { items: lines.length } };
  });
  try {
    const { ids, truncations } = await readAllByOffset(h, "sophos_get_billing_summary", { year: 2026, month: 10 }, "customers");
    assert.ok(truncations > 0, "150 customers with product breakdowns do not fit");
    assert.deepEqual(ids, Array.from({ length: 150 }, (_, i) => uuid(i)));

    const second = await h.call("sophos_get_billing_summary", { year: 2026, month: 10, offset: 20, limit: 5, compact: true });
    assert.deepEqual(second.customers.map((c) => c.rank), [21, 22, 23, 24, 25]);
    assert.deepEqual(second.customers.map((c) => c.accountId), [20, 21, 22, 23, 24].map(uuid));
    assert.equal(second.totalCustomers, 150);
  } finally {
    await h.close();
  }
});
