/**
 * Request shapes for the tools fixed in the 13/10/2026 audit against the
 * published Sophos specs (and the live API where the two disagree). Each case
 * calls a tool through its real handler with fetch stubbed and checks the
 * exact method, path, query and body sent. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const A = "00000000-0000-4000-8000-0000000000a1";
const B = "00000000-0000-4000-8000-0000000000b1";
const C = "00000000-0000-4000-8000-0000000000c1";

/**
 * Registers one tools module on a real SophosClient. `answer(method, path, query)`
 * returns the JSON body for a request (default {}).
 */
async function harness(modulePath, registrar, answer = () => ({})) {
  const mod = await import(modulePath);
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    const query = Object.fromEntries(u.searchParams);
    calls.push({ method, path: u.pathname, query, body });
    return new Response(JSON.stringify(answer(method, u.pathname, query, body) ?? {}), {
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
  mod[registrar](server, client, tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = result.content.map((c) => c.text ?? "").join("\n");
      return { isError: Boolean(result.isError), text, json: result.isError ? null : JSON.parse(text) };
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

const sent = (h) => h.calls.map(({ method, path, query, body }) => ({ method, path, query, body }));
const req = (method, path, body, query = {}) => ({ method, path, query, body });

test("email quarantine tools use the /quarantine/messages routes and batch bodies", async () => {
  const h = await harness("../dist/tools/email.js", "registerEmailTools", (m, p) =>
    p.endsWith("/attachments/download") ? { id: "job", status: "done", url: "https://example.invalid/x" } : {}
  );
  try {
    await h.call("sophos_search_quarantine", {
      begin_date: "2026-10-01T00:00:00Z",
      end_date: "2026-10-13T00:00:00Z",
      subject_contains: "invoice",
      reason: ["spam"],
      direction: "inbound",
      sort: ["quarantinedAt:desc"],
      page_from_key: "k1",
    });
    await h.call("sophos_preview_quarantine_message", { message_id: A });
    await h.call("sophos_release_quarantine_message", { message_ids: [A, B], allow_sender: true, for_recipients: ["zz@example.com"] });
    await h.call("sophos_delete_quarantine_message", { message_ids: [A], block_sender: true });
    await h.call("sophos_strip_quarantine_attachments", { message_id: A, attachments: ["x.exe"] });
    await h.call("sophos_download_quarantine_attachment", { message_id: A });
    assert.deepEqual(sent(h), [
      req("POST", "/email/v1/quarantine/messages/search", {
        beginDate: "2026-10-01T00:00:00Z",
        endDate: "2026-10-13T00:00:00Z",
        pageSize: 50,
        filter: { subjectContains: "invoice", reason: ["spam"], direction: "inbound" },
        sort: ["quarantinedAt:desc"],
        pageFromKey: "k1",
      }),
      req("GET", `/email/v1/quarantine/messages/${A}/preview`),
      req("POST", "/email/v1/quarantine/messages/release", {
        items: [
          { id: A, forRecipients: ["zz@example.com"] },
          { id: B, forRecipients: ["zz@example.com"] },
        ],
        allowSender: true,
      }),
      req("POST", "/email/v1/quarantine/messages/delete", { items: [{ id: A }], blockSender: true }),
      req("POST", `/email/v1/quarantine/messages/${A}/attachments/strip`, { attachments: ["x.exe"] }),
      req("POST", `/email/v1/quarantine/messages/${A}/attachments/download`, {}),
    ]);
  } finally {
    await h.close();
  }
});

test("email clawback, status and post-delivery release use the spec routes", async () => {
  const h = await harness("../dist/tools/email.js", "registerEmailTools");
  try {
    await h.call("sophos_clawback_message", { message_id: A, reason: "phishing" });
    await h.call("sophos_get_clawback_status", { message_id: A });
    await h.call("sophos_search_post_delivery_quarantine", { begin_date: "2026-10-01T00:00:00Z", end_date: "2026-10-13T00:00:00Z", page: 2 });
    await h.call("sophos_release_post_delivery_message", { message_ids: [A] });
    assert.deepEqual(sent(h), [
      req("POST", `/email/v1/messages/${A}/clawback`, { reason: "phishing" }),
      req("GET", `/email/v1/messages/${A}/status`),
      req("POST", "/email/v1/post-delivery-quarantine/messages/search", {
        beginDate: "2026-10-01T00:00:00Z",
        endDate: "2026-10-13T00:00:00Z",
        page: 2,
        pageSize: 50,
      }),
      req("POST", "/email/v1/post-delivery-quarantine/messages/release", { items: [{ id: A }] }),
    ]);
  } finally {
    await h.close();
  }
});

test("mailbox tools send type, email and name, and change aliases with add/remove lists", async () => {
  const h = await harness("../dist/tools/email.js", "registerEmailTools", (m, p) =>
    m === "GET" && p.endsWith(A) ? { id: A, email: "zz@example.com", aliases: ["a@example.com"], delegates: [] } : {}
  );
  try {
    await h.call("sophos_create_mailbox", { email: "zz@example.com", name: "ZZ", type: "user" });
    await h.call("sophos_bulk_create_mailboxes", { mailboxes: [{ email: "zz2@example.com", name: "ZZ2", type: "sharedMailbox" }] });
    await h.call("sophos_update_mailbox", { mailbox_id: A, name: "ZZ 2" });
    await h.call("sophos_add_mailbox_alias", { mailbox_id: A, addresses: ["b@example.com"] });
    await h.call("sophos_delete_mailbox_delegate", { mailbox_id: A, addresses: ["c@example.com"] });
    const aliases = await h.call("sophos_list_mailbox_aliases", { mailbox_id: A });
    await h.call("sophos_list_mailboxes", { email_starts_with: "zz", page_from_key: "k" });
    assert.deepEqual(sent(h), [
      req("POST", "/email/v1/mailboxes", { type: "user", email: "zz@example.com", name: "ZZ" }),
      req("POST", "/email/v1/mailboxes/bulk", { items: [{ type: "sharedMailbox", email: "zz2@example.com", name: "ZZ2" }] }),
      req("PATCH", `/email/v1/mailboxes/${A}`, { name: "ZZ 2" }),
      req("POST", `/email/v1/mailboxes/${A}/aliases`, { add: ["b@example.com"] }),
      req("POST", `/email/v1/mailboxes/${A}/delegates`, { remove: ["c@example.com"] }),
      req("GET", `/email/v1/mailboxes/${A}`),
      req("GET", "/email/v1/mailboxes", undefined, { pageSize: "50", emailStartsWith: "zz", pageFromKey: "k" }),
    ]);
    assert.deepEqual(aliases.json.aliases, ["a@example.com"]);
  } finally {
    await h.close();
  }
});

test("alerts page by key, and the search sends flat filters", async () => {
  const h = await harness("../dist/tools/alerts.js", "registerAlertTools", () => ({ items: [], pages: { size: 0, maxSize: 1000, nextKey: "next" } }));
  try {
    const list = await h.call("sophos_list_alerts", { severity: "high", page_from_key: "k1" });
    await h.call("sophos_search_alerts", { severity: ["high"], category: ["malware"], sort: ["raisedAt:desc"], page_from_key: "k2" });
    assert.deepEqual(sent(h), [
      req("GET", "/common/v1/alerts", undefined, { pageSize: "50", pageTotal: "true", pageFromKey: "k1", severity: "high" }),
      req("POST", "/common/v1/alerts/search", {
        pageSize: 50,
        pageTotal: true,
        severity: ["high"],
        category: ["malware"],
        sort: ["raisedAt:desc"],
        pageFromKey: "k2",
      }),
    ]);
    assert.equal(list.json.next_page_from_key, "next");
  } finally {
    await h.close();
  }
});

test("endpoint actions send the spec bodies", async () => {
  const h = await harness("../dist/tools/endpoints.js", "registerEndpointTools");
  try {
    await h.call("sophos_bulk_delete_endpoints", { ids: [A] });
    await h.call("sophos_request_forensic_logs", { endpoint_id: A, expires: "PT1H" });
    await h.call("sophos_request_memory_dump", { endpoint_id: A, mode: "process", expires: "PT30M", image_name: "lsass.exe" });
    const refused = await h.call("sophos_request_memory_dump", { endpoint_id: A, mode: "process", expires: "PT30M" });
    const badDuration = await h.call("sophos_request_forensic_logs", { endpoint_id: A, expires: "1 hour" });
    assert.deepEqual(sent(h), [
      req("POST", "/endpoint/v1/endpoints/delete", { endpointIds: [A] }),
      req("POST", `/endpoint/v1/endpoints/${A}/forensic-logs`, { mode: "standard", expires: "PT1H" }),
      req("POST", `/endpoint/v1/endpoints/${A}/memory-dumps`, { mode: "process", expires: "PT30M", imageName: "lsass.exe" }),
    ]);
    assert.match(refused.text, /needs pid or image_name/);
    assert.match(badDuration.text, /Input validation error/);
  } finally {
    await h.close();
  }
});

test("endpoint settings: blocked addresses in bulk, IPS and isolation exclusions, TLS categories", async () => {
  const h = await harness("../dist/tools/endpoint-settings.js", "registerEndpointSettingsTools");
  try {
    await h.call("sophos_add_blocked_address", { addresses: ["203.0.113.7", "198.51.100.0/24"], comment: "ZZ", expire_in_days: 7 });
    await h.call("sophos_delete_blocked_address", { address_ids: [A] });
    await h.call("sophos_add_ips_exclusion", { direction: "inbound", remote_address: "203.0.113.7", local_port: 443 });
    await h.call("sophos_add_isolation_exclusion", { direction: "both", remote_addresses: ["203.0.113.7"], remote_ports: [443] });
    await h.call("sophos_update_tls_decryption_settings", { categories: [{ id: 14, decryption_enabled: false }] });
    await h.call("sophos_get_exploit_mitigation_category", { category_id: "java" });
    await h.call("sophos_list_exploit_mitigation_categories", {});
    assert.deepEqual(sent(h), [
      req("POST", "/endpoint/v1/settings/blocked-addresses/bulk", {
        items: [
          { item: "203.0.113.7", comment: "ZZ", expireInDays: 7 },
          { item: "198.51.100.0/24", comment: "ZZ", expireInDays: 7 },
        ],
      }),
      req("POST", "/endpoint/v1/settings/blocked-addresses/bulk/delete", { ids: [A] }),
      req("POST", "/endpoint/v1/settings/exclusions/intrusion-prevention", { direction: "inbound", remoteAddresses: ["203.0.113.7"], localPorts: [443] }),
      req("POST", "/endpoint/v1/settings/exclusions/isolation", { direction: "both", remoteAddresses: ["203.0.113.7"], remotePorts: [443] }),
      req("PATCH", "/endpoint/v1/settings/web-control/tls-decryption", { categories: [{ id: 14, decryptionEnabled: false }] }),
      req("GET", "/endpoint/v1/settings/exploit-mitigation/categories/java"),
      req("GET", "/endpoint/v1/settings/exploit-mitigation/categories"),
    ]);
  } finally {
    await h.close();
  }
});

test("allowed and blocked items need a comment; scanning exclusions send comment, not description", async () => {
  const h = await harness("../dist/tools/exclusions.js", "registerExclusionTools", () => ({ id: A, properties: {} }));
  try {
    const noComment = await h.call("sophos_add_allowed_item", { type: "sha256", properties: { sha256: "ab" } });
    assert.match(noComment.text, /Input validation error/);
    await h.call("sophos_add_blocked_item", { properties: { sha256: "ab" }, comment: "ZZ" });
    await h.call("sophos_add_exclusion", { type: "web", value: "example.com", comment: "ZZ" });
    assert.deepEqual(sent(h), [
      req("POST", "/endpoint/v1/settings/blocked-items", { type: "sha256", properties: { sha256: "ab" }, comment: "ZZ" }),
      req("POST", "/endpoint/v1/settings/exclusions/scanning", { type: "web", value: "example.com", comment: "ZZ" }),
    ]);
  } finally {
    await h.close();
  }
});

test("migrations: the receiving side POSTs, the sending side PUTs to the job", async () => {
  const h = await harness("../dist/tools/endpoint-migrations.js", "registerEndpointMigrationTools");
  try {
    await h.call("sophos_create_migration", { side: "receiving", from_tenant: B, endpoints: [A] });
    await h.call("sophos_create_migration", { side: "sending", migration_id: C, token: "t0k", endpoints: [A] });
    const missing = await h.call("sophos_create_migration", { side: "sending", endpoints: [A] });
    await h.call("sophos_list_static_packages", { platform: "windows" });
    await h.call("sophos_list_recommended_packages", {});
    assert.deepEqual(sent(h), [
      req("POST", "/endpoint/v1/migrations", { fromTenant: B, endpoints: [A] }),
      req("PUT", `/endpoint/v1/migrations/${C}`, { token: "t0k", endpoints: [A] }),
      req("GET", "/endpoint/v1/software/packages/static", undefined, { platform: "windows" }),
      req("GET", "/endpoint/v1/software/packages/recommended"),
    ]);
    assert.match(missing.text, /needs migration_id and token/);
  } finally {
    await h.close();
  }
});

test("user group policies come from the policy list, filtered by the group", async () => {
  const h = await harness("../dist/tools/directory.js", "registerDirectoryTools", (m, p, q) =>
    p === "/endpoint/v1/policies"
      ? q.page === "1"
        ? { items: [{ id: A, name: "P1", type: "web-control", enabled: true, priority: 1, appliesTo: { users: [], userGroups: [B] } }], pages: { total: 2 } }
        : { items: [{ id: C, name: "P2", type: "threat-protection", enabled: true, priority: 2, appliesTo: { users: [], userGroups: [] } }], pages: { total: 2 } }
      : {}
  );
  try {
    const { json } = await h.call("sophos_list_user_group_policies", { group_id: B });
    assert.deepEqual(json.policies, [{ id: A, name: "P1", type: "web-control", enabled: true, priority: 1 }]);
    assert.equal(h.calls.length, 2, "both pages read");
    await h.call("sophos_list_roles", { type: "custom" });
    assert.deepEqual(h.calls.at(-1).query, { type: "custom" });
  } finally {
    await h.close();
  }
});

test("admins are created from a directory user; roles carry principal type and permission sets", async () => {
  const h = await harness("../dist/tools/admin-management.js", "registerAdminManagementTools");
  try {
    await h.call("sophos_create_admin", { user_id: A, role_id: B });
    await h.call("sophos_create_role", { name: "ZZ", principal_type: "user", permission_sets: ["central_readonly", "endpoint_product_readonly"] });
    await h.call("sophos_update_role", { role_id: B, permission_sets: ["central_readonly"] });
    assert.deepEqual(sent(h), [
      req("POST", "/common/v1/admins", { userId: A, roleAssignments: [{ roleId: B }] }),
      req("POST", "/common/v1/roles", { name: "ZZ", principalType: "user", permissionSets: ["central_readonly", "endpoint_product_readonly"] }),
      // The live API takes the plain array on PATCH (13/10/2026); the spec's object forms get 400
      req("PATCH", `/common/v1/roles/${B}`, { permissionSets: ["central_readonly"] }),
    ]);
  } finally {
    await h.close();
  }
});

test("partner tools send the spec bodies, and billing pages by key without re-reading page one", async () => {
  let pages = 0;
  const h = await harness("../dist/tools/partner.js", "registerPartnerTools", (m, p, q) => {
    if (p.startsWith("/partner/v1/billing/usage")) {
      pages++;
      return q.pageFromKey === "k2"
        ? { items: [{ assignedAccountIdentifier: "Two", billableQuantity: 1, unitPrice: 1 }], pages: {} }
        : { items: [{ assignedAccountIdentifier: "One", billableQuantity: 1, unitPrice: 1 }], pages: { nextKey: "k2" } };
    }
    return {};
  });
  try {
    await h.call("sophos_create_tenant", {
      name: "ZZ", billing_type: "trial", contact_first_name: "Z", contact_last_name: "Z", contact_phone: "+61200000000",
      address1: "1 Test St", city: "Wollongong", country_code: "AU", postal_code: "2500",
    });
    await h.call("sophos_create_partner_admin", {
      username: "zz@example.com", first_name: "Z", last_name: "Z",
      role_assignments: [{ role_id: A, scope_type: "allManagedTenants" }],
    });
    await h.call("sophos_create_partner_role", { name: "ZZ", principal_type: "user", permission_sets: ["x"] });
    await h.call("sophos_add_partner_admin_role_assignment", { admin_id: A, role_id: B, scope_type: "tenant", scope_id: C });
    const writes = sent(h).filter((c) => c.method !== "GET");
    assert.deepEqual(writes, [
      req("POST", "/partner/v1/tenants", {
        name: "ZZ",
        billingType: "trial",
        contact: { firstName: "Z", lastName: "Z", phone: "+61200000000", address: { address1: "1 Test St", city: "Wollongong", countryCode: "AU", postalCode: "2500" } },
      }),
      req("POST", "/partner/v1/admins", {
        username: "zz@example.com",
        profile: { name: "Z Z", firstName: "Z", lastName: "Z" },
        roleAssignments: [{ roleId: A, scope: { type: "allManagedTenants" } }],
      }),
      req("POST", "/partner/v1/roles", { name: "ZZ", principalType: "user", permissionSets: ["x"] }),
      req("POST", `/partner/v1/admins/${A}/role-assignments`, { roleId: B, scope: { type: "tenant", id: C } }),
    ]);

    await h.call("sophos_get_billing_usage", { year: 2026, month: 9, cursor: "k2" });
    assert.equal(h.calls.at(-1).query.pageFromKey, "k2");
    pages = 0;
    const summary = await h.call("sophos_get_billing_summary", { year: 2026, month: 9 });
    assert.equal(pages, 2, "two distinct pages, then stop");
    assert.match(summary.text, /One/);
    assert.match(summary.text, /Two/);
  } finally {
    await h.close();
  }
});

test("firewall groups: create needs assignFirewalls, a single group is found through the list, a firewall moves through its group", async () => {
  const h = await harness("../dist/tools/firewall.js", "registerFirewallTools", (m, p) =>
    m === "GET" && p === "/firewall/v1/firewall-groups" ? { items: [{ id: B, name: "ZZ" }], pages: { total: 1 } } : {}
  );
  try {
    await h.call("sophos_create_firewall_group", { name: "ZZ" });
    const group = await h.call("sophos_get_firewall_group", { group_id: B });
    await h.call("sophos_update_firewall", { firewall_id: A, name: "fw1", group_id: B });
    await h.call("sophos_search_threat_feed_indicators", { firewall_id: A, indicator_values: ["203.0.113.7"] });
    await h.call("sophos_update_threat_feed_settings", { firewall_id: A, action: "logOnly" });
    assert.deepEqual(group.json, { id: B, name: "ZZ" });
    assert.deepEqual(sent(h).filter((c) => c.method !== "GET"), [
      req("POST", "/firewall/v1/firewall-groups", { name: "ZZ", assignFirewalls: [] }),
      req("PATCH", `/firewall/v1/firewalls/${A}`, { name: "fw1" }),
      req("PATCH", `/firewall/v1/firewall-groups/${B}`, { assignFirewalls: [A] }),
      req("POST", `/firewall/v1/firewall-config/firewalls/${A}/mdr-threat-feed/indicators/search`, { indicatorValues: ["203.0.113.7"] }),
      req("PATCH", `/firewall/v1/firewall-config/firewalls/${A}/mdr-threat-feed/settings`, { action: "logOnly" }),
    ]);
  } finally {
    await h.close();
  }
});

test("DNS locations send ipAddresses and domainNames; updates take full lists or add/remove", async () => {
  const h = await harness("../dist/tools/dns-protection.js", "registerDnsProtectionTools");
  try {
    await h.call("sophos_create_dns_location", { name: "ZZ office", ip_addresses: ["203.0.113.7"] });
    await h.call("sophos_update_dns_location", { location_id: A, add_ip_addresses: ["203.0.113.8"], domain_names: ["example.com"] });
    const both = await h.call("sophos_update_dns_location", { location_id: A, ip_addresses: ["x"], add_ip_addresses: ["y"] });
    assert.deepEqual(sent(h), [
      req("POST", "/dns-protection/v2/locations", { name: "ZZ office", ipAddresses: ["203.0.113.7"] }),
      req("PATCH", `/dns-protection/v2/locations/${A}`, { ipAddresses: { add: ["203.0.113.8"] }, domainNames: ["example.com"] }),
    ]);
    assert.match(both.text, /not both/);
  } finally {
    await h.close();
  }
});

test("Wi-Fi MAC filtering reads the list and PUTs it back", async () => {
  const h = await harness("../dist/tools/wifi.js", "registerWifiTools", (m, p, q, body) =>
    m === "GET" ? { macAddresses: ["00:11:22:33:44:55"] } : body
  );
  try {
    await h.call("sophos_add_wifi_mac_filter", { mac_addresses: ["00:11:22:33:44:66", "00-11-22-33-44-55"] });
    await h.call("sophos_delete_wifi_mac_filter", { mac_addresses: ["00:11:22:33:44:55"] });
    const none = await h.call("sophos_delete_wifi_mac_filter", { mac_addresses: ["00:11:22:33:44:77"] });
    assert.deepEqual(sent(h).filter((c) => c.method === "PUT"), [
      req("PUT", "/wifi/v1/settings/mac-filtering", { macAddresses: ["00:11:22:33:44:55", "00:11:22:33:44:66"] }),
      req("PUT", "/wifi/v1/settings/mac-filtering", { macAddresses: [] }),
    ]);
    assert.equal(none.json.status, "unchanged");
  } finally {
    await h.close();
  }
});

test("mobile actions wrap their options in arguments; the device list filters by platform and compliance", async () => {
  const h = await harness("../dist/tools/mobile.js", "registerMobileTools");
  try {
    await h.call("sophos_lock_mobile_device", { device_id: A, message: "Call IT", pin: "123456" });
    await h.call("sophos_locate_mobile_device", { device_id: A, reason: "Lost" });
    await h.call("sophos_wipe_mobile_device", { device_id: A, preserve_data_plan: true });
    await h.call("sophos_send_mobile_device_message", { device_id: A, message: "Hi" });
    await h.call("sophos_list_mobile_devices", { platform: "android", compliant: false });
    assert.deepEqual(sent(h), [
      req("POST", "/mobile/v1/actions/lock", { endpoints: [A], arguments: { lockScreenMessage: "Call IT", lockCode: "123456" } }),
      req("POST", "/mobile/v1/actions/locate", { endpoints: [A], arguments: { reason: "Lost" } }),
      req("POST", "/mobile/v1/actions/wipe", { endpoints: [A], arguments: { preserveDataPlan: true } }),
      req("POST", "/mobile/v1/actions/send-message", { endpoints: [A], arguments: { message: "Hi" } }),
      req("GET", "/mobile/v1/devices", undefined, { page: "1", pageSize: "50", platform: "android", compliant: "false" }),
    ]);
  } finally {
    await h.close();
  }
});

test("attestations, XDR cancel and the cloud security content lookup use the spec routes", async () => {
  const ua = await harness("../dist/tools/user-activity.js", "registerUserActivityTools");
  try {
    await ua.call("sophos_create_attestation", {
      user_id: A, title: "Check", question: "Was this you?", options: [{ key: "yes", text: "Yes" }], timeout_in_seconds: 600,
    });
    await ua.call("sophos_get_attestation", { attestation_id: B });
    assert.deepEqual(sent(ua), [
      req("POST", "/user-activity-verification/v1/attestations", {
        userId: A,
        title: { text: "Check" },
        question: { text: "Was this you?" },
        options: [{ key: "yes", value: { text: "Yes" } }],
        timeoutInSeconds: 600,
      }),
      req("GET", `/user-activity-verification/v1/attestations/${B}`),
    ]);
  } finally {
    await ua.close();
  }
  const xdr = await harness("../dist/tools/xdr.js", "registerXdrTools");
  try {
    await xdr.call("sophos_cancel_xdr_query_run", { run_id: A });
    assert.deepEqual(sent(xdr), [req("POST", `/xdr-query/v1/queries/runs/${A}/cancel`, {})]);
  } finally {
    await xdr.close();
  }
  const cs = await harness("../dist/tools/cloud-security.js", "registerCloudSecurityTools", () => ({ items: [{ id: A, version: "2026.26.7" }] }));
  try {
    const { json } = await cs.call("sophos_list_cloud_security_default_contents", {});
    assert.deepEqual(json, { total: 1, contents: [{ id: A, version: "2026.26.7" }] });
    await cs.call("sophos_create_cloud_security_profile", { content_version: "2026.26.7", settings: { rules: [{ name: "r", enabled: false }] } });
    assert.deepEqual(sent(cs).at(-1), req("POST", "/cloud-security/v1/profiles", { contentVersion: "2026.26.7", settings: { rules: [{ name: "r", enabled: false }] } }));
  } finally {
    await cs.close();
  }
});
