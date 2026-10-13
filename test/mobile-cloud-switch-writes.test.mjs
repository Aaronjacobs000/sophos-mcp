/**
 * The PUT and PATCH update tools outside web filtering, with fetch stubbed:
 * Sophos Mobile updates read the full view first and send the whole record
 * the spec requires (mobile-v1 1.0.13), app groups use PATCH, the cloud
 * security update is a rename by query parameter and delete targets the
 * collection, and every tool that replaces state is marked destructive.
 * No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerMobileTools } from "../dist/tools/mobile.js";
import { registerCloudSecurityTools } from "../dist/tools/cloud-security.js";
import { registerSwitchTools } from "../dist/tools/switch.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const DEVICE = "00000000-0000-4000-8000-0000000000a1";
const GROUP = "00000000-0000-4000-8000-0000000000b1";
const GROUP2 = "00000000-0000-4000-8000-0000000000b2";
const PERSON = "00000000-0000-4000-8000-0000000000c1";
const POLICY = "00000000-0000-4000-8000-0000000000d1";
const POLICY2 = "00000000-0000-4000-8000-0000000000d2";
const APPS = "00000000-0000-4000-8000-0000000000e1";
const PROFILE = "00000000-0000-4000-8000-0000000000f1";

const STORED = {
  [`/mobile/v1/devices/${DEVICE}`]: {
    id: DEVICE,
    name: "ZZ phone",
    description: "desk",
    phoneNumber: "+61 400 000 000",
    email: "zz@example.com",
    assignedPerson: { id: PERSON, name: "ZZ", email: "zz@example.com" },
    ownershipType: "corporate",
    logLevel: "info",
    deviceGroup: { id: GROUP, name: "ZZ group" },
    os: { platform: "android" },
  },
  [`/mobile/v1/device-groups/${GROUP}`]: {
    id: GROUP,
    name: "ZZ group",
    description: "keep",
    employeeCompliancePolicy: { id: POLICY, name: "Default" },
    corporateCompliancePolicy: { id: POLICY2, name: "Strict" },
    iosAutoEnrollment: { enabled: false, url: "https://example.invalid/enroll" },
  },
  "/mobile/v1/settings/ixm-auto-enrollment": {
    deviceGroup: { id: GROUP, name: "ZZ group" },
    ownershipType: "employee",
    androidPolicy: { id: POLICY, name: "A" },
    iosPolicy: { id: POLICY2, name: "I" },
    connectionCode: "redacted",
  },
  [`/cloud-security/v1/profiles/${PROFILE}`]: { id: PROFILE, name: "ZZ renamed" },
};

async function harness(register) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    calls.push({ method, path: u.pathname, params: Object.fromEntries(u.searchParams), body: init?.body === undefined ? undefined : JSON.parse(init.body) });
    if (method === "GET") return new Response(JSON.stringify(STORED[u.pathname] ?? {}), { status: 200 });
    if (method === "DELETE") return new Response(JSON.stringify({ skippedProfiles: [] }), { status: 200 });
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };
  const tenantResolver = { resolveApiHost: async () => HOST, resolveTenantId: (id) => id ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  register(server, new SophosClient({ getToken: async () => "fake-token" }, tenantResolver), tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    mcp,
    writes: () => calls.filter((c) => c.method !== "GET"),
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

test("a mobile device update reads the full view and sends the whole record the PUT requires", async () => {
  const h = await harness(registerMobileTools);
  try {
    const { isError } = await h.call("sophos_update_mobile_device", { device_id: DEVICE, name: "ZZ phone 2" });
    assert.equal(isError, false);
    assert.equal(h.calls[0].method, "GET");
    assert.equal(h.calls[0].params.view, "full");
    assert.deepEqual(h.writes()[0], {
      method: "PUT",
      path: `/mobile/v1/devices/${DEVICE}`,
      params: {},
      body: {
        name: "ZZ phone 2",
        description: "desk",
        phoneNumber: "+61 400 000 000",
        assignedPersonId: PERSON,
        ownershipType: "corporate",
        logLevel: "info",
        groupId: GROUP,
      },
    });
  } finally {
    await h.close();
  }
});

test("a mobile device group update keeps the compliance policies and iOS setting it did not change", async () => {
  const h = await harness(registerMobileTools);
  try {
    const { isError } = await h.call("sophos_update_mobile_device_group", { group_id: GROUP, corporate_compliance_policy_id: POLICY });
    assert.equal(isError, false);
    assert.equal(h.calls[0].params.view, "full");
    assert.deepEqual(h.writes()[0].body, {
      name: "ZZ group",
      description: "keep",
      employeeCompliancePolicyId: POLICY,
      corporateCompliancePolicyId: POLICY,
      iosAutoEnrollment: { enabled: false },
    });
  } finally {
    await h.close();
  }
});

test("an app group update is a PATCH of only the fields passed, and needs at least one", async () => {
  const h = await harness(registerMobileTools);
  try {
    const { isError } = await h.call("sophos_update_mobile_app_group", { group_id: APPS, name: "ZZ apps 2" });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0], { method: "PATCH", path: `/mobile/v1/app-groups/${APPS}`, params: {}, body: { name: "ZZ apps 2" } });
    const none = await h.call("sophos_update_mobile_app_group", { group_id: APPS });
    assert.equal(none.isError, true);
    assert.equal(h.writes().length, 1);
  } finally {
    await h.close();
  }
});

test("mobile creates send the fields the spec requires", async () => {
  const h = await harness(registerMobileTools);
  try {
    await h.call("sophos_create_mobile_device", { name: "ZZ phone", platform: "android", ownership_type: "corporate", group_id: GROUP });
    await h.call("sophos_create_mobile_device_group", {
      name: "ZZ group",
      employee_compliance_policy_id: POLICY,
      corporate_compliance_policy_id: POLICY,
      ios_auto_enrollment: { enabled: false },
    });
    await h.call("sophos_create_mobile_app_group", { name: "ZZ apps", platform: "android", apps: [{ name: "Chrome", identifier: "com.android.chrome" }] });
    assert.deepEqual(h.writes().map((c) => [c.path, c.body]), [
      ["/mobile/v1/devices", { name: "ZZ phone", platform: "android", ownershipType: "corporate", groupId: GROUP }],
      ["/mobile/v1/device-groups", { name: "ZZ group", employeeCompliancePolicyId: POLICY, corporateCompliancePolicyId: POLICY, iosAutoEnrollment: { enabled: false } }],
      ["/mobile/v1/app-groups", { name: "ZZ apps", platform: "android", apps: [{ name: "Chrome", identifier: "com.android.chrome" }] }],
    ]);
    const missing = await h.call("sophos_create_mobile_device_group", { name: "ZZ group" });
    assert.equal(missing.isError, true, "the compliance policy IDs are required");
  } finally {
    await h.close();
  }
});

test("auto-enrollment reads and writes the settings path and keeps what it was not told to change", async () => {
  const h = await harness(registerMobileTools);
  try {
    await h.call("sophos_get_mobile_auto_enrollment", {});
    const { isError, json } = await h.call("sophos_update_mobile_auto_enrollment", { ownership_type: "corporate" });
    assert.equal(isError, false);
    assert.deepEqual(h.calls.map((c) => `${c.method} ${c.path}`), [
      "GET /mobile/v1/settings/ixm-auto-enrollment",
      "GET /mobile/v1/settings/ixm-auto-enrollment",
      "PUT /mobile/v1/settings/ixm-auto-enrollment",
    ]);
    const expected = { deviceGroupId: GROUP, ownershipType: "corporate", androidPolicyId: POLICY, iosPolicyId: POLICY2 };
    assert.deepEqual(h.writes()[0].body, expected);
    assert.deepEqual(json.sent, expected);
  } finally {
    await h.close();
  }
});

test("the cloud security update renames by query parameter and reads the name back; delete targets the collection", async () => {
  const h = await harness(registerCloudSecurityTools);
  try {
    const rename = await h.call("sophos_update_cloud_security_profile", { profile_id: PROFILE, name: "ZZ renamed" });
    assert.equal(rename.isError, false);
    assert.deepEqual(h.writes()[0], { method: "PUT", path: `/cloud-security/v1/profiles/${PROFILE}`, params: { name: "ZZ renamed" }, body: undefined });
    assert.equal(rename.json.status, "renamed");
    assert.equal(rename.json.name_stored, "ZZ renamed");

    const del = await h.call("sophos_delete_cloud_security_profile", { profile_id: PROFILE });
    assert.equal(del.json.status, "deleted");
    assert.deepEqual(h.writes()[1], { method: "DELETE", path: "/cloud-security/v1/profiles", params: { profileIds: PROFILE }, body: undefined });

    await h.call("sophos_create_cloud_security_profile", { name: "ZZ cs", content_version: "5.8.0.8", settings: {} });
    assert.deepEqual(h.writes()[2].body, { contentVersion: "5.8.0.8", settings: {}, name: "ZZ cs" });
  } finally {
    await h.close();
  }
});

test("every tool that replaces state with a PUT or replaces a list is marked destructive", async () => {
  const destructive = {
    mobile: ["sophos_update_mobile_device", "sophos_update_mobile_device_group", "sophos_update_mobile_app_group", "sophos_update_mobile_auto_enrollment"],
    switch: ["sophos_update_switch_mac_filtering"],
  };
  for (const [register, names] of [[registerMobileTools, destructive.mobile], [registerSwitchTools, destructive.switch]]) {
    const h = await harness(register);
    try {
      const { tools } = await h.mcp.listTools();
      for (const name of names) {
        assert.equal(tools.find((t) => t.name === name).annotations.destructiveHint, true, name);
      }
    } finally {
      await h.close();
    }
  }
  const h = await harness(registerCloudSecurityTools);
  try {
    const { tools } = await h.mcp.listTools();
    const rename = tools.find((t) => t.name === "sophos_update_cloud_security_profile");
    assert.equal(rename.annotations.destructiveHint, false, "a rename replaces nothing else");
    assert.match(rename.description, /changes only the name/);
  } finally {
    await h.close();
  }
});
