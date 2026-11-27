/**
 * The tools built on the November 2026 Endpoint API v1 releases: bulk change
 * group (POST /endpoint/v1/endpoint-groups/endpoints, 16/11/2026) and the Helm
 * chart values download (GET /endpoint/v1/downloads/helm/values, 17/11/2026).
 * Each case calls a tool through its real handler with fetch stubbed and checks
 * the exact request sent and what the tool reports. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerGroupTools } from "../dist/tools/groups.js";
import { registerEndpointSettingsTools } from "../dist/tools/endpoint-settings.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const GROUP = "00000000-0000-4000-8000-000000000091";
const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const ids = (from, count) => Array.from({ length: count }, (_, i) => id(from + i));

/**
 * Connects an MCP client to one registrar. `answer(method, path, body, n)`
 * returns { status, body, contentType } or a plain JSON body (status 200);
 * n counts the requests from 0.
 */
async function harness(registrar, answer = () => ({})) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    calls.push({ method, path: u.pathname, query: Object.fromEntries(u.searchParams), body, tenant: init?.headers?.["X-Tenant-ID"] });
    const reply = answer(method, u.pathname, body, calls.length - 1) ?? {};
    const shaped = reply && typeof reply === "object" && "status" in reply && "body" in reply;
    const payload = shaped ? reply.body : reply;
    return new Response(typeof payload === "string" ? payload : JSON.stringify(payload), {
      status: shaped ? reply.status : 200,
      headers: { "Content-Type": (shaped && reply.contentType) || "application/json" },
    });
  };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (tid) => tid ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registrar(server, client, tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    async tools() {
      return (await mcp.listTools()).tools;
    },
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

/** Answers a bulk change group request: every ID changed, except those in `fail` with their errorCode. */
const changeGroup = (fail = {}) => (method, path, body) => ({
  items: body.ids.filter((x) => !fail[x]).map((x) => ({ id: x, hostname: `host-${x.slice(-4)}` })),
  errors: body.ids.filter((x) => fail[x]).map((x) => ({ id: x, errorCode: fail[x], errorMessage: `${fail[x]} for ${x}` })),
});

test("bulk change group POSTs { ids, groupId } to /endpoint-groups/endpoints with the tenant header", async () => {
  const h = await harness(registerGroupTools, changeGroup());
  try {
    const [a, b] = ids(1, 2);
    const res = await h.call("sophos_bulk_change_endpoint_group", { endpoint_ids: [a, b, a], group_id: GROUP, tenant_id: TENANT });
    assert.equal(res.isError, false, res.text);
    assert.deepEqual(h.calls, [
      { method: "POST", path: "/endpoint/v1/endpoint-groups/endpoints", query: {}, body: { ids: [a, b], groupId: GROUP }, tenant: TENANT },
    ]);
    assert.deepEqual(res.json, {
      group_id: GROUP,
      requested: 2,
      accepted: 2,
      rejected: 0,
      items: [
        { id: a, hostname: `host-${a.slice(-4)}` },
        { id: b, hostname: `host-${b.slice(-4)}` },
      ],
      errors: [],
    });
  } finally {
    await h.close();
  }
});

test("bulk change group sends groupId null to take endpoints out of their group, and requires group_id", async () => {
  const h = await harness(registerGroupTools, changeGroup());
  try {
    const [a] = ids(1, 1);
    const res = await h.call("sophos_bulk_change_endpoint_group", { endpoint_ids: [a], group_id: null });
    assert.equal(res.isError, false, res.text);
    assert.deepEqual(h.calls.map((c) => c.body), [{ ids: [a], groupId: null }]);
    assert.equal(res.json.group_id, null);
    assert.equal(res.json.accepted, 1);

    const missing = await h.call("sophos_bulk_change_endpoint_group", { endpoint_ids: [a] });
    assert.equal(missing.isError, true, "omitting group_id is refused, never read as null");
    for (const bad of [{ endpoint_ids: [], group_id: GROUP }, { endpoint_ids: ids(1, 5001), group_id: GROUP }, { endpoint_ids: ["nope"], group_id: GROUP }]) {
      assert.equal((await h.call("sophos_bulk_change_endpoint_group", bad)).isError, true);
    }
    assert.equal(h.calls.length, 1, "refused input sends nothing");
  } finally {
    await h.close();
  }
});

test("bulk change group sends 500 IDs per request, in order, and merges the results", async () => {
  const all = ids(1, 1201);
  const fail = { [all[3]]: "notFound", [all[700]]: "conflict", [all[1200]]: "permissionDenied" };
  const h = await harness(registerGroupTools, changeGroup(fail));
  try {
    const res = await h.call("sophos_bulk_change_endpoint_group", { endpoint_ids: all, group_id: GROUP });
    assert.equal(res.isError, false, res.text);
    assert.deepEqual(h.calls.map((c) => c.body.ids.length), [500, 500, 201]);
    assert.deepEqual(h.calls.flatMap((c) => c.body.ids), all);
    assert.ok(h.calls.every((c) => c.body.groupId === GROUP));
    assert.equal(res.json.requested, 1201);
    assert.equal(res.json.accepted, 1198);
    assert.equal(res.json.rejected, 3);
    assert.deepEqual(
      res.json.errors.map((e) => [e.id, e.errorCode]),
      [[all[3], "notFound"], [all[700], "conflict"], [all[1200], "permissionDenied"]]
    );
    assert.equal(res.json.stopped, undefined);
  } finally {
    await h.close();
  }
});

test("bulk change group reports per-endpoint errors as Sophos sent them", async () => {
  const [a, b, c, d] = ids(1, 4);
  const h = await harness(registerGroupTools, () => ({
    items: [{ id: a, hostname: "pc-a" }],
    errors: [
      { id: b, errorCode: "notFound", errorMessage: "Endpoint not found" },
      { id: c, errorCode: "notSupported", endpointErrorCode: "x1", errorMessage: "Not supported" },
      { id: d, errorCode: "internalError", errorMessage: "Try again" },
    ],
  }));
  try {
    const res = await h.call("sophos_bulk_change_endpoint_group", { endpoint_ids: [a, b, c, d], group_id: GROUP });
    assert.equal(res.json.accepted, 1);
    assert.equal(res.json.rejected, 3);
    assert.deepEqual(res.json.errors[1], { id: c, errorCode: "notSupported", endpointErrorCode: "x1", errorMessage: "Not supported" });
  } finally {
    await h.close();
  }
});

test("bulk change group: a first request that fails is an error; a later one stops with what is unconfirmed and unsent", async () => {
  const refused = { status: 409, body: { error: "conflict", message: "You can't modify groups synced from Active Directory." } };
  const first = await harness(registerGroupTools, () => refused);
  try {
    const res = await first.call("sophos_bulk_change_endpoint_group", { endpoint_ids: ids(1, 3), group_id: GROUP });
    assert.equal(res.isError, true);
    assert.match(res.text, /409/);
    assert.match(res.text, /Active Directory/);
    assert.equal(first.calls.length, 1);
  } finally {
    await first.close();
  }

  const all = ids(1, 1300);
  const later = await harness(registerGroupTools, (m, p, body, n) => (n === 1 ? refused : changeGroup()(m, p, body)));
  try {
    const res = await later.call("sophos_bulk_change_endpoint_group", { endpoint_ids: all, group_id: GROUP });
    assert.equal(res.isError, false, res.text);
    assert.equal(later.calls.length, 2, "stops at the failed batch");
    assert.equal(res.json.stopped, true);
    assert.match(res.json.stopped_error, /409/);
    assert.equal(res.json.requested, 1300);
    assert.equal(res.json.accepted, 500);
    assert.deepEqual(res.json.unconfirmed, all.slice(500, 1000));
    assert.deepEqual(res.json.not_sent, all.slice(1000));
    assert.match(res.json.note, /Stopped at batch 2 of 3/);
  } finally {
    await later.close();
  }
});

test("Helm values: GET /endpoint/v1/downloads/helm/values with the tenant header, file passed through", async () => {
  const yaml = 'endpoint:\n  sensor:\n    params:\n      customerID: tenant\n      mcsURL: "https://mcs.example.invalid"\n      mcsToken: "SLS-FAKE"\n';
  for (const reply of [
    { status: 200, body: JSON.stringify(yaml), contentType: "application/json" },
    { status: 200, body: yaml, contentType: "application/x-yaml" },
  ]) {
    const h = await harness(registerEndpointSettingsTools, () => reply);
    try {
      const res = await h.call("sophos_get_helm_values", { tenant_id: TENANT });
      assert.equal(res.isError, false, res.text);
      assert.deepEqual(h.calls, [{ method: "GET", path: "/endpoint/v1/downloads/helm/values", query: {}, body: undefined, tenant: TENANT }]);
      assert.deepEqual(res.json, { values_yaml: yaml }, reply.contentType);
    } finally {
      await h.close();
    }
  }
});

test("Helm values: an API error comes back as an error", async () => {
  const h = await harness(registerEndpointSettingsTools, () => ({ status: 403, body: { error: "forbidden", message: "Authorization required" } }));
  try {
    const res = await h.call("sophos_get_helm_values", {});
    assert.equal(res.isError, true);
    assert.match(res.text, /403/);
  } finally {
    await h.close();
  }
});

test("the new tools' descriptions carry the warnings", async () => {
  const h = await harness((server, client, resolver) => {
    registerGroupTools(server, client, resolver);
    registerEndpointSettingsTools(server, client, resolver);
  });
  try {
    const byName = new Map((await h.tools()).map((t) => [t.name, t]));
    const bulk = byName.get("sophos_bulk_change_endpoint_group");
    assert.match(bulk.description, /null to remove the endpoints/);
    assert.match(bulk.description, /synced from Active Directory/);
    assert.deepEqual(bulk.annotations, { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true });
    const helm = byName.get("sophos_get_helm_values");
    assert.match(helm.description, /Returns a secret/);
    assert.match(helm.description, /mcsToken/);
    assert.match(helm.description, /Sophos Linux Sensor entitlement/);
    assert.equal(helm.annotations.readOnlyHint, true);
  } finally {
    await h.close();
  }
});
