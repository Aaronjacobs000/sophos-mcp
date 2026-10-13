/**
 * Handler-level tests for policy assignment (appliesTo) writes through the
 * real SophosClient and the registered schemas, with fetch answered by an
 * in-memory policy store that behaves the way the live API measured on
 * 13/10/2026: plain ID arrays, PATCH replaces the whole assignment, a
 * user/device mix gets 400, user keys on a server policy get 400, and
 * endpointGroups without endpoints gets 500. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerPolicyTools } from "../dist/tools/policies.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const U1 = "00000000-0000-4000-8000-0000000000a1";
const U2 = "00000000-0000-4000-8000-0000000000a2";
const UG1 = "00000000-0000-4000-8000-0000000000b1";
const E1 = "00000000-0000-4000-8000-0000000000c1";
const G1 = "00000000-0000-4000-8000-0000000000d1";
const G2 = "00000000-0000-4000-8000-0000000000d2";
const P_USER = "00000000-0000-4000-8000-0000000000e1";
const P_DEVICE = "00000000-0000-4000-8000-0000000000e2";
const P_SERVER = "00000000-0000-4000-8000-0000000000e3";
const P_EMPTY = "00000000-0000-4000-8000-0000000000e4";

const USER_KEYS = ["users", "userGroups"];
const DEVICE_KEYS = ["endpoints", "endpointGroups"];

const reply = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/** Validates and normalises appliesTo the way Sophos does, or returns an error Response. */
function applyAppliesTo(type, appliesTo) {
  const keys = Object.keys(appliesTo);
  const user = keys.some((k) => USER_KEYS.includes(k));
  const device = keys.some((k) => DEVICE_KEYS.includes(k));
  const all = keys.flatMap((k) => appliesTo[k]);
  if (all.some((id) => typeof id !== "string")) {
    return { error: reply(400, { error: "badRequest", message: "Error parsing the query params or request body" }) };
  }
  if (user && device) {
    return { error: reply(400, { error: "badRequest", message: "AppliesTo node should include only either endpoints, endpointGroups or users, userGroups but not a mix of them" }) };
  }
  if (user && type.startsWith("server-")) {
    return { error: reply(400, { error: "badRequest", message: `Policy type ${type} can only be applied to endpoints` }) };
  }
  if ("endpointGroups" in appliesTo && !("endpoints" in appliesTo)) {
    return { error: reply(500, { error: "internalServerError", message: "Error processing data" }) };
  }
  return {
    value: device
      ? { endpoints: appliesTo.endpoints ?? [], endpointGroups: appliesTo.endpointGroups ?? [] }
      : { users: appliesTo.users ?? [], userGroups: appliesTo.userGroups ?? [] },
  };
}

/**
 * Registers the policy tools on a real SophosClient over an in-memory store.
 * `tamper(policy)` lets a test change what GET returns, to prove the
 * read-back reports what is stored rather than what was sent.
 */
async function harness({ tamper } = {}) {
  const store = new Map([
    [P_USER, { id: P_USER, name: "ZZ user", type: "web-control", enabled: false, priority: 3, appliesTo: { users: [U1], userGroups: [] } }],
    [P_DEVICE, { id: P_DEVICE, name: "ZZ device", type: "threat-protection", enabled: false, priority: 4, appliesTo: { endpoints: [E1], endpointGroups: [G1] } }],
    [P_SERVER, { id: P_SERVER, name: "ZZ server", type: "server-web-control", enabled: false, priority: 1, appliesTo: { endpoints: [], endpointGroups: [] } }],
    [P_EMPTY, { id: P_EMPTY, name: "ZZ empty", type: "web-control", enabled: false, priority: 5, appliesTo: { users: [], userGroups: [] } }],
  ]);
  let nextId = 1;
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    calls.push({ method, path: u.pathname, body });
    const id = u.pathname.split("/")[4];
    if (u.pathname === "/endpoint/v1/policies" && method === "GET") {
      return reply(200, { items: [...store.values()], pages: { current: 1, total: 1, items: store.size } });
    }
    if (u.pathname === "/endpoint/v1/policies" && method === "POST") {
      const created = { id: `00000000-0000-4000-8000-${String(nextId++).padStart(12, "0")}`, enabled: true, priority: 1, ...body };
      const result = applyAppliesTo(body.type, body.appliesTo ?? {});
      if (result.error) return result.error;
      created.appliesTo = result.value;
      store.set(created.id, created);
      return reply(201, created);
    }
    const policy = store.get(id);
    if (!policy) return reply(404, { error: "notFound", message: "Policy not found" });
    if (method === "PATCH") {
      const { appliesTo, ...rest } = body;
      let next = policy.appliesTo;
      if (appliesTo) {
        const result = applyAppliesTo(policy.type, appliesTo);
        if (result.error) return result.error;
        next = result.value;
      }
      Object.assign(policy, rest, { appliesTo: next });
      return reply(200, policy);
    }
    if (method === "GET") return reply(200, tamper ? tamper(structuredClone(policy)) : policy);
    return reply(405, { error: "methodNotAllowed" });
  };

  const tokenManager = { getToken: async () => "fake-token" };
  const tenantResolver = { resolveApiHost: async () => HOST, resolveTenantId: (tid) => tid ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerPolicyTools(server, new SophosClient(tokenManager, tenantResolver), tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    store,
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

test("create with users sends plain IDs, reads the policy back by ID and reports what is stored", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_create_policy", {
      name: "ZZ create users",
      type: "web-control",
      enabled: false,
      users: [U1, U1],
    });
    assert.equal(isError, false);
    assert.deepEqual(h.calls.map((c) => c.method), ["POST", "GET"]);
    assert.deepEqual(h.calls[0].body, {
      name: "ZZ create users",
      type: "web-control",
      enabled: false,
      appliesTo: { users: [U1], userGroups: [] },
    });
    assert.equal(h.calls[1].path, `/endpoint/v1/policies/${json.policy.id}`);
    assert.deepEqual(json.assignment_sent, { kind: "user", users: [U1], user_groups: [] });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [U1], user_groups: [] });
    assert.equal(json.assignment_matches, true);
    assert.deepEqual(json.policy.applies_to, { kind: "user", users: 1, user_groups: 0 });
  } finally {
    await h.close();
  }
});

test("create with endpoint groups always carries the endpoints companion key", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_create_policy", {
      name: "ZZ create groups",
      type: "server-threat-protection",
      enabled: false,
      endpoint_groups: [G2],
    });
    assert.equal(isError, false);
    assert.deepEqual(h.calls[0].body.appliesTo, { endpoints: [], endpointGroups: [G2] });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [], endpoint_groups: [G2] });
    assert.equal(json.assignment_matches, true);
  } finally {
    await h.close();
  }
});

test("create with no assignment sends no appliesTo and makes no read-back", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_create_policy", { name: "ZZ plain", type: "web-control" });
    assert.equal(isError, false);
    assert.equal(h.calls.length, 1);
    assert.equal("appliesTo" in h.calls[0].body, false);
    assert.equal("assignment_sent" in json, false);
  } finally {
    await h.close();
  }
});

test("a user and device mix is refused before anything is sent", async () => {
  const h = await harness();
  try {
    for (const [name, args] of [
      ["sophos_create_policy", { name: "ZZ mix", type: "web-control", users: [U1], endpoints: [E1] }],
      ["sophos_update_policy", { policy_id: P_USER, user_groups: [UG1], endpoint_groups: [G1] }],
      ["sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [], endpoints: [E1] }],
    ]) {
      const { isError, text } = await h.call(name, args);
      assert.equal(isError, true, name);
      assert.match(text, /never both/, name);
      assert.match(text, /Nothing was sent/, name);
    }
    assert.equal(h.calls.length, 0, "no request was sent");
  } finally {
    await h.close();
  }
});

test("user keys on a server policy are refused before any write", async () => {
  const h = await harness();
  try {
    const create = await h.call("sophos_create_policy", { name: "ZZ srv", type: "server-web-control", user_groups: [UG1] });
    assert.equal(create.isError, true);
    assert.match(create.text, /server-web-control applies only to endpoints and endpoint groups/);
    assert.equal(h.calls.length, 0, "create sent nothing");

    const update = await h.call("sophos_update_policy", { policy_id: P_SERVER, users: [U1] });
    assert.equal(update.isError, true);
    assert.match(update.text, /applies only to endpoints and endpoint groups/);

    const set = await h.call("sophos_set_policy_assignments", { policy_id: P_SERVER, mode: "add", users: [U1] });
    assert.equal(set.isError, true);
    assert.deepEqual(h.writes(), [], "only reads were made");
  } finally {
    await h.close();
  }
});

test("{id} objects are refused by the schema", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_create_policy", { name: "ZZ obj", type: "web-control", users: [{ id: U1 }] });
    assert.equal(isError, true);
    assert.match(text, /Input validation error/);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("update with an assignment replaces the whole assignment and reads it back", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_update_policy", { policy_id: P_USER, user_groups: [UG1] });
    assert.equal(isError, false);
    assert.deepEqual(h.calls.map((c) => c.method), ["GET", "PATCH", "GET"]);
    assert.deepEqual(h.calls[1].body, { appliesTo: { users: [], userGroups: [UG1] } });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [], user_groups: [UG1] });
    assert.equal(json.assignment_matches, true);
  } finally {
    await h.close();
  }
});

test("update with device keys flips a user policy to a device policy, with no pre-read", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_update_policy", { policy_id: P_USER, endpoint_groups: [G1], name: "ZZ flipped" });
    assert.equal(isError, false);
    assert.deepEqual(h.calls.map((c) => c.method), ["PATCH", "GET"]);
    assert.deepEqual(h.calls[0].body, { name: "ZZ flipped", appliesTo: { endpoints: [], endpointGroups: [G1] } });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [], endpoint_groups: [G1] });
    assert.deepEqual(json.policy.applies_to, { kind: "device", endpoints: 0, endpoint_groups: 1 });
  } finally {
    await h.close();
  }
});

test("update with no fields names the assignment keys", async () => {
  const h = await harness();
  try {
    const { json } = await h.call("sophos_update_policy", { policy_id: P_USER });
    assert.match(json.error, /users, user_groups, endpoints, endpoint_groups/);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("set add merges with what the policy holds", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [U2, U1] });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { users: [U1, U2], userGroups: [] } });
    assert.deepEqual(json.assignment_before, { kind: "user", users: [U1], user_groups: [] });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [U1, U2], user_groups: [] });
    assert.equal(json.assignment_matches, true);
    assert.equal(json.status, "updated");
  } finally {
    await h.close();
  }
});

test("set add refuses a kind change while the policy holds the other kind", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", endpoints: [E1] });
    assert.equal(isError, true);
    assert.match(text, /is a user policy with 1 assignment/);
    assert.match(text, /mode "replace"/);
    assert.deepEqual(h.writes(), []);
  } finally {
    await h.close();
  }
});

test("set add on an empty user policy makes it a device policy", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_EMPTY, mode: "add", endpoint_groups: [G1] });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { endpoints: [], endpointGroups: [G1] } });
    assert.equal(json.assignment_stored.kind, "device");
  } finally {
    await h.close();
  }
});

test("set remove takes IDs out and lists the ones that were not assigned", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", {
      policy_id: P_DEVICE,
      mode: "remove",
      endpoint_groups: [G1, G2],
    });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { endpoints: [E1], endpointGroups: [] } });
    assert.deepEqual(json.not_assigned, { kind: "device", endpoints: [], endpoint_groups: [G2] });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [E1], endpoint_groups: [] });
  } finally {
    await h.close();
  }
});

test("set writes nothing when nothing would change", async () => {
  const h = await harness();
  try {
    const remove = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "remove", endpoints: [E1] });
    assert.equal(remove.json.status, "unchanged");
    assert.deepEqual(remove.json.not_assigned, { kind: "device", endpoints: [E1], endpoint_groups: [] });
    const add = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [U1] });
    assert.equal(add.json.status, "unchanged");
    const replace = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "replace", endpoints: [E1], endpoint_groups: [G1] });
    assert.equal(replace.json.status, "unchanged");
    assert.deepEqual(h.writes(), []);
  } finally {
    await h.close();
  }
});

test("set needs at least one assignment key", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "replace" });
    assert.equal(isError, true);
    assert.match(text, /at least one of users, user_groups, endpoints or endpoint_groups/);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("set replace sends the whole family and can empty a device policy", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_DEVICE, mode: "replace", endpoints: [] });
    assert.equal(isError, false);
    assert.deepEqual(h.writes()[0].body, { appliesTo: { endpoints: [], endpointGroups: [] } });
    assert.deepEqual(json.assignment_stored, { kind: "device", endpoints: [], endpoint_groups: [] });
  } finally {
    await h.close();
  }
});

test("the read-back reports what Sophos stored when it differs from what was sent", async () => {
  const h = await harness({
    tamper: (p) => ({ ...p, appliesTo: { users: p.appliesTo.users?.slice(0, 1) ?? [], userGroups: [] } }),
  });
  try {
    const { isError, json } = await h.call("sophos_set_policy_assignments", { policy_id: P_USER, mode: "add", users: [U2] });
    assert.equal(isError, false);
    assert.deepEqual(json.assignment_sent, { kind: "user", users: [U1, U2], user_groups: [] });
    assert.deepEqual(json.assignment_stored, { kind: "user", users: [U1], user_groups: [] });
    assert.equal(json.assignment_matches, false);
    assert.match(json.warning, /differs from what was sent/);
  } finally {
    await h.close();
  }
});

test("list and get report the stored plain ID arrays and the kind", async () => {
  const h = await harness();
  try {
    const list = await h.call("sophos_list_policies", {});
    const byId = new Map(list.json.policies.map((p) => [p.id, p]));
    assert.deepEqual(byId.get(P_USER).applies_to, { kind: "user", users: 1, user_groups: 0 });
    assert.deepEqual(byId.get(P_DEVICE).applies_to, { kind: "device", endpoints: 1, endpoint_groups: 1 });
    assert.deepEqual(byId.get(P_SERVER).applies_to, { kind: "device", endpoints: 0, endpoint_groups: 0 });

    const get = await h.call("sophos_get_policy", { policy_id: P_DEVICE });
    assert.deepEqual(get.json.applies_to_detail, { kind: "device", endpoints: [E1], endpoint_groups: [G1] });
  } finally {
    await h.close();
  }
});
