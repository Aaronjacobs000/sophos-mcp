/**
 * In-memory stand-in for the Sophos endpoint policy, endpoint and endpoint
 * group APIs, shaped by what the live API did on 13/10/2026:
 * - appliesTo is plain ID arrays; PATCH replaces the whole assignment; a
 *   user/device mix gets 400; user keys on a server policy get 400;
 *   endpointGroups without endpoints gets 500; server targets on a computer
 *   policy are accepted (the gap the tools close).
 * - web-profile-id is ignored unless filter-by-web-profile.enabled is true in
 *   the same write; clearing it while filter-by stays true gets 400; a new
 *   web control policy defaults to web-profile.enabled true.
 * - Groups listed in `unlisted` answer GET by ID but not the ids= list (lag).
 * - plainNotFound: an unknown endpoint or group ID gets a 404 with a non-JSON body.
 * Registers the policy tools on a real SophosClient. No network.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerPolicyTools } from "../dist/tools/policies.js";

export const TENANT = "00000000-0000-4000-8000-000000000001";
export const HOST = "https://api-au01.central.sophos.com";
export const U1 = "00000000-0000-4000-8000-0000000000a1";
export const U2 = "00000000-0000-4000-8000-0000000000a2";
export const UG1 = "00000000-0000-4000-8000-0000000000b1";
export const E1 = "00000000-0000-4000-8000-0000000000c1"; // computer
export const ES1 = "00000000-0000-4000-8000-0000000000c2"; // server
export const EV1 = "00000000-0000-4000-8000-0000000000c3"; // security VM
export const G1 = "00000000-0000-4000-8000-0000000000d1"; // computer group
export const G2 = "00000000-0000-4000-8000-0000000000d2"; // server group
export const G3 = "00000000-0000-4000-8000-0000000000d3"; // computer group, not in the list yet
export const MISSING = "00000000-0000-4000-8000-0000000000ff";
export const P_USER = "00000000-0000-4000-8000-0000000000e1";
export const P_DEVICE = "00000000-0000-4000-8000-0000000000e2";
export const P_SERVER = "00000000-0000-4000-8000-0000000000e3";
export const P_EMPTY = "00000000-0000-4000-8000-0000000000e4";
export const P_WEB = "00000000-0000-4000-8000-0000000000e5";
export const PROFILE = "00000000-0000-4000-8000-0000000000f1";

const WP = "endpoint.web-control.";
const USER_KEYS = ["users", "userGroups"];
const DEVICE_KEYS = ["endpoints", "endpointGroups"];

const reply = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function applyAppliesTo(type, appliesTo) {
  const keys = Object.keys(appliesTo);
  const user = keys.some((k) => USER_KEYS.includes(k));
  const device = keys.some((k) => DEVICE_KEYS.includes(k));
  if (keys.flatMap((k) => appliesTo[k]).some((id) => typeof id !== "string")) {
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

/** Merges a settings write the way Sophos does for the web profile keys. */
function applySettings(stored, write) {
  const next = { ...stored };
  for (const [key, value] of Object.entries(write)) {
    if (key !== `${WP}web-profile-id`) next[key] = value;
  }
  if (`${WP}web-profile-id` in write) {
    const id = write[`${WP}web-profile-id`].value;
    const filterBy = write[`${WP}filter-by-web-profile.enabled`]?.value;
    if (id === "" && next[`${WP}filter-by-web-profile.enabled`]?.value === true) {
      return { error: reply(400, { error: "badRequest", message: "Invalid Web Profile Id: " }) };
    }
    if (id === "" || filterBy === true) next[`${WP}web-profile-id`] = { value: id };
  }
  return { value: next };
}

export async function policyHarness({ tamper, failPatch = false, plainNotFound = false } = {}) {
  const endpoints = new Map([
    [E1, { id: E1, type: "computer", hostname: "victim" }],
    [ES1, { id: ES1, type: "server", hostname: "DC01" }],
    [EV1, { id: EV1, type: "securityVm", hostname: "svm" }],
  ]);
  const groups = new Map([
    [G1, { id: G1, type: "computer", name: "ZZ computers" }],
    [G2, { id: G2, type: "server", name: "ZZ servers" }],
    [G3, { id: G3, type: "computer", name: "ZZ new computers" }],
  ]);
  const unlisted = new Set([G3]);
  const webDefaults = () => ({
    [`${WP}web-profile.enabled`]: { value: true },
    [`${WP}filter-by-web-profile.enabled`]: { value: false },
    [`${WP}web-profile-id`]: { value: "" },
  });
  const store = new Map([
    [P_USER, { id: P_USER, name: "ZZ user", type: "web-control", enabled: false, priority: 3, appliesTo: { users: [U1], userGroups: [] }, settings: webDefaults() }],
    [P_DEVICE, { id: P_DEVICE, name: "ZZ device", type: "threat-protection", enabled: false, priority: 4, appliesTo: { endpoints: [E1], endpointGroups: [G1] }, settings: {} }],
    [P_SERVER, { id: P_SERVER, name: "ZZ server", type: "server-web-control", enabled: false, priority: 1, appliesTo: { endpoints: [], endpointGroups: [] }, settings: webDefaults() }],
    [P_EMPTY, { id: P_EMPTY, name: "ZZ empty", type: "web-control", enabled: false, priority: 5, appliesTo: { users: [], userGroups: [] }, settings: webDefaults() }],
    [P_WEB, { id: P_WEB, name: "ZZ web", type: "web-control", enabled: false, priority: 6, appliesTo: { users: [], userGroups: [] }, settings: { ...webDefaults(), [`${WP}web-profile.enabled`]: { value: false } } }],
  ]);
  let nextId = 1;
  const newId = () => `00000000-0000-4000-8000-1${String(nextId++).padStart(11, "0")}`;
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    calls.push({ method, path: u.pathname, params: Object.fromEntries(u.searchParams), body });
    const parts = u.pathname.split("/").filter(Boolean); // endpoint, v1, <resource>, <id>, <action>
    const [, , resource, id, action] = parts;

    if (resource === "endpoints" || resource === "endpoint-groups") {
      const map = resource === "endpoints" ? endpoints : groups;
      if (id && !map.has(id) && plainNotFound) {
        return new Response("<html><body>404 Not Found</body></html>", { status: 404, headers: { "Content-Type": "text/html" } });
      }
      if (id) return map.has(id) ? reply(200, map.get(id)) : reply(404, { error: "resourceNotFound", message: "Not found" });
      const ids = (u.searchParams.get("ids") ?? "").split(",").filter(Boolean);
      const items = ids.filter((x) => map.has(x) && !unlisted.has(x)).map((x) => map.get(x));
      return reply(200, { items, pages: {} });
    }
    if (resource !== "policies") return reply(404, { error: "notFound" });

    if (!id && method === "GET") {
      return reply(200, { items: [...store.values()], pages: { current: 1, total: 1, items: store.size } });
    }
    if (!id && method === "POST") {
      const web = body.type === "web-control" || body.type === "server-web-control";
      const settings = applySettings(web ? webDefaults() : {}, body.settings ?? {});
      if (settings.error) return settings.error;
      const result = applyAppliesTo(body.type, body.appliesTo ?? {});
      if (result.error) return result.error;
      const created = { id: newId(), enabled: true, priority: 1, ...body, appliesTo: result.value, settings: settings.value };
      store.set(created.id, created);
      return reply(201, created);
    }
    const policy = store.get(id);
    if (!policy) return reply(404, { error: "notFound", message: "Policy not found" });
    if (action === "clone" && method === "POST") {
      const clone = { ...structuredClone(policy), id: newId(), name: body.name, enabled: false };
      store.set(clone.id, clone);
      return reply(201, clone);
    }
    if (method === "PATCH") {
      if (failPatch) return reply(400, { error: "badRequest", message: "Rejected by the test" });
      const { appliesTo, settings, ...rest } = body;
      let next = policy.appliesTo;
      if (appliesTo) {
        const result = applyAppliesTo(policy.type, appliesTo);
        if (result.error) return result.error;
        next = result.value;
      }
      let nextSettings = policy.settings;
      if (settings) {
        const result = applySettings(policy.settings, settings);
        if (result.error) return result.error;
        nextSettings = result.value;
      }
      Object.assign(policy, rest, { appliesTo: next, settings: nextSettings });
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
    lookups: () => calls.filter((c) => c.method === "GET" && /endpoints|endpoint-groups/.test(c.path)),
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
