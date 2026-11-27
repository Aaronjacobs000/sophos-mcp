/**
 * sophos_add_endpoints_to_group reports what Sophos actually did. The 201 body
 * of POST /endpoint/v1/endpoint-groups/{groupId}/endpoints (Endpoint API
 * reference, "Add to group") carries addedEndpoints ({ id, hostname }) and
 * errors.endpointsNotFound / errors.endpointsOfWrongType; the endpoint groups
 * guide shows addedEndpoints as bare IDs and says an endpoint already in the
 * group is in neither list. Before, the tool ignored the body and reported
 * every requested ID as added. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerGroupTools } from "../dist/tools/groups.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const GROUP = "00000000-0000-4000-8000-000000000091";
const A = "00000000-0000-4000-8000-0000000000a1";
const B = "00000000-0000-4000-8000-0000000000b1";
const C = "00000000-0000-4000-8000-0000000000c1";
const D = "00000000-0000-4000-8000-0000000000d1";
const E = "00000000-0000-4000-8000-0000000000e1";

/** Registers the group tools on a real SophosClient whose fetch answers `body` with a 201. */
async function harness(body) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    calls.push({
      method: init?.method ?? "GET",
      path: u.pathname,
      body: init?.body === undefined ? undefined : JSON.parse(init.body),
    });
    return new Response(JSON.stringify(body), { status: 201, headers: { "Content-Type": "application/json" } });
  };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerGroupTools(server, client, tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    async add(endpoint_ids) {
      const result = await mcp.callTool({
        name: "sophos_add_endpoints_to_group",
        arguments: { group_id: GROUP, endpoint_ids },
      });
      assert.equal(result.isError, undefined, result.content[0]?.text);
      return JSON.parse(result.content[0].text);
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

test("every endpoint added: status added, with the hostnames Sophos returned", async () => {
  const h = await harness({
    addedEndpoints: [
      { id: A, hostname: "pc-a" },
      { id: B, hostname: "pc-b" },
    ],
  });
  try {
    const json = await h.add([A, B]);
    assert.deepEqual(h.calls, [
      { method: "POST", path: `/endpoint/v1/endpoint-groups/${GROUP}/endpoints`, body: { ids: [A, B] } },
    ]);
    assert.deepEqual(json, {
      status: "added",
      group_id: GROUP,
      requested: 2,
      endpoints_added: 2,
      added: [
        { id: A, hostname: "pc-a" },
        { id: B, hostname: "pc-b" },
      ],
      not_added: [],
      message: `Added 2 endpoint(s) to group ${GROUP}.`,
    });
  } finally {
    await h.close();
  }
});

test("some not found, some of the wrong type, one left out: partially_added with a reason for each", async () => {
  // The guide's example: two added, one already in the group (in neither list),
  // one not an endpoint ID, one a server sent to a computer group.
  const h = await harness({
    addedEndpoints: [{ id: A, hostname: "pc-a" }, { id: B, hostname: "pc-b" }],
    errors: { endpointsNotFound: [D], endpointsOfWrongType: [E] },
  });
  try {
    const json = await h.add([A, B, C, D, E]);
    assert.equal(json.status, "partially_added");
    assert.equal(json.requested, 5);
    assert.equal(json.endpoints_added, 2);
    assert.deepEqual(json.added, [{ id: A, hostname: "pc-a" }, { id: B, hostname: "pc-b" }]);
    assert.deepEqual(json.not_added, [
      { id: D, reason: "not_found" },
      { id: E, reason: "wrong_type" },
      { id: C, reason: "not_in_response" },
    ]);
    assert.equal(
      json.message,
      `Added 2 of 5 endpoint(s) to group ${GROUP}. Not added: 1 not found, 1 of the wrong type for the group, 1 not in the response (most likely already in the group).`
    );
    assert.match(json.note, /already in the group/);
    assert.match(json.note, /sophos_get_endpoint_group/);
  } finally {
    await h.close();
  }
});

test("nothing added: none_added, never added", async () => {
  const h = await harness({ addedEndpoints: [], errors: { endpointsNotFound: [A], endpointsOfWrongType: [B] } });
  try {
    const json = await h.add([A, B]);
    assert.equal(json.status, "none_added");
    assert.equal(json.endpoints_added, 0);
    assert.deepEqual(json.not_added, [
      { id: A, reason: "not_found" },
      { id: B, reason: "wrong_type" },
    ]);
    assert.equal(json.message, `Added none of 2 endpoint(s) to group ${GROUP}. Not added: 1 not found, 1 of the wrong type for the group.`);
    assert.equal(json.note, undefined);
  } finally {
    await h.close();
  }
});

test("a response with no lists claims nothing: every ID is not_in_response", async () => {
  const h = await harness({});
  try {
    const json = await h.add([A, B]);
    assert.equal(json.status, "none_added");
    assert.equal(json.endpoints_added, 0);
    assert.deepEqual(json.added, []);
    assert.deepEqual(json.not_added, [
      { id: A, reason: "not_in_response" },
      { id: B, reason: "not_in_response" },
    ]);
    assert.equal(
      json.message,
      `Added none of 2 endpoint(s) to group ${GROUP}. Not added: 2 not in the response (most likely already in the group).`
    );
    assert.match(json.note, /already in the group/);
  } finally {
    await h.close();
  }
});

test("addedEndpoints as bare IDs (the guide's shape) and IDs in another case still match", async () => {
  const h = await harness({ addedEndpoints: [A], errors: { endpointsNotFound: [B] } });
  try {
    const json = await h.add([A.toUpperCase(), B]);
    assert.equal(json.status, "partially_added");
    assert.deepEqual(json.added, [{ id: A }]);
    assert.deepEqual(json.not_added, [{ id: B, reason: "not_found" }]);
  } finally {
    await h.close();
  }
});

test("duplicate IDs are sent once, since the API requires unique IDs", async () => {
  const h = await harness({ addedEndpoints: [{ id: A, hostname: "pc-a" }, { id: B, hostname: "pc-b" }] });
  try {
    const json = await h.add([A, B, A, A.toUpperCase()]);
    assert.deepEqual(h.calls.map((c) => c.body), [{ ids: [A, B] }]);
    assert.equal(json.status, "added");
    assert.equal(json.requested, 2);
  } finally {
    await h.close();
  }
});
