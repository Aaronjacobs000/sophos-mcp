/**
 * The REST client refuses a path an ID argument has bent toward another
 * resource ("..", encoded dots, backslashes, "?", "#", an encoded "/", control
 * characters) before it fetches a token or sends anything, and still sends
 * the IDs Sophos actually uses. fetch is stubbed; no network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerEmailTools } from "../dist/tools/email.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";

function harness() {
  const calls = [];
  let tokens = 0;
  const tokenManager = { getToken: async () => (tokens++, "fake-token") };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method });
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  return {
    client: new SophosClient(tokenManager, tenantResolver),
    tenantResolver,
    calls,
    tokens: () => tokens,
    restore: () => (globalThis.fetch = realFetch),
  };
}

const TRAVERSAL_IDS = [
  "../../../common/v1/admins/x",
  "..",
  ".",
  "%2e%2e",
  ".%2E",
  "%252e%252e",
  "..%2Fcommon",
  "x%2fy",
  "x%5Cy",
  "a\\..\\..\\common",
  ".\t.",
  "x\ny",
  "x?pageSize=1",
  "x#",
  "%zz",
];

test("a traversal ID is refused before any token fetch or request", async () => {
  const h = harness();
  try {
    for (const id of TRAVERSAL_IDS) {
      await assert.rejects(
        h.client.tenantRequest(TENANT, `/endpoint/v1/settings/exclusions/scanning/${id}`, { method: "DELETE" }),
        /Refused request path/,
        JSON.stringify(id)
      );
      await assert.rejects(h.client.globalRequest(`/partner/v1/admins/${id}`, { method: "DELETE" }), /Refused request path/);
    }
    assert.equal(h.calls.length, 0, "no request was sent");
    assert.equal(h.tokens(), 0, "no token was fetched");
  } finally {
    h.restore();
  }
});

test("the IDs Sophos uses still go through unchanged", async () => {
  const h = harness();
  try {
    const ids = [
      "659240aa-797e-42cf-bb82-cca43c4e80d8", // UUID: endpoints, alerts, firewalls, policies
      "1-598868", // Classic case ID
      "abc_DEF-123",
      "v1.2.3", // a dot inside a segment is fine
      "...", // three dots is not a dot segment
      encodeURIComponent("Q 12345"), // the one value tools already encode
    ];
    for (const id of ids) {
      await h.client.tenantRequest(TENANT, `/email/v1/mailboxes/${id}`, { params: { pageSize: "10" } });
    }
    await h.client.globalRequest("/partner/v1/tenants/659240aa-797e-42cf-bb82-cca43c4e80d8");
    assert.deepEqual(
      h.calls.map((c) => c.url),
      [
        `${HOST}/email/v1/mailboxes/659240aa-797e-42cf-bb82-cca43c4e80d8?pageSize=10`,
        `${HOST}/email/v1/mailboxes/1-598868?pageSize=10`,
        `${HOST}/email/v1/mailboxes/abc_DEF-123?pageSize=10`,
        `${HOST}/email/v1/mailboxes/v1.2.3?pageSize=10`,
        `${HOST}/email/v1/mailboxes/...?pageSize=10`,
        `${HOST}/email/v1/mailboxes/Q%2012345?pageSize=10`,
        "https://api.central.sophos.com/partner/v1/tenants/659240aa-797e-42cf-bb82-cca43c4e80d8",
      ]
    );
  } finally {
    h.restore();
  }
});

test("the refusal reaches the model as a tool error and nothing is deleted", async () => {
  const h = harness();
  try {
    const server = new McpServer({ name: "test", version: "0.0.0" });
    registerEmailTools(server, h.client, h.tenantResolver);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "test-client", version: "0.0.0" });
    await client.connect(clientTransport);

    const result = await client.callTool({
      name: "sophos_delete_mailbox",
      arguments: { mailbox_id: "../../../endpoint/v1/endpoints/659240aa-797e-42cf-bb82-cca43c4e80d8" },
    });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /Refused request path/);
    assert.equal(h.calls.length, 0);

    await client.close();
    await server.close();
  } finally {
    h.restore();
  }
});
