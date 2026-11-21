/**
 * Read-only mode (SOPHOS_READ_ONLY), second half: with the mode on, the
 * request guard refuses every request that could write before anything is
 * sent, on its own, with no help from the tool filter. The mode cannot be
 * turned off again, so this file turns it on once at the top. fetch is
 * stubbed and counted; no network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  enableReadOnlyMode,
  guardedFetch,
  isGraphQLReadOnly,
  isReadOnlyMode,
  READ_ONLY_POST_PATHS,
  ReadOnlyModeError,
  requestRefusal,
} from "../dist/client/read-only-guard.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { FusionClient } from "../dist/client/fusion-client.js";
import { TokenManager } from "../dist/auth/token-manager.js";
import { registerEndpointTools } from "../dist/tools/endpoints.js";
import { SOPHOS_AUTH_URL, SOPHOS_FUSION_GRAPHQL_URL } from "../dist/config/config.js";

enableReadOnlyMode();

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const ENDPOINT = "659240aa-797e-42cf-bb82-cca43c4e80d8";

function harness() {
  const calls = [];
  let tokens = 0;
  const tokenManager = { getToken: async () => (tokens++, "fake-token") };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "partner", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Partner-ID", value: TENANT }),
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method ?? "GET" });
    const body = String(url) === SOPHOS_AUTH_URL ? { access_token: "t", expires_in: 3600, errorCode: "success" } : { data: { ok: true }, items: [], pages: {} };
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  return {
    rest: new SophosClient(tokenManager, tenantResolver),
    fusion: new FusionClient(tokenManager, { backoffBaseMs: 1 }),
    tenantResolver,
    calls,
    tokens: () => tokens,
    restore: () => (globalThis.fetch = realFetch),
  };
}

test("the mode is on and stays on", () => {
  assert.equal(isReadOnlyMode(), true);
  enableReadOnlyMode();
  assert.equal(isReadOnlyMode(), true);
});

test("a REST write is refused before a token is fetched or anything is sent", async () => {
  const h = harness();
  try {
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      await assert.rejects(
        h.rest.tenantRequest(TENANT, `/endpoint/v1/endpoints/${ENDPOINT}/isolation`, { method, body: { enabled: true } }),
        (error) => error instanceof ReadOnlyModeError && error.message.includes(`refused ${method} /endpoint/v1`),
        method
      );
      await assert.rejects(h.rest.globalRequest("/partner/v1/tenants", { method, body: {} }), ReadOnlyModeError, method);
    }
    assert.equal(h.calls.length, 0, "nothing was sent");
    assert.equal(h.tokens(), 0, "no token was fetched");
  } finally {
    h.restore();
  }
});

test("a REST read and the allowlisted searches still go out", async () => {
  const h = harness();
  try {
    await h.rest.tenantRequest(TENANT, "/endpoint/v1/endpoints");
    await h.rest.tenantRequest(TENANT, "/common/v1/alerts/search", { method: "POST", body: {} });
    await h.rest.tenantRequest(TENANT, "/email/v1/quarantine/messages/search", { method: "POST", body: {} });
    await h.rest.tenantRequest(TENANT, "/email/v1/post-delivery-quarantine/messages/search", { method: "POST", body: {} });
    await h.rest.tenantRequest(TENANT, `/firewall/v1/firewall-config/firewalls/${ENDPOINT}/mdr-threat-feed/indicators/search`, { method: "POST", body: {} });
    await h.rest.globalRequest("/partner/v1/tenants");
    assert.deepEqual(h.calls.map((c) => c.method), ["GET", "POST", "POST", "POST", "POST", "GET"]);
    assert.equal(READ_ONLY_POST_PATHS.length, 4);
  } finally {
    h.restore();
  }
});

test("a Fusion mutation is refused before a token is fetched; a query still goes out", async () => {
  const h = harness();
  try {
    await assert.rejects(h.fusion.query(TENANT, "mutation FusionCreateCase($input: X) { createCase(input: $input) { id } }"), ReadOnlyModeError);
    await assert.rejects(h.fusion.query(TENANT, "query A { a }\nmutation B { b }"), ReadOnlyModeError);
    await assert.rejects(h.fusion.putPresigned("https://fake-upload.test/put", new Uint8Array([1]), "text/plain"), ReadOnlyModeError);
    assert.equal(h.calls.length, 0, "nothing was sent");
    assert.equal(h.tokens(), 0, "no token was fetched");
    await h.fusion.query(TENANT, "query FusionListCases { cases { totalCount } }");
    assert.deepEqual(h.calls.map((c) => c.url), [SOPHOS_FUSION_GRAPHQL_URL]);
  } finally {
    h.restore();
  }
});

test("every mutation document in the server is refused and every query document passes", async () => {
  const dir = new URL("../dist/fusion/queries/", import.meta.url);
  let queries = 0;
  let mutations = 0;
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".js"))) {
    for (const [name, document] of Object.entries(await import(new URL(file, dir).href))) {
      if (typeof document !== "string" || !/^\s*(query|mutation)\b/.test(document)) continue;
      const mutation = /^\s*mutation\b/.test(document);
      mutation ? mutations++ : queries++;
      assert.equal(isGraphQLReadOnly(document), !mutation, `${file} ${name}`);
      const body = JSON.stringify({ query: document, variables: {} });
      assert.equal(requestRefusal(SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body }) === null, !mutation, `${file} ${name}`);
    }
  }
  assert.ok(queries > 30 && mutations > 20, `${queries} queries, ${mutations} mutations`);
});

test("the guard itself refuses anything that could write and sends nothing", async () => {
  const h = harness();
  try {
    const refused = [
      ["https://fake-upload.test/put", { method: "PUT", body: "x" }],
      [`${HOST}/endpoint/v1/endpoints/${ENDPOINT}`, { method: "DELETE" }],
      [`${HOST}/endpoint/v1/endpoints/${ENDPOINT}/scans`, { method: "POST", body: "{}" }],
      [`${HOST}/firewall/v1/firewall-config/firewalls/import`, { method: "POST" }],
      // An allowlisted path counts only on an https sophos.com host
      ["https://attacker.example/common/v1/alerts/search", { method: "POST", body: "{}" }],
      ["http://api-au01.central.sophos.com/common/v1/alerts/search", { method: "POST", body: "{}" }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: JSON.stringify({ query: "mutation { deleteCaseFile(input: {}) { id } }" }) }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: JSON.stringify({ query: "  ,mutation{a}" }) }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: JSON.stringify([{ query: "query { a }" }]) }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: JSON.stringify({ extensions: { persistedQuery: {} } }) }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: "not json" }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: new Uint8Array([1]) }],
      [`${SOPHOS_FUSION_GRAPHQL_URL}?query=mutation%7Ba%7D`, { method: "GET" }],
      ["not a url", { method: "POST" }],
    ];
    for (const [url, init] of refused) {
      assert.notEqual(requestRefusal(url, init), null, `${init.method} ${url}`);
      await assert.rejects(guardedFetch(url, init), ReadOnlyModeError, `${init.method} ${url}`);
    }
    assert.equal(h.calls.length, 0, "nothing was sent");

    const allowed = [
      [SOPHOS_AUTH_URL, { method: "POST", body: "grant_type=client_credentials" }],
      ["https://api.central.sophos.com/whoami/v1", undefined],
      [`${HOST}/endpoint/v1/endpoints`, { method: "HEAD" }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: JSON.stringify({ query: "query X { cases { totalCount } }", variables: {} }) }],
      [SOPHOS_FUSION_GRAPHQL_URL, { method: "POST", body: JSON.stringify({ query: "{ cases { totalCount } }" }) }],
    ];
    for (const [url, init] of allowed) {
      assert.equal(requestRefusal(url, init), null, `${init?.method ?? "GET"} ${url}`);
      await guardedFetch(url, init);
    }
    assert.equal(h.calls.length, allowed.length);
  } finally {
    h.restore();
  }
});

test("the token request still goes out, so reads keep working", async () => {
  const h = harness();
  try {
    const token = await new TokenManager("id", "secret").getToken();
    assert.equal(token, "t");
    assert.deepEqual(h.calls.map((c) => [c.url, c.method]), [[SOPHOS_AUTH_URL, "POST"]]);
  } finally {
    h.restore();
  }
});

test("a write tool registered without the filter is still stopped by the guard", async () => {
  const h = harness();
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerEndpointTools(server, h.rest, h.tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  try {
    for (const [name, args] of [
      ["sophos_isolate_endpoint", { endpoint_id: ENDPOINT, tenant_id: TENANT }],
      ["sophos_delete_endpoint", { endpoint_id: ENDPOINT, tenant_id: TENANT }],
      ["sophos_scan_endpoint", { endpoint_id: ENDPOINT, tenant_id: TENANT }],
    ]) {
      const result = await client.callTool({ name, arguments: args });
      assert.equal(result.isError, true, name);
      assert.match(result.content[0].text, /Read-only mode \(SOPHOS_READ_ONLY\) refused/, name);
    }
    assert.equal(h.calls.length, 0, "nothing was sent");
    assert.equal(h.tokens(), 0, "no token was fetched");
  } finally {
    await client.close();
    await server.close();
    h.restore();
  }
});
