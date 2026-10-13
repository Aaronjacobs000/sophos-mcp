/**
 * Web filtering profile tools with fetch stubbed: consumers is never sent
 * (Sophos ignores it on a profile write, measured 13/10/2026), and the
 * metadata call sends a bare "en" Accept-Language (Node's default "*" gets a
 * 400). No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerWebFilteringTools } from "../dist/tools/web-filtering.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const POLICY = "00000000-0000-4000-8000-0000000000e1";
const PROFILE = "00000000-0000-4000-8000-0000000000f1";

async function harness() {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({
      url: new URL(String(url)),
      method: init?.method ?? "GET",
      headers: init?.headers ?? {},
      body: init?.body === undefined ? undefined : JSON.parse(init.body),
    });
    return new Response(JSON.stringify({ id: PROFILE }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const tenantResolver = { resolveApiHost: async () => HOST, resolveTenantId: (id) => id ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerWebFilteringTools(server, new SophosClient({ getToken: async () => "fake-token" }, tenantResolver), tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    mcp,
    call: (name, args) => mcp.callTool({ name, arguments: args }),
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

test("profile create and update never send consumers, even when a caller passes it", async () => {
  const h = await harness();
  try {
    const consumers = [{ type: "computerWebControlPolicy", id: POLICY }];
    await h.call("sophos_create_web_filtering_profile", { name: "ZZ p", preset: "keep-it-clean", consumers });
    await h.call("sophos_update_web_filtering_profile", { profile_id: PROFILE, name: "ZZ p", preset: "keep-it-clean", consumers });
    assert.equal(h.calls.length, 2);
    for (const call of h.calls) {
      assert.deepEqual(call.body, { name: "ZZ p", preset: "keep-it-clean" });
    }
    const { tools } = await h.mcp.listTools();
    for (const name of ["sophos_create_web_filtering_profile", "sophos_update_web_filtering_profile"]) {
      const tool = tools.find((t) => t.name === name);
      assert.equal(tool.inputSchema.properties.consumers, undefined, `${name} takes no consumers`);
      assert.match(tool.description, /Sophos\s+ignores\s+(consumers|it)/, name);
    }
  } finally {
    await h.close();
  }
});

test("the metadata call sends a bare en Accept-Language", async () => {
  const h = await harness();
  try {
    await h.call("sophos_get_web_filtering_metadata", {});
    assert.equal(h.calls[0].url.pathname, "/web-filters/v1/profiles/metadata");
    assert.equal(h.calls[0].headers["Accept-Language"], "en");
  } finally {
    await h.close();
  }
});
