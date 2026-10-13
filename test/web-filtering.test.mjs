/**
 * Web filtering profile and site list tools against an in-memory API that
 * behaves as Sophos did on 13/10/2026: PUT replaces the whole object (an
 * omitted field is cleared), a preset beside category actions gets 400, and
 * consumers is ignored. Also checks the metadata call sends a bare "en"
 * Accept-Language (Node's default "*" gets a 400). No network.
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
const LIST = "00000000-0000-4000-8000-0000000000f2";

const reply = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const WRITABLE = ["name", "description", "filterByCategory", "preset", "categoryGroupActions", "categoryActions", "filterBySiteList", "siteListActions"];

async function harness() {
  const profiles = new Map([
    [PROFILE, {
      id: PROFILE,
      name: "ZZ profile",
      description: "keep me",
      filterByCategory: true,
      categoryGroupActions: [{ name: "adult", action: "block" }],
      categoryActions: [{ name: "uncategorized", action: "warn" }],
      filterBySiteList: true,
      siteListActions: [{ id: LIST, action: "allow", priority: 1 }],
      consumers: [{ type: "computerWebControlPolicy", id: POLICY }],
      updatedAt: "2026-10-13T00:00:00.000Z",
    }],
  ]);
  const lists = new Map([[LIST, { id: LIST, name: "ZZ list", description: "keep me too", sites: ["a.example", "b.example"] }]]);
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    calls.push({ url: u, method, headers: init?.headers ?? {}, body });
    const [, , kind, id] = u.pathname.split("/").filter(Boolean);
    if (kind === "profiles" && id === "metadata") return reply(200, { presets: [], categories: [] });
    const map = kind === "profiles" ? profiles : lists;
    if (method === "POST") return reply(201, { id: PROFILE, ...body });
    const item = map.get(id);
    if (!item) return reply(404, { error: "notFound" });
    if (method === "GET") return reply(200, item);
    if (method === "PUT") {
      if (kind === "profiles" && body.preset && (body.categoryActions || body.categoryGroupActions)) {
        return reply(400, { error: "badRequest", message: "Profile preset specified with categoryActions." });
      }
      // PUT replaces: every writable field not in the body is cleared; consumers is ignored
      const next = { id, consumers: item.consumers };
      const writable = kind === "profiles" ? WRITABLE : ["name", "description", "sites"];
      for (const key of writable) if (key in body) next[key] = body[key];
      map.set(id, next);
      return reply(200, next);
    }
    return reply(405, { error: "methodNotAllowed" });
  };
  const tenantResolver = { resolveApiHost: async () => HOST, resolveTenantId: (tid) => tid ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerWebFilteringTools(server, new SophosClient({ getToken: async () => "fake-token" }, tenantResolver), tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    profiles,
    lists,
    mcp,
    puts: () => calls.filter((c) => c.method === "PUT"),
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

test("profile create and update never send consumers, even when a caller passes it", async () => {
  const h = await harness();
  try {
    const consumers = [{ type: "computerWebControlPolicy", id: POLICY }];
    await h.call("sophos_create_web_filtering_profile", { name: "ZZ p", preset: "keep-it-clean", consumers });
    await h.call("sophos_update_web_filtering_profile", { profile_id: PROFILE, name: "ZZ p", consumers });
    for (const call of h.calls.filter((c) => c.method !== "GET")) {
      assert.equal("consumers" in call.body, false, `${call.method} sent no consumers`);
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

test("a profile update that names one field keeps every other stored field", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_update_web_filtering_profile", { profile_id: PROFILE, name: "ZZ renamed" });
    assert.equal(isError, false, JSON.stringify(json));
    assert.deepEqual(h.calls.map((c) => c.method), ["GET", "PUT"]);
    const stored = h.profiles.get(PROFILE);
    assert.equal(stored.name, "ZZ renamed");
    assert.equal(stored.description, "keep me");
    assert.deepEqual(stored.categoryGroupActions, [{ name: "adult", action: "block" }]);
    assert.deepEqual(stored.categoryActions, [{ name: "uncategorized", action: "warn" }]);
    assert.deepEqual(stored.siteListActions, [{ id: LIST, action: "allow", priority: 1 }]);
    assert.equal(stored.filterBySiteList, true);
    assert.deepEqual(json.kept_from_stored.sort(), ["categoryActions", "categoryGroupActions", "description", "filterByCategory", "filterBySiteList", "siteListActions"]);
  } finally {
    await h.close();
  }
});

test("a preset replaces the stored category actions as one unit, so Sophos does not refuse it", async () => {
  const h = await harness();
  try {
    const { isError } = await h.call("sophos_update_web_filtering_profile", { profile_id: PROFILE, preset: "keep-it-clean" });
    assert.equal(isError, false);
    const body = h.puts()[0].body;
    assert.equal(body.preset, "keep-it-clean");
    assert.equal("categoryActions" in body, false);
    assert.equal("categoryGroupActions" in body, false);
    assert.equal(body.description, "keep me", "unrelated fields still kept");

    const back = await h.call("sophos_update_web_filtering_profile", {
      profile_id: PROFILE,
      category_group_actions: [{ name: "adult", action: "warn" }],
    });
    assert.equal(back.isError, false);
    assert.equal("preset" in h.puts()[1].body, false, "the stored preset is dropped when actions are passed");
  } finally {
    await h.close();
  }
});

test("a site list update keeps the stored sites and description unless they are passed", async () => {
  const h = await harness();
  try {
    const renamed = await h.call("sophos_update_site_list", { site_list_id: LIST, name: "ZZ list 2" });
    assert.equal(renamed.isError, false);
    assert.deepEqual(h.lists.get(LIST), { id: LIST, consumers: undefined, name: "ZZ list 2", description: "keep me too", sites: ["a.example", "b.example"] });
    assert.deepEqual(renamed.json.kept_from_stored, ["description", "sites"]);

    const resited = await h.call("sophos_update_site_list", { site_list_id: LIST, sites: ["c.example"] });
    assert.equal(resited.isError, false);
    assert.deepEqual(h.lists.get(LIST).sites, ["c.example"]);
    assert.equal(h.lists.get(LIST).name, "ZZ list 2");
    assert.equal(h.lists.get(LIST).description, "keep me too");
  } finally {
    await h.close();
  }
});

test("the replacing updates are marked destructive and say they replace the whole object", async () => {
  const h = await harness();
  try {
    const { tools } = await h.mcp.listTools();
    for (const [name, pattern] of [
      ["sophos_update_web_filtering_profile", /replaces the whole profile/],
      ["sophos_update_site_list", /replaces the whole list/],
    ]) {
      const tool = tools.find((t) => t.name === name);
      assert.equal(tool.annotations.destructiveHint, true, name);
      assert.match(tool.description, pattern, name);
      assert.match(tool.description, /fields you leave out keep their values/, name);
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
