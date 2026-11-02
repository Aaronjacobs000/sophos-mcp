/**
 * Tool responses stay within CHARACTER_LIMIT, and a page that does not fit
 * loses nothing. The old jsonResult cut the text at CHARACTER_LIMIT and then
 * appended its notice, so a response ran 92 characters over: a client capped
 * at the same size cut it mid-JSON and dropped the notice. Live (02/11/2026)
 * sophos_list_cases at 50, and sophos_list_firewalls and
 * sophos_list_live_discover_queries at 100, came back that way, and the next
 * page started after the items that were cut.
 *
 * Now a list that does not fit is cut to whole items, stays valid JSON, and
 * leads with a truncated key whose next request returns the omitted items.
 * The paging tests read a whole fake list through each tool by following
 * truncated.next (and resume) and the tool's own paging, and check every item
 * arrives in order. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { jsonResult } from "../dist/tools/helpers.js";
import { CHARACTER_LIMIT } from "../dist/config/config.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";

const textOf = (result) => result.content.map((c) => c.text ?? "").join("");
// Item i carries a string whose length varies with i, so pages differ in size.
const bulky = (i) => ({ id: `item-${String(i).padStart(4, "0")}`, blob: "x".repeat(400 + ((i * 397) % 1600)) });
const page = (count, from = 0) => Array.from({ length: count }, (_, i) => bulky(from + i));

test("a result that fits is returned unchanged", () => {
  const data = { total: 2, items: page(2) };
  assert.equal(textOf(jsonResult(data, { page: 1, limit: 50 })), JSON.stringify(data, null, 2));
});

test("an oversized page is cut to whole items inside the limit, with truncated as the first key", () => {
  const items = page(100);
  const text = textOf(jsonResult({ total: 250, page: 1, queries: items, other: [1, 2] }, { page: 1, limit: 100 }));
  assert.ok(text.length <= CHARACTER_LIMIT, `${text.length} characters`);
  const out = JSON.parse(text);
  assert.equal(Object.keys(out)[0], "truncated");
  assert.equal(out.truncated.field, "queries");
  assert.equal(out.truncated.returned, out.queries.length);
  assert.equal(out.truncated.returned + out.truncated.omitted, 100);
  assert.ok(out.truncated.returned > 0 && out.truncated.returned < 100);
  assert.deepEqual(out.queries, items.slice(0, out.truncated.returned));
  assert.deepEqual(out.other, [1, 2]);
  assert.equal(out.total, 250);
  // As many items as fit: one more would not.
  const k = out.truncated.returned;
  const withOneMore = JSON.stringify({ ...out, queries: items.slice(0, k + 1) }, null, 2);
  assert.ok(withOneMore.length > CHARACTER_LIMIT);
});

test("page paging: read the gap at the smaller size, then resume at the next page at the original size", () => {
  const first = JSON.parse(textOf(jsonResult({ items: page(100) }, { page: 1, limit: 100 })));
  const k = first.truncated.returned;
  assert.deepEqual(first.truncated.next, { page: 2, limit: k });
  assert.equal(first.truncated.next_through_page, Math.ceil(100 / k));
  assert.deepEqual(first.truncated.resume, { page: 2, limit: 100 });

  const third = JSON.parse(textOf(jsonResult({ items: page(100, 200) }, { page: 3, page_size: 100 })));
  const kept = third.truncated.returned;
  const { page: from, page_size: size } = third.truncated.next;
  const through = third.truncated.next_through_page;
  assert.equal(size, kept);
  // Pages from..through at the smaller size cover every omitted item (200+kept to 299).
  assert.ok((from - 1) * size <= 200 + kept, "the first gap page starts at or before the first omitted item");
  assert.ok(through * size >= 300, "the last gap page reaches the end of this page");
  assert.deepEqual(third.truncated.resume, { page: 4, page_size: 100 });

  // A short page is the last one: nothing to resume at.
  const last = JSON.parse(textOf(jsonResult({ items: page(90) }, { page: 2, limit: 100 })));
  assert.equal(last.truncated.resume, null);
  assert.ok(last.truncated.next_through_page * last.truncated.returned >= 190);
});

test("cursor paging: repeat with the same cursor (or none) at the smaller size", () => {
  const firstPage = JSON.parse(textOf(jsonResult({ endpoints: page(100) }, { cursor: undefined, limit: 100 })));
  assert.deepEqual(firstPage.truncated.next, { limit: firstPage.truncated.returned });
  const later = JSON.parse(textOf(jsonResult({ rows: page(100) }, { page_from_key: "key-9", limit: 100 })));
  assert.deepEqual(later.truncated.next, { page_from_key: "key-9", limit: later.truncated.returned });
  // Fusion list cases pages by number unless after is given.
  const byNumber = JSON.parse(textOf(jsonResult({ cases: page(100) }, { page: 1, per_page: 100, after: undefined })));
  assert.deepEqual(byNumber.truncated.next, { page: 2, per_page: byNumber.truncated.returned });
  const byCursor = JSON.parse(textOf(jsonResult({ cases: page(100) }, { page: 1, per_page: 100, after: "c1" })));
  assert.deepEqual(byCursor.truncated.next, { after: "c1", per_page: byCursor.truncated.returned });
});

test("offset paging: the next request starts at the first omitted item, at the same size", () => {
  const out = JSON.parse(textOf(jsonResult({ detections: page(100) }, { offset: 40, limit: 100 })));
  const k = out.truncated.returned;
  assert.deepEqual(out.truncated.next, { offset: 40 + k, limit: 100 });
});

test("pageField picks the page when another array is larger", () => {
  const values = page(20);
  const fields = Array.from({ length: 300 }, (_, i) => ({ name: `field_${i}`, type: "string".repeat(12) }));
  assert.ok(JSON.stringify(fields).length > JSON.stringify(values).length, "fields is the larger array");
  const out = JSON.parse(textOf(jsonResult({ values, fields }, { cursor: "c", limit: 20 }, "values")));
  assert.equal(out.truncated.field, "values");
  assert.equal(out.fields.length, 300);
  assert.deepEqual(out.truncated.next, { cursor: "c", limit: out.values.length });
});

test("without paging arguments the cut is still explicit, with no next request", () => {
  const out = JSON.parse(textOf(jsonResult(page(100))));
  assert.equal(out.truncated.field, "items");
  assert.equal(out.truncated.next, null);
  assert.equal(out.items.length, out.truncated.returned);
});

test("a result's own truncated key cannot replace the notice", () => {
  const out = JSON.parse(textOf(jsonResult({ truncated: false, items: page(100) }, { page: 1, limit: 100 })));
  assert.equal(typeof out.truncated, "object");
  assert.equal(out.truncated.returned, out.items.length);
});

test("a result with no array, or whose first item alone is too big, is cut as text inside the limit with a notice", () => {
  for (const data of [{ settings: "y".repeat(CHARACTER_LIMIT * 2) }, { items: [{ blob: "z".repeat(CHARACTER_LIMIT * 2) }] }]) {
    const text = textOf(jsonResult(data, { page: 1, limit: 50 }));
    assert.ok(text.length <= CHARACTER_LIMIT, `${text.length} characters`);
    assert.match(text, /\[TRUNCATED\] Response exceeded size limit/);
  }
});

// --- Reading a whole list through the tools ---

const ALL = page(260);

async function harness(module, registrar, answer) {
  const mod = await import(`../dist/tools/${module}.js`);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) =>
    new Response(JSON.stringify(answer(new URL(String(url)))), { status: 200, headers: { "Content-Type": "application/json" } });
  const identity = { id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => identity,
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  mod[registrar](server, client, tenantResolver, { assertClassic: async () => [] });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = textOf(result);
      assert.ok(!result.isError, `${name} failed: ${text}`);
      assert.ok(text.length <= CHARACTER_LIMIT, `${name} returned ${text.length} characters`);
      return JSON.parse(text);
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

// An offset API: page and pageSize select a slice of ALL.
const offsetApi = (shape) => (u) => {
  const size = Number(u.searchParams.get("pageSize"));
  const current = Number(u.searchParams.get("page"));
  const items = ALL.slice((current - 1) * size, current * size).map(shape);
  return { items, pages: { current, size, total: Math.ceil(ALL.length / size), items: ALL.length, maxSize: 100 } };
};

// A key API: pageFromKey is the index of the first item.
const keyApi = (shape) => (u) => {
  const size = Number(u.searchParams.get("pageSize"));
  const from = Number(u.searchParams.get("pageFromKey") ?? 0);
  const end = Math.min(from + size, ALL.length);
  return {
    items: ALL.slice(from, end).map(shape),
    pages: { size, maxSize: 500, items: ALL.length, ...(end < ALL.length ? { nextKey: String(end) } : {}) },
  };
};

/**
 * Pages through a page-numbered tool until the list ends. On a truncated page
 * it reads truncated.next through next_through_page, then takes resume (a
 * stack, since a gap page can be cut too); with resume false it ignores resume
 * and pages on at the smaller size. Returns the IDs in the order first seen,
 * the truncation count and the call count.
 */
async function readAllByPage(h, tool, args, field, { resume = true } = {}) {
  const ids = [];
  const pending = [];
  let truncations = 0;
  let request = { tenant_id: TENANT, ...args };
  for (let calls = 1; calls <= 300; calls++) {
    const out = await h.call(tool, request);
    for (const item of out[field]) if (!ids.includes(item.id)) ids.push(item.id);
    if (out.truncated) {
      truncations++;
      assert.ok(out.truncated.next, `${tool} names the next request`);
      if (resume) pending.push({ size: out.truncated.next.limit, through: out.truncated.next_through_page, resume: out.truncated.resume });
      request = { ...request, ...out.truncated.next };
      continue;
    }
    if (out.page >= out.total_pages) return { ids, truncations, calls };
    request = { ...request, page: out.page + 1 };
    while (pending.length && request.limit === pending.at(-1).size && request.page > pending.at(-1).through) {
      const done = pending.pop();
      if (!done.resume) return { ids, truncations, calls };
      request = { ...request, ...done.resume };
    }
  }
  assert.fail(`${tool} did not reach the end of the list`);
}

const CASES = [
  [
    "live-discover", "registerLiveDiscoverTools", "sophos_list_live_discover_queries", "/live-discover/v1/queries",
    { limit: 100 }, "queries", (q) => ({ id: q.id, name: q.id, description: "d", template: q.blob }),
  ],
  [
    "firewall", "registerFirewallTools", "sophos_list_firewalls", "/firewall/v1/firewalls",
    { limit: 100 }, "firewalls", (f) => ({ id: f.id, hostname: f.id, notes: f.blob }),
  ],
  [
    "cases", "registerCaseTools", "sophos_list_cases", "/cases/v1/cases",
    { limit: 50 }, "cases",
    (c) => ({ id: c.id, name: c.id, type: "investigation", severity: "high", status: "new", overview: c.blob.repeat(2), tenant: { id: TENANT }, createdAt: "2026-11-01T00:00:00Z" }),
  ],
];

for (const [module, registrar, tool, path, args, field, shape] of CASES) {
  test(`${tool}: at its largest page size every item arrives, in order, within the limit`, async () => {
    const h = await harness(module, registrar, (u) => {
      assert.equal(u.pathname, path);
      return offsetApi(shape)(u);
    });
    try {
      const resumed = await readAllByPage(h, tool, args, field);
      assert.ok(resumed.truncations > 0, "the first page does not fit");
      assert.deepEqual(resumed.ids, ALL.map((item) => item.id));
      const stayedSmall = await readAllByPage(h, tool, args, field, { resume: false });
      assert.deepEqual(stayedSmall.ids, ALL.map((item) => item.id), "paging on at the smaller size skips nothing");
    } finally {
      await h.close();
    }
  });
}

test("sophos_list_endpoints: at limit 100 every endpoint arrives, in order, by cursor", async () => {
  const shape = (e) => ({ id: e.id, hostname: e.blob.slice(0, 600), type: "computer", lastSeenAt: "2026-11-01T00:00:00Z", ipv4Addresses: [e.blob.slice(0, 400)] });
  const h = await harness("endpoints", "registerEndpointTools", keyApi(shape));
  try {
    const ids = [];
    let truncations = 0;
    let request = { tenant_id: TENANT, limit: 100 };
    for (let calls = 0; calls < 200; calls++) {
      const out = await h.call("sophos_list_endpoints", request);
      for (const item of out.endpoints) if (!ids.includes(item.id)) ids.push(item.id);
      if (out.truncated) {
        truncations++;
        request = { tenant_id: TENANT, ...out.truncated.next };
        continue;
      }
      if (!out.next_cursor) break;
      // Any limit works after the repeat: go back to 100.
      request = { tenant_id: TENANT, cursor: out.next_cursor, limit: 100 };
    }
    assert.ok(truncations > 0, "the first page does not fit");
    assert.deepEqual(ids, ALL.map((item) => item.id));
  } finally {
    await h.close();
  }
});
