/**
 * sophos_fusion_endpoint_inventory: the QL it sends, the reduction of Data
 * Lake inventory rows to each device's latest snapshot, and the stale flag
 * from the Endpoint API's lastSeenAt. The pure functions are tested directly;
 * the tool runs through its real handler with a fake Fusion client and fetch
 * stubbed for the Endpoint API. The fixtures follow the shapes measured live
 * on 03/11/2026: snapshot rows a few milliseconds apart, snapshots a day apart,
 * results newest first, aggregate keys max_time, row_count and
 * device_hostname. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerFusionInventoryTools } from "../dist/tools/fusion-inventory.js";
import { SEARCH_RESULTS_TIMEOUT_MS } from "../dist/fusion/queries/search.js";
import {
  DAY_MS,
  SNAPSHOT_SPREAD_MS,
  buildDevicesQl,
  buildRowsQl,
  classifyLastSeen,
  compactRow,
  compareDevices,
  inventoryWindow,
  kbFromTitle,
  latestSnapshots,
  lookupIds,
  mergeDeviceAggregates,
  pick,
  readFloor,
  sortRows,
} from "../dist/fusion/inventory.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const NOW = Date.parse("2026-11-03T03:48:55Z");
const BATCH = Date.parse("2026-11-02T22:08:22.600Z");
const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

test("the window ends at the next whole UTC hour, so a repeat in the same hour builds the same query", () => {
  assert.deepEqual(inventoryWindow(NOW, 2), { earliest: "2026-11-01T04:00:00Z", latest: "2026-11-03T04:00:00Z" });
  assert.deepEqual(inventoryWindow(Date.parse("2026-11-03T03:00:01Z"), 1), inventoryWindow(Date.parse("2026-11-03T03:59:59Z"), 1));
  assert.deepEqual(inventoryWindow(Date.parse("2026-11-03T04:00:00Z"), 30), {
    earliest: "2026-10-04T04:00:00Z",
    latest: "2026-11-03T04:00:00Z",
  });
});

test("the QL: discovery events dropped, filters quoted and joined, aggregate and projection per schema", () => {
  const window = inventoryWindow(NOW, 2);
  const bounds = "earliest='2026-11-01T04:00:00Z' latest='2026-11-03T04:00:00Z'";
  assert.equal(
    buildDevicesQl("inventoryinfo", {}, window),
    `from inventoryinfo where normalizer != 'sophos-xdr-telemetry-normalizer' ${bounds} | aggregate max(time), count by host_id, device.hostname, sensor_type`
  );
  assert.equal(
    buildRowsQl("softwareinfo", { hostname: "web", softwareName: "Chrome", endpointId: id(1) }, window),
    `from softwareinfo where normalizer != 'sophos-xdr-telemetry-normalizer' and host_id = '${id(1)}' and device.hostname contains 'web' and product.name contains 'Chrome' ${bounds} | fields host_id, time, sensor_type, device.hostname, device.os.name, product.name, product.version, product.vendor_name, install_time`
  );
  assert.equal(
    buildRowsQl("patchstate", { kb: "KB5007651" }, window),
    `from patchstate where normalizer != 'sophos-xdr-telemetry-normalizer' and kb_article.title contains 'KB5007651' ${bounds} | fields host_id, time, sensor_type, device.hostname, device.os.name, kb_article.title, kb_article.install_time, actor.user.name`
  );
  assert.match(buildRowsQl("inventoryinfo", {}, window), /\| fields .*device\.os\.last_update_time.*device\.ip$/);
  assert.doesNotMatch(buildRowsQl("inventoryinfo", {}, window), /storage_volumes/, "QL refuses device.storage_volumes");
  assert.throws(() => buildRowsQl("patchstate", { softwareName: "x" }, window), /software_name filters softwareinfo only/);
  assert.throws(() => buildDevicesQl("softwareinfo", { kb: "KB1" }, window), /kb filters patchstate only/);
  assert.throws(() => buildRowsQl("softwareinfo", { hostname: "it's" }, window), /cannot contain a single quote/);
});

test("aggregate rows merge per device: a renamed device sums its counts and takes the newest hostname", () => {
  const devices = mergeDeviceAggregates([
    { host_id: id(1), device_hostname: "OLD-NAME", sensor_type: "ENDPOINT_SOPHOS", max_time: BATCH - DAY_MS, row_count: 30 },
    { host_id: id(1), device_hostname: "NEW-NAME", sensor_type: "ENDPOINT_SOPHOS", max_time: String(BATCH), row_count: "2" },
    { host_id: id(2), device_hostname: null, sensor_type: null, max_time: BATCH, row_count: 1 },
    { host_id: id(2), device_hostname: "NAMED", sensor_type: "ENDPOINT_SOPHOS", max_time: BATCH, row_count: 1 },
    { host_id: null, max_time: BATCH, row_count: 5 },
    { host_id: id(3), max_time: "not a time", row_count: 5 },
  ]);
  assert.deepEqual([...devices.keys()], [id(1), id(2)]);
  assert.deepEqual(devices.get(id(1)), { hostId: id(1), hostname: "NEW-NAME", sensorType: "ENDPOINT_SOPHOS", maxTime: BATCH, rowCount: 32 });
  assert.equal(devices.get(id(2)).hostname, "NAMED", "a named row beats a null hostname at the same time");
  assert.equal(devices.get(id(2)).rowCount, 2);
  assert.equal(readFloor(devices.values()), BATCH - SNAPSHOT_SPREAD_MS);
  assert.equal(readFloor([]), null);
  assert.equal(
    readFloor([{ maxTime: BATCH }, { maxTime: BATCH - 5 * DAY_MS }]),
    BATCH - 5 * DAY_MS - SNAPSHOT_SPREAD_MS,
    "the floor is the oldest device's snapshot start"
  );
});

/** Rows newest first, as the search returns them. */
function rowsOf(...specs) {
  return specs
    .flatMap(([host, time, count, extra = {}]) =>
      Array.from({ length: count }, (_, i) => ({ host_id: host, time: time - i, sensor_type: "ENDPOINT_SOPHOS", ...extra }))
    )
    .sort((a, b) => b.time - a.time);
}

test("the latest snapshot per device: rows milliseconds apart are one snapshot, a day earlier is another", () => {
  const rows = rowsOf([id(1), BATCH, 3], [id(1), BATCH - DAY_MS, 3], [id(2), BATCH - 2 * DAY_MS, 2], [id(2), BATCH - 3 * DAY_MS, 2]);
  const all = latestSnapshots(rows, true);
  assert.equal(all.get(id(1)).rows.length, 3);
  assert.ok(all.get(id(1)).rows.every((r) => r.time > BATCH - 10), "only the newest day");
  assert.equal(all.get(id(1)).time, BATCH);
  assert.equal(all.get(id(2)).rows.length, 2, "an offline device's own newest snapshot, though older than the others");
  assert.equal(all.get(id(2)).time, BATCH - 2 * DAY_MS);
  assert.ok([...all.values()].every((s) => s.complete), "everything read");
});

test("completeness: a snapshot is whole once an older row was read, cut off when reading stopped inside it", () => {
  const rows = rowsOf([id(1), BATCH, 4], [id(2), BATCH - 100, 4], [id(3), BATCH - DAY_MS, 4]);
  // Stopped after 6 rows: id(1) whole, id(2) cut at 2 of 4, id(3) not reached.
  const cut = latestSnapshots(rows.slice(0, 6), false);
  assert.equal(cut.get(id(1)).rows.length, 4);
  assert.equal(cut.get(id(1)).complete, false, "the last row read is inside id(1)'s spread, so more of it could follow");
  assert.equal(cut.get(id(2)).rows.length, 2);
  assert.equal(cut.get(id(2)).complete, false);
  assert.equal(cut.has(id(3)), false, "a device not reached has no snapshot");
  // Stopped after reading into id(3), a day older: id(1) and id(2) are whole.
  const past = latestSnapshots(rows.slice(0, 9), false);
  assert.equal(past.get(id(1)).complete, true);
  assert.equal(past.get(id(2)).complete, true);
  assert.equal(past.get(id(2)).rows.length, 4);
  assert.equal(past.get(id(3)).complete, false);
  // Rows without a host or time are ignored.
  assert.equal(latestSnapshots([{ time: BATCH }, { host_id: id(9) }], true).size, 0);
});

test("stale, fresh and unmatched come from lastSeenAt against stale_after_days", () => {
  assert.deepEqual(classifyLastSeen("2026-11-03T03:00:00Z", NOW, 3), { status: "fresh", daysSinceSeen: 0 });
  assert.deepEqual(classifyLastSeen("2026-10-16T10:33:31.946Z", NOW, 3), { status: "stale", daysSinceSeen: 17.7 });
  assert.equal(classifyLastSeen(new Date(NOW - 3 * DAY_MS).toISOString(), NOW, 3).status, "fresh", "exactly the threshold is fresh");
  assert.equal(classifyLastSeen(new Date(NOW - 3 * DAY_MS - 1000).toISOString(), NOW, 3).status, "stale");
  assert.equal(classifyLastSeen(new Date(NOW - 5 * DAY_MS).toISOString(), NOW, 7).status, "fresh");
  assert.deepEqual(classifyLastSeen(undefined, NOW, 3), { status: "unmatched", daysSinceSeen: null });
  assert.deepEqual(classifyLastSeen("garbage", NOW, 3), { status: "unmatched", daysSinceSeen: null });
});

test("rows compact per schema, from nested objects or dotted keys", () => {
  assert.deepEqual(
    compactRow("softwareinfo", {
      product: { name: "Google Chrome", version: "156.0.8078.36", vendor_name: "Google LLC" },
      install_time: Date.parse("2026-10-16T00:00:00Z"),
    }),
    { name: "Google Chrome", version: "156.0.8078.36", vendor: "Google LLC", installed_at: "2026-10-16T00:00:00.000Z" }
  );
  assert.deepEqual(
    compactRow("patchstate", {
      "kb_article.title": "Update for Windows Security platform - KB5007651 (Version 10.0.29628.1000)",
      "kb_article.install_time": 1785536208000,
      actor: { user: { name: "Windows Update" } },
    }),
    {
      kb: "KB5007651",
      title: "Update for Windows Security platform - KB5007651 (Version 10.0.29628.1000)",
      installed_at: "2026-07-31T22:16:48.000Z",
      installed_by: "Windows Update",
    }
  );
  const inventory = compactRow("inventoryinfo", {
    device: {
      os: { name: "Windows 11 Pro ", version: "11.0", last_update_time: 1785536289000 },
      boot_time: 1790488630000,
      domain: "WORKGROUP",
      type_id: "TYPE_ID_DESKTOP",
      is_domain_controller: false,
      mac: "00:0C:29:7A:4C:35",
      ip: null,
      storage_volumes: [{ uid: "vol1", encryption_status_id: "ENCRYPTION_STATUS_ID_NOT_ENCRYPTED" }],
    },
  });
  assert.equal(inventory.os, "Windows 11 Pro", "trimmed");
  assert.equal(inventory.os_last_update_at, "2026-07-31T22:18:09.000Z");
  assert.equal(inventory.is_domain_controller, false, "false is kept, not nulled");
  assert.equal(inventory.ip, null);
  assert.deepEqual(inventory.storage_volumes, [{ uid: "vol1", encryption_status: "ENCRYPTION_STATUS_ID_NOT_ENCRYPTED" }]);
  assert.equal(compactRow("inventoryinfo", { device: {} }).storage_volumes, null);
  assert.equal(compactRow("softwareinfo", { install_time: 0 }).installed_at, null, "0 is no install time");
  assert.equal(kbFromTitle("9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2"), null);
  assert.equal(kbFromTitle("Windows Malicious Software Removal Tool x64 - v5.139 (kb890830)"), "KB890830");
  assert.equal(pick({ "a.b": 1, a: { b: 2 } }, "a.b"), 1, "a flat dotted key wins");
  assert.equal(pick({ a: null }, "a.b"), undefined);
});

test("ordering: devices stale, unmatched, fresh then hostname; rows by name and version or KB, nulls last", () => {
  const devices = [
    { status: "fresh", hostname: "b", endpoint_id: "2" },
    { status: "unmatched", hostname: "a", endpoint_id: "3" },
    { status: "stale", hostname: "Z", endpoint_id: "4" },
    { status: "fresh", hostname: "A", endpoint_id: "1" },
    { status: "stale", hostname: null, endpoint_id: "5" },
  ].sort(compareDevices);
  assert.deepEqual(devices.map((d) => d.endpoint_id), ["5", "4", "3", "1", "2"]);
  assert.deepEqual(
    sortRows("softwareinfo", [
      { name: "chrome", version: "10.0" },
      { name: null, version: "1" },
      { name: "Chrome", version: "9.0" },
      { name: "Acrobat", version: "1" },
    ]).map((r) => `${r.name}@${r.version}`),
    ["Acrobat@1", "Chrome@9.0", "chrome@10.0", "null@1"]
  );
  assert.deepEqual(
    sortRows("patchstate", [{ kb: "KB5007651" }, { kb: null, title: "x" }, { kb: "KB890830" }]).map((r) => r.kb),
    ["KB890830", "KB5007651", null]
  );
  assert.deepEqual(lookupIds([id(1), "not-a-uuid", id(1), "abcdef0123456789abcdef0123456789", id(2)]), [id(1), id(2)]);
});

// ---------------------------------------------------------------------------
// The tool, through its handler
// ---------------------------------------------------------------------------

function searchRecord(urn, text, status = "COMPLETE", success = "ALL") {
  return {
    urn,
    status,
    overThreshold: false,
    errors: [],
    outcome: { success, errors: success === "NONE" ? [{ urn: `${urn}:p`, errors: ["partition failed"] }] : [] },
    queryText: text,
    searchPartitions: [],
    createTime: "2026-11-03T03:48:55Z",
    startTime: null,
    endTime: null,
    expireTime: "2026-12-03T03:48:55Z",
    metadata: null,
    hostnameMappings: [],
  };
}

/**
 * A fake Fusion client over two result sets: `devices` (aggregate rows) and
 * `rows` (newest first). `pending` polls before a search completes.
 */
function fakeFusion({ devices, rows, pending = 0, success = "ALL" }) {
  const calls = [];
  const polls = new Map();
  const urnFor = (text) => (text.includes("| aggregate") ? "urn:sophos:search:1:devices" : "urn:sophos:search:1:rows");
  const status = (urn) => ((polls.get(urn) ?? 0) >= pending ? "COMPLETE" : "IN_PROGRESS");
  return {
    calls,
    query: async (tenantId, document, variables, options) => {
      const operation = document.match(/^(query|mutation) (\w+)/)[2];
      calls.push({ tenantId, operation, variables, options });
      if (operation === "FusionGetOrCreateSearch" || operation === "FusionCreateSearch") {
        const urn = urnFor(variables.input.text);
        const record = searchRecord(urn, variables.input.text, status(urn), success);
        return { data: operation === "FusionCreateSearch" ? { createSearch: record } : { getOrCreateSearch: record }, warnings: [] };
      }
      if (operation === "FusionSearch") {
        polls.set(variables.urn, (polls.get(variables.urn) ?? 0) + 1);
        return { data: { search: searchRecord(variables.urn, "", status(variables.urn), success) }, warnings: [] };
      }
      if (operation === "FusionSearchResults") {
        const set = variables.urn.endsWith(":devices") ? devices : rows;
        const start = Number(variables.cursor ?? 0);
        const values = set.slice(start, start + variables.limit);
        const end = start + values.length;
        return {
          data: {
            searchResults: {
              values,
              totals: { total: { value: Math.min(set.length, 10000) }, subtotals: [] },
              nextCursor: end < set.length ? String(end) : null,
              previousCursor: null,
              hostnameMappings: [],
            },
          },
          warnings: [],
        };
      }
      throw new Error(`unexpected ${operation}`);
    },
  };
}

/** Connects the tool with the fake Fusion client and a stubbed Endpoint API. */
async function harness(fusion, endpoints, { failLookup = false, waitMs = 1000 } = {}) {
  const rest = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = new URL(String(url));
    const query = Object.fromEntries(u.searchParams);
    rest.push({ path: u.pathname, query });
    if (failLookup) {
      return new Response(JSON.stringify({ error: "forbidden", message: "Forbidden" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }
    const wanted = query.ids ? new Set(query.ids.split(",")) : null;
    const all = endpoints.filter((e) => !wanted || wanted.has(e.id));
    const start = Number(query.pageFromKey ?? 0);
    const size = Number(query.pageSize);
    const items = all.slice(start, start + size);
    const next = start + items.length < all.length ? String(start + items.length) : undefined;
    return new Response(JSON.stringify({ pages: { size, maxSize: 500, ...(next ? { nextKey: next } : {}) }, items }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  const tenantResolver = {
    resolveApiHost: async () => "https://api-au01.central.sophos.com",
    resolveTenantId: (tid) => tid ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const sophos = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFusionInventoryTools(server, fusion, sophos, tenantResolver, { now: () => NOW, pollIntervalMs: 1, waitMs });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    rest,
    async call(args) {
      const result = await mcp.callTool({ name: "sophos_fusion_endpoint_inventory", arguments: args });
      const text = result.content.map((c) => c.text ?? "").join("");
      return { isError: Boolean(result.isError), text, json: result.isError ? null : JSON.parse(text) };
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

const sw = (name, version) => ({ product: { name, version, vendor_name: "Vendor" }, install_time: null });
const fleet = () => {
  const aggregate = [
    { host_id: id(1), device_hostname: "FRESH-PC", sensor_type: "ENDPOINT_SOPHOS", max_time: BATCH, row_count: 4 },
    { host_id: id(2), device_hostname: "STALE-PC", sensor_type: "ENDPOINT_SOPHOS", max_time: BATCH, row_count: 4 },
    { host_id: id(3), device_hostname: "DELETED-PC", sensor_type: "ENDPOINT_SOPHOS", max_time: BATCH - DAY_MS, row_count: 2 },
    { host_id: "abcdef0123456789abcdef0123456789", device_hostname: "CS-HOST", sensor_type: "ENDPOINT_CROWDSTRIKE", max_time: BATCH, row_count: 1 },
  ];
  const rows = [
    { host_id: id(1), time: BATCH, device: { hostname: "FRESH-PC", os: { name: "Windows 11 Pro " } }, ...sw("Zoom", "6.0") },
    { host_id: id(1), time: BATCH - 1, device: { hostname: "FRESH-PC" }, ...sw("Chrome", "156") },
    { host_id: id(2), time: BATCH - 2, device: { hostname: "STALE-PC" }, ...sw("Chrome", "150") },
    { host_id: id(2), time: BATCH - 3, device: { hostname: "STALE-PC" }, ...sw("Acrobat", "24") },
    { host_id: "abcdef0123456789abcdef0123456789", time: BATCH - 4, device: { hostname: "CS-HOST" }, ...sw("Falcon", "7") },
    { host_id: id(1), time: BATCH - DAY_MS, device: { hostname: "FRESH-PC" }, ...sw("Zoom", "5.9") },
    { host_id: id(1), time: BATCH - DAY_MS - 1, device: { hostname: "FRESH-PC" }, ...sw("Chrome", "155") },
    { host_id: id(2), time: BATCH - DAY_MS - 2, device: { hostname: "STALE-PC" }, ...sw("Chrome", "150") },
    { host_id: id(2), time: BATCH - DAY_MS - 3, device: { hostname: "STALE-PC" }, ...sw("Acrobat", "24") },
    { host_id: id(3), time: BATCH - DAY_MS - 4, device: { hostname: "DELETED-PC" }, ...sw("Chrome", "140") },
    { host_id: id(3), time: BATCH - 2 * DAY_MS, device: { hostname: "DELETED-PC" }, ...sw("Chrome", "139") },
  ];
  const endpoints = [
    { id: id(1), hostname: "FRESH-PC", lastSeenAt: "2026-11-03T03:40:00Z" },
    { id: id(2), hostname: "STALE-PC", lastSeenAt: "2026-10-16T10:33:31.946Z" },
  ];
  return { aggregate, rows, endpoints };
};

test("the tool: two reused searches, the latest snapshot per device, statuses from lastSeenAt, rows tagged", async () => {
  const { aggregate, rows, endpoints } = fleet();
  const fusion = fakeFusion({ devices: aggregate, rows, pending: 2 });
  const h = await harness(fusion, endpoints);
  try {
    const result = await h.call({ schema: "softwareinfo" });
    assert.equal(result.isError, false, result.text);
    const out = result.json;

    const starts = fusion.calls.filter((c) => c.operation === "FusionGetOrCreateSearch").map((c) => c.variables.input.text);
    assert.deepEqual(starts, [
      buildDevicesQl("softwareinfo", {}, inventoryWindow(NOW, 2)),
      buildRowsQl("softwareinfo", {}, inventoryWindow(NOW, 2)),
    ]);
    assert.ok(fusion.calls.some((c) => c.operation === "FusionSearch"), "polled while the searches ran");
    assert.equal(fusion.calls.filter((c) => c.operation === "FusionCreateSearch").length, 0, "reuses, never forces a new search");
    const pages = fusion.calls.filter((c) => c.operation === "FusionSearchResults");
    assert.equal(pages.length, 2, "one page from each search");
    for (const page of pages) {
      assert.deepEqual(page.options, { timeoutMs: SEARCH_RESULTS_TIMEOUT_MS }, "a results page waits past the client's 30 s");
    }
    assert.ok(
      fusion.calls.filter((c) => c.operation !== "FusionSearchResults").every((c) => c.options === undefined),
      "starts and polls keep the client's timeout"
    );

    // One Endpoint API call for the three UUID host IDs; the CrowdStrike ID is not sent.
    assert.equal(h.rest.length, 1);
    assert.equal(h.rest[0].path, "/endpoint/v1/endpoints");
    assert.deepEqual(h.rest[0].query, { ids: [id(1), id(2), id(3)].join(","), fields: "id,hostname,lastSeenAt", pageSize: "100" });

    assert.deepEqual(out.summary, {
      devices: 4,
      fresh: 1,
      stale: 1,
      unmatched: 2,
      rows_in_window: 11,
      rows_read: 11,
      latest_snapshot_rows: 6,
      incomplete_devices: 0,
    });
    assert.equal(out.window.latest, "2026-11-03T04:00:00Z");
    assert.equal(out.searches.devices, "urn:sophos:search:1:devices");
    assert.equal(out.last_seen_source, "Endpoint API lastSeenAt, matched on host_id = endpoint ID");

    const byHost = Object.fromEntries(out.devices.map((d) => [d.hostname, d]));
    assert.deepEqual(out.devices.map((d) => d.hostname), ["STALE-PC", "CS-HOST", "DELETED-PC", "FRESH-PC"]);
    assert.equal(byHost["STALE-PC"].status, "stale");
    assert.equal(byHost["STALE-PC"].days_since_seen, 17.7);
    assert.equal(byHost["STALE-PC"].snapshot_time, new Date(BATCH - 2).toISOString());
    assert.equal(byHost["FRESH-PC"].status, "fresh");
    assert.equal(byHost["FRESH-PC"].os, "Windows 11 Pro");
    assert.equal(byHost["FRESH-PC"].snapshot_rows, 2);
    assert.equal(byHost["DELETED-PC"].status, "unmatched");
    assert.match(byHost["DELETED-PC"].reason, /No Sophos endpoint has this ID/);
    assert.equal(byHost["DELETED-PC"].snapshot_rows, 1, "its own newest day, not the one before");
    assert.match(byHost["CS-HOST"].reason, /third-party sensor/);
    assert.equal(byHost["CS-HOST"].last_seen_at, null);

    assert.equal(out.total, 6);
    assert.equal(out.next_offset, null);
    assert.deepEqual(
      out.rows.map((r) => `${r.hostname}:${r.status}:${r.name}@${r.version}`),
      [
        "STALE-PC:stale:Acrobat@24",
        "STALE-PC:stale:Chrome@150",
        "CS-HOST:unmatched:Falcon@7",
        "DELETED-PC:unmatched:Chrome@140",
        "FRESH-PC:fresh:Chrome@156",
        "FRESH-PC:fresh:Zoom@6.0",
      ]
    );
  } finally {
    await h.close();
  }
});

test("the tool: status filter, row paging, devices only, refresh, and the stop once every snapshot is read", async () => {
  const { aggregate, rows, endpoints } = fleet();
  const fusion = fakeFusion({ devices: aggregate, rows });
  const h = await harness(fusion, endpoints);
  try {
    const stale = await h.call({ schema: "softwareinfo", status: "stale" });
    assert.equal(stale.json.summary.devices, 4, "the summary counts every device");
    assert.deepEqual(stale.json.devices.map((d) => d.hostname), ["STALE-PC"]);
    assert.equal(stale.json.total, 2);

    const paged = await h.call({ schema: "softwareinfo", offset: 2, limit: 2 });
    assert.deepEqual(paged.json.rows.map((r) => r.name), ["Falcon", "Chrome"]);
    assert.deepEqual(paged.json.devices.map((d) => d.hostname), ["CS-HOST", "DELETED-PC"], "only the devices on this page");
    assert.equal(paged.json.next_offset, 4);

    const before = fusion.calls.length;
    const devicesOnly = await h.call({ schema: "softwareinfo", include_rows: false, refresh: true, limit: 3 });
    const made = fusion.calls.slice(before);
    assert.deepEqual(
      made.filter((c) => c.operation === "FusionCreateSearch").map((c) => c.variables.input.text),
      [buildDevicesQl("softwareinfo", {}, inventoryWindow(NOW, 2))],
      "refresh starts a new search, and only the device search runs"
    );
    assert.equal(devicesOnly.json.rows, undefined);
    assert.equal(devicesOnly.json.devices.length, 3);
    assert.equal(devicesOnly.json.devices[0].snapshot_complete, undefined);
    assert.equal(devicesOnly.json.next_offset, 3);
    assert.equal(devicesOnly.json.summary.rows_read, undefined);
  } finally {
    await h.close();
  }

  // 2,500 rows, newest 1,000 hold every device's snapshot: one page is read.
  const many = [
    ...Array.from({ length: 1000 }, (_, i) => ({ host_id: id(1), time: BATCH - i, ...sw(`App${i}`, "1") })),
    ...Array.from({ length: 1500 }, (_, i) => ({ host_id: id(1), time: BATCH - DAY_MS - i, ...sw(`App${i}`, "0") })),
  ];
  const big = fakeFusion({ devices: [{ host_id: id(1), device_hostname: "FRESH-PC", max_time: BATCH, row_count: 2500 }], rows: many });
  const h2 = await harness(big, endpoints);
  try {
    const out = (await h2.call({ schema: "softwareinfo", limit: 1 })).json;
    const reads = big.calls.filter((c) => c.operation === "FusionSearchResults" && c.variables.urn.endsWith(":rows"));
    assert.equal(reads.length, 2, "the second page passes the floor, so reading stops");
    assert.equal(out.summary.rows_read, 2000);
    assert.equal(out.summary.latest_snapshot_rows, 1000);
    assert.equal(out.summary.incomplete_devices, 0);
    assert.equal(out.total, 1000);
  } finally {
    await h2.close();
  }
});

test("the tool: max_rows cutting a snapshot marks it incomplete and says how to see the rest", async () => {
  const { aggregate, rows, endpoints } = fleet();
  const h = await harness(fakeFusion({ devices: aggregate, rows }), endpoints);
  try {
    const out = (await h.call({ schema: "softwareinfo", max_rows: 3 })).json;
    assert.equal(out.summary.rows_read, 3);
    assert.equal(out.summary.incomplete_devices, 4);
    assert.match(out.notes[0], /4 device\(s\) have snapshot_complete false/);
    assert.match(out.notes[0], /Raise max_rows/);
    const stale = out.devices.find((d) => d.hostname === "STALE-PC");
    assert.equal(stale.snapshot_complete, false);
    assert.equal(stale.snapshot_rows, 1);
  } finally {
    await h.close();
  }
});

test("the tool: still running, a failed search, a failed lookup, and the full listing for many devices", async () => {
  const { aggregate, rows, endpoints } = fleet();
  const slow = await harness(fakeFusion({ devices: aggregate, rows, pending: 1_000_000 }), endpoints, { waitMs: 20 });
  try {
    const out = (await slow.call({ schema: "softwareinfo" })).json;
    assert.equal(out.status, "running");
    assert.match(out.next_step, /Call again with the same arguments/);
    assert.deepEqual(out.searches, { devices: "urn:sophos:search:1:devices", rows: "urn:sophos:search:1:rows" });
    assert.equal(slow.rest.length, 0, "no lookup before the searches finish");
  } finally {
    await slow.close();
  }

  const failed = await harness(fakeFusion({ devices: aggregate, rows, success: "NONE" }), endpoints);
  try {
    const out = await failed.call({ schema: "softwareinfo" });
    assert.equal(out.isError, true);
    assert.match(out.text, /The device search failed: partition failed\. Retry with refresh true/);
  } finally {
    await failed.close();
  }

  const partial = await harness(fakeFusion({ devices: aggregate, rows, success: "PARTIAL" }), endpoints);
  try {
    const out = (await partial.call({ schema: "softwareinfo" })).json;
    assert.match(out.warnings.join(" "), /completed with outcome PARTIAL/);
  } finally {
    await partial.close();
  }

  const noLookup = await harness(fakeFusion({ devices: aggregate, rows }), endpoints, { failLookup: true });
  try {
    const out = (await noLookup.call({ schema: "softwareinfo" })).json;
    assert.equal(out.summary.unmatched, 4);
    assert.match(out.warnings.join(" "), /Last seen lookup in the Endpoint API failed/);
    assert.match(out.devices.find((d) => d.hostname === "FRESH-PC").reason, /lookup failed/);
  } finally {
    await noLookup.close();
  }

  // 600 devices: more than 500 IDs, so the whole endpoint list is paged at 500 instead.
  const fleet600 = Array.from({ length: 600 }, (_, i) => ({ host_id: id(i + 1), device_hostname: `H${i}`, max_time: BATCH, row_count: 1 }));
  const known = Array.from({ length: 700 }, (_, i) => ({ id: id(i + 1), hostname: `H${i}`, lastSeenAt: "2026-11-03T00:00:00Z" }));
  const wide = await harness(fakeFusion({ devices: fleet600, rows: [] }), known);
  try {
    const out = (await wide.call({ schema: "inventoryinfo", include_rows: false, limit: 1 })).json;
    assert.deepEqual(
      wide.rest.map((c) => c.query),
      [
        { pageSize: "500", fields: "id,hostname,lastSeenAt" },
        { pageSize: "500", fields: "id,hostname,lastSeenAt", pageFromKey: "500" },
      ]
    );
    assert.equal(out.summary.fresh, 600);
  } finally {
    await wide.close();
  }

  // 250 devices: IDs in batches of 100.
  const fleet250 = fleet600.slice(0, 250);
  const batched = await harness(fakeFusion({ devices: fleet250, rows: [] }), known);
  try {
    await batched.call({ schema: "inventoryinfo", include_rows: false });
    assert.deepEqual(batched.rest.map((c) => c.query.ids.split(",").length), [100, 100, 50]);
  } finally {
    await batched.close();
  }
});

test("the tool refuses a filter on the wrong schema and a bad argument before any search", async () => {
  const { aggregate, rows, endpoints } = fleet();
  const fusion = fakeFusion({ devices: aggregate, rows });
  const h = await harness(fusion, endpoints);
  try {
    assert.match((await h.call({ schema: "patchstate", software_name: "Chrome" })).text, /software_name filters softwareinfo only/);
    assert.match((await h.call({ schema: "inventoryinfo", kb: "KB1" })).text, /kb filters patchstate only/);
    assert.match((await h.call({ schema: "process" })).text, /Input validation error/);
    assert.match((await h.call({ schema: "softwareinfo", days: 31 })).text, /Input validation error/);
    assert.match((await h.call({ schema: "softwareinfo", max_rows: 10001 })).text, /Input validation error/);
    assert.match((await h.call({ schema: "softwareinfo", endpoint_id: "not-an-id" })).text, /Input validation error/);
    assert.equal(fusion.calls.length, 0);
  } finally {
    await h.close();
  }
});
