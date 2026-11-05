/**
 * A page cut to fit CHARACTER_LIMIT must not say the list is finished, and the
 * Fusion case summary must stay valid JSON inside the limit. Live (05/11/2026,
 * 0.12.1): sophos_fusion_list_cases at per_page 100 on a 90 case tenant came
 * back with 54 cases and has_next_page false, so a client trusting
 * has_next_page lost 36; and sophos_fusion_get_case_summary on a case with
 * 1,693 attached events was cut mid-JSON at the limit whatever max_detections
 * was, because the event ID list sits inside evidence, out of reach of the
 * top-level array cut. Synthetic data only. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerFusionCaseTools } from "../dist/tools/fusion-cases.js";
import { jsonResult } from "../dist/tools/helpers.js";
import { CHARACTER_LIMIT } from "../dist/config/config.js";

const TENANT = "11111111-2222-4333-8444-555555555555";
const CASE_ID = "22222222-3333-4444-8555-666666666666";
const textOf = (result) => result.content.map((c) => c.text ?? "").join("");
const bulky = (i) => ({ id: `item-${String(i).padStart(4, "0")}`, blob: "x".repeat(400 + ((i * 397) % 1600)) });
const items = (count, from = 0) => Array.from({ length: count }, (_, i) => bulky(from + i));
const hex = (i, width) => String(i).padStart(width, "0");

// --- The shared cut: the page's own paging fields agree with truncated.next ---

test("a cut page never reports has_next_page false, and its end_cursor no longer skips the omitted items", () => {
  const out = JSON.parse(
    textOf(jsonResult({ has_next_page: false, end_cursor: "after-90", cases: items(90) }, { page: 1, per_page: 100, after: undefined }))
  );
  assert.ok(out.truncated.omitted > 0);
  assert.equal(out.has_next_page, true);
  assert.equal(out.end_cursor, null);
  assert.match(out.truncated.how, /has_next_page is true/);
  assert.match(out.truncated.how, /end_cursor is null/);
});

test("has_more reads true and its cursor null on a cut cursor page", () => {
  const out = JSON.parse(textOf(jsonResult({ has_more: false, next_key: "k-2", rows: items(100) }, { page_from_key: "k-1", limit: 100 })));
  assert.equal(out.has_more, true);
  assert.equal(out.next_key, null);
  assert.deepEqual(out.truncated.next, { page_from_key: "k-1", limit: out.rows.length });
});

test("next_offset reads the first omitted item on a cut offset page, even where Sophos said the list ended", () => {
  const out = JSON.parse(textOf(jsonResult({ offset: 40, next_offset: null, detections: items(100) }, { offset: 40, limit: 100 })));
  const k = out.truncated.returned;
  assert.equal(out.next_offset, 40 + k);
  assert.deepEqual(out.truncated.next, { offset: 40 + k, limit: 100 });
});

test("a page that fits keeps its own paging fields, and a cursor with no has_more beside it is left alone", () => {
  const fits = { has_next_page: false, end_cursor: "c", next_offset: null, cases: items(2) };
  assert.deepEqual(JSON.parse(textOf(jsonResult(fits, { page: 1, per_page: 100 }))), fits);
  const out = JSON.parse(textOf(jsonResult({ next_cursor: "n-2", endpoints: items(100) }, { cursor: "n-1", limit: 100 })));
  assert.equal(out.next_cursor, "n-2");
});

// --- sophos_fusion_list_cases through the tool ---

const STATUS = { id: "33333333-4444-4555-8666-777777777777", name: "in_progress", title: "In Progress", isClosed: false };
const TYPE = { id: "44444444-5555-4666-8777-888888888888", name: "investigation", title: "Investigation" };

function caseRow(i) {
  return {
    id: `55555555-6666-4777-8888-${hex(i, 12)}`,
    shortId: `CSE${hex(i, 5)}`,
    title: `Synthetic case ${i} `.padEnd(300 + ((i * 211) % 700), "x"),
    severity: 6,
    type: TYPE,
    primaryStatus: STATUS,
    secondaryStatus: null,
    tags: ["synthetic"],
    assigneeId: "",
    managedBy: "CUSTOMER",
    tenantId: "000000",
    createdAt: "2026-10-01T00:00:00Z",
    updatedAt: "2026-10-01T00:00:00Z",
    closedAt: null,
    archivedAt: null,
    riskScore: 0,
  };
}

/** A Fusion client holding `count` cases, paged by number or by cursor (a cursor is the index after a row). */
function casesClient(count) {
  const all = Array.from({ length: count }, (_, i) => caseRow(i + 1));
  return {
    query: async (_tenantId, document, variables) => {
      assert.ok(document.startsWith("query FusionListCases("), `unexpected document: ${document.slice(0, 40)}`);
      const { offset, cursor } = variables.arguments.pagination;
      const start = offset ? (offset.page - 1) * offset.perPage : Number(cursor.after ?? 0);
      const size = offset ? offset.perPage : cursor.first;
      const rows = all.slice(start, start + size);
      const end = start + rows.length;
      return {
        data: {
          cases: {
            totalCount: count,
            pageInfo: {
              startCursor: rows.length ? String(start + 1) : null,
              endCursor: rows.length ? String(end) : null,
              hasNextPage: end < count,
              hasPreviousPage: start > 0,
            },
            cases: rows,
          },
        },
        warnings: [],
      };
    },
  };
}

const referenceData = {
  resolveTypeId: async (_t, v) => v,
  resolveStatusId: async (_t, v) => v,
  resolveVerdictId: async (_t, v) => v,
};
const tenantResolver = { resolveTenantId: (id) => id ?? TENANT };

async function connect(client) {
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFusionCaseTools(server, client, tenantResolver, referenceData);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = textOf(result);
      assert.ok(!result.isError, `${name} failed: ${text.slice(0, 300)}`);
      assert.ok(text.length <= CHARACTER_LIMIT, `${name} returned ${text.length} characters`);
      return JSON.parse(text);
    },
    async close() {
      await mcp.close();
      await server.close();
    },
  };
}

/**
 * A client that stops the moment has_next_page is false, and otherwise takes
 * the continuation the response states: truncated.next when the page was cut,
 * else the next page number or end_cursor.
 */
async function readTrustingHasNextPage(h, first) {
  const ids = [];
  let truncations = 0;
  let request = first;
  for (let calls = 0; calls < 50; calls++) {
    const out = await h.call("sophos_fusion_list_cases", request);
    for (const c of out.cases) if (!ids.includes(c.short_id)) ids.push(c.short_id);
    if (!out.has_next_page) return { ids, truncations };
    if (out.truncated) {
      truncations++;
      request = { ...request, ...out.truncated.next };
    } else if (request.after !== undefined) {
      request = { ...request, after: out.end_cursor };
    } else {
      request = { ...request, page: out.page + 1 };
    }
  }
  assert.fail("did not reach the end of the list");
}

const EXPECTED = Array.from({ length: 90 }, (_, i) => `CSE${hex(i + 1, 5)}`);

test("sophos_fusion_list_cases at per_page 100: a client trusting has_next_page reaches all 90 cases, by page number", async () => {
  const h = await connect(casesClient(90));
  try {
    const first = await h.call("sophos_fusion_list_cases", { per_page: 100 });
    assert.ok(first.truncated, "90 bulky cases do not fit one response");
    assert.equal(first.has_next_page, true, "rows were left out, so the page is not the last");
    assert.equal(first.end_cursor, null);
    const read = await readTrustingHasNextPage(h, { per_page: 100 });
    assert.deepEqual(read.ids, EXPECTED);
  } finally {
    await h.close();
  }
});

test("sophos_fusion_list_cases at per_page 100: a client trusting has_next_page reaches all 90 cases, by cursor", async () => {
  const h = await connect(casesClient(90));
  try {
    // Cursor "0" starts at the first case in this fake; the tool replays it verbatim.
    const read = await readTrustingHasNextPage(h, { per_page: 100, after: "0" });
    assert.ok(read.truncations > 0);
    assert.deepEqual(read.ids, EXPECTED);
  } finally {
    await h.close();
  }
});

// --- sophos_fusion_get_case_summary through the tool ---

const rn = (kind, i) => `${kind}://priv:synthetic.source:000000:1700000000000:66666666-7777-4888-8999-${hex(i, 12)}`;

function summaryClient({ events, detections, detectionBlob = 0 }) {
  const detectionIds = Array.from({ length: detections }, (_, i) => rn("alert", i));
  const caseRecord = {
    ...caseRow(1),
    id: CASE_ID,
    title: "Synthetic summary case",
    keyFindings: { documentType: "markdown", content: "Synthetic key findings." },
    primaryVerdict: null,
    secondaryVerdict: null,
    secondaryStatusReason: [],
    closeReason: null,
    closedById: null,
    createdById: "u1",
    updatedById: "u1",
    contributorIds: [],
    incidentAdvisorId: null,
    ruleId: null,
    source: null,
    links: [],
    processingStatus: { assets: "SUCCESS", events: "SUCCESS", detections: "SUCCESS" },
    isCreatedByPartner: false,
    isCreatedByMDRProvider: false,
    detectionsCount: detections,
    eventsCount: events,
    assetsCount: 3,
  };
  const evidence = {
    id: CASE_ID,
    detectionsEvidenceCount: detections,
    detectionsEvidence: detectionIds.map((id, i) => ({ detectionId: id, createdAt: "2026-10-01T00:00:00Z", createdBy: null, isGenesis: i === 0 })),
    eventsEvidenceCount: events,
    eventsEvidence: Array.from({ length: events }, (_, i) => ({ eventId: rn("event", i), createdAt: "2026-10-01T00:00:00Z", createdBy: "u1", isGenesis: false })),
    assetsEvidenceCount: 3,
    assetsEvidence: [0, 1, 2].map((i) => ({ assetId: `77777777-8888-4999-8aaa-${hex(i, 12)}`, createdAt: "2026-10-01T00:00:00Z", createdBy: null })),
    searchQueriesEvidenceCount: 0,
    searchQueriesEvidence: [],
  };
  const record = (id, i) => ({
    id,
    status: "OPEN",
    resolution_reason: null,
    attack_technique_ids: ["T1059"],
    sensor_types: ["ENDPOINT"],
    tags: [],
    metadata: {
      title: `Synthetic detection ${i}`,
      description: "d",
      severity: 0.6,
      confidence: 0.9,
      origin: "synthetic",
      created_at: { seconds: 1790000000, nanos: 0 },
      first_seen_at: { seconds: 1790000000, nanos: 0 },
      creator: { detector: { detector_id: "det-1", detector_name: "Synthetic detector" } },
    },
    enrichment_details: [{ mitre_attack_info: { technique_id: "T1059", technique: "Command and Scripting Interpreter", tactics: ["Execution"] } }],
    source_entities: [{ display_name: "host".padEnd(detectionBlob, "h"), subtype: "hostname", identifiers: [] }],
    target_entities: [],
    event_ids: [{ id: rn("event", i) }],
  });
  const requested = [];
  return {
    requested,
    query: async (_tenantId, document, variables) => {
      if (document.startsWith("query FusionGetCase(")) return { data: { case: caseRecord }, warnings: [] };
      if (document.startsWith("query FusionGetCaseEvidence(")) return { data: { caseEvidence: evidence }, warnings: [] };
      if (document.startsWith("query FusionDetectionsById(")) {
        requested.push(variables.in.iDs.length);
        const list = variables.in.iDs.map((id) => record(id, detectionIds.indexOf(id)));
        return { data: { detectionRetrieveById: { alerts: { total_results: list.length, list } } }, warnings: [] };
      }
      throw new Error(`unexpected document: ${document.slice(0, 40)}`);
    },
  };
}

test("sophos_fusion_get_case_summary on a case with 1,693 events is valid JSON inside the limit, whatever max_detections is", async () => {
  for (const max_detections of [10, 50]) {
    const client = summaryClient({ events: 1693, detections: 60 });
    const h = await connect(client);
    try {
      const out = await h.call("sophos_fusion_get_case_summary", { case_id: CASE_ID, max_detections });
      assert.equal(Object.keys(out)[0], "truncated");
      const events = out.truncated.fields.find((f) => f.field === "evidence.event_ids");
      assert.ok(events, "the event ID list is named as cut");
      assert.equal(events.returned, out.evidence.event_ids.length);
      assert.equal(events.returned + events.omitted, 1693);
      assert.match(events.how, /sophos_fusion_get_case_evidence/);
      assert.deepEqual(out.evidence.event_ids, Array.from({ length: events.returned }, (_, i) => rn("event", i)));
      assert.equal(out.evidence.events, 1693);
      assert.deepEqual(client.requested, [max_detections], "max_detections bounds the detections resolved");
      assert.equal(out.detections.length, max_detections);
      assert.equal(out.detections_resolved, max_detections);
      assert.equal(out.detections_total, 60);
      assert.equal(out.mitre_summary.detection_count, max_detections);
    } finally {
      await h.close();
    }
  }
});

test("sophos_fusion_get_case_summary cuts the biggest list first and says what each cut left out", async () => {
  const client = summaryClient({ events: 1693, detections: 100, detectionBlob: 900 });
  const h = await connect(client);
  try {
    const out = await h.call("sophos_fusion_get_case_summary", { case_id: CASE_ID, max_detections: 100 });
    const fields = out.truncated.fields.map((f) => f.field);
    assert.equal(fields[0], "evidence.event_ids", "the event IDs are the biggest list, so they go first");
    assert.ok(fields.includes("detections"), "100 bulky detections do not fit either");
    const detections = out.truncated.fields.find((f) => f.field === "detections");
    assert.equal(detections.returned, out.detections.length);
    assert.equal(detections.returned + detections.omitted, 100);
    assert.equal(out.detections_resolved, 100);
    assert.equal(out.mitre_summary.detection_count, 100, "the roll-up still counts every resolved detection");
    assert.match(detections.how, /mitre_summary/);
    assert.equal(out.evidence.asset_ids.length, 3, "a small list is kept whole");
  } finally {
    await h.close();
  }
});

test("sophos_fusion_get_case_summary that fits carries no truncated key", async () => {
  const h = await connect(summaryClient({ events: 5, detections: 3 }));
  try {
    const out = await h.call("sophos_fusion_get_case_summary", { case_id: CASE_ID });
    assert.equal(out.truncated, undefined);
    assert.equal(out.evidence.event_ids.length, 5);
    assert.equal(out.detections.length, 3);
  } finally {
    await h.close();
  }
});
