/**
 * Pure helpers behind the Fusion case tools: severity, timestamps, ID checks,
 * the QL builder, the reference-data cache and the MITRE roll-up.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  caseSeverityLabel,
  isCaseShortId,
  isLegacyCaseId,
  isUuid,
  looksLikeEmail,
  normaliseCaseSeverity,
  qlString,
  timestampToIso,
} from "../dist/fusion/format.js";
import { buildCasesQl } from "../dist/fusion/cases-ql.js";
import { CaseReferenceDataCache, matchReference } from "../dist/fusion/case-reference-data.js";
import { buildMitreSummary } from "../dist/tools/fusion-cases.js";

const TYPE_ID = "11111111-1111-4111-8111-111111111111";
const NEW_ID = "22222222-2222-4222-8222-222222222222";
const CLOSED_ID = "33333333-3333-4333-8333-333333333333";
const VERDICT_ID = "44444444-4444-4444-8444-444444444444";

// --- format.ts ---

test("normaliseCaseSeverity accepts integers and labels", () => {
  assert.equal(normaliseCaseSeverity(8), 8);
  assert.equal(normaliseCaseSeverity("High"), 8);
  assert.equal(normaliseCaseSeverity("informational"), 2);
  assert.throws(() => normaliseCaseSeverity(11), /2 to 10/);
  assert.throws(() => normaliseCaseSeverity(0), /2 to 10/);
  assert.throws(() => normaliseCaseSeverity("bogus"), /Unknown case severity/);
});

test("caseSeverityLabel maps the documented values", () => {
  assert.equal(caseSeverityLabel(10), "critical");
  assert.equal(caseSeverityLabel(7), "unknown (7)");
  assert.equal(caseSeverityLabel(null), null);
});

test("timestampToIso converts seconds and nanos", () => {
  assert.equal(timestampToIso({ seconds: 1700000000, nanos: 500000000 }), "2023-11-14T22:13:20.500Z");
  assert.equal(timestampToIso(null), null);
});

test("ID shape checks tell Fusion, short and legacy IDs apart", () => {
  assert.equal(isUuid(TYPE_ID), true);
  assert.equal(isUuid("CSE00001"), false);
  assert.equal(isCaseShortId("CSE00001"), true);
  assert.equal(isCaseShortId("cse12"), true);
  assert.equal(isCaseShortId("1-598868"), false);
  assert.equal(isLegacyCaseId("1-598868"), true);
  assert.equal(isLegacyCaseId("3-201650"), true);
  assert.equal(isLegacyCaseId(TYPE_ID), false);
  assert.equal(isLegacyCaseId("CSE00001"), false);
});

test("qlString quotes and refuses embedded quotes", () => {
  assert.equal(qlString("phishing"), "'phishing'");
  assert.throws(() => qlString("O'Brien"), /single quote/);
});

test("looksLikeEmail guards the assignee field", () => {
  assert.equal(looksLikeEmail("jane.doe@example.com"), true);
  assert.equal(looksLikeEmail("@customer"), false);
  assert.equal(looksLikeEmail(TYPE_ID), false);
});

// --- cases-ql.ts ---

test("buildCasesQl returns undefined when nothing filters", () => {
  assert.equal(buildCasesQl({}), undefined);
});

test("buildCasesQl joins resolved IDs and predicates with and", () => {
  const ql = buildCasesQl({
    typeId: TYPE_ID,
    statusIds: [NEW_ID, CLOSED_ID],
    severityMin: 8,
    openOnly: true,
    titleContains: "phishing",
    tag: "malware",
    sort: "updatedAt desc",
  });
  assert.equal(
    ql,
    `typeId = '${TYPE_ID}' and primaryStatusId in ('${NEW_ID}', '${CLOSED_ID}') and severity >= 8 and closedAt is null and title contains 'phishing' and tags contains 'malware' | sort updatedAt desc`
  );
});

test("buildCasesQl uses = for a single status and handles the rest of the fields", () => {
  const ql = buildCasesQl({
    statusIds: [NEW_ID],
    verdictId: VERDICT_ID,
    severity: 10,
    assigneeId: "subject-1",
    createdAfter: "2026-09-01T00:00:00Z",
    createdBefore: "2026-09-30T23:59:59Z",
    updatedAfter: "2026-09-15T00:00:00Z",
  });
  assert.equal(
    ql,
    `primaryStatusId = '${NEW_ID}' and primaryVerdictId = '${VERDICT_ID}' and severity = 10 and assigneeId = 'subject-1' and createdAt >= '2026-09-01T00:00:00Z' and createdAt <= '2026-09-30T23:59:59Z' and updatedAt >= '2026-09-15T00:00:00Z'`
  );
  assert.equal(buildCasesQl({ unassigned: true }), "assigneeId is null");
});

test("buildCasesQl keeps a raw query's pipe after the added predicates", () => {
  const ql = buildCasesQl({ query: "severity >= 6 | sort severity desc", openOnly: true });
  assert.equal(ql, "severity >= 6 and closedAt is null | sort severity desc");
  assert.equal(buildCasesQl({ query: "title contains 'a | b'" }), "title contains 'a | b'");
});

test("buildCasesQl refuses two sorts and malformed sorts", () => {
  assert.throws(
    () => buildCasesQl({ query: "severity >= 6 | sort severity desc", sort: "createdAt" }),
    /already contains a pipe/
  );
  assert.throws(() => buildCasesQl({ sort: "severity; drop" }), /sort must be/);
});

// --- case-reference-data.ts ---

const referenceBody = {
  caseTypes: {
    types: [
      {
        id: TYPE_ID,
        name: "investigation",
        title: "Investigation",
        managedBy: "CUSTOMER",
        supportedPrimaryStatusIds: [NEW_ID, CLOSED_ID],
        supportedPrimaryVerdictIds: [VERDICT_ID],
      },
    ],
  },
  casePrimaryStatuses: {
    primaryStatuses: [
      { id: NEW_ID, name: "NEW", title: "New", isClosed: false },
      { id: CLOSED_ID, name: "CLOSED", title: "Closed", isClosed: true },
    ],
  },
  casePrimaryVerdicts: {
    primaryVerdicts: [{ id: VERDICT_ID, name: "TRUE_POSITIVE", title: "True positive" }],
  },
};

function fakeClient(body = referenceBody, warnings = []) {
  const calls = [];
  return {
    calls,
    query: async (tenantId, document, variables) => {
      calls.push({ tenantId, document, variables });
      return { data: structuredClone(body), warnings };
    },
  };
}

test("reference cache resolves names, titles and UUIDs", async () => {
  const client = fakeClient();
  const cache = new CaseReferenceDataCache(client);
  assert.equal(await cache.resolveTypeId("t1", "investigation"), TYPE_ID);
  assert.equal(await cache.resolveTypeId("t1", "Investigation"), TYPE_ID);
  assert.equal(await cache.resolveTypeId("t1", TYPE_ID), TYPE_ID);
  assert.equal(await cache.resolveStatusId("t1", "closed"), CLOSED_ID);
  assert.equal(await cache.resolveVerdictId("t1", "True positive"), VERDICT_ID);
  const closed = await cache.resolveStatus("t1", "CLOSED");
  assert.equal(closed.isClosed, true);
  assert.equal(client.calls.length, 1, "one fetch serves every lookup for the tenant");
});

test("reference cache names the options when a value is unknown", async () => {
  const cache = new CaseReferenceDataCache(fakeClient());
  await assert.rejects(
    () => cache.resolveStatusId("t1", "on hold"),
    /Unknown primary status "on hold" for this tenant\. Available: NEW, CLOSED/
  );
});

test("reference cache is per tenant, honours refresh and expires on the TTL", async () => {
  const client = fakeClient();
  const cache = new CaseReferenceDataCache(client, 20);
  await cache.get("t1");
  await cache.get("t1");
  assert.equal(client.calls.length, 1);
  await cache.get("t2");
  assert.equal(client.calls.length, 2);
  await cache.get("t1", { refresh: true });
  assert.equal(client.calls.length, 3);
  await new Promise((resolve) => setTimeout(resolve, 30));
  await cache.get("t1");
  assert.equal(client.calls.length, 4);
  cache.invalidate("t2");
  await cache.get("t2");
  assert.equal(client.calls.length, 5);
});

test("reference cache deduplicates concurrent fetches", async () => {
  const client = fakeClient();
  const cache = new CaseReferenceDataCache(client);
  await Promise.all([cache.get("t1"), cache.get("t1"), cache.resolveTypeId("t1", "investigation")]);
  assert.equal(client.calls.length, 1);
});

test("reference cache refuses a partial response with a missing list", async () => {
  const client = fakeClient({ ...referenceBody, casePrimaryVerdicts: null }, ["verdicts subgraph down"]);
  const cache = new CaseReferenceDataCache(client);
  await assert.rejects(
    () => cache.get("t1"),
    /incomplete for tenant t1 \(missing casePrimaryVerdicts\): verdicts subgraph down/
  );
});

test("matchReference prefers name over title", () => {
  const items = [
    { id: "1", name: "open", title: "Closed" },
    { id: "2", name: "closed", title: "Open" },
  ];
  assert.equal(matchReference("x", items, "closed").id, "2");
});

// --- MITRE roll-up ---

test("buildMitreSummary groups techniques under tactics with detection counts", () => {
  const records = [
    {
      id: "d1",
      attack_technique_ids: ["T1059.001", "T1027"],
      enrichment_details: [
        {
          mitre_attack_info: {
            technique_id: "T1059.001",
            technique: "PowerShell",
            tactics: ["Execution"],
          },
        },
      ],
    },
    {
      id: "d2",
      attack_technique_ids: ["T1059.001"],
      enrichment_details: [
        {
          mitre_attack_info: {
            technique_id: "T1059.001",
            technique: "PowerShell",
            tactics: ["Execution", "Defense Evasion"],
          },
        },
      ],
    },
  ];
  const summary = buildMitreSummary(records);
  assert.equal(summary.detection_count, 2);
  assert.equal(summary.technique_count, 2);
  assert.deepEqual(
    summary.tactics.map((t) => t.tactic),
    ["Defense Evasion", "Execution"]
  );
  const execution = summary.tactics.find((t) => t.tactic === "Execution");
  assert.deepEqual(execution.techniques, [
    { technique_id: "T1059.001", technique: "PowerShell", detection_count: 2 },
  ]);
  assert.deepEqual(summary.techniques_without_tactic, [
    { technique_id: "T1027", technique: null, detection_count: 1 },
  ]);
});
