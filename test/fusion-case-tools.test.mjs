/**
 * Handler-level tests for sophos_fusion_update_case through a fake Fusion
 * client: the closed-case freeze refuses before any write, the reopen clears
 * the verdict, and the archive ordering. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerFusionCaseTools } from "../dist/tools/fusion-cases.js";

const CASE_ID = "659240aa-797e-42cf-bb82-cca43c4e80d8";
const OPEN = { id: "28a4f2df-dd5f-44b5-8316-da1f6cfbd254", name: "in_progress", title: "In Progress", isClosed: false };
const CLOSED = { id: "5e2b9d40-1111-4111-8111-111111111111", name: "closed", title: "Closed", isClosed: true };
const VERDICT = { id: "6d7e8f9a-0b1c-2d3e-4f5a-6b7c8d9e0f1a", name: "false_positive", title: "False Positive" };

function caseRecord(overrides = {}) {
  return {
    id: CASE_ID,
    shortId: "CSE00009",
    title: "MCP test",
    severity: 4,
    type: { id: "dcc5aac7-5aca-4b11-90d6-14ca417307f7", name: "investigation", title: "Investigation" },
    primaryStatus: OPEN,
    secondaryStatus: null,
    tags: ["a"],
    assigneeId: null,
    managedBy: "CUSTOMER",
    tenantId: "123456",
    createdAt: "2026-09-22T07:21:21Z",
    updatedAt: "2026-09-22T07:21:21Z",
    closedAt: null,
    archivedAt: null,
    riskScore: 0,
    keyFindings: null,
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
    detectionsCount: 0,
    eventsCount: 0,
    assetsCount: 0,
    ...overrides,
  };
}

/** A Fusion client that serves one case and records every mutation sent. */
function fakeClient(current) {
  const sent = [];
  let state = current;
  return {
    sent,
    query: async (_tenantId, document, variables) => {
      if (document.startsWith("query FusionGetCase(")) return { data: { case: state }, warnings: [] };
      if (document.startsWith("mutation FusionUpdateCase(")) {
        sent.push(variables.input);
        const input = variables.input;
        state = {
          ...state,
          ...(input.title !== undefined ? { title: input.title } : {}),
          ...(input.isArchived === true ? { archivedAt: "2026-09-22T08:00:00Z" } : {}),
          ...(input.isArchived === false ? { archivedAt: null } : {}),
          ...(input.primaryStatusId === OPEN.id ? { primaryStatus: OPEN, closedAt: null } : {}),
          ...(input.primaryVerdictId === "" ? { primaryVerdict: null } : {}),
        };
        return { data: { updateCase: state }, warnings: [] };
      }
      if (document.startsWith("query FusionCasePrimaryVerdictsFor(")) {
        return { data: { casePrimaryVerdicts: { primaryVerdicts: [VERDICT] } }, warnings: [] };
      }
      throw new Error(`unexpected document: ${document.slice(0, 40)}`);
    },
  };
}

const referenceData = {
  get: async () => ({ types: [], primaryStatuses: [OPEN, CLOSED], primaryVerdicts: [VERDICT], fetchedAt: "" }),
  resolveTypeId: async (_t, v) => v,
  resolveStatusId: async (_t, v) => (v === "closed" ? CLOSED.id : OPEN.id),
  resolveStatus: async (_t, v) => (v === "closed" ? CLOSED : OPEN),
  resolveVerdictId: async () => VERDICT.id,
};

const tenantResolver = { resolveTenantId: (id) => id ?? "11111111-2222-3333-4444-555555555555" };

async function updateCase(current, args) {
  const client = fakeClient(current);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFusionCaseTools(server, client, tenantResolver, referenceData);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  const result = await mcp.callTool({ name: "sophos_fusion_update_case", arguments: { case_id: CASE_ID, ...args } });
  await mcp.close();
  await server.close();
  const text = result.content.map((c) => c.text ?? "").join("\n");
  return { isError: Boolean(result.isError), text, json: result.isError ? null : JSON.parse(text), sent: client.sent };
}

test("a title change on a closed case is refused before any write, with the reopen hint", async () => {
  const closed = caseRecord({ primaryStatus: CLOSED, closedAt: "2026-09-22T07:30:00Z", primaryVerdict: VERDICT });
  const { isError, text, sent } = await updateCase(closed, { title: "new title", archived: true });
  assert.equal(isError, true);
  assert.match(text, /This case is closed \(closed\)/);
  assert.match(text, /title cannot/);
  assert.match(text, /Reopen it first in its own call/);
  assert.match(text, /Nothing was changed/);
  assert.equal(sent.length, 0, "no mutation was sent");
});

test("archive alone on a closed case is sent, and nothing else", async () => {
  const closed = caseRecord({ primaryStatus: CLOSED, closedAt: "2026-09-22T07:30:00Z", primaryVerdict: VERDICT });
  const { isError, json, sent } = await updateCase(closed, { archived: true });
  assert.equal(isError, false);
  assert.deepEqual(sent, [{ id: CASE_ID, isArchived: true }]);
  assert.notEqual(json.archived_at, null);
});

test("reopening a closed case with a verdict clears the verdict in the same update and says so", async () => {
  const closed = caseRecord({ primaryStatus: CLOSED, closedAt: "2026-09-22T07:30:00Z", primaryVerdict: VERDICT });
  const { isError, json, sent } = await updateCase(closed, { status: "in_progress" });
  assert.equal(isError, false);
  assert.deepEqual(sent, [{ id: CASE_ID, primaryStatusId: OPEN.id, primaryVerdictId: "" }]);
  assert.equal(json.verdict, null);
  assert.match(json.notes.join(" "), /Cleared the recorded verdict false_positive/);
});

test('verdict "" clears the recorded verdict on an open case', async () => {
  const open = caseRecord({ primaryVerdict: VERDICT });
  const { isError, json, sent } = await updateCase(open, { verdict: "" });
  assert.equal(isError, false);
  assert.deepEqual(sent, [{ id: CASE_ID, primaryVerdictId: "" }]);
  assert.equal(json.verdict, null);
});

test("an archived case is refused before any write unless the call unarchives it", async () => {
  const archived = caseRecord({ primaryStatus: CLOSED, closedAt: "2026-09-22T07:30:00Z", archivedAt: "2026-09-22T08:00:00Z" });
  const refused = await updateCase(archived, { title: "should not apply" });
  assert.equal(refused.isError, true);
  assert.match(refused.text, /archived and refuses every update/);
  assert.equal(refused.sent.length, 0);

  // Unarchive first, then the status change; the title is still frozen while closed.
  const reopened = await updateCase(archived, { archived: false, status: "in_progress" });
  assert.equal(reopened.isError, false);
  assert.deepEqual(reopened.sent, [
    { id: CASE_ID, isArchived: false },
    { id: CASE_ID, primaryStatusId: OPEN.id },
  ]);
  assert.match(reopened.json.notes.join(" "), /Unarchived first/);
});

test("closing without a verdict is refused with the valid verdict names and no write", async () => {
  const { isError, text, sent } = await updateCase(caseRecord(), { status: "closed" });
  assert.equal(isError, true);
  assert.match(text, /requires a verdict/);
  assert.match(text, /false_positive \(False Positive\)/);
  assert.equal(sent.length, 0);
});

test("a return to new is refused once the case has left it", async () => {
  const referenceWithNew = {
    ...referenceData,
    resolveStatus: async () => ({ id: "n", name: "new", title: "New", isClosed: false }),
  };
  const client = fakeClient(caseRecord());
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFusionCaseTools(server, client, tenantResolver, referenceWithNew);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  const result = await mcp.callTool({ name: "sophos_fusion_update_case", arguments: { case_id: CASE_ID, status: "new" } });
  await mcp.close();
  await server.close();
  assert.equal(Boolean(result.isError), true);
  assert.match(result.content[0].text, /cannot move a case back to new/);
  assert.equal(client.sent.length, 0);
});

test("tags are merged with the current list unless replace_tags is set", async () => {
  const merged = await updateCase(caseRecord({ tags: ["a", "b"] }), { tags: ["b", "c"] });
  assert.deepEqual(merged.sent, [{ id: CASE_ID, tags: ["a", "b", "c"] }]);
  assert.match(merged.json.notes.join(" "), /Tags merged/);
  const replaced = await updateCase(caseRecord({ tags: ["a", "b"] }), { tags: ["c"], replace_tags: true });
  assert.deepEqual(replaced.sent, [{ id: CASE_ID, tags: ["c"] }]);
});
