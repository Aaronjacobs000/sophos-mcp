#!/usr/bin/env node
/**
 * Live smoke test for the Sophos Fusion GraphQL tools and the Classic REST
 * case tools. Read-only by default.
 *
 * Spawns the built server over stdio with the credentials from the
 * environment (or .env) and calls the tools through the MCP client, so what
 * runs here is exactly what an MCP host runs.
 *
 * Modes:
 *   node scripts/fusion-smoke.mjs [tenant-id]                  read-only Fusion checks
 *   node scripts/fusion-smoke.mjs --write [tenant-id]          plus the Fusion write tools
 *   node scripts/fusion-smoke.mjs --write-classic [tenant-id]  plus the Classic REST case tools
 *   node scripts/fusion-smoke.mjs --all [tenant-id]            everything
 *
 * Read-only:
 *   1. sophos_fusion_list_case_reference_data
 *   2. sophos_fusion_list_cases (newest 5), plus filter variants
 *   3. sophos_fusion_get_case on the newest case, by short ID
 *   4. sophos_fusion_get_case_evidence and sophos_fusion_get_case_summary
 *   5. sophos_fusion_list_case_comments
 *   6. Classic: sophos_list_cases, sophos_get_case, sophos_list_case_detections,
 *      sophos_get_case_detection, sophos_get_case_mitre_summary,
 *      sophos_list_case_impacted_entities
 *
 * --write creates ONE clearly named Fusion case ("MCP smoke test <timestamp>"),
 * exercises comment, link, update, evidence add and remove on that case only,
 * then closes it with a verdict and archives it (Fusion has no delete).
 * Evidence is borrowed from the newest existing case and detached again;
 * that case itself is never modified.
 *
 * --write-classic creates ONE Classic case, updates it, then deletes it. The
 * Cases API requires an assignee and a detection that still exists, so set
 * SMOKE_CLASSIC_ASSIGNEE (a tenant admin email) and, when the newest Classic
 * case's detection has aged out, SMOKE_CLASSIC_DETECTION_ID (a recent
 * detection ID from sophos_list_detections).
 *
 * Every write is listed in a ledger at the end. Exits non-zero if any check
 * fails. Run `npm run build` first.
 */

import "dotenv/config";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const serverPath = fileURLToPath(new URL("../dist/index.js", import.meta.url));
if (!existsSync(serverPath)) {
  console.error("dist/index.js is missing; run npm run build first");
  process.exit(1);
}
if (!process.env.SOPHOS_CLIENT_ID || !process.env.SOPHOS_CLIENT_SECRET) {
  console.error("SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET must be set (or in .env)");
  process.exit(1);
}

const flags = new Set(process.argv.slice(2).filter((a) => a.startsWith("--")));
const tenantId = process.argv.slice(2).find((a) => !a.startsWith("--"));
const scope = tenantId ? { tenant_id: tenantId } : {};
const writeFusion = flags.has("--write") || flags.has("--all");
const writeClassic = flags.has("--write-classic") || flags.has("--all");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  env: { ...process.env, TRANSPORT: "stdio" },
  stderr: "inherit",
});
const client = new Client({ name: "fusion-smoke", version: "0.0.0" });
await client.connect(transport);

let failures = 0;
const ledger = [];

/** Calls a tool and prints the result. Returns { ok, text, json }. */
async function call(name, args, { expectError = false, quiet = false } = {}) {
  console.log(`\n== ${name} ${JSON.stringify(args)} ==`);
  const result = await client.callTool({ name, arguments: args });
  const text = result.content.map((c) => c.text ?? "").join("\n");
  console.log(quiet ? `${text.slice(0, 600)}${text.length > 600 ? " ..." : ""}` : text);
  const ok = !result.isError;
  if (ok === expectError) {
    failures += 1;
    console.log(expectError ? "!! expected an error but the call succeeded" : "!! call failed");
  }
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // error text or non-JSON
  }
  return { ok, text, json };
}

function record(what) {
  ledger.push(what);
  console.log(`   [write] ${what}`);
}

function check(condition, message) {
  if (!condition) {
    failures += 1;
    console.log(`!! check failed: ${message}`);
  } else {
    console.log(`   ok: ${message}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Polls the case until every processing_status is SUCCESS or FAILED. */
async function waitForProcessing(caseId, attempts = 12) {
  for (let i = 0; i < attempts; i++) {
    const { json } = await call("sophos_fusion_get_case", { ...scope, case_id: caseId }, { quiet: true });
    const status = json?.processing_status ?? {};
    const states = Object.values(status);
    if (states.every((s) => s === "SUCCESS" || s === "FAILED" || s === null)) return json;
    await sleep(2500);
  }
  return null;
}

const stamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

try {
  // --- Fusion, read-only ---
  const ref = await call("sophos_fusion_list_case_reference_data", scope, { quiet: true });
  check(ref.json?.types?.length > 0, "reference data lists at least one case type");
  check(ref.json?.primary_statuses?.some((s) => s.is_closed), "reference data has a closed status");

  const list = await call("sophos_fusion_list_cases", { ...scope, per_page: 5 }, { quiet: true });
  check(typeof list.json?.total === "number", "list_cases returns a total");
  const newest = list.json?.cases?.[0];

  const unassigned = await call(
    "sophos_fusion_list_cases",
    { ...scope, unassigned: true, open_only: true, per_page: 3 },
    { quiet: true }
  );
  check(
    unassigned.json?.ql_query === "closedAt is null and (assigneeId is null or assigneeId = '')",
    "unassigned compiles to the null-or-empty predicate"
  );

  await call("sophos_fusion_list_cases", { ...scope, severity_min: 8, sort: "severity desc", per_page: 3 }, { quiet: true });

  if (list.json?.has_next_page && list.json?.end_cursor) {
    const page2 = await call(
      "sophos_fusion_list_cases",
      { ...scope, per_page: 5, after: list.json.end_cursor },
      { quiet: true }
    );
    check(page2.json?.cases?.length > 0, "cursor pagination returns a second page");
  }

  let borrowedDetectionId = null;
  let borrowedEventId = null;

  if (newest) {
    const byShort = await call("sophos_fusion_get_case", { ...scope, case_id: newest.short_id }, { quiet: true });
    check(byShort.json?.id === newest.id, "short ID resolves to the same case as the UUID");

    const evidence = await call("sophos_fusion_get_case_evidence", { ...scope, case_id: newest.id }, { quiet: true });
    borrowedDetectionId = evidence.json?.detections?.at(-1)?.detection_id ?? null;

    const summary = await call(
      "sophos_fusion_get_case_summary",
      { ...scope, case_id: newest.id, max_detections: 10 },
      { quiet: true }
    );
    check(summary.json?.mitre_summary !== undefined, "summary carries the MITRE roll-up (not truncated away)");
    if (summary.json?.detections?.length) {
      check(
        summary.json.detections.every((d) => d.severity_0_to_1 === null || d.severity_0_to_1 <= 1),
        "detection severity is on the 0 to 1 scale"
      );
    }
    borrowedEventId = summary.json?.evidence?.event_ids?.[0] ?? null;

    await call("sophos_fusion_list_case_comments", { ...scope, case_id: newest.id, per_page: 5 }, { quiet: true });
  } else {
    console.log("\nNo Fusion cases in this tenant; per-case reads skipped.");
  }

  await call(
    "sophos_fusion_get_case",
    { ...scope, case_id: "00000000-0000-4000-8000-000000000000" },
    { expectError: true }
  );
  await call("sophos_fusion_get_case", { ...scope, case_id: "1-598868" }, { expectError: true });

  // --- Classic REST, read-only ---
  const classic = await call("sophos_list_cases", { ...scope, limit: 5 }, { quiet: true });
  const classicNewest = classic.json?.cases?.[0];
  if (classicNewest) {
    await call("sophos_get_case", { ...scope, case_id: classicNewest.id }, { quiet: true });
    const dets = await call(
      "sophos_list_case_detections",
      { ...scope, case_id: classicNewest.id, limit: 2 },
      { quiet: true }
    );
    const det = dets.json?.detections?.[0];
    if (det) {
      await call(
        "sophos_get_case_detection",
        { ...scope, case_id: classicNewest.id, detection_id: det.id },
        { quiet: true }
      );
    }
    await call("sophos_get_case_mitre_summary", { ...scope, case_id: classicNewest.id }, { quiet: true });
    await call(
      "sophos_list_case_impacted_entities",
      { ...scope, case_id: classicNewest.id, limit: 5 },
      { quiet: true }
    );
  }

  // --- Fusion, writes on one new case ---
  let fusionCreated = null;
  const fusionTitle = `MCP smoke test ${stamp}`;
  if (writeFusion) {
    fusionCreated = await call("sophos_fusion_create_case", {
      ...scope,
      title: fusionTitle,
      type: "investigation",
      severity: "informational",
      tags: ["mcp-smoke-test"],
      key_findings: `# MCP smoke test\n\nCreated by scripts/fusion-smoke.mjs at ${stamp}. Safe to ignore.`,
    });
    const caseId = fusionCreated.json?.id;
    if (!caseId) {
      console.log("\nFusion create_case failed; the remaining Fusion write tools need a case of their own and are skipped.");
    }
  }

  if (writeFusion && newest && !newest.status?.is_closed) {
    // The verdict-on-close check runs before any mutation is sent: the tool
    // reads the case and its valid verdicts, then refuses when a verdict is
    // required and missing. The existing case is not modified.
    const refused = await call(
      "sophos_fusion_update_case",
      { ...scope, case_id: newest.id, status: "closed" },
      { expectError: true }
    );
    check(
      /requires a verdict/.test(refused.text),
      "close without verdict is refused with the verdict list (no mutation sent)"
    );
  }

  if (writeFusion && fusionCreated?.json?.id) {
    const created = fusionCreated;
    const caseId = created.json.id;
    const title = fusionTitle;
    record(`Fusion case created: ${created.json.short_id} (${caseId}) "${title}", status ${created.json.status?.name}`);
    check(created.json.status?.is_closed === false, `default status is open (${created.json.status?.name})`);
    check(created.json.severity === 2, "severity label resolved to 2");
    check(created.json.key_findings?.content?.includes("MCP smoke test"), "key findings stored");

    const comment = await call("sophos_fusion_add_case_comment", {
      ...scope,
      case_id: created.json.short_id,
      comment: `MCP smoke test comment ${stamp}`,
    });
    if (comment.ok) record(`Comment ${comment.json?.id} added to ${created.json.short_id}`);

    const comments = await call("sophos_fusion_list_case_comments", { ...scope, case_id: caseId });
    check(comments.json?.total === 1, "one comment listed on the new case");

    const link = await call("sophos_fusion_create_case_link", {
      ...scope,
      case_id: caseId,
      url: "https://example.com/mcp-smoke-test",
      title: "MCP smoke test link",
      type: "Test",
      reference: "MCP-1",
    });
    if (link.ok) record(`Link ${link.json?.id} added to ${created.json.short_id}`);

    const updated = await call("sophos_fusion_update_case", {
      ...scope,
      case_id: caseId,
      title: `${title} (updated)`,
      severity: 4,
      status: "in_progress",
      tags: ["mcp-smoke-test", "updated"],
      key_findings: `# MCP smoke test (updated)\n\nUpdated at ${new Date().toISOString()}.`,
    });
    if (updated.ok) record(`Case ${created.json.short_id} updated: title, severity 4, status in_progress, tags, key findings`);
    check(updated.json?.severity === 4, "severity updated to 4");
    check(updated.json?.status?.name === "in_progress", "status updated to in_progress");
    check(updated.json?.links?.length === 1, "link visible on the updated case");

    const evidenceIn = {};
    if (borrowedEventId) evidenceIn.event_ids = [borrowedEventId];
    if (borrowedDetectionId) evidenceIn.detection_ids = [borrowedDetectionId];
    if (Object.keys(evidenceIn).length > 0) {
      const added = await call("sophos_fusion_add_case_evidence", { ...scope, case_id: caseId, ...evidenceIn });
      if (added.ok) record(`Evidence attached to ${created.json.short_id}: ${JSON.stringify(evidenceIn)}`);
      const afterAdd = await waitForProcessing(caseId);
      check(afterAdd !== null, "evidence processing finished");
      const ev = await call("sophos_fusion_get_case_evidence", { ...scope, case_id: caseId });
      if (borrowedEventId) check(ev.json?.counts?.events === 1, "one event attached");
      if (borrowedDetectionId) check(ev.json?.counts?.detections === 1, "one detection attached");

      const removeIn = {};
      if (borrowedEventId) removeIn.event_ids = [borrowedEventId];
      if (borrowedDetectionId) removeIn.detection_ids = [borrowedDetectionId];
      const removed = await call("sophos_fusion_remove_case_evidence", { ...scope, case_id: caseId, ...removeIn });
      if (removed.ok) record(`Evidence detached from ${created.json.short_id}: ${JSON.stringify(removeIn)}`);
      await waitForProcessing(caseId);
      const evAfter = await call("sophos_fusion_get_case_evidence", { ...scope, case_id: caseId });
      check(evAfter.json?.counts?.events === 0, "events back to 0 after removal");
      check(evAfter.json?.counts?.detections === 0, "detections back to 0 after removal");
    } else {
      console.log("\nNo evidence to borrow; add/remove evidence skipped.");
    }

    await call("sophos_fusion_get_case_summary", { ...scope, case_id: caseId }, { quiet: true });

    // Closing without a verdict must be refused with the valid verdict names.
    const refused = await call(
      "sophos_fusion_update_case",
      { ...scope, case_id: caseId, status: "closed" },
      { expectError: true }
    );
    check(/requires a verdict/.test(refused.text), "close without verdict is refused with the verdict list");

    const closed = await call("sophos_fusion_update_case", {
      ...scope,
      case_id: caseId,
      status: "closed",
      verdict: "false_positive",
      close_reason: "MCP smoke test complete",
    });
    if (closed.ok) record(`Case ${created.json.short_id} closed with verdict false_positive`);
    check(closed.json?.closed_at !== null, "closed_at set");
    check(closed.json?.verdict?.name === "false_positive", "verdict recorded");

    const byVerdict = await call(
      "sophos_fusion_list_cases",
      { ...scope, verdict: "false_positive", title_contains: "MCP smoke test", per_page: 5 },
      { quiet: true }
    );
    check(byVerdict.json?.cases?.some((c) => c.id === caseId), "verdict filter finds the closed case");

    const archived = await call("sophos_fusion_update_case", { ...scope, case_id: caseId, archived: true });
    if (archived.ok) record(`Case ${created.json.short_id} archived`);
    check(archived.json?.archived_at !== null, "archived_at set");
  }

  // --- Classic REST, writes on one new case ---
  if (writeClassic) {
    // The Cases API needs a detection that still exists in the detections
    // store (older cases' detections age out: "No detections found for the
    // given ID") and an assignee. Both come from the environment so nothing
    // tenant-specific lives in the repo; the detection falls back to the
    // newest Classic case's initial detection.
    const assignee = process.env.SMOKE_CLASSIC_ASSIGNEE;
    let detectionId = process.env.SMOKE_CLASSIC_DETECTION_ID;
    if (!detectionId) {
      const recent = await call("sophos_list_cases", { ...scope, limit: 50 }, { quiet: true });
      const newest = (recent.json?.cases ?? [])
        .filter((c) => c.initial_detection_id)
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
      detectionId = newest?.initial_detection_id;
    }
    if (!detectionId) {
      console.log("\nNo detection to seed a Classic case from; Classic writes skipped.");
    } else if (!assignee) {
      console.log("\nSMOKE_CLASSIC_ASSIGNEE (a tenant admin email) is not set; Classic writes skipped.");
    } else {
      const name = `MCP smoke test ${stamp}`;
      const created = await call("sophos_create_case", {
        ...scope,
        name,
        severity: "informational",
        status: "new",
        initial_detection_id: detectionId,
        assignee,
        overview: "Created by scripts/fusion-smoke.mjs. Safe to delete.",
      });
      const caseId = created.json?.id;
      if (caseId) {
        record(`Classic case created: ${caseId} "${name}"`);
        const updated = await call("sophos_update_case", {
          ...scope,
          case_id: caseId,
          name: `${name} (updated)`,
          severity: "low",
          status: "investigating",
          overview: "Updated by the smoke test.",
        });
        if (updated.ok) record(`Classic case ${caseId} updated: name, severity low, status investigating, overview`);
        check(updated.json?.status === "investigating", "Classic status updated");
        const deleted = await call("sophos_delete_case", { ...scope, case_id: caseId });
        if (deleted.ok) record(`Classic case ${caseId} deleted`);
        await call("sophos_get_case", { ...scope, case_id: caseId }, { expectError: true });
      }
    }
  }
} finally {
  await client.close();
}

if (ledger.length > 0) {
  console.log("\nWrites performed against the tenant:");
  for (const line of ledger) console.log(`  - ${line}`);
} else {
  console.log("\nNo writes performed.");
}

console.log(failures === 0 ? "\nSmoke test passed." : `\nSmoke test failed: ${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
