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
 *   node scripts/fusion-smoke.mjs --write-ai-defense [tenant-id]  plus the AI Defense policy writes
 *   node scripts/fusion-smoke.mjs --all [tenant-id]            everything
 *
 * Read-only:
 *   1. sophos_fusion_list_case_reference_data (its tenant_type, from the
 *      tenant record's xdrOwnership, says whether the tenant has migrated)
 *   2. sophos_fusion_list_cases (newest 5), plus filter variants
 *   3. sophos_fusion_get_case on the newest case, by short ID
 *   4. sophos_fusion_get_case_evidence and sophos_fusion_get_case_summary
 *   5. sophos_fusion_list_case_comments and sophos_fusion_list_case_files
 *   6. sophos_fusion_search_detections
 *   7. sophos_fusion_create_search, sophos_fusion_get_search and
 *      sophos_fusion_get_search_results on a small process search
 *   8. AI Defense: policies (list, cursor, get with rule previews), app
 *      sanctioning, rule and impact previews, starter templates, mechanisms,
 *      policy activity, activities (list, cursor, get), app and user
 *      inventory, user apps, inventory summary, settings, and the not-found
 *      and both-windows refusals
 *   9. Classic: on a migrated tenant, the migration refusal on sophos_list_cases
 *      and sophos_run_detections_query; otherwise sophos_list_cases, sophos_get_case,
 *      sophos_list_case_detections, sophos_get_case_detection,
 *      sophos_get_case_mitre_summary, sophos_list_case_impacted_entities
 *
 * --write creates ONE clearly named Fusion case ("MCP smoke test <timestamp>",
 * managed_by CUSTOMER), exercises comment add, update and delete (with the
 * mention read-back), link create, update and delete, tag merge and replace,
 * evidence add and remove_all, file upload, list and soft delete, the
 * reopen rule (verdict cleared, read back), the one way door on new and the
 * closed-case freeze, then closes it with a verdict and archives it (Fusion
 * has no delete). Evidence is borrowed from
 * the newest existing case or the detection search and detached again; no
 * existing case is modified.
 *
 * --write-ai-defense creates AI Defense policies named "ZZ Claude MCP test
 * <timestamp> ..." scoped to a made-up user, so they enforce on nobody: one from
 * the education-v1 starter template, one ENABLED, one with an empty scope (to
 * check that enabling it is refused). It updates, enables, disables, clones and
 * moves them, reorders only when every reorderable policy on the tenant is one
 * of its own, reads each write back, then deletes them all and reads the
 * deletion back. No other policy is changed, and the tenant settings are never
 * written.
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
import { randomUUID } from "node:crypto";
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
const writeAiDefense = flags.has("--write-ai-defense") || flags.has("--all");

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

/**
 * Calls a tool and prints the result. Returns { ok, text, json }.
 * quiet trims the output, silent suppresses it (polling), tolerate records
 * neither outcome as a failure (diagnostics).
 */
async function call(name, args, { expectError = false, quiet = false, silent = false, tolerate = false } = {}) {
  if (!silent) console.log(`\n== ${name} ${JSON.stringify(args)} ==`);
  const result = await client.callTool({ name, arguments: args });
  const text = result.content.map((c) => c.text ?? "").join("\n");
  if (!silent) console.log(quiet ? `${text.slice(0, 600)}${text.length > 600 ? " ..." : ""}` : text);
  const ok = !result.isError;
  if (!tolerate && ok === expectError) {
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

/**
 * Polls the case evidence every 2 s until done(counts) holds or maxSeconds
 * pass, printing each read with its offset. Reads lag writes by a few
 * seconds, so a count taken straight after a write proves nothing.
 */
async function waitForEvidence(caseId, done, maxSeconds = 45) {
  const started = Date.now();
  for (;;) {
    const { json } = await call("sophos_fusion_get_case_evidence", { ...scope, case_id: caseId }, { silent: true });
    const counts = json?.counts ?? {};
    const elapsed = Math.round((Date.now() - started) / 1000);
    console.log(`   evidence at +${elapsed}s: ${JSON.stringify(counts)}`);
    if (done(counts)) return { json, elapsed, timedOut: false };
    if (Date.now() - started >= maxSeconds * 1000) return { json, elapsed, timedOut: true };
    await sleep(2000);
  }
}

const allZero = (c) => c.detections === 0 && c.events === 0 && c.assets === 0 && c.search_queries === 0;

const stamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

try {
  // --- Fusion, read-only ---
  const ref = await call("sophos_fusion_list_case_reference_data", scope, { quiet: true });
  check(ref.json?.types?.length > 0, "reference data lists at least one case type");
  check(ref.json?.primary_statuses?.some((s) => s.is_closed), "reference data has a closed status");
  // tenant_type comes from xdrOwnership. Case types don't decide it: a tenant
  // not yet upgraded can list them too. On an upgraded tenant the Classic
  // case and detection tools must refuse.
  const migrated = ref.json?.tenant_type === "upgraded";
  console.log(`\nTenant type: ${ref.json?.tenant_type} (${ref.json?.tenant_type_detail}).`);

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

    const files = await call("sophos_fusion_list_case_files", { ...scope, case_id: newest.id }, { quiet: true });
    check(Array.isArray(files.json?.files), "list_case_files returns a file list for the case");
  } else {
    console.log("\nNo Fusion cases in this tenant; per-case reads skipped.");
  }

  const tenantFiles = await call("sophos_fusion_list_case_files", { ...scope, per_page: 5 }, { quiet: true });
  check(typeof tenantFiles.json?.tenant_total_files === "number", "list_case_files returns the tenant file count");

  const RN = /^[a-z][a-z0-9+.-]*:\/\/[^:\s]+(?::[^:\s]+){4}$/i;
  const search = await call("sophos_fusion_search_detections", { ...scope, limit: 5 }, { quiet: true });
  check(Array.isArray(search.json?.detections), "search_detections returns a detection list");
  if (search.json?.detections?.length) {
    check(search.json.detections.every((d) => RN.test(d.id)), "detection IDs are six section resource names");
    check(
      search.json.detections.every((d) => d.severity_0_to_1 === null || d.severity_0_to_1 <= 1),
      "search detection severity is on the 0 to 1 scale"
    );
    if (!borrowedDetectionId) borrowedDetectionId = search.json.detections[0].id;
  }

  // Search GraphQL v1: start a small QL search, poll it, read one page
  const started = await call(
    "sophos_fusion_create_search",
    { ...scope, query: "from process earliest=-1h | fields host_id, image_path" },
    { quiet: true }
  );
  const searchUrn = started.json?.search?.urn;
  check(typeof searchUrn === "string" && searchUrn.startsWith("urn:"), "create_search returns a search URN");
  if (searchUrn) {
    let status = started.json.search.status;
    for (let i = 0; i < 20 && status !== "COMPLETE"; i++) {
      await sleep(3000);
      status = (await call("sophos_fusion_get_search", { ...scope, urn: searchUrn }, { silent: true })).json?.search?.status;
    }
    check(status === "COMPLETE", "the search completes within a minute");
    const page = await call("sophos_fusion_get_search_results", { ...scope, urn: searchUrn, limit: 3 }, { quiet: true });
    check(Array.isArray(page.json?.values), "get_search_results returns a values array");
  }

  await call(
    "sophos_fusion_get_case",
    { ...scope, case_id: "00000000-0000-4000-8000-000000000000" },
    { expectError: true }
  );
  await call("sophos_fusion_get_case", { ...scope, case_id: "1-598868" }, { expectError: true });

  // AI Defense Policy and Activity GraphQL v1, read-only
  const AID = "sophos_fusion_ai_defense_";
  const aiPolicies = await call(`${AID}list_policies`, { ...scope, limit: 2 }, { quiet: true });
  check(typeof aiPolicies.json?.total === "number", "AI Defense list_policies returns a total");
  if (aiPolicies.json?.has_next_page) {
    const next = await call(`${AID}list_policies`, { ...scope, limit: 2, after: aiPolicies.json.end_cursor }, { quiet: true });
    check(next.json?.policies?.every((p) => !aiPolicies.json.policies.some((q) => q.id === p.id)), "AI Defense policy cursor page 2 has new policies");
  }
  const aiPolicy = aiPolicies.json?.policies?.find((p) => p.rules.length > 0);
  if (aiPolicy) {
    const got = await call(`${AID}get_policy`, { ...scope, policy_id: aiPolicy.id, include_rule_previews: true }, { quiet: true });
    check(got.json?.policy?.rules?.every((r) => typeof r.targetPreviewV2?.matchedCount === "number"), "AI Defense rule previews present");
    const impact = await call(`${AID}preview_impact`, { ...scope, rules: got.json?.policy?.rules ?? [] }, { quiet: true });
    check(impact.json?.impact?.totalApps > 0, "AI Defense preview_impact takes rules as get_policy returns them");
  }
  await call(`${AID}get_policy`, { ...scope, policy_id: "00000000-0000-4000-8000-000000000000" }, { expectError: true });
  const sanction = await call(`${AID}get_app_sanctioning`, { ...scope, app_ids: ["chatgpt", "no-such-app"] }, { quiet: true });
  check(sanction.json?.entries?.find((e) => e.appId === "no-such-app")?.status === "NOT_COVERED", "an unknown app is NOT_COVERED");
  const critical = [{ dimension: "risk_level", operator: "IN", values: ["critical"] }];
  const target = await call(`${AID}preview_rule_target`, { ...scope, conditions: critical, action: "BLOCK" }, { quiet: true });
  check(target.json?.preview?.matchedCount > 0, "AI Defense preview_rule_target matches the critical apps");
  const sequence = await call(
    `${AID}preview_rule_targets`,
    {
      ...scope,
      rules: [
        { conditions: [{ dimension: "app", operator: "IN", values: ["chatgpt"] }], action: "ALLOW" },
        { conditions: [{ dimension: "category", operator: "IN", values: ["general_assistant"] }], action: "BLOCK" },
      ],
    },
    { quiet: true }
  );
  check(sequence.json?.previews?.length === 2, "AI Defense preview_rule_targets returns one preview per rule");
  const templates = await call(`${AID}list_templates`, scope, { quiet: true });
  check(templates.json?.templates?.length > 0, "AI Defense starter templates listed");
  if (templates.json?.templates?.[0]) {
    const template = await call(`${AID}get_template`, { ...scope, key: templates.json.templates[0].key }, { quiet: true });
    check(typeof template.json?.template?.impact?.totalApps === "number", "AI Defense get_template carries its impact");
  }
  await call(`${AID}list_mechanisms`, scope, { quiet: true });
  await call(`${AID}get_policy_activity`, scope, { quiet: true });
  await call(`${AID}get_policy_activity`, { ...scope, time_range: "SINCE_BEGINNING_OF_MONTH", start_time: "2026-11-01T00:00:00Z" }, { expectError: true });
  const activities = await call(`${AID}list_activities`, { ...scope, time_range: "SINCE_BEGINNING_OF_WEEK_MONDAY", limit: 2 }, { quiet: true });
  check(typeof activities.json?.total === "number", "AI Defense list_activities returns a total");
  if (activities.json?.has_next_page) {
    const next = await call(
      `${AID}list_activities`,
      { ...scope, time_range: "SINCE_BEGINNING_OF_WEEK_MONDAY", limit: 2, after: activities.json.end_cursor },
      { quiet: true }
    );
    check(next.json?.activities?.every((a) => !activities.json.activities.some((b) => b.id === a.id)), "AI Defense activity cursor page 2 has new rows");
  }
  if (activities.json?.activities?.[0]) {
    const one = await call(`${AID}get_activity`, { ...scope, activity_id: activities.json.activities[0].id }, { quiet: true });
    check(one.json?.activity?.additionalData !== undefined, "AI Defense get_activity carries additionalData");
  }
  const month = { ...scope, time_range: "SINCE_BEGINNING_OF_MONTH" };
  const apps = await call(`${AID}list_app_inventory`, { ...month, limit: 3 }, { quiet: true });
  const users = await call(`${AID}list_user_inventory`, { ...month, limit: 3 }, { quiet: true });
  if (users.json?.users?.[0]) {
    const userApps = await call(`${AID}list_user_apps`, { ...month, user_id: users.json.users[0].id, limit: 3 }, { quiet: true });
    check(userApps.json?.total === users.json.users[0].appsUsed, "AI Defense user apps total equals the user's appsUsed");
  }
  const summary = await call(`${AID}inventory_summary`, month, { quiet: true });
  check(summary.json?.summary?.apps?.totalApps === apps.json?.total, "AI Defense summary app count equals the app inventory total");
  await call(`${AID}get_settings`, scope, { quiet: true });

  // --- Classic REST, read-only ---
  if (migrated) {
    const refusedList = await call("sophos_list_cases", { ...scope, limit: 5 }, { expectError: true });
    check(/has migrated to Sophos Fusion/.test(refusedList.text), "sophos_list_cases refuses a migrated tenant");
    check(/sophos_fusion_list_cases/.test(refusedList.text), "the refusal names the Fusion tool");
    const refusedRun = await call("sophos_run_detections_query", { ...scope }, { expectError: true });
    check(/sophos_fusion_search_detections/.test(refusedRun.text), "sophos_run_detections_query refuses and points at the Fusion search");
  }
  const classic = migrated ? { json: null } : await call("sophos_list_cases", { ...scope, limit: 5 }, { quiet: true });
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
    // managed_by must contradict the type to be refused before any call is made.
    const contradiction = await call(
      "sophos_fusion_create_case",
      { ...scope, title: "never created", type: "health_check", severity: 2, managed_by: "CUSTOMER" },
      { expectError: true }
    );
    check(/always managed by PROVIDER/.test(contradiction.text), "managed_by that contradicts the type is refused client side");

    fusionCreated = await call("sophos_fusion_create_case", {
      ...scope,
      title: fusionTitle,
      type: "investigation",
      severity: "informational",
      managed_by: "CUSTOMER",
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
    check(created.json.managed_by === "CUSTOMER", "managed_by stored as CUSTOMER");
    check(created.json.severity === 2, "severity label resolved to 2");
    check(created.json.key_findings?.content?.includes("MCP smoke test"), "key findings stored");

    // Mentions: a made-up token is dropped silently by the API and must be
    // reported back as unresolved; no real group is named, so nobody is notified.
    const comment = await call("sophos_fusion_add_case_comment", {
      ...scope,
      case_id: created.json.short_id,
      comment: `MCP smoke test comment ${stamp} @zzz_not_a_group`,
    });
    if (comment.ok) record(`Comment ${comment.json?.id} added to ${created.json.short_id}`);
    check(
      Array.isArray(comment.json?.mentions_unresolved) && comment.json.mentions_unresolved.includes("@zzz_not_a_group"),
      "an unrecognised mention is reported as unresolved"
    );
    check(comment.json?.mentions_resolved?.length === 0, "no mention resolved");

    const comments = await call("sophos_fusion_list_case_comments", { ...scope, case_id: caseId });
    check(comments.json?.total === 1, "one comment listed on the new case");

    const editedComment = await call("sophos_fusion_update_case_comment", {
      ...scope,
      comment_id: comment.json?.id,
      comment: `MCP smoke test comment ${stamp} (edited)`,
      mark_as_read: true,
    });
    if (editedComment.ok) record(`Comment ${comment.json?.id} edited and marked read`);
    check(/\(edited\)$/.test(editedComment.json?.comment ?? ""), "comment text updated");

    const deletedComment = await call("sophos_fusion_delete_case_comment", { ...scope, comment_id: comment.json?.id });
    if (deletedComment.ok) record(`Comment ${comment.json?.id} deleted`);
    const commentsAfter = await call("sophos_fusion_list_case_comments", { ...scope, case_id: caseId }, { quiet: true });
    check(commentsAfter.json?.total === 0, "no comments left after the delete");

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
      tags: ["updated"],
      key_findings: `# MCP smoke test (updated)\n\nUpdated at ${new Date().toISOString()}.`,
    });
    if (updated.ok) record(`Case ${created.json.short_id} updated: title, severity 4, status in_progress, tags, key findings`);
    check(updated.json?.severity === 4, "severity updated to 4");
    check(updated.json?.status?.name === "in_progress", "status updated to in_progress");
    check(updated.json?.links?.length === 1, "link visible on the updated case");
    check(
      JSON.stringify(updated.json?.tags) === JSON.stringify(["mcp-smoke-test", "updated"]),
      "tags merged with the existing list rather than replacing it"
    );

    const replacedTags = await call("sophos_fusion_update_case", {
      ...scope,
      case_id: caseId,
      tags: ["mcp-smoke-test"],
      replace_tags: true,
    });
    if (replacedTags.ok) record(`Case ${created.json.short_id} tags replaced`);
    check(JSON.stringify(replacedTags.json?.tags) === JSON.stringify(["mcp-smoke-test"]), "replace_tags replaces the list");

    const backToNew = await call(
      "sophos_fusion_update_case",
      { ...scope, case_id: caseId, status: "new" },
      { expectError: true }
    );
    check(/cannot move a case back to new/.test(backToNew.text), "new is a one way door (refused before any mutation)");

    const editedLink = await call("sophos_fusion_update_case_link", {
      ...scope,
      link_id: link.json?.id,
      title: "MCP smoke test link (updated)",
      reference: "MCP-2",
    });
    if (editedLink.ok) record(`Link ${link.json?.id} updated`);
    check(editedLink.json?.reference === "MCP-2", "link reference updated");

    const deletedLink = await call("sophos_fusion_delete_case_link", { ...scope, link_id: link.json?.id });
    if (deletedLink.ok) record(`Link ${link.json?.id} deleted`);
    const afterLink = await call("sophos_fusion_get_case", { ...scope, case_id: caseId }, { quiet: true });
    check(afterLink.json?.links?.length === 0, "no links left after the delete");

    const evidenceIn = {};
    if (borrowedEventId) evidenceIn.event_ids = [borrowedEventId];
    if (borrowedDetectionId) evidenceIn.detection_ids = [borrowedDetectionId];
    if (Object.keys(evidenceIn).length > 0) {
      const bareUuid = await call(
        "sophos_fusion_add_case_evidence",
        { ...scope, case_id: caseId, detection_ids: ["00000000-0000-4000-8000-000000000000"] },
        { expectError: true }
      );
      check(/six section resource names/.test(bareUuid.text), "a bare UUID detection ID is refused client side");

      const added = await call("sophos_fusion_add_case_evidence", { ...scope, case_id: caseId, ...evidenceIn });
      if (added.ok) record(`Evidence attached to ${created.json.short_id}: ${JSON.stringify(evidenceIn)}`);
      const wanted = (c) =>
        (!borrowedDetectionId || c.detections >= 1) && (!borrowedEventId || c.events >= 1);
      const afterAdd = await waitForEvidence(caseId, wanted, 45);
      check(!afterAdd.timedOut, `the added evidence appeared (after ${afterAdd.elapsed}s)`);
      // The expansion (asset and events that ride in with a detection) can
      // land a beat after the detection itself; give it a moment to settle.
      await sleep(4000);
      const ev = await call("sophos_fusion_get_case_evidence", { ...scope, case_id: caseId });
      if (borrowedEventId) check(ev.json?.counts?.events >= 1, "at least one event attached");
      if (borrowedDetectionId) check(ev.json?.counts?.detections === 1, "one detection attached");
      if (borrowedDetectionId) {
        console.log(`   detection expansion: ${ev.json?.counts?.assets} asset(s), ${ev.json?.counts?.events} event(s) came with it`);
      }

      // remove_all enumerates the evidence and removes every category, which
      // is the only way to take back what a detection brought with it.
      const removed = await call("sophos_fusion_remove_case_evidence", { ...scope, case_id: caseId, remove_all: true });
      if (removed.ok) record(`All evidence detached from ${created.json.short_id}`);
      const afterRemove = await waitForEvidence(caseId, allZero, 60);
      const counts = afterRemove.json?.counts ?? {};
      check(counts.detections === 0, "detections back to 0 after remove_all");
      check(counts.assets === 0, "assets back to 0 after remove_all");
      check(counts.events === 0, `events back to 0 after remove_all (settled after ${afterRemove.elapsed}s)`);
      check(counts.search_queries === 0, "search queries back to 0 after remove_all");

      if (counts.events > 0) {
        // Diagnostic: does an events-only removal take the leftovers? Tells a
        // combined-call problem apart from events that cannot be removed.
        const leftover = (afterRemove.json?.events ?? []).map((e) => e.event_id);
        console.log(`\n   diagnostic: ${leftover.length} event(s) survived remove_all; trying an events-only removal`);
        const retry = await call(
          "sophos_fusion_remove_case_evidence",
          { ...scope, case_id: caseId, event_ids: leftover },
          { tolerate: true }
        );
        if (retry.ok) record(`Events-only removal retried on ${created.json.short_id}`);
        const afterRetry = await waitForEvidence(caseId, allZero, 45);
        console.log(`   diagnostic result: events ${afterRetry.json?.counts?.events} after an events-only call (${afterRetry.elapsed}s)`);
      }
    } else {
      console.log("\nNo evidence to borrow; add/remove evidence skipped.");
    }

    const uploaded = await call("sophos_fusion_upload_case_file", {
      ...scope,
      case_id: caseId,
      name: "mcp-smoke-test.txt",
      content: `MCP smoke test file ${stamp}\n`,
    });
    if (uploaded.ok) record(`File ${uploaded.json?.id} uploaded to ${created.json.short_id}`);
    check(uploaded.json?.upload_status === "UPLOADED", "file status reached UPLOADED");
    const caseFiles = await call("sophos_fusion_list_case_files", { ...scope, case_id: caseId });
    check(caseFiles.json?.files?.some((f) => f.id === uploaded.json?.id), "uploaded file listed on the case");

    if (uploaded.json?.id) {
      const deletedFile = await call("sophos_fusion_delete_case_file", { ...scope, file_id: uploaded.json.id });
      if (deletedFile.ok) record(`File ${uploaded.json.id} soft deleted`);
      const filesAfter = await call("sophos_fusion_list_case_files", { ...scope, case_id: caseId }, { quiet: true });
      check(!filesAfter.json?.files?.some((f) => f.id === uploaded.json.id), "deleted file hidden by default");
      const filesWithDeleted = await call(
        "sophos_fusion_list_case_files",
        { ...scope, case_id: caseId, include_deleted: true },
        { quiet: true }
      );
      check(
        filesWithDeleted.json?.files?.some((f) => f.id === uploaded.json.id && f.status === "DELETED"),
        "deleted file visible with include_deleted, status DELETED (soft delete)"
      );
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

    // Reopening a closed case that holds a verdict: Fusion refuses the
    // transition unless the update clears the verdict. A null satisfies the
    // rule but leaves the stored verdict in place; an empty string clears it
    // (live tenant, 22/09/2026). The tool sends the empty string and the
    // read back must show no verdict.
    const reopened = await call("sophos_fusion_update_case", { ...scope, case_id: caseId, status: "in_progress" });
    if (reopened.ok) record(`Case ${created.json.short_id} reopened (verdict cleared by the tool)`);
    check(reopened.json?.status?.name === "in_progress", "reopened to in_progress");
    check(reopened.json?.closed_at === null, "closed_at cleared on reopen");
    check(reopened.json?.verdict === null, "verdict cleared on reopen (in the update response)");
    const reread = await call("sophos_fusion_get_case", { ...scope, case_id: caseId }, { quiet: true });
    check(reread.json?.verdict === null, "verdict cleared on reopen (read back)");
    check(
      (reopened.json?.notes ?? []).some((n) => /Cleared the recorded verdict false_positive/.test(n)),
      "the tool reports the verdict clear"
    );

    const closedAgain = await call("sophos_fusion_update_case", {
      ...scope,
      case_id: caseId,
      status: "closed",
      verdict: "false_positive",
      close_reason: "MCP smoke test complete",
    });
    if (closedAgain.ok) record(`Case ${created.json.short_id} closed again with verdict false_positive`);

    const byVerdict = await call(
      "sophos_fusion_list_cases",
      { ...scope, verdict: "false_positive", title_contains: "MCP smoke test", per_page: 5 },
      { quiet: true }
    );
    check(byVerdict.json?.cases?.some((c) => c.id === caseId), "verdict filter finds the closed case");

    // A closed case is frozen apart from status, verdict, secondary status,
    // reasons and archive. The tool refuses a retitle on a closed case before
    // any write rather than reopening it on the caller's behalf.
    const frozenClosed = await call(
      "sophos_fusion_update_case",
      { ...scope, case_id: caseId, title: `${title} (archived)`, archived: true },
      { expectError: true }
    );
    check(
      /closed/.test(frozenClosed.text) && /title cannot/.test(frozenClosed.text) && /Reopen it first/.test(frozenClosed.text),
      "retitle plus archive on a closed case is refused with the closed hint"
    );
    const unchanged = await call("sophos_fusion_get_case", { ...scope, case_id: caseId }, { quiet: true });
    check(
      unchanged.json?.archived_at === null && !/\(archived\)$/.test(unchanged.json?.title ?? ""),
      "the refused call changed nothing (not archived, not retitled)"
    );

    const archived = await call("sophos_fusion_update_case", { ...scope, case_id: caseId, archived: true });
    if (archived.ok) record(`Case ${created.json.short_id} archived`);
    check(archived.json?.archived_at !== null, "archived_at set");
    const frozenArchived = await call(
      "sophos_fusion_update_case",
      { ...scope, case_id: caseId, title: "should not apply" },
      { expectError: true }
    );
    check(/archived and refuses every update/.test(frozenArchived.text), "an archived case refuses updates with the archived hint");
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

  // --- AI Defense, policy writes on this run's own policies ---
  if (writeAiDefense) {
    const AID = "sophos_fusion_ai_defense_";
    const prefix = `ZZ Claude MCP test ${stamp}`;
    const mine = [];
    // A made-up user: the policies enforce on nobody
    const sensors = { endpoint: { enabled: true, scope: { users: [{ id: randomUUID(), name: "zz-claude-mcp-test-user" }] } } };
    const read = async (id) => (await call(`${AID}get_policy`, { ...scope, policy_id: id }, { silent: true })).json?.policy;
    const keep = (result, what) => {
      const policy = result.json?.policy;
      if (policy?.id) {
        mine.push(policy.id);
        record(`AI Defense policy created: ${policy.id} "${policy.name}" (${what})`);
      }
      return policy;
    };
    try {
      const template = (await call(`${AID}get_template`, { ...scope, key: "education-v1", include_impact: false }, { quiet: true })).json?.template;
      const a = keep(
        await call(
          `${AID}create_policy`,
          {
            ...scope,
            name: `${prefix} A`,
            rules: template?.rules ?? [],
            base_rule: template?.baseRule,
            sensors,
            tags: { purpose: "smoke" },
            ...(template ? { built_in_key: template.key, built_in_version: template.version } : {}),
          },
          { quiet: true }
        ),
        "from education-v1"
      );
      check(a?.state === "DISABLED" && a?.rank === 1, "a new AI Defense policy is DISABLED at rank 1");
      const b = keep(await call(`${AID}create_policy`, { ...scope, name: `${prefix} B`, sensors, state: "ENABLED" }, { quiet: true }), "ENABLED");
      check(b?.state === "ENABLED", "state ENABLED creates it enabled");
      const c = keep(
        await call(`${AID}create_policy`, { ...scope, name: `${prefix} C`, sensors: { endpoint: { enabled: true, scope: {} } } }, { quiet: true }),
        "empty scope"
      );
      if (c) {
        const refused = await call(`${AID}enable_policy`, { ...scope, policy_id: c.id }, { expectError: true });
        check(/everyone/.test(refused.text), "enabling an empty Endpoint scope is refused");
      }
      if (a) {
        const before = await read(a.id);
        check(JSON.stringify(before.tags) === '{"purpose":"smoke"}', "create stored the tags");
        const updated = await call(
          `${AID}update_policy`,
          { ...scope, policy_id: a.id, version: before.version, rules: before.rules.slice(0, 2), tags: { stage: "smoke-2" } },
          { quiet: true }
        );
        if (updated.ok) record(`AI Defense policy ${a.id} updated: two rules, tags replaced`);
        const after = await read(a.id);
        check(after.rules.length === 2, "update read back: rules replaced");
        // A different key from the one created with: a merge would keep purpose beside stage
        check(JSON.stringify(after.tags) === '{"stage":"smoke-2"}', `update read back: tags replaced, not merged (${JSON.stringify(after.tags)})`);
        const stale = await call(`${AID}update_policy`, { ...scope, policy_id: a.id, version: before.version, name: "stale" }, { expectError: true });
        check(/version conflict/.test(stale.text), "a stale version is refused");
        const enabled = await call(`${AID}enable_policy`, { ...scope, policy_id: a.id }, { quiet: true });
        if (enabled.ok) record(`AI Defense policy ${a.id} enabled`);
        check((await read(a.id)).state === "ENABLED", "enable read back");
        const disabled = await call(`${AID}disable_policy`, { ...scope, policy_id: a.id }, { quiet: true });
        if (disabled.ok) record(`AI Defense policy ${a.id} disabled`);
        check((await read(a.id)).state === "DISABLED", "disable read back");
        const clone = keep(await call(`${AID}clone_policy`, { ...scope, policy_id: a.id }, { quiet: true }), "clone of A");
        check(clone?.name === `${after.name} - cloned` && clone?.state === "DISABLED", "the clone is named '- cloned' and DISABLED");
        if (b) {
          await call(`${AID}move_policy`, { ...scope, policy_id: b.id }, { quiet: true });
          await call(`${AID}move_policy`, { ...scope, policy_id: b.id, after_policy_id: a.id }, { quiet: true });
          record(`AI Defense policy ${b.id} moved to the top, then after ${a.id}`);
          check((await read(b.id)).rank === (await read(a.id)).rank + 1, "move read back: B straight after A");
        }
      }
      const reorderable = (await call(`${AID}list_policies`, { ...scope, kind: "TENANT", limit: 100 }, { silent: true })).json?.policies?.filter(
        (p) => p.origin !== "PARTNER"
      );
      if (reorderable?.length > 1 && reorderable.every((p) => mine.includes(p.id))) {
        const reversed = reorderable.map((p) => p.id).reverse();
        const reordered = await call(`${AID}reorder_policies`, { ...scope, policy_ids: reversed }, { quiet: true });
        if (reordered.ok) record(`AI Defense policies reordered: ${reversed.join(", ")}`);
        const order = (await call(`${AID}list_policies`, { ...scope, kind: "TENANT", limit: 100 }, { silent: true })).json?.policies?.map((p) => p.id);
        check(JSON.stringify(order) === JSON.stringify(reversed), "reorder read back");
      } else {
        console.log("\nReorder skipped: the tenant has reorderable AI Defense policies this run did not create.");
      }
    } finally {
      for (const id of mine) {
        const deleted = await call(`${AID}delete_policy`, { ...scope, policy_id: id }, { quiet: true });
        if (deleted.ok) record(`AI Defense policy ${id} deleted`);
        const gone = await call(`${AID}get_policy`, { ...scope, policy_id: id }, { expectError: true, silent: true });
        check(/was deleted at/.test(gone.text), `deleted policy ${id} reads as deleted`);
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
