/**
 * Handler tests for the Sophos AI Defense tools (Policy and Activity GraphQL
 * APIs v1) through the real FusionClient with fetch stubbed: the request each
 * tool sends, the GraphQL 200 rule (errors with no data is an error, errors
 * beside data are warnings), not-found and deleted policies, the stale
 * version hint, the input checks that refuse before any call, and the
 * mutation no-retry rule. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { FusionClient } from "../dist/client/fusion-client.js";
import { registerFusionAiDefensePolicyTools } from "../dist/tools/fusion-ai-defense-policies.js";
import { registerFusionAiDefenseActivityTools } from "../dist/tools/fusion-ai-defense-activity.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const POLICY_ID = "7dc57312-fc7e-420a-a44d-8d84d0a9ca3b";
const OTHER_ID = "8da8b66e-37f6-4892-905c-285750366fef";
const ACTIVITY_ID = "event://priv:scwx.secureai:123456:1794048000000:5f0c2a9e-1d3b-4c7a-9e21-6a8b4d2c7f10";

function policy(overrides = {}) {
  return {
    id: POLICY_ID,
    tenantId: "123456",
    name: "ZZ test",
    description: null,
    priority: 1000,
    rank: 1,
    state: "DISABLED",
    enforcementStatus: "INACTIVE",
    origin: "CUSTOM",
    kind: "TENANT",
    partnerPolicyId: null,
    builtInKey: null,
    builtInVersion: null,
    rules: [
      {
        position: 0,
        target: { conditions: [{ dimension: "app", operator: "IN", values: ["chatgpt"] }] },
        action: "WARN",
        enforcementMechanismOverride: null,
        note: "probe",
        dataControls: null,
      },
    ],
    baseRule: { generativeAiCategoryAction: "ALLOW", appControlCategoryAction: null },
    sensors: { endpoint: { enabled: true, scope: { users: [] } }, firewall: null, dns: null, browser: null },
    tags: {},
    createdAt: "2026-11-07T11:00:00Z",
    updatedAt: "2026-11-07T11:00:00Z",
    createdBy: "u1",
    updatedBy: null,
    version: 3,
    ...overrides,
  };
}

const ok = (data) => ({ data });
const http = (status, body) => ({ status, body });

/**
 * Connects both AI Defense registrars on a real FusionClient. answer(operation,
 * variables, callNumber) returns a GraphQL body, or http(status, body).
 */
async function harness(answer = () => ok({})) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    const operation = /^(?:query|mutation) (\w+)/.exec(body.query)?.[1];
    calls.push({ url: String(url), headers: init.headers, operation, document: body.query, variables: body.variables });
    const reply = answer(operation, body.variables, calls.length) ?? ok({});
    const status = reply.status ?? 200;
    return new Response(JSON.stringify(reply.body ?? reply), { status, headers: { "Content-Type": "application/json" } });
  };
  const client = new FusionClient({ getToken: async () => "test-token" }, { url: "https://fusion.test/graphql", backoffBaseMs: 1 });
  const tenantResolver = { resolveTenantId: (id) => id ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFusionAiDefensePolicyTools(server, client, tenantResolver);
  registerFusionAiDefenseActivityTools(server, client, tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    async call(name, args = {}) {
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

async function withHarness(answer, run) {
  const h = await harness(answer);
  try {
    await run(h);
  } finally {
    await h.close();
  }
}

// --- Success paths and request shapes ---

test("list_policies sends the filter, page size and cursor, and reports the page", async () => {
  await withHarness(
    (operation) =>
      operation === "FusionAiDefensePolicies"
        ? ok({
            policies: {
              totalCount: 7,
              enabledCount: 2,
              failedCount: 0,
              pageInfo: { hasNextPage: true, endCursor: "MjAwMA==" },
              policies: [policy()],
            },
          })
        : undefined,
    async (h) => {
      const bare = await h.call("sophos_fusion_ai_defense_list_policies");
      assert.equal(bare.isError, false, bare.text);
      assert.deepEqual(h.calls[0].variables, { first: 50 }, "no filter key when nothing filters");
      assert.equal(h.calls[0].headers["X-Tenant-ID"], TENANT);
      assert.equal(bare.json.total, 7);
      assert.equal(bare.json.enabled_count, 2);
      assert.equal(bare.json.has_next_page, true);
      assert.equal(bare.json.end_cursor, "MjAwMA==");
      assert.equal(bare.json.policies[0].id, POLICY_ID);

      await h.call("sophos_fusion_ai_defense_list_policies", { kind: "TENANT", name_search: "ZZ", state: "ENABLED", limit: 2, after: "abc" });
      assert.deepEqual(h.calls[1].variables, {
        first: 2,
        after: "abc",
        filter: { state: "ENABLED", kind: "TENANT", nameSearch: "ZZ" },
      });
    }
  );
});

test("get_policy selects rule previews only when asked", async () => {
  await withHarness(
    () => ok({ policy: policy() }),
    async (h) => {
      const plain = await h.call("sophos_fusion_ai_defense_get_policy", { policy_id: POLICY_ID });
      assert.equal(plain.isError, false, plain.text);
      assert.equal(plain.json.policy.version, 3);
      assert.doesNotMatch(h.calls[0].document, /targetPreview/);
      assert.doesNotMatch(h.calls[0].document, /Subject/, "federated subjects are not selected");
      await h.call("sophos_fusion_ai_defense_get_policy", { policy_id: POLICY_ID, include_rule_previews: true });
      assert.match(h.calls[1].document, /targetPreviewV2 \{/);
      assert.doesNotMatch(h.calls[1].document, /targetPreview \{/, "the legacy preview is never selected");
    }
  );
});

test("create_policy maps rules without their read-only fields and sends the template pair", async () => {
  await withHarness(
    () => ok({ createPolicy: policy({ builtInKey: "education-v1", builtInVersion: 1 }) }),
    async (h) => {
      const rule = policy().rules[0];
      const result = await h.call("sophos_fusion_ai_defense_create_policy", {
        name: "ZZ test",
        rules: [{ ...rule, targetPreviewV2: { matchedCount: 1 } }],
        sensors: { endpoint: { enabled: true, scope: { users: [{ id: "u", name: "n" }] } } },
        tags: { env: "test" },
        built_in_key: "education-v1",
        built_in_version: 1,
      });
      assert.equal(result.isError, false, result.text);
      assert.equal(result.json.status, "created");
      const input = h.calls[0].variables.input;
      assert.equal(input.kind, "TENANT");
      assert.deepEqual(input.rules, [
        {
          target: { conditions: [{ dimension: "app", operator: "IN", values: ["chatgpt"] }] },
          action: "WARN",
          enforcementMechanismOverride: null,
          note: "probe",
          dataControls: null,
        },
      ]);
      assert.equal(input.builtInKey, "education-v1");
      assert.equal(input.builtInVersion, 1);
      assert.deepEqual(input.tags, { env: "test" });
      assert.equal("state" in input, false, "state left to the API default (DISABLED)");
    }
  );
});

test("update_policy sends only the fields given, with the version", async () => {
  await withHarness(
    () => ok({ updatePolicy: policy({ name: "renamed", version: 4 }) }),
    async (h) => {
      const result = await h.call("sophos_fusion_ai_defense_update_policy", {
        policy_id: POLICY_ID,
        version: "3",
        name: "renamed",
        base_rule: { appControlCategoryAction: null },
      });
      assert.equal(result.isError, false, result.text);
      assert.deepEqual(h.calls[0].variables, {
        id: POLICY_ID,
        input: { version: "3", name: "renamed", baseRule: { appControlCategoryAction: null } },
      });
      assert.equal(result.json.policy.version, 4);
    }
  );
});

test("move, reorder, enable, disable, clone and delete send their IDs", async () => {
  await withHarness(
    (operation) => {
      if (operation === "FusionAiDefenseReorderPolicies") return ok({ reorderPolicies: [OTHER_ID, POLICY_ID] });
      if (operation === "FusionAiDefenseDeletePolicy") return ok({ deletePolicy: true });
      const field = {
        FusionAiDefenseMovePolicy: "movePolicy",
        FusionAiDefenseEnablePolicy: "enablePolicy",
        FusionAiDefenseDisablePolicy: "disablePolicy",
        FusionAiDefenseClonePolicy: "clonePolicy",
      }[operation];
      return ok({ [field]: policy() });
    },
    async (h) => {
      await h.call("sophos_fusion_ai_defense_move_policy", { policy_id: POLICY_ID });
      assert.deepEqual(h.calls[0].variables, { id: POLICY_ID, afterId: null }, "omitted anchor moves to the top");
      await h.call("sophos_fusion_ai_defense_move_policy", { policy_id: POLICY_ID, after_policy_id: OTHER_ID });
      assert.deepEqual(h.calls[1].variables, { id: POLICY_ID, afterId: OTHER_ID });
      const reorder = await h.call("sophos_fusion_ai_defense_reorder_policies", { policy_ids: [OTHER_ID, POLICY_ID] });
      assert.deepEqual(h.calls[2].variables, { policyIds: [OTHER_ID, POLICY_ID] });
      assert.deepEqual(reorder.json.policy_ids, [OTHER_ID, POLICY_ID]);
      for (const name of ["enable_policy", "disable_policy", "clone_policy"]) {
        const result = await h.call(`sophos_fusion_ai_defense_${name}`, { policy_id: POLICY_ID });
        assert.equal(result.isError, false, result.text);
      }
      const deleted = await h.call("sophos_fusion_ai_defense_delete_policy", { policy_id: POLICY_ID });
      assert.deepEqual(deleted.json, { tenant_id: TENANT, status: "deleted", policy_id: POLICY_ID });
      assert.ok(h.calls.every((c) => c.url === "https://fusion.test/graphql"));
    }
  );
});

test("list_activities always sends a filter, so the documented today default applies, and never selects additionalData", async () => {
  await withHarness(
    () => ok({ activities: { totalCount: 578, pageInfo: { hasNextPage: true, endCursor: "c1" }, activities: [{ id: ACTIVITY_ID }] } }),
    async (h) => {
      const result = await h.call("sophos_fusion_ai_defense_list_activities");
      assert.equal(result.isError, false, result.text);
      assert.deepEqual(h.calls[0].variables, { filter: {}, sort: { field: "TIMESTAMP", order: "DESC" }, first: 20 });
      assert.doesNotMatch(h.calls[0].document, /additionalData/);
      assert.equal(result.json.total, 578);
      assert.equal(result.json.end_cursor, "c1");

      await h.call("sophos_fusion_ai_defense_list_activities", {
        time_range: "SINCE_BEGINNING_OF_WEEK_MONDAY",
        actions: ["BLOCKED"],
        application_ids: ["chatgpt"],
        is_unsanctioned: false,
        limit: 100,
        after: "c1",
      });
      assert.deepEqual(h.calls[1].variables.filter, {
        actions: ["BLOCKED"],
        applicationIds: ["chatgpt"],
        isUnsanctioned: false,
        timeRange: { relative: "SINCE_BEGINNING_OF_WEEK_MONDAY" },
      });
      assert.equal(h.calls[1].variables.first, 100);
      assert.equal(h.calls[1].variables.after, "c1");

      await h.call("sophos_fusion_ai_defense_list_activities", { start_time: "2026-11-01T00:00:00Z", end_time: "2026-11-02T00:00:00Z" });
      assert.deepEqual(h.calls[2].variables.filter.timeRange, { startTime: "2026-11-01T00:00:00Z", endTime: "2026-11-02T00:00:00Z" });
    }
  );
});

test("get_activity selects additionalData", async () => {
  await withHarness(
    () => ok({ activity: { id: ACTIVITY_ID, additionalData: { sourceAddresses: "192.0.2.10" } } }),
    async (h) => {
      const result = await h.call("sophos_fusion_ai_defense_get_activity", { activity_id: ACTIVITY_ID });
      assert.equal(result.isError, false, result.text);
      assert.match(h.calls[0].document, /additionalData/);
      assert.equal(result.json.activity.additionalData.sourceAddresses, "192.0.2.10");
    }
  );
});

test("the inventories page by offset and say where the next page starts", async () => {
  await withHarness(
    (operation) => {
      const page = { totalCount: 47, offset: 20, limit: 20, hasNextPage: true, entries: [{ id: "a" }, { id: "b" }] };
      if (operation === "FusionAiDefenseAppInventory") return ok({ appInventory: page });
      if (operation === "FusionAiDefenseUserInventory") return ok({ userInventory: page });
      if (operation === "FusionAiDefenseUserApps") return ok({ userApps: { ...page, hasNextPage: false } });
      return ok({ inventorySummary: { apps: { totalApps: 14 }, users: { totalUsers: 5 } } });
    },
    async (h) => {
      const apps = await h.call("sophos_fusion_ai_defense_list_app_inventory", { offset: 20, sort_by: "USAGE", risk_levels: ["CRITICAL"] });
      assert.equal(apps.isError, false, apps.text);
      assert.deepEqual(h.calls[0].variables, {
        filter: { riskLevels: ["CRITICAL"] },
        limit: 20,
        offset: 20,
        sort: { field: "USAGE", order: "DESC" },
      });
      assert.doesNotMatch(h.calls[0].document, /trainsOnUserData|complianceCertificates \}|trainingPolicy\b/, "fields the live API lacks are not selected");
      assert.equal(apps.json.next_offset, 22);
      assert.equal(apps.json.apps.length, 2);

      const users = await h.call("sophos_fusion_ai_defense_list_user_inventory", { used_app_ids: ["chatgpt"], time_range: "LAST_MONTH" });
      assert.deepEqual(h.calls[1].variables.filter, { usedAppIds: ["chatgpt"], timeRange: { relative: "LAST_MONTH" } });
      assert.equal("sort" in h.calls[1].variables, false, "no sort unless asked");
      assert.equal(users.json.users.length, 2);

      const userApps = await h.call("sophos_fusion_ai_defense_list_user_apps", { user_id: "u-1" });
      assert.equal(h.calls[2].variables.userId, "u-1");
      assert.deepEqual(h.calls[2].variables.filter, {});
      assert.equal(userApps.json.next_offset, null);
      assert.equal(userApps.json.user_id, "u-1");

      const summary = await h.call("sophos_fusion_ai_defense_inventory_summary", { time_range: "SINCE_BEGINNING_OF_YEAR" });
      assert.deepEqual(h.calls[3].variables, { filter: { timeRange: { relative: "SINCE_BEGINNING_OF_YEAR" } } });
      assert.equal(summary.json.summary.apps.totalApps, 14);
    }
  );
});

test("the policy reads and previews send their arguments", async () => {
  await withHarness(
    (operation) => {
      switch (operation) {
        case "FusionAiDefenseAppSanctioning":
          return ok({ appSanctioning: { entries: [{ appId: "nope", status: "NOT_COVERED", enforcementTargets: [] }] } });
        case "FusionAiDefensePreviewRuleTarget":
          return ok({ previewRuleTarget: { matchedCount: 9, effectiveCount: null } });
        case "FusionAiDefensePreviewRuleTargets":
          return ok({ previewRuleTargets: [{ matchedCount: 1, effectiveCount: 1 }] });
        case "FusionAiDefensePreviewPolicyImpact":
          return ok({ previewPolicyImpact: { totalApps: 55, blocked: 16, warned: 0, allowed: 39 } });
        case "FusionAiDefenseStarterTemplates":
        case "FusionAiDefenseStarterTemplatesWithImpact":
          return ok({ starterTemplates: [{ key: "education-v1" }] });
        case "FusionAiDefenseStarterTemplateWithImpact":
          return ok({ starterTemplate: { key: "education-v1", impact: { totalApps: 55 } } });
        case "FusionAiDefenseEnforcementMechanisms":
          return ok({ supportedEnforcementMechanisms: ["WEB_CONTROL", "APP_CONTROL"] });
        case "FusionAiDefensePolicyActivityMetrics":
          return ok({ secureAIPolicyActivityMetrics: { policiesWithActivityCount: 1 } });
        default:
          throw new Error(`unexpected ${operation}`);
      }
    },
    async (h) => {
      const sanction = await h.call("sophos_fusion_ai_defense_get_app_sanctioning", { app_ids: ["nope"] });
      assert.deepEqual(h.calls[0].variables, { appIds: ["nope"] });
      assert.equal(sanction.json.entries[0].status, "NOT_COVERED");
      const conditions = [{ dimension: "risk_level", operator: "IN", values: ["critical"] }];
      await h.call("sophos_fusion_ai_defense_preview_rule_target", { conditions, action: "BLOCK" });
      assert.deepEqual(h.calls[1].variables, { conditions, action: "BLOCK" });
      await h.call("sophos_fusion_ai_defense_preview_rule_targets", { rules: [{ conditions, action: "BLOCK", inEffect: false }] });
      assert.deepEqual(h.calls[2].variables, { rules: [{ conditions, action: "BLOCK", inEffect: false }] });
      const impact = await h.call("sophos_fusion_ai_defense_preview_impact", { rules: [{ target: { conditions }, action: "BLOCK" }] });
      assert.deepEqual(h.calls[3].variables, { rules: [{ target: { conditions }, action: "BLOCK" }] });
      assert.equal(impact.json.impact.blocked, 16);
      await h.call("sophos_fusion_ai_defense_list_templates");
      assert.doesNotMatch(h.calls[4].document, /impact/, "impact is opt-in on the list");
      await h.call("sophos_fusion_ai_defense_get_template", { key: "education-v1" });
      assert.match(h.calls[5].document, /impact \{/, "impact is on by default for one template");
      const mechanisms = await h.call("sophos_fusion_ai_defense_list_mechanisms");
      assert.deepEqual(mechanisms.json.mechanisms, ["WEB_CONTROL", "APP_CONTROL"]);
      await h.call("sophos_fusion_ai_defense_get_policy_activity");
      assert.deepEqual(h.calls[7].variables, {}, "omitted window leaves the API default");
      await h.call("sophos_fusion_ai_defense_get_policy_activity", { start_time: "2026-10-01T00:00:00Z" });
      assert.deepEqual(h.calls[8].variables, { timeFrame: { startTime: "2026-10-01T00:00:00Z" } });
    }
  );
});

test("settings: null record reads as none yet; an update sends the onboarding section and a confirmed base policy", async () => {
  let stored = null;
  await withHarness(
    (operation, variables) => {
      if (operation === "FusionAiDefenseTenantSettings") return ok({ secureAITenantSettings: stored });
      stored = { onboarding: { status: variables.input.onboarding.status, selections: null } };
      return ok({ updateSecureAITenantSettings: stored });
    },
    async (h) => {
      const none = await h.call("sophos_fusion_ai_defense_get_settings");
      assert.equal(none.isError, false, none.text);
      assert.equal(none.json.settings, null);
      assert.match(none.json.note, /onboarding has not been started/);

      const selections = { passedStepKeys: ["organization-details"], organizationDetails: { role: "it-administrator" } };
      const updated = await h.call("sophos_fusion_ai_defense_update_settings", { onboarding_status: "IN_PROGRESS", selections });
      assert.equal(updated.isError, false, updated.text);
      assert.deepEqual(h.calls[1].variables, { input: { onboarding: { status: "IN_PROGRESS", selections } } });

      await h.call("sophos_fusion_ai_defense_update_settings", {
        onboarding_status: "COMPLETED",
        selections,
        base_policy: { name: "Base", sensors: { endpoint: { enabled: true, scope: { type: "EVERYONE" } } } },
        confirm_base_policy: true,
      });
      assert.deepEqual(h.calls[2].variables.input.onboarding.basePolicy, {
        kind: "TENANT_BASE",
        state: "ENABLED",
        name: "Base",
        sensors: { endpoint: { enabled: true, scope: { type: "EVERYONE" } } },
        rules: [],
      });
    }
  );
});

// --- The GraphQL 200 rule ---

test("HTTP 200 with errors and no data is an error, sent once, with Sophos's message", async () => {
  await withHarness(
    () => ({
      errors: [
        {
          message: "at least one sensor must be enabled",
          path: ["createPolicy"],
          extensions: { serviceName: "secure-ai-policy", code: "DOWNSTREAM_SERVICE_ERROR" },
        },
      ],
      data: null,
    }),
    async (h) => {
      const result = await h.call("sophos_fusion_ai_defense_create_policy", { name: "ZZ test", sensors: {} });
      assert.equal(result.isError, true);
      assert.match(result.text, /at least one sensor must be enabled/);
      assert.equal(h.calls.length, 1, "a GraphQL-layer error is not retried");
    }
  );
});

test("errors beside usable data come back as warnings, never dropped", async () => {
  await withHarness(
    () => ({
      data: { activities: { totalCount: 1, pageInfo: { hasNextPage: false, endCursor: null }, activities: [{ id: ACTIVITY_ID }] } },
      errors: [{ message: "model lookup failed", path: ["activities", "activities", 0, "model"] }],
    }),
    async (h) => {
      const result = await h.call("sophos_fusion_ai_defense_list_activities");
      assert.equal(result.isError, false, result.text);
      assert.equal(result.json.activities.length, 1);
      assert.deepEqual(result.json.warnings, ["model lookup failed (path: activities.activities.0.model)"]);
    }
  );
});

test("an activities page whose rows all fail (additionalData null) is an error, not an empty page", async () => {
  await withHarness(
    () => ({
      errors: [
        {
          message: "the requested element is null which the schema does not allow",
          path: ["activities", "activities", 0, "additionalData"],
          extensions: { code: "DOWNSTREAM_SERVICE_ERROR" },
        },
      ],
      data: null,
    }),
    async (h) => {
      const result = await h.call("sophos_fusion_ai_defense_list_activities");
      assert.equal(result.isError, true);
      assert.match(result.text, /requested element is null/);
    }
  );
});

test("a mutation that gets a 5xx is not repeated", async () => {
  await withHarness(
    () => http(502, { error: "badGateway", message: "Bad Gateway" }),
    async (h) => {
      const result = await h.call("sophos_fusion_ai_defense_enable_policy", { policy_id: POLICY_ID });
      assert.equal(result.isError, true);
      assert.equal(h.calls.length, 1);
      assert.match(result.text, /may already have taken effect/);
    }
  );
});

// --- Not found ---

test("an unknown policy reads as not found, a deleted one as deleted with its time", async () => {
  await withHarness(
    (_operation, variables) =>
      variables.id === POLICY_ID
        ? { errors: [{ message: "policy not found", path: ["policy"], extensions: { code: "NOT_FOUND" } }], data: { policy: null } }
        : {
            errors: [
              { message: "policy not found", path: ["policy"], extensions: { code: "GONE", deletedAt: "2026-11-07T11:08:27.290477Z" } },
            ],
            data: { policy: null },
          },
    async (h) => {
      const missing = await h.call("sophos_fusion_ai_defense_get_policy", { policy_id: POLICY_ID });
      assert.equal(missing.isError, true);
      assert.match(missing.text, new RegExp(`AI Defense policy ${POLICY_ID} not found`));
      const gone = await h.call("sophos_fusion_ai_defense_get_policy", { policy_id: OTHER_ID });
      assert.equal(gone.isError, true);
      assert.match(gone.text, /was deleted at 2026-11-07T11:08:27.290477Z/);
      assert.match(gone.text, /cannot be undone/);
    }
  );
});

test("a write on an unknown policy names it, and a stale version says how to recover", async () => {
  await withHarness(
    (operation) =>
      operation === "FusionAiDefenseDeletePolicy"
        ? { errors: [{ message: "policy not found", path: ["deletePolicy"], extensions: { code: "DOWNSTREAM_SERVICE_ERROR" } }], data: null }
        : { errors: [{ message: "version conflict: policy has been modified", path: ["updatePolicy"] }], data: null },
    async (h) => {
      const deleted = await h.call("sophos_fusion_ai_defense_delete_policy", { policy_id: POLICY_ID });
      assert.equal(deleted.isError, true);
      assert.match(deleted.text, /not found\. List policies with sophos_fusion_ai_defense_list_policies/);
      const stale = await h.call("sophos_fusion_ai_defense_update_policy", { policy_id: POLICY_ID, version: 1, name: "x" });
      assert.equal(stale.isError, true);
      assert.match(stale.text, /version conflict/);
      assert.match(stale.text, /sophos_fusion_ai_defense_get_policy and pass its current version/);
    }
  );
});

test("an unknown activity ID and an unknown template read as not found", async () => {
  await withHarness(
    (operation) =>
      operation === "FusionAiDefenseActivity"
        ? {
            errors: [{ message: "input: failed to retrieve activity", path: ["activity"], extensions: { code: "DOWNSTREAM_SERVICE_ERROR" } }],
            data: { activity: null },
          }
        : ok({ starterTemplate: null }),
    async (h) => {
      const activity = await h.call("sophos_fusion_ai_defense_get_activity", { activity_id: ACTIVITY_ID });
      assert.equal(activity.isError, true);
      assert.match(activity.text, /could not retrieve activity .*no activity with that ID on this tenant/);
      assert.equal(h.calls.length, 1, "not retried");
      const template = await h.call("sophos_fusion_ai_defense_get_template", { key: "no-such-template" });
      assert.equal(template.isError, true);
      assert.match(template.text, /No AI Defense starter template with key no-such-template/);
    }
  );
});

// --- Input checks that refuse before any call ---

test("bad input is refused before anything is sent", async () => {
  await withHarness(undefined, async (h) => {
    const refused = [
      ["sophos_fusion_ai_defense_get_policy", { policy_id: "nope" }, /policy_id|guid|uuid/i],
      ["sophos_fusion_ai_defense_list_policies", { limit: 101 }, /limit|100/],
      ["sophos_fusion_ai_defense_list_activities", { limit: 500 }, /limit|100/],
      [
        "sophos_fusion_ai_defense_list_activities",
        { time_range: "SINCE_BEGINNING_OF_DAY", start_time: "2026-11-01T00:00:00Z" },
        /time_range or start_time\/end_time, not both/,
      ],
      ["sophos_fusion_ai_defense_list_activities", { start_time: "yesterday" }, /ISO 8601/],
      ["sophos_fusion_ai_defense_get_activity", { activity_id: "garbage" }, /event:\/\//],
      [
        "sophos_fusion_ai_defense_create_policy",
        { name: "ZZ", sensors: { endpoint: { enabled: true } }, tags: { n: 1 } },
        /tags|string/i,
      ],
      [
        "sophos_fusion_ai_defense_create_policy",
        { name: "ZZ", sensors: { endpoint: { enabled: true, scope: { type: "EVERYONE" } } }, kind: "TENANT_BASE" },
        /confirm_base_policy true/,
      ],
      [
        "sophos_fusion_ai_defense_create_policy",
        { name: "ZZ", sensors: { endpoint: { enabled: true } }, built_in_key: "education-v1" },
        /built_in_key and built_in_version go together/,
      ],
      [
        "sophos_fusion_ai_defense_create_policy",
        { name: "ZZ", sensors: { endpoint: { enabled: true } }, rules: [{ target: { conditions: [] }, action: "BLOCK", dataControl: {} }] },
        /dataControl|unrecognized/i,
      ],
      ["sophos_fusion_ai_defense_create_policy", { name: "ZZ", sensors: { edr: { enabled: true } } }, /edr|unrecognized/i],
      ["sophos_fusion_ai_defense_update_policy", { policy_id: POLICY_ID, version: 3 }, /Nothing to update/],
      ["sophos_fusion_ai_defense_update_policy", { policy_id: POLICY_ID, name: "x" }, /version/],
      ["sophos_fusion_ai_defense_update_policy", { policy_id: POLICY_ID, version: "v3", name: "x" }, /version|whole number/],
      ["sophos_fusion_ai_defense_reorder_policies", { policy_ids: [POLICY_ID, POLICY_ID] }, /repeats an ID/],
      ["sophos_fusion_ai_defense_get_app_sanctioning", { app_ids: [] }, /app_ids|least/i],
      [
        "sophos_fusion_ai_defense_preview_rule_target",
        { conditions: [{ dimension: "app", operator: "NOT_IN", values: ["x"] }], action: "BLOCK" },
        /operator|IN/,
      ],
      [
        "sophos_fusion_ai_defense_update_settings",
        { onboarding_status: "IN_PROGRESS", selections: {}, base_policy: { name: "Base", sensors: {} }, confirm_base_policy: true },
        /only with onboarding_status COMPLETED/,
      ],
      [
        "sophos_fusion_ai_defense_update_settings",
        { onboarding_status: "COMPLETED", selections: {}, base_policy: { name: "Base", sensors: {} } },
        /confirm_base_policy true/,
      ],
      ["sophos_fusion_ai_defense_update_settings", { onboarding_status: "DONE", selections: {} }, /onboarding_status|NOT_STARTED/],
      // An update with no selections clears organizationDetails and productIntegration (measured), so it is refused
      ["sophos_fusion_ai_defense_update_settings", { onboarding_status: "COMPLETED" }, /selections/],
      [
        "sophos_fusion_ai_defense_update_settings",
        { onboarding_status: "COMPLETED", selections: { organizationDetails: { title: "x" } } },
        /title|unrecognized/i,
      ],
      ["sophos_fusion_ai_defense_list_user_apps", {}, /user_id/],
    ];
    for (const [name, args, pattern] of refused) {
      const result = await h.call(name, args);
      assert.equal(result.isError, true, `${name} ${JSON.stringify(args)} is refused`);
      assert.match(result.text, pattern, `${name} ${JSON.stringify(args)}: ${result.text}`);
    }
    assert.equal(h.calls.length, 0, "nothing reached Sophos");
  });
});
