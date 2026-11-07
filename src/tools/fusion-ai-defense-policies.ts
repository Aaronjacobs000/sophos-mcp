/**
 * Tools: sophos_fusion_ai_defense_list_policies, sophos_fusion_ai_defense_get_policy,
 *        sophos_fusion_ai_defense_get_app_sanctioning,
 *        sophos_fusion_ai_defense_preview_rule_target, sophos_fusion_ai_defense_preview_rule_targets,
 *        sophos_fusion_ai_defense_preview_impact,
 *        sophos_fusion_ai_defense_list_templates, sophos_fusion_ai_defense_get_template,
 *        sophos_fusion_ai_defense_list_mechanisms, sophos_fusion_ai_defense_get_policy_activity,
 *        sophos_fusion_ai_defense_create_policy, sophos_fusion_ai_defense_update_policy,
 *        sophos_fusion_ai_defense_delete_policy, sophos_fusion_ai_defense_enable_policy,
 *        sophos_fusion_ai_defense_disable_policy, sophos_fusion_ai_defense_move_policy,
 *        sophos_fusion_ai_defense_reorder_policies, sophos_fusion_ai_defense_clone_policy
 * Sophos AI Defense Policy GraphQL API v1 on https://api.taegis.sophos.com/graphql
 * (released 15/10/2026).
 *
 * Policies are evaluated by priority (rank 1 first), rules top to bottom
 * within a policy, and the first matching rule wins. Every rule below about
 * scope, versions, ordering and naming was measured on live tenants 07/11/2026.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { FusionClient } from "../client/fusion-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import {
  AI_DEFENSE_MAX_PAGE,
  DESTRUCTIVE,
  POLICY_ACTIONS,
  READ_ONLY,
  WRITE,
  baseRuleSchema,
  buildTimeRange,
  conditionSchema,
  policyIdField,
  rethrowPolicyError,
  ruleSchema,
  sensorsSchema,
  tagsSchema,
  tenantIdField,
  timeRangeFields,
  toRuleInput,
} from "../fusion/ai-defense.js";
import {
  AI_DEFENSE_APP_SANCTIONING,
  AI_DEFENSE_CLONE_POLICY,
  AI_DEFENSE_CREATE_POLICY,
  AI_DEFENSE_DELETE_POLICY,
  AI_DEFENSE_DISABLE_POLICY,
  AI_DEFENSE_ENABLE_POLICY,
  AI_DEFENSE_ENFORCEMENT_MECHANISMS,
  AI_DEFENSE_MOVE_POLICY,
  AI_DEFENSE_POLICIES,
  AI_DEFENSE_POLICY,
  AI_DEFENSE_POLICY_ACTIVITY_METRICS,
  AI_DEFENSE_POLICY_WITH_PREVIEWS,
  AI_DEFENSE_PREVIEW_POLICY_IMPACT,
  AI_DEFENSE_PREVIEW_RULE_TARGET,
  AI_DEFENSE_PREVIEW_RULE_TARGETS,
  AI_DEFENSE_REORDER_POLICIES,
  AI_DEFENSE_STARTER_TEMPLATE,
  AI_DEFENSE_STARTER_TEMPLATES,
  AI_DEFENSE_STARTER_TEMPLATES_WITH_IMPACT,
  AI_DEFENSE_STARTER_TEMPLATE_WITH_IMPACT,
  AI_DEFENSE_UPDATE_POLICY,
} from "../fusion/queries/ai-defense-policy.js";
import type { AiDefensePoliciesResponse, AiDefensePolicy } from "../fusion/types.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";

const RULES_NOTE =
  "Rules run top to bottom and the first match wins. Each is { target: { conditions: [{ dimension, operator, values }] }, action: BLOCK|WARN|ALLOW, enforcementMechanismOverride?, note?, dataControls? }, in the shape sophos_fusion_ai_defense_get_policy returns, so a rule read back can be sent back (position and previews are ignored). Dimensions seen: app, category, risk_level, compliance, training_policies, with lower-case values such as 'chatgpt', 'general_assistant', 'critical', 'soc2_type2', 'trains_on_input'. A misspelled dimension or value matches nothing and raises no error, so check a rule with sophos_fusion_ai_defense_preview_rule_target first. Empty conditions match every application (a catch-all).";

const SCOPE_NOTE =
  "At least one sensor must be enabled. An enabled ordinary policy needs an Endpoint scope naming users, user groups, devices or device groups: an empty Endpoint scope means everyone, and only the base policy may apply to everyone, so enabling one is refused.";

const versionField = z
  .union([z.number().int().min(0), z.string().regex(/^\d+$/, "a whole number")])
  .describe("The policy's current version, from the last read or write. Every write raises it, enable and disable included");

const policyStateField = z.enum(["ENABLED", "DISABLED"]);

/** A list or mutation result: the policy as returned, plus the tenant. */
function policyResult(tenantId: string, policy: AiDefensePolicy, warnings: string[], extra: Record<string, unknown> = {}) {
  return withWarnings({ tenant_id: tenantId, ...extra, policy }, warnings);
}

export function registerFusionAiDefensePolicyTools(
  server: McpServer,
  client: FusionClient,
  tenantResolver: TenantResolver
): void {
  // --- List Policies ---
  server.registerTool(
    "sophos_fusion_ai_defense_list_policies",
    {
      title: "List AI Defense Policies",
      description: `List Sophos AI Defense policies in priority order (rank 1 is evaluated first), with their rules, base rule, sensors and scope.

Each policy has a kind (TENANT, or TENANT_BASE for the one catch-all base policy, which sits last and can't be disabled, deleted, cloned or moved), an origin (CUSTOM, BUILT_IN from a starter template, PARTNER and read-only), a state (ENABLED or DISABLED) and a computed enforcementStatus (INACTIVE, PENDING, ENFORCED, FAILED). version is the concurrency token sophos_fusion_ai_defense_update_policy needs. Ranks are tenant wide, so a filtered list can skip numbers.

Args:
  - state (string, optional): ENABLED or DISABLED.
  - origin (string, optional): CUSTOM, BUILT_IN or PARTNER.
  - kind (string, optional): TENANT lists exactly the policies sophos_fusion_ai_defense_reorder_policies needs.
  - search (string, optional): Text in the name or description. name_search (string, optional): text in the name only.
  - limit (number, optional): 1 to 100, default 50.
  - after (string, optional): end_cursor from the previous page.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  total, enabled_count and failed_count (whole filtered set), has_next_page, end_cursor, and policies as the API returns them.`,
      inputSchema: {
        state: policyStateField.optional().describe("ENABLED or DISABLED"),
        origin: z.enum(["CUSTOM", "BUILT_IN", "PARTNER"]).optional().describe("Who created the policy"),
        kind: z.enum(["TENANT", "TENANT_BASE"]).optional().describe("TENANT or TENANT_BASE"),
        search: z.string().min(1).optional().describe("Text in the name or description"),
        name_search: z.string().min(1).optional().describe("Text in the name only"),
        limit: z.number().int().min(1).max(AI_DEFENSE_MAX_PAGE).optional().default(50).describe("Policies per page (1-100, default 50)"),
        after: z.string().optional().describe("end_cursor from the previous page"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const filter: Record<string, unknown> = {};
      if (args.state) filter.state = args.state;
      if (args.origin) filter.origin = args.origin;
      if (args.kind) filter.kind = args.kind;
      if (args.search) filter.search = args.search;
      if (args.name_search) filter.nameSearch = args.name_search;
      const variables: Record<string, unknown> = { first: args.limit };
      if (Object.keys(filter).length > 0) variables.filter = filter;
      if (args.after) variables.after = args.after;
      const { data, warnings } = await client.query<AiDefensePoliciesResponse>(tenantId, AI_DEFENSE_POLICIES, variables);
      const page = data.policies;
      return jsonResult(
        withWarnings(
          {
            tenant_id: tenantId,
            total: page.totalCount,
            enabled_count: page.enabledCount,
            failed_count: page.failedCount,
            has_next_page: page.pageInfo.hasNextPage,
            end_cursor: page.pageInfo.endCursor,
            policies: page.policies,
          },
          warnings
        ),
        { after: args.after, limit: args.limit },
        "policies"
      );
    })
  );

  // --- Get Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_get_policy",
    {
      title: "Get AI Defense Policy",
      description: `Get one Sophos AI Defense policy by ID: rules, base rule, sensors and scope, state, enforcement status and version.

include_rule_previews adds each rule's targetPreviewV2: how many catalog applications the rule matches, how many it actually acts on after the rules above it (effectiveCount, set only when effectiveReachStatus is DETERMINED), up to 5 of them, risk counts, warnings and the web control domains and app control applications it enforces. It costs a catalog lookup per rule, so it is off by default.

A deleted policy reads as deleted with its deletion time; deletion cannot be undone.

Args:
  - policy_id (string): Policy UUID.
  - include_rule_previews (boolean, optional): Add each rule's matched applications. Default false.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The policy as the API returns it.`,
      inputSchema: {
        policy_id: policyIdField.describe("Policy UUID"),
        include_rule_previews: z.boolean().optional().default(false).describe("Add each rule's targetPreviewV2"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ policy_id, include_rule_previews, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<{ policy: AiDefensePolicy | null }>(
          tenantId,
          include_rule_previews ? AI_DEFENSE_POLICY_WITH_PREVIEWS : AI_DEFENSE_POLICY,
          { id: policy_id }
        )
        .catch(rethrowPolicyError(policy_id));
      if (!data.policy) throw new Error(`AI Defense policy ${policy_id} not found.`);
      return jsonResult(policyResult(tenantId, data.policy, warnings));
    })
  );

  // --- App Sanctioning ---
  server.registerTool(
    "sophos_fusion_ai_defense_get_app_sanctioning",
    {
      title: "Get AI Defense App Sanctioning",
      description: `Get the sanctioning status the tenant's Sophos AI Defense policies give each AI application: APPROVED, BLOCKED, WARNED or NOT_COVERED.

The status is scope agnostic: the first matching rule across all policies by priority decides it, and sensor scope is ignored, so it says what the policies say about the app, not what a given user sees. enforcementTargets breaks it down per enforcement identity: the web control site and each app control application (for example ChatGPT's desktop app), each with its own status, the policy and rule position that set it, and when it was computed. App IDs are catalog slugs such as chatgpt, claude or microsoft-copilot (from sophos_fusion_ai_defense_list_app_inventory or an activity's application.id). An unknown ID comes back NOT_COVERED, so a typo reads as uncovered.

Args:
  - app_ids (string[]): 1 to 100 catalog application IDs.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  entries: appId, status and enforcementTargets (mechanism, applicationId, applicationName, status, matchedPolicy, matchedRulePosition, computedAt).`,
      inputSchema: {
        app_ids: z.array(z.string().min(1)).min(1).max(100).describe("Catalog application IDs, e.g. ['chatgpt', 'claude']"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ app_ids, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ appSanctioning: { entries: unknown[] } }>(
        tenantId,
        AI_DEFENSE_APP_SANCTIONING,
        { appIds: app_ids }
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, entries: data.appSanctioning.entries }, warnings), {
        narrow_with: ["app_ids"],
      });
    })
  );

  // --- Preview Rule Target ---
  server.registerTool(
    "sophos_fusion_ai_defense_preview_rule_target",
    {
      title: "Preview AI Defense Rule Target",
      description: `Preview which catalog AI applications one Sophos AI Defense rule's conditions match, before saving it. Works on unsaved rules and ignores every other rule and policy.

Returns matchedCount, up to 500 matched applications sorted by name (topApps), their risk counts, warnings, and the concrete enforcement: web control domains and app control applications. effectiveCount is always null here; for a rule's reach after the rules above it, use sophos_fusion_ai_defense_preview_rule_targets. Conditions are ANDed, values within one are ORed. A misspelled dimension or value matches nothing (matchedCount 0) with no error. Example: [{ dimension: "risk_level", operator: "IN", values: ["critical"] }] matched 9 applications in testing.

Args:
  - conditions (object[]): { dimension, operator: IN|MISSING_ANY, values }. Empty matches every application.
  - action (string): BLOCK, WARN or ALLOW. Shapes the warnings.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The preview: matchedCount, effectiveCount, topApps, riskCounts, warnings, enforcementImpact.`,
      inputSchema: {
        conditions: z.array(conditionSchema).describe("Target conditions, ANDed"),
        action: z.enum(POLICY_ACTIONS).describe("BLOCK, WARN or ALLOW"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ conditions, action, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ previewRuleTarget: Record<string, unknown> }>(
        tenantId,
        AI_DEFENSE_PREVIEW_RULE_TARGET,
        { conditions, action }
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, preview: data.previewRuleTarget }, warnings));
    })
  );

  // --- Preview Rule Targets ---
  server.registerTool(
    "sophos_fusion_ai_defense_preview_rule_targets",
    {
      title: "Preview AI Defense Rule Sequence",
      description: `Preview an ordered Sophos AI Defense rule sequence as a unit: for each rule, the applications it matches and the ones it actually acts on once earlier rules have claimed theirs (first match wins).

Only the rules you send count; saved policies never affect the result. previews[i] describes rules[i]. effectiveCount is null when a rule above could not be resolved against the catalog. Each preview lists at most 5 applications; for the full list of one rule use sophos_fusion_ai_defense_preview_rule_target. Set inEffect false on a rule still being written so it claims nothing from the rules below it.

Args:
  - rules (object[]): 1 to 100 of { conditions, action, inEffect? (default true) }.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  previews, one per rule in order: matchedCount, effectiveCount, topApps, riskCounts, warnings, enforcementImpact.`,
      inputSchema: {
        rules: z
          .array(
            z.strictObject({
              conditions: z.array(conditionSchema),
              action: z.enum(POLICY_ACTIONS),
              inEffect: z.boolean().optional().describe("false: preview it but let it claim no applications. Default true"),
            })
          )
          .min(1)
          .max(100)
          .describe("Ordered rules"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ rules, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ previewRuleTargets: unknown[] }>(
        tenantId,
        AI_DEFENSE_PREVIEW_RULE_TARGETS,
        { rules }
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, previews: data.previewRuleTargets }, warnings), {
        narrow_with: ["rules"],
      });
    })
  );

  // --- Preview Policy Impact ---
  server.registerTool(
    "sophos_fusion_ai_defense_preview_impact",
    {
      title: "Preview AI Defense Policy Impact",
      description: `Count how many catalog AI applications an ordered Sophos AI Defense rule list would block, warn on and allow, first match wins. Check a template, a new policy or an edit before saving.

Version 1 evaluates against the whole catalog (55 applications in testing), not the applications seen on the tenant, and ignores the base rule. Applications no rule matches count as allowed.

Args:
  - rules (object[]): The rules, in order. ${RULES_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  impact: totalApps, blocked, warned, allowed.`,
      inputSchema: {
        rules: z.array(ruleSchema).max(500).describe("Ordered rules, as sophos_fusion_ai_defense_get_policy returns them"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ rules, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ previewPolicyImpact: Record<string, unknown> }>(
        tenantId,
        AI_DEFENSE_PREVIEW_POLICY_IMPACT,
        { rules: rules.map(toRuleInput) }
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, impact: data.previewPolicyImpact }, warnings));
    })
  );

  // --- List Starter Templates ---
  server.registerTool(
    "sophos_fusion_ai_defense_list_templates",
    {
      title: "List AI Defense Starter Templates",
      description: `List the Sophos AI Defense starter templates that Sophos ships: industry policy presets with ordered rules (each with a note saying why), default sensors and a base rule. The same on every tenant.

To create a policy from one, pass its rules and baseRule to sophos_fusion_ai_defense_create_policy with built_in_key set to the template key and built_in_version to its version, and set the sensors and scope yourself (the default sensors carry an empty scope). Three templates in testing: healthcare-v1, financial-legal-v1 and education-v1.

Args:
  - include_impact (boolean, optional): Add each template's block, warn and allow counts against the catalog. Default false.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  templates: key, name, description, recommended, version, rules, defaultSensors, baseRule, and impact when asked.`,
      inputSchema: {
        include_impact: z.boolean().optional().default(false).describe("Add impact counts"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ include_impact, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ starterTemplates: unknown[] }>(
        tenantId,
        include_impact ? AI_DEFENSE_STARTER_TEMPLATES_WITH_IMPACT : AI_DEFENSE_STARTER_TEMPLATES
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, templates: data.starterTemplates }, warnings), {
        narrow_with: [],
        note: "Read one template at a time with sophos_fusion_ai_defense_get_template.",
      });
    })
  );

  // --- Get Starter Template ---
  server.registerTool(
    "sophos_fusion_ai_defense_get_template",
    {
      title: "Get AI Defense Starter Template",
      description: `Get one Sophos AI Defense starter template by key, with its impact against the current catalog (blocked, warned, allowed).

Args:
  - key (string): Template key, e.g. education-v1 (from sophos_fusion_ai_defense_list_templates).
  - include_impact (boolean, optional): Default true.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The template: key, name, description, recommended, version, rules, defaultSensors, baseRule, impact.`,
      inputSchema: {
        key: z.string().min(1).describe("Template key"),
        include_impact: z.boolean().optional().default(true).describe("Add impact counts"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ key, include_impact, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ starterTemplate: Record<string, unknown> | null }>(
        tenantId,
        include_impact ? AI_DEFENSE_STARTER_TEMPLATE_WITH_IMPACT : AI_DEFENSE_STARTER_TEMPLATE,
        { key }
      );
      if (!data.starterTemplate) {
        throw new Error(`No AI Defense starter template with key ${key}. List them with sophos_fusion_ai_defense_list_templates.`);
      }
      return jsonResult(withWarnings({ tenant_id: tenantId, template: data.starterTemplate }, warnings));
    })
  );

  // --- Supported Enforcement Mechanisms ---
  server.registerTool(
    "sophos_fusion_ai_defense_list_mechanisms",
    {
      title: "List AI Defense Enforcement Mechanisms",
      description: `List the enforcement mechanisms Sophos AI Defense compiles policies to: WEB_CONTROL (browser enforcement by site) and APP_CONTROL (application enforcement), the two seen in testing.

These are the values a rule's enforcementMechanismOverride takes.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  mechanisms: the list.`,
      inputSchema: { tenant_id: tenantIdField },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ supportedEnforcementMechanisms: string[] }>(
        tenantId,
        AI_DEFENSE_ENFORCEMENT_MECHANISMS
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, mechanisms: data.supportedEnforcementMechanisms }, warnings));
    })
  );

  // --- Policy Activity Metrics ---
  server.registerTool(
    "sophos_fusion_ai_defense_get_policy_activity",
    {
      title: "Get AI Defense Policy Activity",
      description: `Report which enabled Sophos AI Defense policies matched any AI activity in a window, which matched none, and which blocked the most.

Use it to find enabled policies that never fire. The window defaults to since Sunday 00:00 UTC (SINCE_BEGINNING_OF_WEEK_SUNDAY).

Args:
  - time_range (string, optional): Relative window, e.g. SINCE_BEGINNING_OF_MONTH. Not with start_time or end_time.
  - start_time, end_time (string, optional): Absolute window, ISO 8601.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  metrics: policiesWithActivityCount, policiesWithoutActivityCount, policiesWithoutActivityIds, windowStart, windowEnd, mostBlockedPolicy (policyId, blockedCount).`,
      inputSchema: { ...timeRangeFields, tenant_id: tenantIdField },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const timeFrame = buildTimeRange(args);
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const { data, warnings } = await client.query<{ secureAIPolicyActivityMetrics: Record<string, unknown> }>(
        tenantId,
        AI_DEFENSE_POLICY_ACTIVITY_METRICS,
        timeFrame ? { timeFrame } : {}
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, metrics: data.secureAIPolicyActivityMetrics }, warnings));
    })
  );

  // --- Create Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_create_policy",
    {
      title: "Create AI Defense Policy",
      description: `Create a Sophos AI Defense policy. It is created DISABLED, at the top of the priority order (rank 1), unless state is ENABLED.

${SCOPE_NOTE} Tag values must be strings.

${RULES_NOTE}

From a starter template: copy its rules and baseRule (sophos_fusion_ai_defense_get_template), set built_in_key and built_in_version, and supply the sensors and scope.

kind TENANT_BASE creates the tenant's catch-all base policy instead: ENABLED, Endpoint scope { "type": "EVERYONE" }, pinned last. It can't be disabled, deleted, cloned or moved afterwards, so it needs confirm_base_policy true. A tenant has one; a repeat returns the existing one unchanged.

Args:
  - name (string): Policy name.
  - description (string, optional).
  - rules (object[], optional): Ordered rules. Default none; the base rule still applies.
  - sensors (object): { endpoint?, firewall?, dns?, browser? }, each { enabled, scope }.
  - base_rule (object, optional): { generativeAiCategoryAction?, appControlCategoryAction? }.
  - tags (object, optional): String to string labels.
  - state (string, optional): ENABLED or DISABLED. Default DISABLED.
  - built_in_key, built_in_version (optional): Template key and version, together.
  - kind (string, optional): TENANT (default) or TENANT_BASE.
  - confirm_base_policy (boolean, optional): Must be true for kind TENANT_BASE.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The created policy, with its id and version.`,
      inputSchema: {
        name: z.string().min(1).describe("Policy name"),
        description: z.string().optional().describe("Policy description"),
        rules: z.array(ruleSchema).max(500).optional().default([]).describe("Ordered rules"),
        sensors: sensorsSchema,
        base_rule: baseRuleSchema.optional(),
        tags: tagsSchema.optional(),
        state: policyStateField.optional().describe("ENABLED or DISABLED. Default DISABLED"),
        built_in_key: z.string().min(1).optional().describe("Starter template key"),
        built_in_version: z.number().int().min(0).optional().describe("Starter template version"),
        kind: z.enum(["TENANT", "TENANT_BASE"]).optional().default("TENANT").describe("TENANT or TENANT_BASE"),
        confirm_base_policy: z
          .boolean()
          .optional()
          .describe("Must be true for kind TENANT_BASE: the base policy can't be disabled or deleted afterwards"),
        tenant_id: tenantIdField,
      },
      annotations: WRITE,
    },
    withErrorHandling(async (args) => {
      if (args.kind === "TENANT_BASE" && args.confirm_base_policy !== true) {
        throw new Error(
          "kind TENANT_BASE creates the tenant's base policy, which can't be disabled, deleted, cloned or moved afterwards. Re-run with confirm_base_policy true to proceed."
        );
      }
      if ((args.built_in_key === undefined) !== (args.built_in_version === undefined)) {
        throw new Error("built_in_key and built_in_version go together: pass both (the template key and its version) or neither.");
      }
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const input: Record<string, unknown> = {
        kind: args.kind,
        name: args.name,
        rules: args.rules.map(toRuleInput),
        sensors: args.sensors,
      };
      if (args.description !== undefined) input.description = args.description;
      if (args.base_rule !== undefined) input.baseRule = args.base_rule;
      if (args.tags !== undefined) input.tags = args.tags;
      if (args.state !== undefined) input.state = args.state;
      if (args.built_in_key !== undefined) {
        input.builtInKey = args.built_in_key;
        input.builtInVersion = args.built_in_version;
      }
      const { data, warnings } = await client.query<{ createPolicy: AiDefensePolicy | null }>(
        tenantId,
        AI_DEFENSE_CREATE_POLICY,
        { input }
      );
      if (!data.createPolicy) throw new Error("createPolicy returned no policy.");
      return jsonResult(policyResult(tenantId, data.createPolicy, warnings, { status: "created" }));
    })
  );

  // --- Update Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_update_policy",
    {
      title: "Update AI Defense Policy",
      description: `Change a Sophos AI Defense policy's name, description, rules, base rule, sensors or tags. Only the fields you pass change, but rules and tags replace the whole list or map.

WARNING: rules replaces every rule (pass the complete ordered list; an empty list removes them all) and tags replaces every tag. Read the policy first and send back what you keep. base_rule is partial: an omitted field keeps its value, and appControlCategoryAction null clears it. ${SCOPE_NOTE} A partner policy is read-only. Use the enable, disable and move tools for state and order.

version is required and must be the current one; a stale version is refused ("version conflict: policy has been modified"). Every write raises the version, enable and disable included, so read it again after one.

${RULES_NOTE}

Args:
  - policy_id (string): Policy UUID.
  - version (number|string): Current version.
  - name, description (string, optional).
  - rules (object[], optional): Complete replacement list.
  - base_rule (object, optional): Partial.
  - sensors (object, optional): { endpoint?, firewall?, dns?, browser? }.
  - tags (object, optional): Complete replacement map.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The updated policy with its new version.`,
      inputSchema: {
        policy_id: policyIdField.describe("Policy UUID"),
        version: versionField,
        name: z.string().min(1).optional().describe("New name"),
        description: z.string().optional().describe("New description"),
        rules: z.array(ruleSchema).max(500).optional().describe("Complete replacement rule list"),
        base_rule: baseRuleSchema.optional(),
        sensors: sensorsSchema.optional(),
        tags: tagsSchema.optional().describe("Complete replacement tag map, string values only"),
        tenant_id: tenantIdField,
      },
      annotations: DESTRUCTIVE,
    },
    withErrorHandling(async (args) => {
      const input: Record<string, unknown> = { version: args.version };
      if (args.name !== undefined) input.name = args.name;
      if (args.description !== undefined) input.description = args.description;
      if (args.rules !== undefined) input.rules = args.rules.map(toRuleInput);
      if (args.base_rule !== undefined) input.baseRule = args.base_rule;
      if (args.sensors !== undefined) input.sensors = args.sensors;
      if (args.tags !== undefined) input.tags = args.tags;
      if (Object.keys(input).length === 1) {
        throw new Error("Nothing to update: pass at least one of name, description, rules, base_rule, sensors or tags.");
      }
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const { data, warnings } = await client
        .query<{ updatePolicy: AiDefensePolicy | null }>(tenantId, AI_DEFENSE_UPDATE_POLICY, {
          id: args.policy_id,
          input,
        })
        .catch(rethrowPolicyError(args.policy_id));
      if (!data.updatePolicy) throw new Error("updatePolicy returned no policy.");
      return jsonResult(policyResult(tenantId, data.updatePolicy, warnings, { status: "updated" }));
    })
  );

  // --- Delete Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_delete_policy",
    {
      title: "Delete AI Defense Policy",
      description: `Delete a Sophos AI Defense policy and tear its enforcement down on every sensor. Cannot be undone: the API has no restore, and the policy then reads as deleted.

The base policy (kind TENANT_BASE) and partner policies cannot be deleted. To stop enforcing a policy but keep it, use sophos_fusion_ai_defense_disable_policy.

Args:
  - policy_id (string): Policy UUID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status deleted and the policy_id.`,
      inputSchema: {
        policy_id: policyIdField.describe("Policy UUID"),
        tenant_id: tenantIdField,
      },
      annotations: DESTRUCTIVE,
    },
    withErrorHandling(async ({ policy_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<{ deletePolicy: boolean | null }>(tenantId, AI_DEFENSE_DELETE_POLICY, { id: policy_id })
        .catch(rethrowPolicyError(policy_id));
      if (data.deletePolicy !== true) throw new Error(`deletePolicy returned ${String(data.deletePolicy)} for ${policy_id}.`);
      return jsonResult(withWarnings({ tenant_id: tenantId, status: "deleted", policy_id }, warnings));
    })
  );

  // --- Enable Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_enable_policy",
    {
      title: "Enable AI Defense Policy",
      description: `Enable a Sophos AI Defense policy and start distributing it to its configured sensors, so its rules are enforced on the users and devices in its scope.

An ordinary policy whose Endpoint scope is empty (everyone) is refused: only the base policy may apply to everyone. enforcementStatus is computed from the distribution and moves after the call (ENFORCED at once, FAILED five seconds later on a test policy scoped to a user that does not exist), so read it back with sophos_fusion_ai_defense_get_policy. Enabling raises the version even when the policy was already enabled.

Args:
  - policy_id (string): Policy UUID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The policy, state ENABLED, with its new version.`,
      inputSchema: {
        policy_id: policyIdField.describe("Policy UUID"),
        tenant_id: tenantIdField,
      },
      annotations: { ...WRITE, idempotentHint: true },
    },
    withErrorHandling(async ({ policy_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<{ enablePolicy: AiDefensePolicy | null }>(tenantId, AI_DEFENSE_ENABLE_POLICY, { id: policy_id })
        .catch(rethrowPolicyError(policy_id));
      if (!data.enablePolicy) throw new Error("enablePolicy returned no policy.");
      return jsonResult(policyResult(tenantId, data.enablePolicy, warnings, { status: "enabled" }));
    })
  );

  // --- Disable Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_disable_policy",
    {
      title: "Disable AI Defense Policy",
      description: `Disable a Sophos AI Defense policy and tear its enforcement down on every sensor. The policy, its rules and its place in the order are kept; enable it again to restore enforcement.

WARNING: the users and devices it covered are then governed by the next policy that applies to them, or by the base policy. The base policy cannot be disabled. Disabling raises the version.

Args:
  - policy_id (string): Policy UUID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The policy, state DISABLED, with its new version.`,
      inputSchema: {
        policy_id: policyIdField.describe("Policy UUID"),
        tenant_id: tenantIdField,
      },
      annotations: { ...DESTRUCTIVE, idempotentHint: true },
    },
    withErrorHandling(async ({ policy_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<{ disablePolicy: AiDefensePolicy | null }>(tenantId, AI_DEFENSE_DISABLE_POLICY, { id: policy_id })
        .catch(rethrowPolicyError(policy_id));
      if (!data.disablePolicy) throw new Error("disablePolicy returned no policy.");
      return jsonResult(policyResult(tenantId, data.disablePolicy, warnings, { status: "disabled" }));
    })
  );

  // --- Move Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_move_policy",
    {
      title: "Move AI Defense Policy",
      description: `Move one Sophos AI Defense policy in the priority order: straight after another policy, or to the top (rank 1, evaluated first) when after_policy_id is omitted.

Only the moved policy changes; the others keep their priority values and their ranks shift around it. A policy can't move after itself, and partner and base policies can't be moved. To set the whole order at once, use sophos_fusion_ai_defense_reorder_policies.

Args:
  - policy_id (string): The policy to move.
  - after_policy_id (string, optional): Place it straight after this policy. Omit to move it to the top.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The moved policy with its new rank and priority.`,
      inputSchema: {
        policy_id: policyIdField.describe("Policy UUID to move"),
        after_policy_id: policyIdField.optional().describe("Anchor policy UUID; omit for the top"),
        tenant_id: tenantIdField,
      },
      annotations: WRITE,
    },
    withErrorHandling(async ({ policy_id, after_policy_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<{ movePolicy: AiDefensePolicy | null }>(tenantId, AI_DEFENSE_MOVE_POLICY, {
          id: policy_id,
          afterId: after_policy_id ?? null,
        })
        .catch(rethrowPolicyError(policy_id));
      if (!data.movePolicy) throw new Error("movePolicy returned no policy.");
      return jsonResult(policyResult(tenantId, data.movePolicy, warnings, { status: "moved" }));
    })
  );

  // --- Reorder Policies ---
  server.registerTool(
    "sophos_fusion_ai_defense_reorder_policies",
    {
      title: "Reorder AI Defense Policies",
      description: `Set the whole Sophos AI Defense priority order in one call: the first ID becomes rank 1.

The list must hold every reorderable policy (kind TENANT, origin not PARTNER) exactly once, or the call is refused ("reorder requires the complete list of non-partner, non-base policy IDs"). Get them with sophos_fusion_ai_defense_list_policies kind TENANT; leave out the base policy and partner policies. Every listed policy gets a new priority value (1000, 2000, and so on in testing). To move one policy, use sophos_fusion_ai_defense_move_policy.

Args:
  - policy_ids (string[]): Every reorderable policy UUID, in the new order.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  policy_ids in their confirmed new order.`,
      inputSchema: {
        policy_ids: z.array(policyIdField).min(1).max(1000).describe("Every reorderable policy UUID, in order"),
        tenant_id: tenantIdField,
      },
      annotations: { ...WRITE, idempotentHint: true },
    },
    withErrorHandling(async ({ policy_ids, tenant_id }) => {
      if (new Set(policy_ids).size !== policy_ids.length) {
        throw new Error("policy_ids repeats an ID: list each reorderable policy exactly once.");
      }
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ reorderPolicies: string[] }>(
        tenantId,
        AI_DEFENSE_REORDER_POLICIES,
        { policyIds: policy_ids }
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, status: "reordered", policy_ids: data.reorderPolicies }, warnings));
    })
  );

  // --- Clone Policy ---
  server.registerTool(
    "sophos_fusion_ai_defense_clone_policy",
    {
      title: "Clone AI Defense Policy",
      description: `Copy a Sophos AI Defense policy (rules, base rule, sensors, scope and tags) into a new DISABLED policy at the top of the order, named "<name> - cloned" (then "- cloned (2)" and so on).

Edit the copy, then enable and move it. Partner policies and the base policy can't be cloned.

Args:
  - policy_id (string): The policy to copy.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The new policy, with its id and version.`,
      inputSchema: {
        policy_id: policyIdField.describe("Policy UUID to copy"),
        tenant_id: tenantIdField,
      },
      annotations: WRITE,
    },
    withErrorHandling(async ({ policy_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<{ clonePolicy: AiDefensePolicy | null }>(tenantId, AI_DEFENSE_CLONE_POLICY, { id: policy_id })
        .catch(rethrowPolicyError(policy_id));
      if (!data.clonePolicy) throw new Error("clonePolicy returned no policy.");
      return jsonResult(policyResult(tenantId, data.clonePolicy, warnings, { status: "cloned", source_policy_id: policy_id }));
    })
  );
}

