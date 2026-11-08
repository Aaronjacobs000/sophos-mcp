/**
 * Tools: sophos_fusion_ai_defense_list_activities, sophos_fusion_ai_defense_get_activity,
 *        sophos_fusion_ai_defense_list_app_inventory, sophos_fusion_ai_defense_list_user_inventory,
 *        sophos_fusion_ai_defense_list_user_apps, sophos_fusion_ai_defense_inventory_summary,
 *        sophos_fusion_ai_defense_get_settings, sophos_fusion_ai_defense_update_settings
 * Sophos AI Defense Activity GraphQL API v1 on https://api.taegis.sophos.com/graphql
 * (released 15/10/2026).
 *
 * Every list sends a filter object, even an empty one: the documented default
 * window (since 00:00 UTC today) sits on filter.timeRange, so a call with no
 * filter at all reads every activity the tenant holds (578 against 210,351 on
 * one tenant, 07/11/2026). Activities page by cursor, up to 100 a page; the
 * inventories page by offset and cap a larger limit to 100 without saying so.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { FusionClient } from "../client/fusion-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import {
  AI_DEFENSE_MAX_PAGE,
  DESTRUCTIVE,
  READ_ONLY,
  RISK_LEVELS,
  SORT_ORDERS,
  UNCLEAR_RETURNS,
  baseRuleSchema,
  buildTimeRange,
  readBackSpan,
  readBackUntil,
  readPolicyList,
  rethrowActivityError,
  ruleSchema,
  sendPolicyWrite,
  sensorsSchema,
  tagsSchema,
  tenantIdField,
  timeRangeFields,
  toRuleInput,
  type TimeRangeArgs,
} from "../fusion/ai-defense.js";
import {
  AI_DEFENSE_ACTIVITIES,
  AI_DEFENSE_ACTIVITY,
  AI_DEFENSE_ACTIVITY_TIMEOUT_MS,
  AI_DEFENSE_APP_INVENTORY,
  AI_DEFENSE_INVENTORY_SUMMARY,
  AI_DEFENSE_TENANT_SETTINGS,
  AI_DEFENSE_UPDATE_TENANT_SETTINGS,
  AI_DEFENSE_USER_APPS,
  AI_DEFENSE_USER_INVENTORY,
} from "../fusion/queries/ai-defense-activity.js";
import type { AiDefenseActivitiesResponse, AiDefenseOffsetPage, AiDefensePolicy, AiDefenseTenantSettings } from "../fusion/types.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";

const WINDOW_NOTE =
  "The window defaults to since 00:00 UTC today. Set time_range (a relative preset such as SINCE_BEGINNING_OF_MONTH or LAST_MONTH, all UTC) or start_time and end_time, not both. A year of data took up to 22 seconds on a busy tenant.";

const RISK_NOTE = "Risk levels: UNKNOWN, INFO, LOW, MEDIUM, HIGH, CRITICAL, ERROR (the catalog could not resolve one)";

const riskLevelsField = z.array(z.enum(RISK_LEVELS)).min(1).optional();
const stringList = z.array(z.string().min(1)).min(1).optional();
const sortOrderField = z.enum(SORT_ORDERS).optional().default("DESC").describe("ASC or DESC, default DESC");
const offsetField = z.number().int().min(0).optional().default(0).describe("Entries to skip, default 0");
const limitField = (fallback: number) =>
  z
    .number()
    .int()
    .min(1)
    .max(AI_DEFENSE_MAX_PAGE)
    .optional()
    .default(fallback)
    .describe(`Entries per page (1-100, default ${fallback})`);

/** The filter object for an Activity API list: the given fields plus the time window, never undefined. */
function withWindow(fields: Record<string, unknown>, window: TimeRangeArgs): Record<string, unknown> {
  const filter: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) filter[key] = value;
  }
  const timeRange = buildTimeRange(window);
  if (timeRange) filter.timeRange = timeRange;
  return filter;
}

/** An offset page in the tools' shape, with next_offset so a cut page says where to resume. */
function offsetPage(tenantId: string, key: string, page: AiDefenseOffsetPage, warnings: string[]) {
  return withWarnings(
    {
      tenant_id: tenantId,
      total: page.totalCount,
      offset: page.offset,
      limit: page.limit,
      has_next_page: page.hasNextPage,
      next_offset: page.hasNextPage ? page.offset + page.entries.length : null,
      [key]: page.entries,
    },
    warnings
  );
}

const onboardingStatusField = z.enum(["NOT_STARTED", "IN_PROGRESS", "COMPLETED"]);

const selectionsSchema = z
  .strictObject({
    organizationDetails: z
      .strictObject({
        role: z.string().nullable().optional(),
        numberOfUsers: z.string().nullable().optional(),
        aiFamiliarity: z.string().nullable().optional(),
        industry: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
    productIntegration: z
      .strictObject({
        acknowledgedCheckKeys: z.array(z.string()),
        selectedProductKeys: z.array(z.enum(["ENDPOINT", "FIREWALL", "SERVER"])).nullable().optional(),
      })
      .nullable()
      .optional(),
    passedStepKeys: z.array(z.string()).nullable().optional(),
  })
  .describe(
    "The complete onboarding selections, in the shape sophos_fusion_ai_defense_get_settings returns: { organizationDetails?, productIntegration?, passedStepKeys? }. A part left out is cleared, apart from passedStepKeys"
  );

const basePolicySchema = z
  .strictObject({
    name: z.string().min(1),
    description: z.string().optional(),
    rules: z.array(ruleSchema).max(500).optional(),
    baseRule: baseRuleSchema.optional(),
    sensors: sensorsSchema,
    tags: tagsSchema.optional(),
  })
  .describe('The base policy to create: { name, description?, rules?, baseRule?, sensors (Endpoint scope { "type": "EVERYONE" }), tags? }');

// --- Read-back of a settings update Sophos gave no clear answer for ---

type Selections = z.infer<typeof selectionsSchema>;

/** One read-back: the settings record, and the base policies when the update sent one. */
interface SettingsRead {
  settings: { kind: "found"; value: AiDefenseTenantSettings } | { kind: "none" } | { kind: "failed"; error: string };
  basePolicies: { policies: AiDefensePolicy[] } | { error: string } | null;
}

async function readSettings(client: FusionClient, tenantId: string): Promise<SettingsRead["settings"]> {
  try {
    const { data } = await client.query<{ secureAITenantSettings: AiDefenseTenantSettings | null }>(tenantId, AI_DEFENSE_TENANT_SETTINGS);
    return data.secureAITenantSettings ? { kind: "found", value: data.secureAITenantSettings } : { kind: "none" };
  } catch (error) {
    return { kind: "failed", error: error instanceof Error ? error.message : String(error) };
  }
}

const keySet = (keys: unknown): string[] => (Array.isArray(keys) ? keys.map(String).sort() : []);

/** organizationDetails in one shape: every field, unset ones null, and null when none is set. */
function comparableOrganization(value: unknown): Record<string, unknown> | null {
  const v = (value ?? {}) as Record<string, unknown>;
  const shaped = { role: v.role ?? null, numberOfUsers: v.numberOfUsers ?? null, aiFamiliarity: v.aiFamiliarity ?? null, industry: v.industry ?? null };
  return Object.values(shaped).every((field) => field === null) ? null : shaped;
}

/** productIntegration in one shape: both key lists sorted, and null when both are empty. */
function comparableProducts(value: unknown): Record<string, string[]> | null {
  const v = (value ?? {}) as Record<string, unknown>;
  const shaped = { acknowledgedCheckKeys: keySet(v.acknowledgedCheckKeys), selectedProductKeys: keySet(v.selectedProductKeys) };
  return shaped.acknowledgedCheckKeys.length === 0 && shaped.selectedProductKeys.length === 0 ? null : shaped;
}

const differs = (a: unknown, b: unknown) => JSON.stringify(a) !== JSON.stringify(b);

/**
 * What reads back different from what was sent. selections replaces the
 * stored set, so organizationDetails or productIntegration left out should
 * read back cleared; passedStepKeys left out is kept, so it is compared only
 * when sent.
 */
function differingSettings(status: string, selections: Selections, settings: AiDefenseTenantSettings): string[] {
  const stored = (settings.onboarding?.selections ?? {}) as Record<string, unknown>;
  const differ: string[] = [];
  if (settings.onboarding?.status !== status) differ.push("onboarding_status");
  if (differs(comparableOrganization(selections.organizationDetails), comparableOrganization(stored.organizationDetails))) {
    differ.push("organizationDetails");
  }
  if (differs(comparableProducts(selections.productIntegration), comparableProducts(stored.productIntegration))) {
    differ.push("productIntegration");
  }
  if (Array.isArray(selections.passedStepKeys) && differs(keySet(selections.passedStepKeys), keySet(stored.passedStepKeys))) {
    differ.push("passedStepKeys");
  }
  return differ;
}

/**
 * Reads the settings back (at once, 1 s and 4 s) until they show the status
 * and selections sent and, when a base policy was sent, a TENANT_BASE policy
 * exists. Creating one when it exists returns the existing one, so any base
 * policy counts.
 */
async function readBackSettings(
  client: FusionClient,
  tenantId: string,
  status: string,
  selections: Selections,
  basePolicySent: boolean
): Promise<{ took_effect: boolean | null; read_back: string; reads: number; [field: string]: unknown }> {
  const read = async (): Promise<SettingsRead> => ({
    settings: await readSettings(client, tenantId),
    basePolicies: basePolicySent ? await readPolicyList(client, tenantId, { kind: "TENANT_BASE" }) : null,
  });
  const inPlace = ({ settings, basePolicies }: SettingsRead) =>
    settings.kind === "found" &&
    differingSettings(status, selections, settings.value).length === 0 &&
    (basePolicies === null || ("policies" in basePolicies && basePolicies.policies.length > 0));
  const { last, reads } = await readBackUntil(read, inPlace);
  const span = readBackSpan(reads);
  const { settings, basePolicies } = last;
  if (settings.kind === "failed") {
    return {
      took_effect: null,
      read_back: `The settings could not be read back (${settings.error}), so whether the update took effect is unknown: check them with sophos_fusion_ai_defense_get_settings before sending it again.`,
      reads,
    };
  }
  if (settings.kind === "none") {
    return { took_effect: false, read_back: `No AI Defense settings record reads back after ${span}, so the update did not take effect. Send it again.`, reads };
  }
  const differ = differingSettings(status, selections, settings.value);
  if (differ.length > 0) {
    return {
      took_effect: false,
      read_back: `The settings read status ${settings.value.onboarding?.status}, and ${differ.join(", ")} read back different from what you sent after ${span}, so the update did not take effect. Send it again.`,
      reads,
      settings: settings.value,
      fields_differing: differ,
    };
  }
  const asSent = `The settings read back as you sent: status ${status}, selections in place`;
  if (basePolicies === null) return { took_effect: true, read_back: `${asSent}.`, reads, settings: settings.value };
  if ("error" in basePolicies) {
    return {
      took_effect: null,
      read_back: `${asSent}, but the base policy could not be read back (${basePolicies.error}): check it with sophos_fusion_ai_defense_list_policies kind TENANT_BASE before sending the update again.`,
      reads,
      settings: settings.value,
    };
  }
  const base = basePolicies.policies[0];
  if (!base) {
    return {
      took_effect: false,
      read_back: `${asSent}, but no base policy (kind TENANT_BASE) exists after ${span}, so the base policy was not created. Send it again.`,
      reads,
      settings: settings.value,
    };
  }
  return {
    took_effect: true,
    read_back: `${asSent}, and the base policy ${base.id} "${base.name}" exists.`,
    reads,
    settings: settings.value,
    base_policy: base,
  };
}

export function registerFusionAiDefenseActivityTools(
  server: McpServer,
  client: FusionClient,
  tenantResolver: TenantResolver
): void {
  const timeout = { timeoutMs: AI_DEFENSE_ACTIVITY_TIMEOUT_MS };

  // --- List Activities ---
  server.registerTool(
    "sophos_fusion_ai_defense_list_activities",
    {
      title: "List AI Defense Activities",
      description: `List the AI activity Sophos AI Defense observed: who used which AI application on which device, the action taken (ALLOWED, BLOCKED, WARNED, MODIFIED, UNKNOWN), the policy behind it and the risk.

${WINDOW_NOTE} Newest first by default. Filters are ANDed; values within one list are ORed. search is a case-insensitive substring across activity, application, provider, model, actor, device and policy names and IDs. Filter policies by policy_ids, not names, since names change. is_unsanctioned true keeps allowed activity for applications no policy covers (shadow AI).

Each row has id, timestamp, actor (id, name, type), application (id, name, categories, trainingPolicies, compliance), applicationProvider, modelProvider, model, sensors, action, policyId, policy, device, risk, appRisk (SAFE, CHECK_POLICY, DANGEROUS), aggregationCount and isUnsanctioned. Source IP addresses are only on sophos_fusion_ai_defense_get_activity: the list's additionalData is null on every row and selecting it fails the whole page, so it is left out.

Args:
  - time_range, start_time, end_time (optional): The window.
  - search (string, optional).
  - actions (string[], optional): ALLOWED, BLOCKED, WARNED, MODIFIED, UNKNOWN.
  - risks (string[], optional): ${RISK_NOTE}.
  - actor_ids, application_ids, device_ids (string[], optional): Exact, case-sensitive IDs. policy_ids (string[], optional): policy UUIDs.
  - actor_type (string, optional): USER, PROCESS, NETWORK_ENTITY, SERVICE, SYSTEM, UNKNOWN.
  - application_categories, application_compliance, application_training_policies (string[], optional): e.g. general_assistant, soc2_type2, trains_on_input.
  - model_provider_name (string, optional): e.g. OpenAI.
  - sensor_types (string[], optional): ENDPOINT, FIREWALL, DNS, BROWSER. device_types, device_platforms (string[], optional).
  - is_unsanctioned, has_policy (boolean, optional).
  - sort_by (string, optional): TIMESTAMP (default), ACTION, ACTOR_NAME, PROVIDER_NAME, DEVICE_NAME. sort_order: DESC (default) or ASC.
  - limit (number, optional): 1 to 100, default 20.
  - after (string, optional): end_cursor from the previous page.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  total (every page), has_next_page, end_cursor and activities.`,
      inputSchema: {
        ...timeRangeFields,
        search: z.string().min(1).optional().describe("Case-insensitive substring"),
        actions: z.array(z.enum(["UNKNOWN", "ALLOWED", "BLOCKED", "WARNED", "MODIFIED"])).min(1).optional().describe("Actions (any of)"),
        risks: riskLevelsField.describe("Risk levels (any of)"),
        actor_ids: stringList.describe("Actor IDs (exact)"),
        actor_type: z.enum(["UNKNOWN", "SYSTEM", "SERVICE", "USER", "PROCESS", "NETWORK_ENTITY"]).optional().describe("Actor type"),
        application_ids: stringList.describe("Application IDs (exact), e.g. chatgpt"),
        application_categories: stringList.describe("Application categories (any of)"),
        application_compliance: stringList.describe("Compliance certifications (any of)"),
        application_training_policies: stringList.describe("Training policies (any of)"),
        model_provider_name: z.string().min(1).optional().describe("Model provider name"),
        sensor_types: z.array(z.enum(["ENDPOINT", "FIREWALL", "DNS", "BROWSER"])).min(1).optional().describe("Sensor types (any of)"),
        device_ids: stringList.describe("Device IDs (exact)"),
        device_types: z.array(z.enum(["COMPUTER", "SERVER", "SECURITY_VM", "UNKNOWN"])).min(1).optional().describe("Device types (any of)"),
        device_platforms: z
          .array(z.enum(["WINDOWS", "LINUX", "MACOS", "IOS", "ANDROID", "UNKNOWN"]))
          .min(1)
          .optional()
          .describe("Device platforms (any of)"),
        policy_ids: z.array(z.string().guid()).min(1).optional().describe("Policy UUIDs (any of)"),
        is_unsanctioned: z.boolean().optional().describe("true: allowed activity no policy covers"),
        has_policy: z.boolean().optional().describe("true: activity a policy was attributed to"),
        sort_by: z
          .enum(["TIMESTAMP", "ACTION", "ACTOR_NAME", "PROVIDER_NAME", "DEVICE_NAME"])
          .optional()
          .default("TIMESTAMP")
          .describe("Sort field, default TIMESTAMP"),
        sort_order: sortOrderField,
        limit: limitField(20),
        after: z.string().optional().describe("end_cursor from the previous page"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const filter = withWindow(
        {
          search: args.search,
          actions: args.actions,
          risks: args.risks,
          actorIds: args.actor_ids,
          actorType: args.actor_type,
          applicationIds: args.application_ids,
          applicationCategories: args.application_categories,
          applicationCompliance: args.application_compliance,
          applicationTrainingPolicies: args.application_training_policies,
          modelProviderName: args.model_provider_name,
          sensorTypes: args.sensor_types,
          deviceIds: args.device_ids,
          deviceTypes: args.device_types,
          devicePlatforms: args.device_platforms,
          policyIds: args.policy_ids,
          isUnsanctioned: args.is_unsanctioned,
          hasPolicy: args.has_policy,
        },
        args
      );
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const variables: Record<string, unknown> = {
        filter,
        sort: { field: args.sort_by, order: args.sort_order },
        first: args.limit,
      };
      if (args.after) variables.after = args.after;
      const { data, warnings } = await client.query<AiDefenseActivitiesResponse>(
        tenantId,
        AI_DEFENSE_ACTIVITIES,
        variables,
        timeout
      );
      const page = data.activities;
      return jsonResult(
        withWarnings(
          {
            tenant_id: tenantId,
            total: page.totalCount,
            has_next_page: page.pageInfo.hasNextPage,
            end_cursor: page.pageInfo.endCursor,
            activities: page.activities,
          },
          warnings
        ),
        { after: args.after, limit: args.limit },
        "activities"
      );
    })
  );

  // --- Get Activity ---
  server.registerTool(
    "sophos_fusion_ai_defense_get_activity",
    {
      title: "Get AI Defense Activity",
      description: `Get one Sophos AI Defense activity by ID, with its enrichment: additionalData carries sourceAddresses, the originating IP addresses the list leaves out.

IDs look like event://priv:scwx.secureai:<tenant>:<ms>:<uuid> and come from sophos_fusion_ai_defense_list_activities. An ID the tenant does not hold is answered "failed to retrieve activity", after several seconds.

Args:
  - activity_id (string): The activity ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The activity: the list fields plus additionalData.`,
      inputSchema: {
        activity_id: z
          .string()
          .regex(/^event:\/\/\S+$/, "an activity ID starting event://, from sophos_fusion_ai_defense_list_activities")
          .describe("Activity ID (event://...)"),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ activity_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<{ activity: Record<string, unknown> | null }>(tenantId, AI_DEFENSE_ACTIVITY, { id: activity_id }, timeout)
        .catch(rethrowActivityError(activity_id));
      if (!data.activity) throw new Error(`AI Defense activity ${activity_id} not found.`);
      return jsonResult(withWarnings({ tenant_id: tenantId, activity: data.activity }, warnings));
    })
  );

  // --- App Inventory ---
  server.registerTool(
    "sophos_fusion_ai_defense_list_app_inventory",
    {
      title: "List AI Defense App Inventory",
      description: `List the AI applications Sophos AI Defense saw on the tenant in a window, with risk, activity count, unique users, last seen and unsanctioned (uncovered and allowed) activity count.

${WINDOW_NOTE} Offset paging; limit tops out at 100 (a larger one is capped without notice, measured).

The reference also documents per-app training, compliance and category fields and a trainsOnUserData filter and sort, but the live API does not serve them (07/11/2026), so they are left out. Filter by categories, compliance_certificates or training_policies instead, or read them on an activity's application.

Args:
  - time_range, start_time, end_time (optional): The window.
  - search (string, optional): Substring of the app ID, name or provider.
  - app_id (string, optional): Exact app ID.
  - risk_levels (string[], optional): ${RISK_NOTE}.
  - categories, compliance_certificates, training_policies (string[], optional): Any of.
  - is_unsanctioned (boolean, optional): true: apps with unsanctioned activity.
  - sort_by (string, optional): NAME, RISK, USAGE, UNIQUE_USERS, LAST_SEEN, UNSANCTIONED_COUNT. sort_order: DESC (default) or ASC.
  - limit (number, optional): 1 to 100, default 20. offset (number, optional): default 0.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  total, offset, limit, has_next_page, next_offset and apps (id, name, provider, risk, usage, uniqueUsers, lastSeen, unsanctionedCount).`,
      inputSchema: {
        ...timeRangeFields,
        search: z.string().min(1).optional().describe("Substring of app ID, name or provider"),
        app_id: z.string().min(1).optional().describe("Exact app ID"),
        risk_levels: riskLevelsField.describe("Risk levels (any of)"),
        categories: stringList.describe("Categories (any of)"),
        compliance_certificates: stringList.describe("Compliance certifications (any of)"),
        training_policies: stringList.describe("Training policies (any of)"),
        is_unsanctioned: z.boolean().optional().describe("true: apps with unsanctioned activity"),
        sort_by: z
          .enum(["NAME", "RISK", "USAGE", "UNIQUE_USERS", "LAST_SEEN", "UNSANCTIONED_COUNT"])
          .optional()
          .describe("Sort field"),
        sort_order: sortOrderField,
        limit: limitField(20),
        offset: offsetField,
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const filter = withWindow(
        {
          search: args.search,
          appId: args.app_id,
          riskLevels: args.risk_levels,
          categories: args.categories,
          complianceCertificates: args.compliance_certificates,
          trainingPolicies: args.training_policies,
          isUnsanctioned: args.is_unsanctioned,
        },
        args
      );
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const variables: Record<string, unknown> = { filter, limit: args.limit, offset: args.offset };
      if (args.sort_by) variables.sort = { field: args.sort_by, order: args.sort_order };
      const { data, warnings } = await client.query<{ appInventory: AiDefenseOffsetPage }>(
        tenantId,
        AI_DEFENSE_APP_INVENTORY,
        variables,
        timeout
      );
      return jsonResult(offsetPage(tenantId, "apps", data.appInventory, warnings), { offset: args.offset, limit: args.limit }, "apps");
    })
  );

  // --- User Inventory ---
  server.registerTool(
    "sophos_fusion_ai_defense_list_user_inventory",
    {
      title: "List AI Defense User Inventory",
      description: `List the users (actors) Sophos AI Defense saw using AI applications in a window, with worst risk, apps used, activity count, policy violations, top app, first and last seen and unsanctioned activity count.

${WINDOW_NOTE} Offset paging, limit 1 to 100.

id is the actor ID: a directory user ID or SID when resolved, an IP address for a network entity, or a temporary "secure-ai-fallback:" ID built from the name. The same person can appear twice, under a resolved ID and a fallback one. Pass id to sophos_fusion_ai_defense_list_user_apps, or to sophos_fusion_ai_defense_list_activities as actor_ids. used_app_ids lists every user of an app; top_app_ids only those whose most used app it is.

Args:
  - time_range, start_time, end_time (optional): The window.
  - search (string, optional): Substring of the user ID or name.
  - risk_levels (string[], optional): ${RISK_NOTE}.
  - used_app_ids, top_app_ids (string[], optional): App IDs (any of).
  - is_unsanctioned (boolean, optional): true: users with unsanctioned activity.
  - sort_by (string, optional): NAME, RISK, APPS_USED, USAGE, LAST_SEEN, UNSANCTIONED_COUNT, POLICY_VIOLATIONS. sort_order: DESC (default) or ASC.
  - limit (number, optional): 1 to 100, default 20. offset (number, optional): default 0.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  total, offset, limit, has_next_page, next_offset and users (id, name, risk, appsUsed, usage, policyViolations, topAppId, topApp, firstSeen, lastSeen, unsanctionedCount).`,
      inputSchema: {
        ...timeRangeFields,
        search: z.string().min(1).optional().describe("Substring of user ID or name"),
        risk_levels: riskLevelsField.describe("Risk levels (any of)"),
        used_app_ids: stringList.describe("Users of any of these apps"),
        top_app_ids: stringList.describe("Users whose top app is one of these"),
        is_unsanctioned: z.boolean().optional().describe("true: users with unsanctioned activity"),
        sort_by: z
          .enum(["NAME", "RISK", "APPS_USED", "USAGE", "LAST_SEEN", "UNSANCTIONED_COUNT", "POLICY_VIOLATIONS"])
          .optional()
          .describe("Sort field"),
        sort_order: sortOrderField,
        limit: limitField(20),
        offset: offsetField,
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const filter = withWindow(
        {
          search: args.search,
          riskLevels: args.risk_levels,
          usedAppIds: args.used_app_ids,
          topAppIds: args.top_app_ids,
          isUnsanctioned: args.is_unsanctioned,
        },
        args
      );
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const variables: Record<string, unknown> = { filter, limit: args.limit, offset: args.offset };
      if (args.sort_by) variables.sort = { field: args.sort_by, order: args.sort_order };
      const { data, warnings } = await client.query<{ userInventory: AiDefenseOffsetPage }>(
        tenantId,
        AI_DEFENSE_USER_INVENTORY,
        variables,
        timeout
      );
      return jsonResult(offsetPage(tenantId, "users", data.userInventory, warnings), { offset: args.offset, limit: args.limit }, "users");
    })
  );

  // --- User Apps ---
  server.registerTool(
    "sophos_fusion_ai_defense_list_user_apps",
    {
      title: "List AI Defense User Apps",
      description: `List the AI applications one user used in a window, per Sophos AI Defense: risk, activity count, policy violations, unsanctioned (uncovered and allowed) count, first and last use.

${WINDOW_NOTE} Offset paging, limit 1 to 100. user_id is the id from sophos_fusion_ai_defense_list_user_inventory. An unknown user_id returns an empty list, not an error.

Args:
  - user_id (string): Actor ID from the user inventory.
  - time_range, start_time, end_time (optional): The window.
  - search (string, optional): Substring of the app ID, name or provider.
  - risk_levels (string[], optional): ${RISK_NOTE}.
  - has_policy_violations, has_not_covered_count (boolean, optional).
  - sort_by (string, optional): USAGE, NAME, RISK, POLICY_VIOLATIONS, NOT_COVERED_COUNT, FIRST_USED, LAST_USED. sort_order: DESC (default) or ASC.
  - limit (number, optional): 1 to 100, default 20. offset (number, optional): default 0.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  total, offset, limit, has_next_page, next_offset and apps (id, name, provider, risk, usage, policyViolations, notCoveredCount, firstUsed, lastUsed).`,
      inputSchema: {
        user_id: z.string().min(1).describe("Actor ID from the user inventory"),
        ...timeRangeFields,
        search: z.string().min(1).optional().describe("Substring of app ID, name or provider"),
        risk_levels: riskLevelsField.describe("Risk levels (any of)"),
        has_policy_violations: z.boolean().optional().describe("true: apps with a policy violation for this user"),
        has_not_covered_count: z.boolean().optional().describe("true: apps with unsanctioned activity for this user"),
        sort_by: z
          .enum(["USAGE", "NAME", "RISK", "POLICY_VIOLATIONS", "NOT_COVERED_COUNT", "FIRST_USED", "LAST_USED"])
          .optional()
          .describe("Sort field"),
        sort_order: sortOrderField,
        limit: limitField(20),
        offset: offsetField,
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const filter = withWindow(
        {
          search: args.search,
          riskLevels: args.risk_levels,
          hasPolicyViolations: args.has_policy_violations,
          hasNotCoveredCount: args.has_not_covered_count,
        },
        args
      );
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const variables: Record<string, unknown> = { userId: args.user_id, filter, limit: args.limit, offset: args.offset };
      if (args.sort_by) variables.sort = { field: args.sort_by, order: args.sort_order };
      const { data, warnings } = await client.query<{ userApps: AiDefenseOffsetPage }>(
        tenantId,
        AI_DEFENSE_USER_APPS,
        variables,
        timeout
      );
      return jsonResult(
        { user_id: args.user_id, ...offsetPage(tenantId, "apps", data.userApps, warnings) },
        { offset: args.offset, limit: args.limit },
        "apps"
      );
    })
  );

  // --- Inventory Summary ---
  server.registerTool(
    "sophos_fusion_ai_defense_inventory_summary",
    {
      title: "Get AI Defense Inventory Summary",
      description: `Count the AI applications and users Sophos AI Defense saw in a window, by risk level, plus apps that train on user data, users with policy violations, and unsanctioned (uncovered and allowed) apps and users.

${WINDOW_NOTE} Apps count under their catalog risk; users under their worst observed risk, so the user risk counts add up to totalUsers.

Args:
  - time_range, start_time, end_time (optional): The window.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  summary: apps (totalApps, criticalRisk to infoRisk, unknownRisk, errorRisk, trainsOnData, unsanctionedCount) and users (totalUsers, criticalRisk to infoRisk, unknownRisk, withViolations, unsanctionedCount).`,
      inputSchema: { ...timeRangeFields, tenant_id: tenantIdField },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const filter = withWindow({}, args);
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const { data, warnings } = await client.query<{ inventorySummary: Record<string, unknown> }>(
        tenantId,
        AI_DEFENSE_INVENTORY_SUMMARY,
        { filter },
        timeout
      );
      return jsonResult(withWarnings({ tenant_id: tenantId, summary: data.inventorySummary }, warnings));
    })
  );

  // --- Get Tenant Settings ---
  server.registerTool(
    "sophos_fusion_ai_defense_get_settings",
    {
      title: "Get AI Defense Settings",
      description: `Get the tenant's Sophos AI Defense settings: onboarding status and the selections captured during onboarding, plus the AI Defense license state, type, expiry and grace period.

settings is null when the tenant has no settings record yet, as on a tenant that has never started AI Defense onboarding; such tenants still answered the policy and inventory queries in testing. License fields are set by Sophos and cannot be changed through the API.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  settings: onboarding (status, selections), licenseState (ACTIVE, GRACE_PERIOD, EXPIRED), gracePeriodEndsAt, licenseExpiryDate, licenseType, licenseId, refreshedAt, renewalPending, created and updated by and at.`,
      inputSchema: { tenant_id: tenantIdField },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ secureAITenantSettings: AiDefenseTenantSettings | null }>(
        tenantId,
        AI_DEFENSE_TENANT_SETTINGS
      );
      const settings = data.secureAITenantSettings;
      return jsonResult(
        withWarnings(
          {
            tenant_id: tenantId,
            settings,
            ...(settings === null ? { note: "No AI Defense settings record on this tenant yet: onboarding has not been started." } : {}),
          },
          warnings
        )
      );
    })
  );

  // --- Update Tenant Settings ---
  server.registerTool(
    "sophos_fusion_ai_defense_update_settings",
    {
      title: "Update AI Defense Settings",
      description: `Set the tenant's Sophos AI Defense onboarding status and selections. Creates the settings record on the first call and updates it after that.

WARNING: selections replaces the stored selections as a whole. organizationDetails or productIntegration left out is cleared; passedStepKeys left out is kept. An update with no selections at all clears both as well (measured 07/11/2026), so selections is required here. Read the settings with sophos_fusion_ai_defense_get_settings first and send back everything you keep, changing only what you mean to; send {} to clear them.

base_policy creates the tenant's base policy (kind TENANT_BASE, ENABLED) before completion is recorded, for a tenant that has none. It is accepted only with onboarding_status COMPLETED, and the base policy can't be disabled or deleted afterwards, so it needs confirm_base_policy true. If the policy service rejects it, the status is not changed and the error carries its reasons (BASE_POLICY_REJECTED).

Args:
  - onboarding_status (string): NOT_STARTED, IN_PROGRESS or COMPLETED.
  - selections (object): The complete selections: { organizationDetails?: { role?, numberOfUsers?, aiFamiliarity?, industry? }, productIntegration?: { acknowledgedCheckKeys, selectedProductKeys? (ENDPOINT, FIREWALL, SERVER) }, passedStepKeys? }.
  - base_policy (object, optional): { name, description?, rules?, baseRule?, sensors, tags? }.
  - confirm_base_policy (boolean, optional): Must be true with base_policy.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The settings as stored after the call. Read them back with sophos_fusion_ai_defense_get_settings to confirm. ${UNCLEAR_RETURNS}`,
      inputSchema: {
        onboarding_status: onboardingStatusField.describe("NOT_STARTED, IN_PROGRESS or COMPLETED"),
        selections: selectionsSchema,
        base_policy: basePolicySchema.optional(),
        confirm_base_policy: z
          .boolean()
          .optional()
          .describe("Must be true with base_policy: the base policy can't be disabled or deleted afterwards"),
        tenant_id: tenantIdField,
      },
      annotations: DESTRUCTIVE,
    },
    withErrorHandling(async (args) => {
      const onboarding: Record<string, unknown> = { status: args.onboarding_status, selections: args.selections };
      if (args.base_policy !== undefined) {
        if (args.onboarding_status !== "COMPLETED") {
          throw new Error("base_policy is accepted only with onboarding_status COMPLETED.");
        }
        if (args.confirm_base_policy !== true) {
          throw new Error(
            "base_policy creates the tenant's base policy, which can't be disabled, deleted, cloned or moved afterwards. Re-run with confirm_base_policy true to proceed."
          );
        }
        const { rules, ...rest } = args.base_policy;
        onboarding.basePolicy = { kind: "TENANT_BASE", state: "ENABLED", ...rest, rules: (rules ?? []).map(toRuleInput) };
      }
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const answer = await sendPolicyWrite<AiDefenseTenantSettings>(
        client,
        tenantId,
        AI_DEFENSE_UPDATE_TENANT_SETTINGS,
        "updateSecureAITenantSettings",
        { input: { onboarding } }
      );
      if (answer.unclear) {
        const { took_effect, read_back, reads, ...state } = await readBackSettings(
          client,
          tenantId,
          args.onboarding_status,
          args.selections,
          args.base_policy !== undefined
        );
        const result = jsonResult(
          withWarnings(
            { tenant_id: tenantId, status: "unclear", write: "updateSecureAITenantSettings", answer: answer.reason, took_effect, read_back, reads, ...state },
            answer.warnings
          )
        );
        return took_effect === true ? result : { ...result, isError: true };
      }
      return jsonResult(withWarnings({ tenant_id: tenantId, status: "updated", settings: answer.value }, answer.warnings));
    })
  );
}
