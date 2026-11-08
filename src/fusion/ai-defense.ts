/**
 * Shared input schemas, input builders and error translation for the Sophos
 * AI Defense tools (AI Defense Policy and Activity GraphQL APIs v1, on the
 * Sophos Fusion GraphQL endpoint).
 *
 * Nested policy inputs (rules, sensors, baseRule, onboarding selections) keep
 * the API's own field names, because a policy read returns them that way and
 * the usual edit is read, change, send back. Fields a read returns but an
 * input does not take (a rule's position and previews) are accepted and
 * dropped; anything else unknown is refused rather than ignored.
 *
 * Measured on live tenants 07/11/2026 (see CLAUDE.md for the full list).
 */

import { z } from "zod";
import { FusionGraphQLError, FusionNoResultError, type FusionClient } from "../client/fusion-client.js";
import { AI_DEFENSE_POLICIES, AI_DEFENSE_POLICY } from "./queries/ai-defense-policy.js";
import type { AiDefensePoliciesResponse, AiDefensePolicy } from "./types.js";

export const RELATIVE_TIME_RANGES = [
  "SINCE_BEGINNING_OF_DAY",
  "SINCE_BEGINNING_OF_WEEK_SUNDAY",
  "SINCE_BEGINNING_OF_WEEK_MONDAY",
  "SINCE_BEGINNING_OF_MONTH",
  "SINCE_BEGINNING_OF_QUARTER",
  "SINCE_BEGINNING_OF_YEAR",
  "LAST_MONTH",
  "LAST_QUARTER",
  "LAST_YEAR",
] as const;

export const POLICY_ACTIONS = ["BLOCK", "WARN", "ALLOW"] as const;
export const ENFORCEMENT_MECHANISMS = ["WEB_CONTROL", "APP_CONTROL"] as const;
export const RISK_LEVELS = ["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "ERROR"] as const;
export const SORT_ORDERS = ["ASC", "DESC"] as const;

/** Page sizes: policies and activities take up to 100; the inventories cap a larger limit to 100 silently. */
export const AI_DEFENSE_MAX_PAGE = 100;

export const tenantIdField = z
  .string()
  .guid()
  .optional()
  .describe("Tenant ID. Required for partner/org callers.");

export const policyIdField = z.string().guid();

const isoTime = (name: string) =>
  z
    .string()
    .datetime({
      offset: true,
      message: `${name} must be ISO 8601 with Z or an explicit offset, e.g. 2026-11-01T00:00:00Z`,
    })
    .optional();

/** time_range, start_time and end_time: a relative preset or absolute bounds, not both. */
export const timeRangeFields = {
  time_range: z
    .enum(RELATIVE_TIME_RANGES)
    .optional()
    .describe("Relative window, e.g. SINCE_BEGINNING_OF_WEEK_MONDAY (UTC). Not with start_time or end_time"),
  start_time: isoTime("start_time").describe("Absolute window start, ISO 8601. Not with time_range"),
  end_time: isoTime("end_time").describe("Absolute window end, ISO 8601. Not with time_range"),
};

export interface TimeRangeArgs {
  time_range?: (typeof RELATIVE_TIME_RANGES)[number];
  start_time?: string;
  end_time?: string;
}

/**
 * The SecureAITimeRange to send, or undefined for the API's default. Both
 * forms together is refused here: the API rejects the pair with only
 * "input: failed to retrieve activities" (measured 07/11/2026).
 */
export function buildTimeRange(args: TimeRangeArgs): Record<string, string> | undefined {
  const absolute = args.start_time !== undefined || args.end_time !== undefined;
  if (args.time_range !== undefined && absolute) {
    throw new Error(
      "Pass time_range or start_time/end_time, not both. The API refuses the pair with only 'input: failed to retrieve activities'."
    );
  }
  if (args.time_range !== undefined) return { relative: args.time_range };
  if (!absolute) return undefined;
  const range: Record<string, string> = {};
  if (args.start_time !== undefined) range.startTime = args.start_time;
  if (args.end_time !== undefined) range.endTime = args.end_time;
  return range;
}

// --- Policy inputs, in the API's own shape ---

export const conditionSchema = z.strictObject({
  dimension: z
    .string()
    .min(1)
    .describe("app, category, risk_level, compliance or training_policies. An unknown dimension matches nothing, with no error"),
  operator: z.enum(["IN", "MISSING_ANY"]).describe("IN, or MISSING_ANY (lacks at least one value; for compliance)"),
  values: z.array(z.string()).describe("Lower-case catalog values, ORed, e.g. ['chatgpt'] or ['critical', 'high']"),
});

const resolvedAction = z.enum(["allow", "block", "warn"]);

const dataControlsSchema = z.strictObject({
  clipboardCopy: resolvedAction,
  clipboardPaste: resolvedAction,
  upload: resolvedAction,
  download: resolvedAction,
});

export const ruleSchema = z
  .strictObject({
    target: z.strictObject({ conditions: z.array(conditionSchema) }).describe("Conditions, ANDed. An empty list matches every application"),
    action: z.enum(POLICY_ACTIONS),
    enforcementMechanismOverride: z
      .array(z.enum(ENFORCEMENT_MECHANISMS))
      .nullable()
      .optional()
      .describe("Limit the rule to these mechanisms; null or omitted uses every mechanism the action supports"),
    note: z.string().nullable().optional().describe("Admin note"),
    dataControls: dataControlsSchema
      .nullable()
      .optional()
      .describe("Browser extension clipboard, upload and download actions (allow, block, warn) on the rule's sites"),
    position: z.unknown().optional().describe("Read-only, ignored: order comes from the array"),
    targetPreview: z.unknown().optional().describe("Read-only, ignored"),
    targetPreviewV2: z.unknown().optional().describe("Read-only, ignored"),
  })
  .describe("A rule: { target: { conditions }, action, enforcementMechanismOverride?, note?, dataControls? }");

export type RuleArg = z.infer<typeof ruleSchema>;

/** The PolicyRuleInput for a rule, without the read-only fields. */
export function toRuleInput(rule: RuleArg): Record<string, unknown> {
  const input: Record<string, unknown> = {
    target: { conditions: rule.target.conditions },
    action: rule.action,
  };
  if (rule.enforcementMechanismOverride !== undefined) input.enforcementMechanismOverride = rule.enforcementMechanismOverride;
  if (rule.note !== undefined) input.note = rule.note;
  if (rule.dataControls !== undefined) input.dataControls = rule.dataControls;
  return input;
}

const sensorSchema = z.strictObject({
  enabled: z.boolean(),
  scope: z
    .record(z.string(), z.unknown())
    .nullable()
    .optional()
    .describe(
      'Endpoint: { users: [{ id, name }], group_ids, device_ids, device_group_ids }. Firewall: { groups: [{ group_id, web_policy_ids }] }. Empty Endpoint scope means everyone, which only the base policy may use ({ "type": "EVERYONE" })'
    ),
});

export const sensorsSchema = z
  .strictObject({
    endpoint: sensorSchema.nullable().optional(),
    firewall: sensorSchema.nullable().optional(),
    dns: sensorSchema.nullable().optional(),
    browser: sensorSchema.nullable().optional(),
  })
  .describe("Per-sensor { enabled, scope }: endpoint, firewall, dns, browser");

export const baseRuleSchema = z
  .strictObject({
    generativeAiCategoryAction: z
      .enum(POLICY_ACTIONS)
      .optional()
      .describe("Action for the endpoint's Generative AI web category traffic no rule matched. Default ALLOW"),
    appControlCategoryAction: z
      .enum(POLICY_ACTIONS)
      .nullable()
      .optional()
      .describe("ALLOW or BLOCK. null clears it, so it inherits generativeAiCategoryAction again"),
  })
  .describe("Policy-wide settings outside the rule list");

export const tagsSchema = z
  .record(z.string(), z.string())
  .describe('Key/value labels, string values only (a number is refused), e.g. { "env": "production" }');

/**
 * On update, a tags map with at least one key replaces the stored map, while
 * an empty map or null is ignored (and still raises the version), so tags
 * can't be cleared through the API (live, 08/11/2026). The reference documents
 * no other way.
 */
export const TAGS_NOTE =
  "tags replaces the whole map when it has at least one key. An empty map or null is ignored by the API, so tags can't be cleared through it: to drop some tags, send the ones to keep.";

// --- Errors ---

/** The deletedAt of a not-found answer when the policy was deleted, or null when the error is not a not-found. */
function notFoundAnswer(error: unknown): { deletedAt: string | null } | null {
  if (!(error instanceof FusionGraphQLError) || error.errors.length === 0) return null;
  if (!error.errors.every((entry) => /\bnot found\b/i.test(entry.message ?? ""))) return null;
  const deletedAt = error.errors.find((entry) => entry.extensions?.code === "GONE")?.extensions?.deletedAt;
  return { deletedAt: typeof deletedAt === "string" ? deletedAt : null };
}

/**
 * Translates the policy service's errors into actionable ones. An unknown ID
 * is "policy not found" (code NOT_FOUND on a read, DOWNSTREAM_SERVICE_ERROR on
 * a write); a deleted one carries code GONE and its deletedAt. A stale version
 * is "version conflict: policy has been modified".
 */
export function rethrowPolicyError(policyId: string) {
  return (error: unknown): never => {
    const notFound = notFoundAnswer(error);
    if (notFound) {
      throw new Error(
        notFound.deletedAt
          ? `AI Defense policy ${policyId} was deleted at ${notFound.deletedAt}. Deletion cannot be undone through the API.`
          : `AI Defense policy ${policyId} not found. List policies with sophos_fusion_ai_defense_list_policies.`
      );
    }
    if (error instanceof FusionGraphQLError && error.errors.some((entry) => /version conflict/i.test(entry.message ?? ""))) {
      throw new Error(
        `${error.message}. Read the policy again with sophos_fusion_ai_defense_get_policy and pass its current version: every write, enable and disable included, raises it.`
      );
    }
    throw error;
  };
}

/** activity(id) answers an ID it does not hold with "input: failed to retrieve activity" (measured 07/11/2026). */
export function rethrowActivityError(activityId: string) {
  return (error: unknown): never => {
    if (
      error instanceof FusionGraphQLError &&
      error.errors.length > 0 &&
      error.errors.every((entry) => /failed to retrieve activity/i.test(entry.message ?? ""))
    ) {
      throw new Error(
        `AI Defense could not retrieve activity ${activityId}: no activity with that ID on this tenant, or the read failed. Copy the id from sophos_fusion_ai_defense_list_activities. (${error.message})`
      );
    }
    throw error;
  };
}

// --- Writes Sophos gave no result for ---

/**
 * Waits before each read of an unclear write's read-back, in milliseconds:
 * at once, then about 1 s and 4 s after the write. Policy reads agreed with
 * every write at once in testing (07/11 and 08/11/2026); the later reads are
 * there in case Sophos lags, so a single read is never taken as proof.
 */
let unclearReadBackDelaysMs = [0, 1000, 3000];

/** Tests shorten the waits. */
export function setUnclearReadBackDelays(ms: number[]): void {
  unclearReadBackDelaysMs = ms.length > 0 ? ms : [0];
}

/** A policy write's answer: its result, or why the answer does not say whether the write took effect. */
export type PolicyWriteAnswer<T> =
  | { unclear: false; value: T; warnings: string[] }
  | { unclear: true; reason: string; warnings: string[] };

/**
 * Sends one AI Defense policy mutation and returns its result field. The
 * answer is unclear when the client throws FusionNoResultError (HTTP 200 with
 * an empty or unreadable body, or with neither data nor errors: enablePolicy
 * answered 200 with an empty body on 08/11/2026), or when the field is null,
 * missing or an empty list with no error. The write may still have been made,
 * so the tool reads the state back instead of reporting success. A GraphQL
 * error is a clear refusal and goes to rethrow.
 */
export async function sendPolicyWrite<T>(
  client: FusionClient,
  tenantId: string,
  document: string,
  field: string,
  variables: Record<string, unknown>,
  rethrow: (error: unknown) => never = (error) => {
    throw error;
  }
): Promise<PolicyWriteAnswer<T>> {
  let data: Record<string, unknown>;
  let warnings: string[];
  try {
    ({ data, warnings } = await client.query<Record<string, unknown>>(tenantId, document, variables));
  } catch (error) {
    if (error instanceof FusionNoResultError) return { unclear: true, reason: error.message, warnings: [] };
    return rethrow(error);
  }
  const value = data[field];
  if (value === null || value === undefined || (Array.isArray(value) && value.length === 0)) {
    const shown = value === undefined ? `no ${field} field` : `${field} ${JSON.stringify(value)}`;
    return {
      unclear: true,
      reason: `Sophos Fusion answered with ${shown} and no error, so the answer does not say whether the write took effect. Not retried.`,
      warnings,
    };
  }
  return { unclear: false, value: value as T, warnings };
}

/** One read of a policy: found, gone (deleted, with its time, or never there), or the read failed. */
export type PolicyRead =
  | { kind: "found"; policy: AiDefensePolicy }
  | { kind: "gone"; deletedAt: string | null }
  | { kind: "failed"; error: string };

export async function readPolicy(client: FusionClient, tenantId: string, policyId: string): Promise<PolicyRead> {
  try {
    const { data } = await client.query<{ policy: AiDefensePolicy | null }>(tenantId, AI_DEFENSE_POLICY, { id: policyId });
    return data.policy ? { kind: "found", policy: data.policy } : { kind: "gone", deletedAt: null };
  } catch (error) {
    const notFound = notFoundAnswer(error);
    if (notFound) return { kind: "gone", deletedAt: notFound.deletedAt };
    return { kind: "failed", error: errorText(error) };
  }
}

/** Every policy the filter matches, in rank order, or why the list could not be read. */
export async function readPolicyList(
  client: FusionClient,
  tenantId: string,
  filter: Record<string, unknown>
): Promise<{ policies: AiDefensePolicy[] } | { error: string }> {
  const policies: AiDefensePolicy[] = [];
  let after: string | null = null;
  try {
    // 20 pages of 100 covers the 1000 IDs reorder takes, twice over
    for (let page = 0; page < 20; page++) {
      const variables: Record<string, unknown> = { filter, first: AI_DEFENSE_MAX_PAGE };
      if (after) variables.after = after;
      const { data } = await client.query<AiDefensePoliciesResponse>(tenantId, AI_DEFENSE_POLICIES, variables);
      policies.push(...data.policies.policies);
      if (!data.policies.pageInfo.hasNextPage || !data.policies.pageInfo.endCursor) break;
      after = data.policies.pageInfo.endCursor;
    }
  } catch (error) {
    return { error: errorText(error) };
  }
  return { policies };
}

/**
 * Reads until settled() accepts a read, waiting before each one, and returns
 * the last read and how many were made. A read that fails or disagrees is
 * read again, since one read proves nothing either way.
 */
export async function readBackUntil<R>(read: () => Promise<R>, settled: (value: R) => boolean): Promise<{ last: R; reads: number }> {
  let last = undefined as R;
  let reads = 0;
  for (const delay of unclearReadBackDelaysMs) {
    if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
    last = await read();
    reads += 1;
    if (settled(last)) break;
  }
  return { last, reads };
}

/** About how long the read-back reads span, for the result's wording. */
export function readBackSpan(reads: number): string {
  const ms = unclearReadBackDelaysMs.slice(0, reads).reduce((total, delay) => total + delay, 0);
  return reads === 1 ? "1 read" : `${reads} reads over about ${Math.round(ms / 1000)} s`;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export const WRITE = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

export const DESTRUCTIVE = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
} as const;
