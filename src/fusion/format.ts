/**
 * Shared value helpers for the Fusion tools: severity scales, timestamps,
 * identifier checks, QL string handling, comment mentions, tag merging and
 * the detection record formatter.
 */

import type { FusionDetectionEntity, FusionDetectionRecord, FusionTimestamp } from "./types.js";

/**
 * Case severity is an integer. Sophos documents these five values and says
 * more may be added between them, so range comparisons are preferred over
 * exact matches when filtering.
 */
export const CASE_SEVERITY_LABELS: Record<number, string> = {
  2: "informational",
  4: "low",
  6: "medium",
  8: "high",
  10: "critical",
};

export const CASE_SEVERITY_NAMES = ["informational", "low", "medium", "high", "critical"] as const;
export type CaseSeverityName = (typeof CASE_SEVERITY_NAMES)[number];

/** Accepts 2, 4, 6, 8, 10 or one of the five labels. Returns the integer. */
export function normaliseCaseSeverity(value: number | string): number {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 2 || value > 10) {
      throw new Error(
        `Case severity must be an integer from 2 to 10 (2 informational, 4 low, 6 medium, 8 high, 10 critical), got ${value}.`
      );
    }
    return value;
  }
  const match = Object.entries(CASE_SEVERITY_LABELS).find(
    ([, label]) => label === value.toLowerCase()
  );
  if (!match) {
    throw new Error(
      `Unknown case severity "${value}". Use 2, 4, 6, 8, 10 or one of: ${CASE_SEVERITY_NAMES.join(", ")}.`
    );
  }
  return Number(match[0]);
}

export function caseSeverityLabel(value: number | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return CASE_SEVERITY_LABELS[value] ?? `unknown (${value})`;
}

/** Detections API `{ seconds, nanos }` to ISO 8601. */
export function timestampToIso(ts: FusionTimestamp | null | undefined): string | null {
  if (!ts || typeof ts.seconds !== "number") return null;
  const millis = ts.seconds * 1000 + Math.floor((ts.nanos ?? 0) / 1_000_000);
  return new Date(millis).toISOString();
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHORT_ID_PATTERN = /^CSE\d+$/i;
const LEGACY_CASE_ID_PATTERN = /^[A-Za-z0-9]+-[A-Za-z0-9]+$/;
const RESOURCE_NAME_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/[^:\s]+(?::[^:\s]+){4}$/i;

export function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}

/** Fusion short IDs look like CSE00001. */
export function isCaseShortId(value: string): boolean {
  return SHORT_ID_PATTERN.test(value);
}

/**
 * Classic (legacy) Sophos Central case IDs look like 1-598868. They never
 * resolve in Fusion, which holds a separate case set.
 */
export function isLegacyCaseId(value: string): boolean {
  return LEGACY_CASE_ID_PATTERN.test(value) && !isUuid(value);
}

/**
 * Detection and event IDs on the case evidence mutations are six section
 * resource names, for example
 * alert://priv:event-filter:123456:1789526908712:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
 * or event://priv:scwx.process:123456:1789526819919:99999999-8888-7777-6666-555555555555.
 * A bare UUID is refused by the API with "invalid rn format, should have 6
 * sections, got: 1" (live tenant, 22/09/2026), so the shape is checked here
 * and the caller gets a useful message instead.
 */
export function isResourceName(value: string): boolean {
  return RESOURCE_NAME_PATTERN.test(value);
}

export const RESOURCE_NAME_EXAMPLE =
  "alert://priv:event-filter:123456:1789526908712:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

/**
 * Single-quote a value for a QL predicate. Sophos does not document an escape
 * sequence for a quote inside a QL string, so values that contain one are
 * refused rather than guessed at; the raw `query` parameter is the way round.
 */
export function qlString(value: string): string {
  if (value.includes("'")) {
    throw new Error(
      `QL filter values cannot contain a single quote (got ${JSON.stringify(value)}). Put the predicate in the query parameter instead.`
    );
  }
  return `'${value}'`;
}

/** Guards assignee_id: Fusion takes a Subject ID or an @mention, never an email. */
export function looksLikeEmail(value: string): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
}

/**
 * The @mention tokens a comment would fire, in the form mentionsIds stores
 * them: lower case, leading @ kept, deduplicated. Only word-initial tokens
 * count, so an email address inside the comment is not a mention. This mirrors
 * the parser's measured behaviour (22/09/2026); the API's mentionsIds is the
 * truth for which tokens actually resolved.
 */
export function parseMentionTokens(text: string): string[] {
  const tokens = new Set<string>();
  for (const match of text.matchAll(/(^|[^A-Za-z0-9_@.])@([A-Za-z0-9_]+)/g)) {
    tokens.add(`@${match[2].toLowerCase()}`);
  }
  return [...tokens];
}

/** Union of the current tags and the additions, order preserved, no duplicates. */
export function mergeTags(current: string[] | null | undefined, additions: string[]): string[] {
  const merged = [...(current ?? [])];
  for (const tag of additions) {
    if (!merged.includes(tag)) merged.push(tag);
  }
  return merged;
}

export function formatEntity(e: FusionDetectionEntity) {
  return { name: e.display_name, subtype: e.subtype, identifiers: e.identifiers ?? [] };
}

/** One detection record as the tools return it. Severity here is the 0 to 1 float. */
export function formatDetection(
  r: FusionDetectionRecord,
  attachment?: { createdAt: string; isGenesis: boolean }
) {
  const m = r.metadata;
  return {
    id: r.id,
    title: m?.title ?? null,
    severity_0_to_1: m?.severity ?? null,
    confidence: m?.confidence ?? null,
    status: r.status ?? null,
    resolution_reason: r.resolution_reason ?? null,
    origin: m?.origin ?? null,
    detector: m?.creator?.detector?.detector_name ?? null,
    detector_id: m?.creator?.detector?.detector_id ?? null,
    created_at: timestampToIso(m?.created_at),
    first_seen_at: timestampToIso(m?.first_seen_at),
    sensor_types: r.sensor_types ?? [],
    tags: r.tags ?? [],
    attack_technique_ids: r.attack_technique_ids ?? [],
    source_entities: (r.source_entities ?? []).map(formatEntity),
    target_entities: (r.target_entities ?? []).map(formatEntity),
    event_count: r.event_ids?.length ?? 0,
    is_genesis: attachment?.isGenesis ?? null,
    attached_at: attachment?.createdAt ?? null,
  };
}
