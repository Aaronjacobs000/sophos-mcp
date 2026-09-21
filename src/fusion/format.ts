/**
 * Shared value helpers for the Fusion tools: severity scales, timestamps,
 * identifier checks and QL string handling.
 */

import type { FusionTimestamp } from "./types.js";

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
