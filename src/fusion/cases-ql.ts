/**
 * Builds the QL string for the Cases `cases(arguments: { query })` search from
 * the convenience filters the list tool accepts. Type, status and verdict
 * arrive already resolved to UUIDs; names never reach QL because the cases
 * search schema is flat and exposes only the `*Id` columns.
 */

import { qlString } from "./format.js";

/**
 * The "Closed" primary status of each status set Fusion has used, the same
 * IDs on every tenant (live, 10/11/2026). A case keeps its status when its
 * tenant moves to the newer set, and the reference data lists only the
 * current set, so it alone can't name every closed status a tenant's cases carry.
 */
export const KNOWN_CLOSED_STATUS_IDS = [
  "b2cf8e1a-f6d1-4858-a42a-2b8f6752934e", // new, in progress, on hold ... closed
  "c519ffc5-fb8e-4d61-be34-4671d0d1a166", // open, active, suspended ... closed (early access)
] as const;

export interface CasesQlFilters {
  /** Raw QL, used verbatim. May carry its own `| sort` pipe. */
  query?: string;
  typeId?: string;
  statusIds?: string[];
  verdictId?: string;
  severity?: number;
  severityMin?: number;
  openOnly?: boolean;
  /**
   * With openOnly, the primary statuses that mean closed. A case in one of
   * them is left out even when its closedAt is null.
   */
  closedStatusIds?: string[];
  assigneeId?: string;
  unassigned?: boolean;
  titleContains?: string;
  tag?: string;
  createdAfter?: string;
  createdBefore?: string;
  updatedAfter?: string;
  /** e.g. "severity desc". Refused when `query` already carries a pipe. */
  sort?: string;
}

const SORT_PATTERN = /^[A-Za-z]+(\s+(asc|desc))?$/i;

/** Returns undefined when nothing filters, so the API applies its default (newest first). */
export function buildCasesQl(filters: CasesQlFilters): string | undefined {
  const predicates: string[] = [];
  let pipe = "";

  if (filters.query && filters.query.trim()) {
    const [where, rest] = splitPipe(filters.query.trim());
    if (where) predicates.push(where);
    pipe = rest;
  }

  if (filters.typeId) predicates.push(`typeId = ${qlString(filters.typeId)}`);
  if (filters.statusIds && filters.statusIds.length > 0) {
    predicates.push(
      filters.statusIds.length === 1
        ? `primaryStatusId = ${qlString(filters.statusIds[0])}`
        : `primaryStatusId in (${filters.statusIds.map(qlString).join(", ")})`
    );
  }
  if (filters.verdictId) predicates.push(`primaryVerdictId = ${qlString(filters.verdictId)}`);
  if (filters.severity !== undefined) predicates.push(`severity = ${filters.severity}`);
  if (filters.severityMin !== undefined) predicates.push(`severity >= ${filters.severityMin}`);
  if (filters.openOnly) {
    predicates.push("closedAt is null");
    // Cases closed in early 2026 kept closedAt null (live tenant, 10/11/2026), so the status decides too.
    // The QL has no "not in": "primaryStatusId not in (...)" is a parse error.
    if (filters.closedStatusIds && filters.closedStatusIds.length > 0) {
      predicates.push(`not (primaryStatusId in (${filters.closedStatusIds.map(qlString).join(", ")}))`);
    }
  }
  if (filters.assigneeId) predicates.push(`assigneeId = ${qlString(filters.assigneeId)}`);
  // Unassigned cases carry assigneeId '' rather than null (live tenant,
  // 21/09/2026: "assigneeId is null" matched 0 of 8 unassigned cases).
  if (filters.unassigned) predicates.push("(assigneeId is null or assigneeId = '')");
  if (filters.titleContains) predicates.push(`title contains ${qlString(filters.titleContains)}`);
  if (filters.tag) predicates.push(`tags contains ${qlString(filters.tag)}`);
  if (filters.createdAfter) predicates.push(`createdAt >= ${qlString(filters.createdAfter)}`);
  if (filters.createdBefore) predicates.push(`createdAt <= ${qlString(filters.createdBefore)}`);
  if (filters.updatedAfter) predicates.push(`updatedAt >= ${qlString(filters.updatedAfter)}`);

  if (filters.sort) {
    if (pipe) {
      throw new Error(
        "sort was given but the query parameter already contains a pipe. Put the sort in one place."
      );
    }
    const sort = filters.sort.trim();
    if (!SORT_PATTERN.test(sort)) {
      throw new Error(
        `sort must be "<field>" or "<field> asc|desc" (for example "severity desc"), got ${JSON.stringify(filters.sort)}.`
      );
    }
    pipe = `| sort ${sort}`;
  }

  const where = predicates.join(" and ");
  const ql = [where, pipe].filter(Boolean).join(" ");
  return ql || undefined;
}

/** Splits at the first `|` outside single quotes. */
function splitPipe(query: string): [string, string] {
  let inQuote = false;
  for (let i = 0; i < query.length; i++) {
    const ch = query[i];
    if (ch === "'") inQuote = !inQuote;
    if (ch === "|" && !inQuote) {
      return [query.slice(0, i).trim(), query.slice(i).trim()];
    }
  }
  return [query, ""];
}
