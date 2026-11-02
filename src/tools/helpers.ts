/**
 * Shared utilities for tool implementations.
 */

import { CHARACTER_LIMIT } from "../config/config.js";

export type ToolResult = {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

/**
 * The paging arguments a list tool was called with, under the tool's own
 * argument names, so an oversized page can say exactly what to request next.
 * Pass the cursor key even when it is undefined (the first page): its presence
 * marks a cursor-paged tool.
 */
export type PageArgs = {
  page?: number;
  offset?: number;
  limit?: number;
  page_size?: number;
  per_page?: number;
  cursor?: string;
  page_from_key?: string;
  after?: string;
};

/**
 * For a list tool whose Sophos API cannot page: the tool's arguments that
 * narrow the list (empty when it has none), and an optional note naming
 * another way to the omitted items, so an oversized list says what to do.
 */
export type Narrowing = {
  narrow_with: string[];
  note?: string;
};

const TRUNCATION_NOTICE =
  "\n\n... [TRUNCATED] Response exceeded size limit and was cut mid-JSON. Use filters or pagination to narrow results.";

/**
 * Creates a successful tool response with JSON content, never longer than
 * CHARACTER_LIMIT. A client cuts a longer one wherever its own limit falls,
 * mid-JSON and with nothing saying so. When the result does not fit, the
 * largest top-level array (the page of items) is cut to the items that fit,
 * the JSON stays valid, and a `truncated` key comes first saying how many were
 * left out and, given the tool's paging arguments, the request that returns
 * them. A list whose API cannot page passes a Narrowing instead, and the
 * notice names the arguments that narrow it. pageField names the array that
 * holds the page when another array in the result can be larger. Only a
 * result with no such array, or whose first item alone is too big, is cut as
 * text with a notice.
 */
export function jsonResult(data: unknown, paging?: PageArgs | Narrowing, pageField?: string): ToolResult {
  const text = JSON.stringify(data, null, 2);
  if (text.length <= CHARACTER_LIMIT) return textResult(text);
  const fitted = fitPage(data, paging, pageField);
  if (fitted !== null) return textResult(fitted);
  return textResult(text.slice(0, CHARACTER_LIMIT - TRUNCATION_NOTICE.length) + TRUNCATION_NOTICE);
}

function textResult(text: string): ToolResult {
  return { content: [{ type: "text", text }] };
}

/** The result with its largest array cut to fit, or null when that can't keep a whole item. */
function fitPage(data: unknown, paging: PageArgs | Narrowing | undefined, pageField: string | undefined): string | null {
  const record: Record<string, unknown> | null = Array.isArray(data)
    ? { items: data }
    : data !== null && typeof data === "object"
      ? (data as Record<string, unknown>)
      : null;
  if (!record) return null;

  const field = pageArrayKey(record, pageField);
  if (field === null) return null;
  const items = record[field] as unknown[];

  // truncated is the first key, and is set again after the spread so a record
  // with its own truncated key cannot replace it.
  const render = (kept: number) => {
    const notice = truncation(field, kept, items.length, paging);
    const out: Record<string, unknown> = { truncated: notice, ...record, [field]: items.slice(0, kept) };
    out.truncated = notice;
    return JSON.stringify(out, null, 2);
  };

  // The largest count that fits: render(low) always fits, render(high) never does.
  let low = 0;
  let high = items.length;
  if (render(low).length > CHARACTER_LIMIT) return null;
  while (high - low > 1) {
    const mid = Math.floor((low + high) / 2);
    if (render(mid).length <= CHARACTER_LIMIT) low = mid;
    else high = mid;
  }
  return low === 0 ? null : render(low);
}

/** pageField when it holds a non-empty array, otherwise the key of the largest non-empty array. */
function pageArrayKey(record: Record<string, unknown>, pageField: string | undefined): string | null {
  const nonEmpty = (value: unknown) => Array.isArray(value) && value.length > 0;
  if (pageField !== undefined && nonEmpty(record[pageField])) return pageField;
  let field: string | null = null;
  let size = -1;
  for (const [key, value] of Object.entries(record)) {
    if (!nonEmpty(value)) continue;
    const length = JSON.stringify(value).length;
    if (length > size) {
      field = key;
      size = length;
    }
  }
  return field;
}

function truncation(field: string, kept: number, onPage: number, paging: PageArgs | Narrowing | undefined) {
  return {
    field,
    returned: kept,
    omitted: onPage - kept,
    reason: `The page ran past the ${CHARACTER_LIMIT} character response limit, so only the first ${kept} of its ${onPage} ${field} are here.`,
    ...(isNarrowing(paging) ? narrowRequest(paging) : nextRequest(kept, onPage, paging)),
  };
}

const SIZE_KEYS = ["limit", "page_size", "per_page"] as const;
const CURSOR_KEYS = ["cursor", "page_from_key", "after"] as const;
const SKIPS_AHEAD = "Do not follow this response's own next page, offset or cursor: it starts after the omitted items.";

type NextRequest = {
  next: Record<string, unknown> | null;
  next_through_page?: number;
  resume?: Record<string, unknown> | null;
  narrow_with?: string[];
  how: string;
};

function isNarrowing(paging: PageArgs | Narrowing | undefined): paging is Narrowing {
  return paging !== undefined && "narrow_with" in paging;
}

/** "a", "a or b", "a, b, or c" */
function orList(names: string[]): string {
  if (names.length < 3) return names.join(" or ");
  return `${names.slice(0, -1).join(", ")}, or ${names[names.length - 1]}`;
}

/**
 * For a list whose API cannot page there is no next request: the notice names
 * the arguments that narrow the list, or says there are none, plus the tool's
 * own note on another way to the omitted items.
 */
function narrowRequest({ narrow_with, note }: Narrowing): NextRequest {
  const how =
    narrow_with.length > 0
      ? `This tool cannot page to the omitted items. Narrow the request with ${orList(narrow_with)} to see them.`
      : "This tool cannot page to the omitted items and has no argument that narrows the list.";
  return { next: null, narrow_with, how: note ? `${how} ${note}` : how };
}

/**
 * The request that returns the omitted items, under the tool's argument names.
 *
 * Offset paging resumes at the first omitted item. Cursor paging repeats this
 * request at the size that fit, which returns the same items with a cursor that
 * continues right after them. Page-number paging reads the pages, at the size
 * that fit, from the one holding the first omitted item to the one holding the
 * last item of this page, then resumes at the next page at the original size.
 * Those pages can repeat items at their edges but never skip one, and paging on
 * at the smaller size instead of resuming skips nothing either.
 */
function nextRequest(kept: number, onPage: number, paging: PageArgs | undefined): NextRequest {
  const sizeKey = paging ? SIZE_KEYS.find((key) => typeof paging[key] === "number") : undefined;
  if (!paging || !sizeKey) {
    return {
      next: null,
      how: "This tool cannot page to the omitted items. Narrow the request (its filters or scope) to see them.",
    };
  }
  const pageSize = paging[sizeKey] as number;

  if ("offset" in paging) {
    const offset = (paging.offset ?? 0) + kept;
    return {
      next: { offset, [sizeKey]: pageSize },
      how: `Request offset ${offset} next: the omitted items start there. ${SKIPS_AHEAD}`,
    };
  }

  const cursorKey = CURSOR_KEYS.find((key) => key in paging);
  if (cursorKey && (paging[cursorKey] !== undefined || typeof paging.page !== "number")) {
    const cursor = paging[cursorKey];
    const same = cursor !== undefined ? `the same ${cursorKey}` : `no ${cursorKey}`;
    return {
      next: { ...(cursor !== undefined ? { [cursorKey]: cursor } : {}), [sizeKey]: kept },
      how: `Repeat this request with ${sizeKey} ${kept} and ${same}: it returns these ${kept} again with a cursor that continues right after them, and any ${sizeKey} works from there. ${SKIPS_AHEAD}`,
    };
  }

  const page = typeof paging.page === "number" ? paging.page : 1;
  const firstOmitted = (page - 1) * pageSize + kept;
  const pageEnd = (page - 1) * pageSize + onPage;
  const from = Math.floor(firstOmitted / kept) + 1;
  const through = Math.ceil(pageEnd / kept);
  // A short page is the last one, so there is nothing to resume at.
  const resume = onPage < pageSize ? null : { page: page + 1, [sizeKey]: pageSize };
  const pages = from === through ? `page ${from}` : `pages ${from} to ${through}`;
  return {
    next: { page: from, [sizeKey]: kept },
    next_through_page: through,
    resume,
    how:
      `Read ${pages} with ${sizeKey} ${kept}` +
      (resume ? `, then resume at page ${page + 1} with ${sizeKey} ${pageSize}` : "") +
      `. Items can repeat at the edges of those pages; none are skipped, and paging on with ${sizeKey} ${kept} skips none either. ${SKIPS_AHEAD}`,
  };
}

/**
 * Creates an error tool response.
 */
export function errorResult(error: unknown): ToolResult {
  const message =
    error instanceof Error ? error.message : String(error);
  return {
    content: [{ type: "text", text: `Error: ${message}` }],
    isError: true,
  };
}

/**
 * Wraps an async tool handler with standard error handling.
 */
export function withErrorHandling<TArgs>(
  handler: (args: TArgs) => Promise<ToolResult>
): (args: TArgs) => Promise<ToolResult> {
  return async (args: TArgs) => {
    try {
      return await handler(args);
    } catch (error) {
      return errorResult(error);
    }
  };
}

/**
 * The item count from a Sophos REST page object. `pages.items` is the count;
 * most APIs send it only when the request has `pageTotal=true`. `pages.total`
 * counts pages, so it says only that a list with no pages has no items. Never
 * the length of the current page: null when Sophos gives no count.
 */
export function itemTotal(
  pages: { total?: unknown; items?: unknown } | null | undefined
): number | null {
  if (typeof pages?.items === "number") return pages.items;
  if (pages?.total === 0) return 0;
  return null;
}

/**
 * Attaches non-empty warnings to a result object. Tools surface partial
 * response and migration warnings this way rather than dropping them.
 */
export function withWarnings<T extends object>(
  result: T,
  warnings: string[]
): T | (T & { warnings: string[] }) {
  return warnings.length > 0 ? { ...result, warnings } : result;
}
