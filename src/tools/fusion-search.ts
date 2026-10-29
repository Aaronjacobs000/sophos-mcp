/**
 * Tools: sophos_fusion_create_search, sophos_fusion_get_or_create_search,
 *        sophos_fusion_get_search, sophos_fusion_get_search_results
 * Sophos Fusion Search GraphQL API v1 on https://api.taegis.sophos.com/graphql
 * (released 12/10/2026): Data Lake searches in Fusion Query Language (QL).
 *
 * Asynchronous: start a search, poll it by its URN until COMPLETE, check
 * outcome.success, then page the results by cursor. The SQL XDR Query API
 * (sophos_run_xdr_query) stays available beside it.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { FusionClient } from "../client/fusion-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";
import {
  CREATE_SEARCH,
  GET_OR_CREATE_SEARCH,
  GET_SEARCH,
  SEARCH_RESULTS,
  SEARCH_RESULTS_WITH_FIELDS,
} from "../fusion/queries/search.js";
import type { FusionSearch, FusionSearchResultPage } from "../fusion/types.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";

/** Verified against a live tenant on 29/10/2026. */
export const EXAMPLE_SEARCH_QUERY = "from process earliest=-1h | fields host_id, image_path";

/** searchResults refuses a limit above 1000 (live tenant, 29/10/2026). */
export const MAX_SEARCH_RESULTS_LIMIT = 1000;

const tenantIdSchema = z.string().guid().optional().describe("Tenant ID. Required for partner/org callers.");
const urnSchema = z.string().regex(/^urn:\S+$/, "a URN starting urn:");
const queryInputSchema = {
  tenant_id: tenantIdSchema,
  query: z.string().min(1).describe(`QL query, for example "${EXAMPLE_SEARCH_QUERY}"`),
  metadata: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Optional JSON object stored with the search and returned with it"),
};

/** The search as Sophos returned it, with the step the caller takes next. */
function searchResult(tenantId: string, search: FusionSearch, warnings: string[]) {
  const next =
    search.status !== "COMPLETE"
      ? "Poll sophos_fusion_get_search with this urn every few seconds until status is COMPLETE."
      : search.outcome.success === "ALL"
        ? "Complete. Read the rows with sophos_fusion_get_search_results."
        : `Complete with outcome ${search.outcome.success}: check outcome.errors before using the rows (sophos_fusion_get_search_results).`;
  return withWarnings({ tenant_id: tenantId, next_step: next, search }, warnings);
}

export function registerFusionSearchTools(
  server: McpServer,
  client: FusionClient,
  tenantResolver: TenantResolver
): void {
  // --- Create Search ---
  server.registerTool(
    "sophos_fusion_create_search",
    {
      title: "Start Fusion Data Lake Search",
      description: `Start a new Sophos Fusion Data Lake search with a Fusion Query Language (QL) query and return its search URN. The QL counterpart of sophos_run_xdr_query (SQL), which stays available.

Asynchronous: poll sophos_fusion_get_search with the urn until status is COMPLETE, check outcome.success (ALL, PARTIAL or NONE), then read rows with sophos_fusion_get_search_results. Results expire at expireTime (30 days in testing).

Working example: "${EXAMPLE_SEARCH_QUERY}". Set an explicit earliest, and project with | fields: an unprojected search returns hundreds of fields per row. hostname and enrichSummary are derived fields and cannot be named in | fields; keep host_id to get hostname.

Every call starts a new execution. After a timeout, check before repeating it, or use sophos_fusion_get_or_create_search.

Args:
  - query (string): QL query.
  - metadata (object, optional): JSON object stored with the search.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  next_step and the search: urn, status, outcome, queryText, searchPartitions (one per output schema), times including expireTime, metadata, hostnameMappings.`,
      inputSchema: queryInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, query, metadata }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const input: Record<string, unknown> = { text: query };
      if (metadata !== undefined) input.metadata = metadata;
      const { data, warnings } = await client.query<{ createSearch: FusionSearch | null }>(
        tenantId,
        CREATE_SEARCH,
        { input }
      );
      if (!data.createSearch) throw new Error("createSearch returned no search.");
      return jsonResult(searchResult(tenantId, data.createSearch, warnings));
    })
  );

  // --- Get Or Create Search ---
  server.registerTool(
    "sophos_fusion_get_or_create_search",
    {
      title: "Reuse or Start Fusion Data Lake Search",
      description: `Return a matching Sophos Fusion Data Lake search that is running or complete, or start a new one if none matches. Queries are matched on their canonical form, not their literal text.

Measured 29/10/2026: a query with relative time bounds (earliest=-1h) starts a new search on every call; one with absolute bounds (earliest='2026-10-28T00:00:00Z' and latest='2026-10-28T01:00:00Z') returns the same search. A reused search is not a fresh run.

Same QL rules as sophos_fusion_create_search, for example "${EXAMPLE_SEARCH_QUERY}". Poll with sophos_fusion_get_search, read rows with sophos_fusion_get_search_results.

Args:
  - query (string): QL query.
  - metadata (object, optional): JSON object stored with a new search.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  next_step and the search, as sophos_fusion_create_search.`,
      inputSchema: queryInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, query, metadata }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const input: Record<string, unknown> = { text: query };
      if (metadata !== undefined) input.metadata = metadata;
      const { data, warnings } = await client.query<{ getOrCreateSearch: FusionSearch | null }>(
        tenantId,
        GET_OR_CREATE_SEARCH,
        { input }
      );
      if (!data.getOrCreateSearch) throw new Error("getOrCreateSearch returned no search.");
      return jsonResult(searchResult(tenantId, data.getOrCreateSearch, warnings));
    })
  );

  // --- Get Search ---
  server.registerTool(
    "sophos_fusion_get_search",
    {
      title: "Get Fusion Data Lake Search Status",
      description: `Get a Sophos Fusion Data Lake search's status and diagnostics by its search URN.

status is QUEUED, IN_PROGRESS or COMPLETE. COMPLETE means execution ended, not that it succeeded: outcome.success is ALL (every partition succeeded), PARTIAL or NONE, and outcome.errors holds the failed partitions' messages. errors holds non-fatal warnings about the query. Read the rows before expireTime.

Args:
  - urn (string): Search URN from sophos_fusion_create_search or sophos_fusion_get_or_create_search.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  next_step and the search: urn, status, outcome, errors, queryText, searchPartitions, times, metadata, hostnameMappings.`,
      inputSchema: {
        urn: urnSchema.describe("Search URN"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ urn, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client.query<{ search: FusionSearch | null }>(tenantId, GET_SEARCH, { urn });
      if (!data.search) throw new Error(`Search ${urn} not found.`);
      return jsonResult(searchResult(tenantId, data.search, warnings));
    })
  );

  // --- Get Search Results ---
  server.registerTool(
    "sophos_fusion_get_search_results",
    {
      title: "Get Fusion Data Lake Search Results",
      description: `Read one page of rows from a completed Sophos Fusion Data Lake search, or from one of its partitions.

values is an array of JSON row objects; a row can omit a field or hold null, nested objects or lists. total counts the whole result set, not this page. Pass next_cursor back unchanged as cursor for the next page; there are no more pages when it is null.

include_fields adds field metadata (name, baseType for timestamp units and list or map shapes, logicalType, enumValues, originSchemaTypes). It is off by default because an unprojected search returns over 800 fields (about 150,000 characters measured), more than one response holds; project with | fields in the query first.

Args:
  - urn (string): Search URN, or a partition URN from searchPartitions.
  - cursor (string, optional): next_cursor or previous_cursor from a previous page. Omit for the first page.
  - limit (number, optional): Rows per page, 1 to 1000. Default 50.
  - include_fields (boolean, optional): Add field metadata. Default false.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  returned, total, subtotals per schema, next_cursor, previous_cursor, hostname_mappings, values, and fields when asked.`,
      inputSchema: {
        urn: urnSchema.describe("Search or partition URN"),
        cursor: z.string().optional().describe("Cursor from a previous page"),
        limit: z
          .number()
          .int()
          .min(1)
          .max(MAX_SEARCH_RESULTS_LIMIT)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Rows per page (1-1000, default 50)"),
        include_fields: z.boolean().optional().default(false).describe("Add field metadata"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ urn, cursor, limit, include_fields, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const variables: Record<string, unknown> = { urn, limit };
      if (cursor) variables.cursor = cursor;
      const { data, warnings } = await client.query<{ searchResults: FusionSearchResultPage | null }>(
        tenantId,
        include_fields ? SEARCH_RESULTS_WITH_FIELDS : SEARCH_RESULTS,
        variables
      );
      const page = data.searchResults;
      if (!page) throw new Error(`searchResults returned nothing for ${urn}.`);
      const values = page.values ?? [];
      return jsonResult(
        withWarnings(
          {
            tenant_id: tenantId,
            urn,
            returned: values.length,
            total: page.totals?.total?.value ?? null,
            subtotals: page.totals?.subtotals ?? [],
            next_cursor: page.nextCursor ?? null,
            previous_cursor: page.previousCursor ?? null,
            hostname_mappings: page.hostnameMappings ?? [],
            values,
            ...(include_fields ? { fields: page.fields ?? [] } : {}),
          },
          warnings
        )
      );
    })
  );
}
