/**
 * Tools: sophos_list_live_discover_queries, sophos_run_live_discover_query,
 *        sophos_get_live_discover_run, sophos_get_live_discover_results
 * Live Discover API — run OSquery-based SQL queries on live endpoints in real time.
 * Pattern: List available queries → POST to start run → GET to poll status → GET results.
 * Rate limit: 10 runs/minute, 500 runs/day.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type {
  SophosLiveDiscoverQueryPage,
  SophosLiveDiscoverRun,
  SophosLiveDiscoverResultsPage,
} from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../config/config.js";

export function registerLiveDiscoverTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Live Discover Queries ---
  server.registerTool(
    "sophos_list_live_discover_queries",
    {
      title: "List Live Discover Queries",
      description: `List available saved queries for Sophos Live Discover.

Returns both Sophos-managed canned queries and custom queries defined in the tenant.
Use the query ID from this list with sophos_run_live_discover_query to run a saved query.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of queries with: id, name, description, template (SQL).`,
      inputSchema: {
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(MAX_PAGE_SIZE)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results per page (default 50)"),
        page: z
          .number()
          .int()
          .min(1)
          .optional()
          .default(1)
          .describe("Page number (default 1)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<SophosLiveDiscoverQueryPage>(
        resolvedTenantId,
        "/live-discover/v1/queries",
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult({
        total: data.pages.total,
        page: data.pages.current ?? page,
        page_size: data.pages.size,
        queries: data.items.map((q) => ({
          id: q.id,
          name: q.name,
          description: q.description ?? null,
          template: q.template ?? null,
        })),
      });
    })
  );

  // --- Run Live Discover Query ---
  server.registerTool(
    "sophos_run_live_discover_query",
    {
      title: "Run Live Discover Query",
      description: `Start an asynchronous Live Discover query on live endpoints using OSquery SQL.

Live Discover queries run directly on live endpoints (not historical Data Lake data).
Rate limited to 10 runs/minute, 500 runs/day.

You can run either a saved query (by query_id) or an ad hoc SQL query.
Target endpoints using endpoint_ids (specific endpoints), hostname_contains (partial match),
or all_endpoints=true (all endpoints in the tenant).

IMPORTANT: Many saved queries use variables (e.g. $$process_name$$). When running a saved
query that has variable placeholders, you MUST provide the variables array with the values.
Check the query template from sophos_list_live_discover_queries to see required variables.

This is an async API. Returns a run_id. Use sophos_get_live_discover_run to poll status,
then sophos_get_live_discover_results to retrieve results once finished.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - query_id (string, optional): ID of a saved query to run (from sophos_list_live_discover_queries).
  - sql (string, optional): Ad hoc SQL query to run (alternative to query_id).
  - query_name (string, optional): Label for the ad hoc query.
  - variables (array, optional): Variable substitutions for saved query templates.
    Each entry: { name: "variable_name", dataType: "text", value: "value" }.
  - endpoint_ids (array, optional): List of specific endpoint UUIDs to target.
  - hostname_contains (string, optional): Target endpoints whose hostname contains this string.
  - all_endpoints (boolean, optional): Target all endpoints in the tenant (use with caution).

Returns:
  run_id and initial status. Poll with sophos_get_live_discover_run.

Example SQL (OSquery):
  SELECT pid, name, path, cmdline FROM processes WHERE name LIKE '%powershell%'`,
      inputSchema: {
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        query_id: z
          .string()
          .guid()
          .optional()
          .describe("ID of a saved query to run (from sophos_list_live_discover_queries)"),
        sql: z
          .string()
          .optional()
          .describe("Ad hoc OSquery SQL to run (alternative to query_id)"),
        query_name: z
          .string()
          .optional()
          .describe("Label for the ad hoc query"),
        variables: z
          .array(
            z.object({
              name: z.string().describe("Variable name (without $$ delimiters)"),
              dataType: z.string().optional().default("text").describe('Data type (default "text")'),
              value: z.string().describe("Variable value"),
            })
          )
          .optional()
          .describe("Variable substitutions for saved query templates"),
        endpoint_ids: z
          .array(z.string().guid())
          .optional()
          .describe("Specific endpoint UUIDs to target"),
        hostname_contains: z
          .string()
          .optional()
          .describe("Target endpoints whose hostname contains this string"),
        all_endpoints: z
          .boolean()
          .optional()
          .describe("Target all endpoints in the tenant"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({
        tenant_id,
        query_id,
        sql,
        query_name,
        variables,
        endpoint_ids,
        hostname_contains,
        all_endpoints,
      }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        if (!query_id && !sql) {
          throw new Error("Either query_id or sql must be provided.");
        }

        // Build query spec
        const body: Record<string, unknown> = {};
        if (query_id) {
          body.savedQuery = { queryId: query_id };
          if (variables?.length) {
            body.variables = variables;
          }
        } else {
          body.adHocQuery = {
            template: sql,
            name: query_name ?? `mcp-query-${Date.now()}`,
          };
        }

        // Build endpoint targeting
        if (endpoint_ids?.length) {
          body.matchEndpoints = { filters: [{ ids: endpoint_ids }] };
        } else if (hostname_contains) {
          body.matchEndpoints = { filters: [{ hostnameContains: hostname_contains }] };
        } else if (all_endpoints) {
          body.matchEndpoints = { all: true };
        } else {
          throw new Error(
            "Must specify endpoint targeting: endpoint_ids, hostname_contains, or all_endpoints=true."
          );
        }

        const run = await client.tenantRequest<SophosLiveDiscoverRun>(
          resolvedTenantId,
          "/live-discover/v1/queries/runs",
          { method: "POST", body }
        );
        return jsonResult({
          run_id: run.id,
          status: run.status,
          created_at: run.createdAt ?? null,
          endpoint_counts: run.endpointCounts ?? null,
          message: `Live Discover query started. Poll status with sophos_get_live_discover_run run_id="${run.id}", then fetch results with sophos_get_live_discover_results.`,
        });
      }
    )
  );

  // --- Get Live Discover Run Status ---
  server.registerTool(
    "sophos_get_live_discover_run",
    {
      title: "Get Live Discover Run Status",
      description: `Poll the status of a Live Discover query run started with sophos_run_live_discover_query.

Args:
  - run_id (string): The run ID returned by sophos_run_live_discover_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status, endpoint_counts (how many endpoints responded/failed/pending), performance metrics.
  When status indicates completion, fetch results with sophos_get_live_discover_results.`,
      inputSchema: {
        run_id: z.string().guid().describe("Run ID from sophos_run_live_discover_query"),
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ run_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const run = await client.tenantRequest<SophosLiveDiscoverRun>(
        resolvedTenantId,
        `/live-discover/v1/queries/runs/${run_id}`
      );
      return jsonResult({
        run_id: run.id,
        status: run.status,
        created_at: run.createdAt ?? null,
        finished_at: run.finishedAt ?? null,
        endpoint_counts: run.endpointCounts ?? null,
        performance: run.performance ?? null,
      });
    })
  );

  // --- Get Live Discover Results ---
  server.registerTool(
    "sophos_get_live_discover_results",
    {
      title: "Get Live Discover Query Results",
      description: `Retrieve aggregated results from a Live Discover query run.

Results are available once sophos_get_live_discover_run shows a completed status.
Uses cursor-based pagination via page_from_key.

Each result row includes the query output columns plus a sophos_endpoint_id field
identifying which endpoint produced the row.

Args:
  - run_id (string): The run ID from sophos_run_live_discover_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-100, default 50).
  - page_from_key (string, optional): Cursor from previous response's next_key for pagination.

Returns:
  items (rows from all endpoints), next_key (for pagination), has_more.`,
      inputSchema: {
        run_id: z.string().guid().describe("Run ID from sophos_run_live_discover_query"),
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(MAX_PAGE_SIZE)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results per page (default 50)"),
        page_from_key: z
          .string()
          .optional()
          .describe("Cursor from previous response's next_key for pagination"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ run_id, tenant_id, limit, page_from_key }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = { pageSize: String(limit) };
      if (page_from_key) params.pageFromKey = page_from_key;

      const data = await client.tenantRequest<SophosLiveDiscoverResultsPage>(
        resolvedTenantId,
        `/live-discover/v1/queries/runs/${run_id}/results`,
        { params }
      );
      return jsonResult({
        run_id,
        count: data.items.length,
        next_key: data.pages.nextKey ?? null,
        has_more: !!data.pages.nextKey,
        rows: data.items,
      });
    })
  );
}
