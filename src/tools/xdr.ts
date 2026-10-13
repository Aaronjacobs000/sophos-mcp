/**
 * Tools: sophos_run_xdr_query, sophos_get_xdr_query_run, sophos_get_xdr_query_results
 * XDR Data Lake query API — async SQL queries against the Sophos Data Lake.
 * Pattern: POST to start → GET to poll status → GET results when finished.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosQueryRun, SophosXdrQueryResultsPage } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../config/config.js";

export function registerXdrTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- Run XDR Query ---
  server.registerTool(
    "sophos_run_xdr_query",
    {
      title: "Run XDR Data Lake Query",
      description: `Start an asynchronous SQL query against the Sophos XDR Data Lake.

The Data Lake contains historical telemetry data from endpoints. You can query tables such as:
running_processes_windows_sophos, network_interfaces, open_sockets, listening_ports,
authentication_activity, runtime_activity, installed_applications, service_activity,
scheduled_task_activity, browser_plugins, chrome_extensions, changed_files_windows_sophos,
sophos_detections_linux, sophos_ips_windows, and many more.

This is an async API. Returns a run_id. Use sophos_get_xdr_query_run to poll status,
then sophos_get_xdr_query_results to fetch results once finished.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - sql (string): SQL query to execute against the Data Lake.
  - from_date (string, optional): ISO 8601 query window start e.g. "2025-01-01T00:00:00Z".
  - to_date (string, optional): ISO 8601 query window end.
  - query_name (string, optional): Optional label for the query run.

Returns:
  run_id and initial status. Poll with sophos_get_xdr_query_run.

Example SQL:
  SELECT endpoint_id, name, path, sha256 FROM running_processes_windows_sophos LIMIT 100`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        sql: z
          .string()
          .describe("SQL query to execute against the Data Lake"),
        from_date: z
          .string()
          .optional()
          .describe('ISO 8601 query window start e.g. "2025-01-01T00:00:00Z"'),
        to_date: z.string().optional().describe("ISO 8601 query window end"),
        query_name: z
          .string()
          .optional()
          .describe("Optional label for the query run"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, sql, from_date, to_date, query_name }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {
        adHocQuery: {
          template: sql,
          name: query_name ?? `mcp-query-${Date.now()}`,
        },
      };
      if (from_date) body.from = from_date;
      if (to_date) body.to = to_date;

      const run = await client.tenantRequest<SophosQueryRun>(
        resolvedTenantId,
        "/xdr-query/v1/queries/runs",
        { method: "POST", body }
      );
      return jsonResult({
        run_id: run.id,
        status: run.status,
        result: run.result,
        created_at: run.createdAt,
        message: `XDR query started. Poll status with sophos_get_xdr_query_run run_id="${run.id}", then fetch results with sophos_get_xdr_query_results.`,
      });
    })
  );

  // --- Get XDR Query Run Status ---
  server.registerTool(
    "sophos_get_xdr_query_run",
    {
      title: "Get XDR Query Run Status",
      description: `Poll the status of an XDR Data Lake query run started with sophos_run_xdr_query.

Args:
  - run_id (string): The run ID returned by sophos_run_xdr_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status ("pending" or "finished"), result ("notAvailable", "succeeded", or "failed"),
  and ready flag (true when results are available).
  When ready is true, fetch results with sophos_get_xdr_query_results.`,
      inputSchema: {
        run_id: z.string().uuid().describe("Run ID from sophos_run_xdr_query"),
        tenant_id: z
          .string()
          .uuid()
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
      const run = await client.tenantRequest<SophosQueryRun>(
        resolvedTenantId,
        `/xdr-query/v1/queries/runs/${run_id}`
      );
      return jsonResult({
        run_id: run.id,
        status: run.status,
        result: run.result,
        created_at: run.createdAt,
        finished_at: run.finishedAt ?? null,
        expires_at: run.expiresAt ?? null,
        ready: run.status === "finished" && run.result === "succeeded",
      });
    })
  );

  // --- Get XDR Query Results ---
  server.registerTool(
    "sophos_get_xdr_query_results",
    {
      title: "Get XDR Query Results",
      description: `Retrieve results from a completed XDR Data Lake query run.

Use after sophos_get_xdr_query_run shows ready=true (status "finished", result "succeeded").
Uses cursor-based pagination via page_from_key.

Args:
  - run_id (string): The run ID from sophos_run_xdr_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-100, default 50).
  - page_from_key (string, optional): Cursor from previous response's next_key for pagination.

Returns:
  items (rows as key-value objects), columns metadata, and pagination keys.
  Pass next_key as page_from_key in the next call to retrieve subsequent pages.`,
      inputSchema: {
        run_id: z.string().uuid().describe("Run ID from sophos_run_xdr_query"),
        tenant_id: z
          .string()
          .uuid()
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

      const data = await client.tenantRequest<SophosXdrQueryResultsPage>(
        resolvedTenantId,
        `/xdr-query/v1/queries/runs/${run_id}/results`,
        { params }
      );
      return jsonResult({
        run_id,
        count: data.items.length,
        columns: data.metadata?.columns ?? null,
        next_key: data.pages.nextKey ?? null,
        has_more: !!data.pages.nextKey,
        rows: data.items,
      });
    })
  );

  // --- List XDR Query Runs ---
  server.registerTool(
    "sophos_list_xdr_query_runs",
    {
      title: "List XDR Query Runs",
      description: `List XDR Data Lake query runs for a tenant.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (default 50).
  - page (number, optional): Page number (default 1).`,
      inputSchema: {
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
        limit: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).optional().default(DEFAULT_PAGE_SIZE).describe("Results per page (default 50)"),
        page: z.coerce.number().int().min(1).optional().default(1).describe("Page number (default 1)"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<{ items: SophosQueryRun[]; pages: Record<string, unknown> }>(
        resolvedTenantId,
        "/xdr-query/v1/queries/runs",
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult({
        total: (data.pages as Record<string, unknown>)?.total ?? data.items.length,
        page: (data.pages as Record<string, unknown>)?.current ?? page,
        runs: data.items.map((r) => ({
          run_id: r.id,
          status: r.status,
          result: r.result,
          created_at: r.createdAt,
          finished_at: r.finishedAt ?? null,
        })),
      });
    })
  );

  // --- Cancel XDR Query Run ---
  server.registerTool(
    "sophos_cancel_xdr_query_run",
    {
      title: "Cancel XDR Query Run",
      description: `Cancel a running XDR Data Lake query.

Args:
  - run_id (string): Run ID to cancel.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        run_id: z.string().uuid().describe("Run ID to cancel"),
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ run_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(resolvedTenantId, `/xdr-query/v1/queries/runs/${run_id}/cancel`, { method: "POST", body: {} });
      return jsonResult({ status: "cancelled", run_id, message: `XDR query run ${run_id} cancelled.` });
    })
  );

  // --- List XDR Query Categories ---
  server.registerTool(
    "sophos_list_xdr_query_categories",
    {
      title: "List XDR Query Categories",
      description: `List available XDR Data Lake query categories.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(resolvedTenantId, "/xdr-query/v1/queries/categories");
      return jsonResult(data);
    })
  );

  // --- Get XDR Query Category ---
  server.registerTool(
    "sophos_get_xdr_query_category",
    {
      title: "Get XDR Query Category",
      description: `Get details of a specific XDR Data Lake query category.

Args:
  - category_id (string): Category ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        category_id: z.string().describe("Category ID"),
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ category_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(resolvedTenantId, `/xdr-query/v1/queries/categories/${category_id}`);
      return jsonResult(data);
    })
  );

  // --- List Saved XDR Queries ---
  server.registerTool(
    "sophos_list_xdr_queries",
    {
      title: "List Saved XDR Queries",
      description: `List saved/canned XDR Data Lake queries.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - category_id (string, optional): Filter by category ID.
  - limit (number, optional): Results per page (default 50).
  - page (number, optional): Page number (default 1).`,
      inputSchema: {
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
        category_id: z.string().optional().describe("Filter by category ID"),
        limit: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).optional().default(DEFAULT_PAGE_SIZE).describe("Results per page (default 50)"),
        page: z.coerce.number().int().min(1).optional().default(1).describe("Page number (default 1)"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ tenant_id, category_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = { pageSize: String(limit), page: String(page) };
      if (category_id) params.categoryId = category_id;
      const data = await client.tenantRequest<Record<string, unknown>>(resolvedTenantId, "/xdr-query/v1/queries", { params });
      return jsonResult(data);
    })
  );

  // --- Get Saved XDR Query ---
  server.registerTool(
    "sophos_get_xdr_query",
    {
      title: "Get Saved XDR Query",
      description: `Get details of a specific saved XDR Data Lake query including its SQL template.

Args:
  - query_id (string): Query ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        query_id: z.string().describe("Query ID"),
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ query_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(resolvedTenantId, `/xdr-query/v1/queries/${query_id}`);
      return jsonResult(data);
    })
  );
}
