/**
 * Tools: sophos_run_detections_query, sophos_get_detections_run, sophos_get_detections_results,
 *        sophos_run_detection_groups_query, sophos_get_detection_groups_run, sophos_get_detection_groups_results
 * Async query API for individual detections and detection groups.
 * Pattern: POST to start → GET to poll status → GET results when finished.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type {
  SophosQueryRun,
  SophosDetectionsResultPage,
} from "../types/sophos.js";
import type { FusionMigrationGuard } from "../fusion/migration.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerDetectionTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver,
  migration: FusionMigrationGuard
): void {
  // --- Run Detections Query ---
  server.registerTool(
    "sophos_run_detections_query",
    {
      title: "Run Sophos Detections Query",
      description: `Start an asynchronous query to retrieve individual detections (XDR/EDR findings).

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_search_detections there.

This is an async API. The tool returns a run ID. Use sophos_get_detections_run to poll
the status, then sophos_get_detections_results to retrieve results once status is "finished".

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - from_date (string, optional): ISO 8601 start date e.g. "2025-01-01T00:00:00Z".
  - to_date (string, optional): ISO 8601 end date.
  - severity (array, optional): Filter by severity levels (integers e.g. [4, 8, 9]).
  - sort_direction (string, optional): Sort order: "asc" or "desc" (default "desc") by sensorGeneratedAt.

Returns:
  run_id and initial status ("pending"). Poll with sophos_get_detections_run.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        from_date: z
          .string()
          .optional()
          .describe('ISO 8601 start date e.g. "2025-01-01T00:00:00Z"'),
        to_date: z.string().optional().describe("ISO 8601 end date"),
        severity: z
          .array(z.coerce.number().int())
          .optional()
          .describe("Filter by severity levels (integers e.g. [4, 8, 9])"),
        sort_direction: z
          .enum(["asc", "desc"])
          .optional()
          .default("desc")
          .describe('Sort by sensorGeneratedAt: "asc" or "desc" (default "desc")'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, from_date, to_date, severity, sort_direction }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_run_detections_query", "sophos_fusion_search_detections");
      const body: Record<string, unknown> = {
        sort: [{ field: "sensorGeneratedAt", direction: sort_direction }],
      };
      if (from_date) body.from = from_date;
      if (to_date) body.to = to_date;
      if (severity?.length) body.severity = severity;

      const run = await client.tenantRequest<SophosQueryRun>(
        resolvedTenantId,
        "/detections/v1/queries/detections",
        { method: "POST", body }
      );
      return jsonResult(withWarnings({
        run_id: run.id,
        status: run.status,
        result: run.result,
        created_at: run.createdAt,
        message: `Query started. Poll status with sophos_get_detections_run run_id="${run.id}", then fetch results with sophos_get_detections_results.`,
      }, warnings));
    })
  );

  // --- Get Detections Run Status ---
  server.registerTool(
    "sophos_get_detections_run",
    {
      title: "Get Sophos Detections Query Run Status",
      description: `Poll the status of a detections query run started with sophos_run_detections_query.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_search_detections there.

Args:
  - run_id (string): The run ID returned by sophos_run_detections_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status ("pending" or "finished"), result ("notAvailable", "succeeded", or "failed").
  When status is "finished" and result is "succeeded", use sophos_get_detections_results to fetch results.`,
      inputSchema: {
        run_id: z.string().uuid().describe("Run ID from sophos_run_detections_query"),
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
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_get_detections_run", "sophos_fusion_search_detections");
      const run = await client.tenantRequest<SophosQueryRun>(
        resolvedTenantId,
        `/detections/v1/queries/detections/${run_id}`
      );
      return jsonResult(withWarnings({
        run_id: run.id,
        status: run.status,
        result: run.result,
        created_at: run.createdAt,
        finished_at: run.finishedAt ?? null,
        ready: run.status === "finished" && run.result === "succeeded",
      }, warnings));
    })
  );

  // --- Get Detections Results ---
  server.registerTool(
    "sophos_get_detections_results",
    {
      title: "Get Sophos Detections Query Results",
      description: `Retrieve results from a completed detections query run.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_search_detections there.

Use after sophos_get_detections_run shows status "finished" and result "succeeded".

Args:
  - run_id (string): The run ID from sophos_run_detections_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated detections with: id, attackType, detectionRule, severity, sensorGeneratedAt, device, sensor.`,
      inputSchema: {
        run_id: z.string().uuid().describe("Run ID from sophos_run_detections_query"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
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
    withErrorHandling(async ({ run_id, tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_get_detections_results", "sophos_fusion_search_detections");
      const data = await client.tenantRequest<SophosDetectionsResultPage>(
        resolvedTenantId,
        `/detections/v1/queries/detections/${run_id}/results`,
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult(withWarnings({
        run_id,
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        page_size: data.pages.size,
        detections: data.items,
      }, warnings));
    })
  );

  // --- Run Detection Groups Query ---
  server.registerTool(
    "sophos_run_detection_groups_query",
    {
      title: "Run Sophos Detection Groups Query",
      description: `Start an asynchronous query to retrieve grouped detections (related detections grouped together).

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_search_detections there.

This is an async API. Returns a run ID. Use sophos_get_detection_groups_run to poll
the status, then sophos_get_detection_groups_results to retrieve results once finished.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - from_date (string, optional): ISO 8601 start date e.g. "2025-01-01T00:00:00Z".
  - to_date (string, optional): ISO 8601 end date.
  - severity (array, optional): Filter by severity levels (integers e.g. [4, 8, 9]).
  - sort_direction (string, optional): Sort order: "asc" or "desc" (default "desc").

Returns:
  run_id and initial status ("pending"). Poll with sophos_get_detection_groups_run.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        from_date: z
          .string()
          .optional()
          .describe('ISO 8601 start date e.g. "2025-01-01T00:00:00Z"'),
        to_date: z.string().optional().describe("ISO 8601 end date"),
        severity: z
          .array(z.coerce.number().int())
          .optional()
          .describe("Filter by severity levels (integers e.g. [4, 8, 9])"),
        sort_direction: z
          .enum(["asc", "desc"])
          .optional()
          .default("desc")
          .describe('Sort direction: "asc" or "desc" (default "desc")'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, from_date, to_date, severity, sort_direction }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_run_detection_groups_query", "sophos_fusion_search_detections");
      const body: Record<string, unknown> = {
        sort: [{ field: "sensorGeneratedAt", direction: sort_direction }],
      };
      if (from_date) body.from = from_date;
      if (to_date) body.to = to_date;
      if (severity?.length) body.severity = severity;

      const run = await client.tenantRequest<SophosQueryRun>(
        resolvedTenantId,
        "/detections/v1/queries/detection-groups",
        { method: "POST", body }
      );
      return jsonResult(withWarnings({
        run_id: run.id,
        status: run.status,
        result: run.result,
        created_at: run.createdAt,
        message: `Query started. Poll with sophos_get_detection_groups_run run_id="${run.id}", then fetch results with sophos_get_detection_groups_results.`,
      }, warnings));
    })
  );

  // --- Get Detection Groups Run Status ---
  server.registerTool(
    "sophos_get_detection_groups_run",
    {
      title: "Get Sophos Detection Groups Query Run Status",
      description: `Poll the status of a detection groups query run started with sophos_run_detection_groups_query.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_search_detections there.

Args:
  - run_id (string): The run ID from sophos_run_detection_groups_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status ("pending" or "finished") and result. When finished and succeeded, fetch results with sophos_get_detection_groups_results.`,
      inputSchema: {
        run_id: z.string().uuid().describe("Run ID from sophos_run_detection_groups_query"),
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
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_get_detection_groups_run", "sophos_fusion_search_detections");
      const run = await client.tenantRequest<SophosQueryRun>(
        resolvedTenantId,
        `/detections/v1/queries/detection-groups/${run_id}`
      );
      const ready = run.status === "finished" && run.result === "succeeded";
      const failed = run.status === "finished" && run.result === "failed";
      return jsonResult(withWarnings({
        run_id: run.id,
        status: run.status,
        result: run.result,
        created_at: run.createdAt,
        finished_at: run.finishedAt ?? null,
        ready,
        ...(failed && {
          message:
            "No grouped detections found for the queried time period. This is expected for tenants with no detection groups. Try sophos_run_detections_query instead to query individual detections.",
        }),
      }, warnings));
    })
  );

  // --- Get Detection Groups Results ---
  server.registerTool(
    "sophos_get_detection_groups_results",
    {
      title: "Get Sophos Detection Groups Query Results",
      description: `Retrieve results from a completed detection groups query run.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_search_detections there.

Use after sophos_get_detection_groups_run shows status "finished" and result "succeeded".

Args:
  - run_id (string): The run ID from sophos_run_detection_groups_query.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated detection groups with grouped detection data.`,
      inputSchema: {
        run_id: z.string().uuid().describe("Run ID from sophos_run_detection_groups_query"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
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
    withErrorHandling(async ({ run_id, tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_get_detection_groups_results", "sophos_fusion_search_detections");
      const data = await client.tenantRequest<SophosDetectionsResultPage>(
        resolvedTenantId,
        `/detections/v1/queries/detection-groups/${run_id}/results`,
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult(withWarnings({
        run_id,
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        page_size: data.pages.size,
        detection_groups: data.items,
      }, warnings));
    })
  );
}
