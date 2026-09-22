/**
 * Tools: sophos_list_cases, sophos_get_case, sophos_create_case, sophos_update_case,
 *        sophos_list_case_detections, sophos_get_case_mitre_summary,
 *        sophos_delete_case, sophos_list_case_impacted_entities, sophos_get_case_detection
 * Interact with the Sophos Cases API /cases/v1/cases
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type {
  SophosCase,
  SophosCasePage,
  SophosCaseDetection,
  SophosCaseDetectionPage,
  SophosCaseMitreSummary,
} from "../types/sophos.js";
import type { FusionMigrationGuard } from "../fusion/migration.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";

// Cases API max page size is 50
const CASES_MAX_PAGE_SIZE = 50;

export function registerCaseTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver,
  migration: FusionMigrationGuard
): void {
  // --- List Cases ---
  server.registerTool(
    "sophos_list_cases",
    {
      title: "List Sophos Cases",
      description: `List investigation cases from a Sophos Central tenant.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_list_cases there.

Retrieves cases from the Cases API with optional pagination.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-50, default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of cases with: id, name, type, severity, status, assignee, detectionCount, createdAt, updatedAt.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(CASES_MAX_PAGE_SIZE)
          .optional()
          .default(CASES_MAX_PAGE_SIZE)
          .describe("Results per page (max 50)"),
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
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_list_cases", "sophos_fusion_list_cases");
      const data = await client.tenantRequest<SophosCasePage>(
        resolvedTenantId,
        "/cases/v1/cases",
        {
          params: {
            pageSize: String(limit),
            page: String(page),
          },
        }
      );
      return jsonResult(withWarnings({
        total: data.pages.total,
        page: data.pages.current ?? page,
        page_size: data.pages.size,
        total_pages: data.pages.total,
        cases: data.items.map(formatCase),
      }, warnings));
    })
  );

  // --- Get Case ---
  server.registerTool(
    "sophos_get_case",
    {
      title: "Get Sophos Case",
      description: `Get full details of a specific Sophos Central case by ID.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_get_case there.

Args:
  - case_id (string): The case ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Full case details including name, severity, status, assignee, overview, detectionCount, createdAt, updatedAt.`,
      inputSchema: {
        case_id: z.string().describe("Case ID to retrieve (e.g. '1-598868')"),
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
    withErrorHandling(async ({ case_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_get_case", "sophos_fusion_get_case");
      const data = await client.tenantRequest<SophosCase>(
        resolvedTenantId,
        `/cases/v1/cases/${case_id}`
      );
      return jsonResult(withWarnings(formatCase(data), warnings));
    })
  );

  // --- Create Case ---
  server.registerTool(
    "sophos_create_case",
    {
      title: "Create Sophos Case",
      description: `Create a new self-managed investigation case in Sophos Central.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_create_case there.

Only self-managed cases can be created via the API.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string): Case name.
  - severity (string): Case severity: "informational", "low", "medium", "high", "critical".
  - status (string): Initial status: "new" or "investigating".
  - initial_detection_id (string): ID of the detection that triggered this case.
  - assignee (string): Email address of a tenant admin. The API rejects a create without one ("Assignee cannot be null or blank").
  - overview (string, optional): Case overview/description.

Returns:
  The created case object.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().describe("Case name"),
        severity: z
          .enum(["informational", "low", "medium", "high", "critical"])
          .describe("Case severity"),
        status: z
          .enum(["new", "investigating"])
          .describe("Initial case status"),
        initial_detection_id: z
          .string()
          .describe("ID of the detection that triggered this case"),
        assignee: z
          .string()
          .email()
          .describe("Email address of a tenant admin (required by the API)"),
        overview: z
          .string()
          .optional()
          .describe("Case overview/description"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({ tenant_id, name, severity, status, initial_detection_id, assignee, overview }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
        const warnings = await migration.assertClassic(resolvedTenantId, "sophos_create_case", "sophos_fusion_create_case");
        // The Cases API rejects a create without an assignee (400
        // "Assignee cannot be null or blank", verified live 21/09/2026).
        const body: Record<string, unknown> = {
          type: "investigation",
          name,
          severity,
          status,
          initialDetectionId: initial_detection_id,
          assignee,
        };
        if (overview) body.overview = overview;

        const data = await client.tenantRequest<SophosCase>(
          resolvedTenantId,
          "/cases/v1/cases",
          { method: "POST", body }
        );
        return jsonResult(withWarnings(formatCase(data), warnings));
      }
    )
  );

  // --- Update Case ---
  server.registerTool(
    "sophos_update_case",
    {
      title: "Update Sophos Case",
      description: `Update an existing self-managed case in Sophos Central.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_update_case there.

Only self-managed cases can be updated via the API. Supply only the fields to change.

Args:
  - case_id (string): The case ID to update.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string, optional): New case name.
  - severity (string, optional): New severity: "informational", "low", "medium", "high", "critical".
  - status (string, optional): New status: "new", "investigating", "closed".
  - assignee (string, optional): Email address of the new assignee.
  - overview (string, optional): Updated case overview.

Returns:
  The updated case object.`,
      inputSchema: {
        case_id: z.string().describe("Case ID to update (e.g. '1-598868')"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().optional().describe("New case name"),
        severity: z
          .enum(["informational", "low", "medium", "high", "critical"])
          .optional()
          .describe("New severity"),
        status: z
          .enum(["new", "investigating", "closed"])
          .optional()
          .describe("New status"),
        assignee: z
          .string()
          .email()
          .optional()
          .describe("Email address of the new assignee"),
        overview: z.string().optional().describe("Updated case overview"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({ case_id, tenant_id, name, severity, status, assignee, overview }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
        const warnings = await migration.assertClassic(resolvedTenantId, "sophos_update_case", "sophos_fusion_update_case");
        const body: Record<string, unknown> = {};
        if (name !== undefined) body.name = name;
        if (severity !== undefined) body.severity = severity;
        if (status !== undefined) body.status = status;
        if (assignee !== undefined) body.assignee = assignee;
        if (overview !== undefined) body.overview = overview;

        const data = await client.tenantRequest<SophosCase>(
          resolvedTenantId,
          `/cases/v1/cases/${case_id}`,
          { method: "PATCH", body }
        );
        return jsonResult(withWarnings(formatCase(data), warnings));
      }
    )
  );

  // --- List Case Detections ---
  server.registerTool(
    "sophos_list_case_detections",
    {
      title: "List Sophos Case Detections",
      description: `List the detections associated with a specific Sophos Central case.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_get_case_evidence for the IDs or sophos_fusion_get_case_summary for the resolved detections there.

Args:
  - case_id (string): The case ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-50, default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of detections: id, attackType, detectionRule, severity, sensorGeneratedAt, device, sensor.`,
      inputSchema: {
        case_id: z.string().describe("Case ID to list detections for (e.g. '1-598868')"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(CASES_MAX_PAGE_SIZE)
          .optional()
          .default(CASES_MAX_PAGE_SIZE)
          .describe("Results per page (max 50)"),
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
    withErrorHandling(async ({ case_id, tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_list_case_detections", "sophos_fusion_get_case_evidence for the IDs or sophos_fusion_get_case_summary for the resolved detections");
      const data = await client.tenantRequest<SophosCaseDetectionPage>(
        resolvedTenantId,
        `/cases/v1/cases/${case_id}/detections`,
        {
          params: {
            pageSize: String(limit),
            page: String(page),
          },
        }
      );
      return jsonResult(withWarnings({
        case_id,
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        page_size: data.pages.size,
        detections: data.items,
      }, warnings));
    })
  );

  // --- Get Case MITRE ATT&CK Summary ---
  server.registerTool(
    "sophos_get_case_mitre_summary",
    {
      title: "Get Case MITRE ATT&CK Summary",
      description: `Get the MITRE ATT&CK tactics and techniques summary for a Sophos Central case.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_get_case_summary, which builds the MITRE roll-up there.

Provides a breakdown of ATT&CK tactics observed in the case detections, with associated techniques and counts.

Args:
  - case_id (string): The case ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  MITRE ATT&CK summary with tactics, techniques, and detection counts.`,
      inputSchema: {
        case_id: z.string().describe("Case ID to get MITRE summary for (e.g. '1-598868')"),
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
    withErrorHandling(async ({ case_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_get_case_mitre_summary", "sophos_fusion_get_case_summary, which builds the MITRE roll-up");
      const data = await client.tenantRequest<SophosCaseMitreSummary>(
        resolvedTenantId,
        `/cases/v1/cases/${case_id}/mitre-attack-summary`
      );
      return jsonResult(withWarnings({ case_id, mitre_attack_summary: data }, warnings));
    })
  );

  // --- Delete Case ---
  server.registerTool(
    "sophos_delete_case",
    {
      title: "Delete Sophos Case",
      description: `Delete an investigation case from Sophos Central.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_update_case to close the case with a verdict and then archive it (Fusion has no delete) there.

Only self-managed cases can be deleted via the API.

Args:
  - case_id (string): Case ID to delete (e.g. '1-598868').
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        case_id: z.string().describe("Case ID to delete (e.g. '1-598868')"),
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ case_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_delete_case", "sophos_fusion_update_case to close the case with a verdict and then archive it (Fusion has no delete)");
      await client.tenantRequest(resolvedTenantId, `/cases/v1/cases/${case_id}`, { method: "DELETE" });
      return jsonResult(withWarnings({ status: "deleted", case_id, message: `Case ${case_id} deleted.` }, warnings));
    })
  );

  // --- List Case Impacted Entities ---
  server.registerTool(
    "sophos_list_case_impacted_entities",
    {
      title: "List Case Impacted Entities",
      description: `List impacted entities (endpoints, users) associated with a Sophos Central case.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_get_case_summary (source and target entities on each detection) there.

Args:
  - case_id (string): Case ID (e.g. '1-598868').
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Results per page (1-50, default 50).
  - page (number, optional): Page number (default 1).`,
      inputSchema: {
        case_id: z.string().describe("Case ID (e.g. '1-598868')"),
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
        limit: z.coerce.number().int().min(1).max(CASES_MAX_PAGE_SIZE).optional().default(CASES_MAX_PAGE_SIZE).describe("Results per page (max 50)"),
        page: z.coerce.number().int().min(1).optional().default(1).describe("Page number (default 1)"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ case_id, tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_list_case_impacted_entities", "sophos_fusion_get_case_summary (source and target entities on each detection)");
      const data = await client.tenantRequest<SophosCaseDetectionPage>(
        resolvedTenantId,
        `/cases/v1/cases/${case_id}/impacted-entities`,
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult(withWarnings({
        case_id,
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        impacted_entities: data.items,
      }, warnings));
    })
  );

  // --- Get Case Detection ---
  server.registerTool(
    "sophos_get_case_detection",
    {
      title: "Get Case Detection Detail",
      description: `Get details of a specific detection within a Sophos Central case.

Refused for a tenant that has migrated to Sophos Fusion, where this Classic API references the pre-migration objects; use sophos_fusion_get_case_summary there.

Args:
  - case_id (string): Case ID (e.g. '1-598868').
  - detection_id (string): Detection ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        case_id: z.string().describe("Case ID (e.g. '1-598868')"),
        detection_id: z.string().describe("Detection ID"),
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ case_id, detection_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const warnings = await migration.assertClassic(resolvedTenantId, "sophos_get_case_detection", "sophos_fusion_get_case_summary");
      const data = await client.tenantRequest<SophosCaseDetection>(
        resolvedTenantId,
        `/cases/v1/cases/${case_id}/detections/${detection_id}`
      );
      return jsonResult(withWarnings(data, warnings));
    })
  );
}

function formatCase(c: SophosCase) {
  return {
    id: c.id,
    name: c.name,
    type: c.type,
    severity: c.severity,
    status: c.status,
    assignee: c.assignee ?? null,
    overview: c.overview ?? null,
    managed_by: c.managedBy ?? null,
    detection_count: c.detectionCount ?? null,
    tenant_id: c.tenant.id,
    created_at: c.createdAt,
    created_by: c.createdBy ?? null,
    updated_at: c.updatedAt ?? null,
    initial_detection_id: c.initialDetection?.id ?? null,
  };
}
