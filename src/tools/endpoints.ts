/**
 * Tools: sophos_list_endpoints, sophos_get_endpoint, sophos_scan_endpoint,
 *        sophos_isolate_endpoint, sophos_release_endpoint,
 *        sophos_delete_endpoint, sophos_bulk_delete_endpoints,
 *        sophos_get_tamper_protection, sophos_toggle_tamper_protection,
 *        sophos_get_adaptive_attack_protection, sophos_toggle_adaptive_attack_protection,
 *        sophos_trigger_update_check, sophos_request_forensic_logs,
 *        sophos_get_forensic_log_status, sophos_request_memory_dump,
 *        sophos_get_memory_dump_status, sophos_bulk_isolate_endpoints,
 *        sophos_get_endpoint_isolation_status, sophos_bulk_scan_endpoints,
 *        sophos_bulk_reset_endpoint_health, sophos_bulk_update_tamper_protection
 * Interact with the Sophos Endpoint API /endpoint/v1/endpoints
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosEndpointPage, SophosEndpoint } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

/** The 202 body the bulk endpoint actions (scan, reset health, tamper protection) share. */
interface BulkActionResponse {
  items?: Array<{ id: string; status: string; requestedAt: string }>;
  errors?: Array<{ id: string; errorCode: string; endpointErrorCode?: string; errorMessage: string }>;
}

/** Counts plus the accepted and rejected lists exactly as Sophos returned them. */
function bulkActionResult(requested: number, data: BulkActionResponse, note?: string) {
  const items = data.items ?? [];
  const errors = data.errors ?? [];
  return {
    requested,
    accepted: items.length,
    rejected: errors.length,
    items,
    errors,
    ...(note ? { note } : {}),
  };
}

export function registerEndpointTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Endpoints ---
  server.registerTool(
    "sophos_list_endpoints",
    {
      title: "List Sophos Endpoints",
      description: `List endpoints (computers and servers) from a Sophos Central tenant.

Supports filtering by health status, hostname, OS platform, type, tamper 
protection status, and isolation status. Uses cursor-based pagination.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - health_status (string, optional): Filter by health: "good", "suspicious", "bad", "unknown".
  - hostname_contains (string, optional): Filter by hostname substring.
  - type (string, optional): Filter by type: "computer", "server".
  - tamper_protection (boolean, optional): Filter by tamper protection status.
  - isolation_status (string, optional): Filter by isolation: "isolated", "notIsolated".
  - limit (number, optional): Max results per page (1-100, default 50).
  - cursor (string, optional): Pagination cursor from previous response.
  - fields (string, optional): Comma-separated field list to return only specific fields.

Returns:
  Paginated list of endpoints with health, OS, IP, hostname, assigned person, and protection details.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        health_status: z
          .string()
          .optional()
          .describe('Filter by health: "good", "suspicious", "bad", "unknown"'),
        hostname_contains: z
          .string()
          .optional()
          .describe("Filter by hostname substring"),
        type: z
          .string()
          .optional()
          .describe('Filter by type: "computer", "server"'),
        tamper_protection: z
          .boolean()
          .optional()
          .describe("Filter by tamper protection enabled/disabled"),
        isolation_status: z
          .string()
          .optional()
          .describe('Filter by isolation: "isolated", "notIsolated"'),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Max results per page (default 50)"),
        cursor: z
          .string()
          .optional()
          .describe("Pagination cursor (pageFromKey) from previous response"),
        fields: z
          .string()
          .optional()
          .describe("Comma-separated field list for partial responses"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({
        tenant_id,
        health_status,
        hostname_contains,
        type,
        tamper_protection,
        isolation_status,
        limit,
        cursor,
        fields,
      }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        const params: Record<string, string> = {
          pageSize: String(limit),
        };

        if (cursor) params.pageFromKey = cursor;
        if (health_status) params.healthStatus = health_status;
        if (hostname_contains) params.hostnameContains = hostname_contains;
        if (type) params.type = type;
        if (tamper_protection !== undefined)
          params.tamperProtectionEnabled = String(tamper_protection);
        if (isolation_status) params.isolationStatus = isolation_status;
        if (fields) params.fields = fields;

        const data = await client.tenantRequest<SophosEndpointPage>(
          resolvedTenantId,
          "/endpoint/v1/endpoints",
          { params }
        );

        return jsonResult({
          count: data.items.length,
          total: data.pages.total ?? data.pages.items ?? null,
          next_cursor: data.pages.nextKey ?? null,
          endpoints: data.items.map(formatEndpoint),
        });
      }
    )
  );

  // --- Get Endpoint ---
  server.registerTool(
    "sophos_get_endpoint",
    {
      title: "Get Sophos Endpoint Detail",
      description: `Get full details of a specific endpoint by ID.

Returns complete information including health status, OS details, IP addresses,
assigned person, tamper protection status, assigned products, isolation state,
and service details.

Args:
  - endpoint_id (string): The endpoint ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID to retrieve"),
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
    withErrorHandling(async ({ endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const endpoint = await client.tenantRequest<SophosEndpoint>(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}`
      );
      return jsonResult(formatEndpointDetailed(endpoint));
    })
  );

  // --- Scan Endpoint ---
  server.registerTool(
    "sophos_scan_endpoint",
    {
      title: "Start Sophos Endpoint Scan",
      description: `Trigger an antivirus scan on a specific endpoint.

This is a write action that initiates an on-demand scan on the target device.
The scan runs asynchronously; this tool returns immediately after submitting the request.

Args:
  - endpoint_id (string): The endpoint ID to scan.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID to scan"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/scans`,
        { method: "POST", body: {} }
      );
      return jsonResult({
        status: "scan_initiated",
        endpoint_id,
        message: `Scan initiated on endpoint ${endpoint_id}. The scan runs asynchronously on the device.`,
      });
    })
  );

  // --- Isolate Endpoint ---
  server.registerTool(
    "sophos_isolate_endpoint",
    {
      title: "Isolate Sophos Endpoint",
      description: `Network-isolate a specific endpoint, preventing all network communication 
except to Sophos Central.

WARNING: This is a disruptive action. The isolated endpoint will lose all 
network connectivity except its management connection to Sophos Central. 
Use this for containment of compromised devices.

Args:
  - endpoint_id (string): The endpoint ID to isolate.
  - comment (string, optional): Reason for isolation.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID to isolate"),
        comment: z
          .string()
          .optional()
          .describe("Reason for isolation"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, comment, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { enabled: true };
      if (comment) body.comment = comment;

      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/isolation`,
        { method: "PATCH", body }
      );
      return jsonResult({
        status: "isolated",
        endpoint_id,
        message: `Endpoint ${endpoint_id} has been network-isolated.`,
      });
    })
  );

  // --- Release Endpoint ---
  server.registerTool(
    "sophos_release_endpoint",
    {
      title: "Release Sophos Endpoint from Isolation",
      description: `Remove network isolation from an endpoint, restoring full connectivity.

Args:
  - endpoint_id (string): The endpoint ID to release.
  - comment (string, optional): Reason for releasing isolation.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID to release"),
        comment: z
          .string()
          .optional()
          .describe("Reason for releasing isolation"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, comment, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { enabled: false };
      if (comment) body.comment = comment;

      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/isolation`,
        { method: "PATCH", body }
      );
      return jsonResult({
        status: "released",
        endpoint_id,
        message: `Endpoint ${endpoint_id} has been released from isolation.`,
      });
    })
  );

  // --- Delete Endpoint ---
  server.registerTool(
    "sophos_delete_endpoint",
    {
      title: "Delete Sophos Endpoint",
      description: `Delete a specific endpoint from Sophos Central.

WARNING: This permanently removes the endpoint record. The device will need
to be re-registered if you want to manage it again.

Args:
  - endpoint_id (string): The endpoint ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID to delete"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        endpoint_id,
        message: `Endpoint ${endpoint_id} has been deleted from Sophos Central.`,
      });
    })
  );

  // --- Bulk Delete Endpoints ---
  server.registerTool(
    "sophos_bulk_delete_endpoints",
    {
      title: "Bulk Delete Sophos Endpoints",
      description: `Bulk delete multiple endpoints from Sophos Central.

WARNING: This permanently removes the endpoint records. The devices will need
to be re-registered if you want to manage them again.

Args:
  - ids (string[]): Endpoint IDs to delete (1 to 1000).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        ids: z
          .array(z.string().uuid())
          .min(1)
          .max(1000)
          .describe("Endpoint IDs to delete"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        "/endpoint/v1/endpoints/delete",
        { method: "POST", body: { endpointIds: ids } }
      );
      return jsonResult(data);
    })
  );

  // --- Get Tamper Protection ---
  server.registerTool(
    "sophos_get_tamper_protection",
    {
      title: "Get Tamper Protection Status",
      description: `Get tamper protection status and password for a specific endpoint.

Returns whether tamper protection is enabled and the tamper protection password
needed to uninstall or reconfigure the agent locally.

Args:
  - endpoint_id (string): The endpoint ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID"),
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
    withErrorHandling(async ({ endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/tamper-protection`
      );
      return jsonResult(data);
    })
  );

  // --- Toggle Tamper Protection ---
  server.registerTool(
    "sophos_toggle_tamper_protection",
    {
      title: "Toggle Tamper Protection",
      description: `Enable or disable tamper protection on a specific endpoint.

Tamper protection prevents users from uninstalling or reconfiguring the Sophos
agent without the tamper protection password. Disabling this reduces security.

Args:
  - endpoint_id (string): The endpoint ID.
  - enabled (boolean): Whether to enable or disable tamper protection.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID"),
        enabled: z
          .boolean()
          .describe("Whether to enable (true) or disable (false) tamper protection"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, enabled, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/tamper-protection`,
        { method: "POST", body: { enabled } }
      );
      return jsonResult(data);
    })
  );

  // --- Get Adaptive Attack Protection ---
  server.registerTool(
    "sophos_get_adaptive_attack_protection",
    {
      title: "Get Adaptive Attack Protection Status",
      description: `Get the Adaptive Attack Protection (AAP) status for a specific endpoint.

AAP automatically applies additional protections when an active attack is
detected on the endpoint.

Args:
  - endpoint_id (string): The endpoint ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID"),
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
    withErrorHandling(async ({ endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/adaptive-attack-protection`
      );
      return jsonResult(data);
    })
  );

  // --- Toggle Adaptive Attack Protection ---
  server.registerTool(
    "sophos_toggle_adaptive_attack_protection",
    {
      title: "Toggle Adaptive Attack Protection",
      description: `Enable or disable Adaptive Attack Protection (AAP) on a specific endpoint.

AAP automatically applies additional protections when an active attack is
detected. Disabling this may reduce protection during active attacks.

Args:
  - endpoint_id (string): The endpoint ID.
  - enabled (boolean): Whether to enable or disable AAP.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID"),
        enabled: z
          .boolean()
          .describe("Whether to enable (true) or disable (false) AAP"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, enabled, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/adaptive-attack-protection`,
        { method: "POST", body: { enabled } }
      );
      return jsonResult(data);
    })
  );

  // --- Trigger Update Check ---
  server.registerTool(
    "sophos_trigger_update_check",
    {
      title: "Trigger Sophos Update Check",
      description: `Trigger a software update check on a specific endpoint.

This initiates an update check for the Sophos agent and related components.
The check runs asynchronously on the device.

Args:
  - endpoint_id (string): The endpoint ID to trigger an update check on.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z
          .string()
          .uuid()
          .describe("Endpoint ID to trigger update check"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/update-checks`,
        { method: "POST", body: {} }
      );
      return jsonResult({
        status: "update_check_initiated",
        endpoint_id,
        message: `Update check initiated on endpoint ${endpoint_id}. The check runs asynchronously on the device.`,
      });
    })
  );

  // --- Request Forensic Logs ---
  server.registerTool(
    "sophos_request_forensic_logs",
    {
      title: "Request Forensic Log Upload",
      description: `Request forensic log collection and upload from a specific endpoint.

The request runs asynchronously; use sophos_get_forensic_log_status to track progress.

Args:
  - endpoint_id (string): The endpoint ID.
  - expires (string): How long the request stays valid, as an ISO 8601 duration of
    5 minutes to 7 days in days, hours, minutes and seconds only, for example "PT1H".
  - mode (string, optional): "standard" (default), "fast" (reduced set), "full",
    or "none" (only the extra paths).
  - paths (array, optional): Up to 50 extra file paths to include.
  - password (string, optional): Password for AES-256 ZIP encryption of the upload.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Request ID and status for tracking the log upload.`,
      inputSchema: {
        endpoint_id: z
          .string()
          .uuid()
          .describe("Endpoint ID to request forensic logs from"),
        expires: z
          .string()
          .regex(/^P(?!$)(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?$/, 'An ISO 8601 duration in days, hours, minutes and seconds, for example "PT1H"')
          .describe('How long the request stays valid, for example "PT1H"'),
        mode: z
          .enum(["standard", "fast", "full", "none"])
          .optional()
          .default("standard")
          .describe("Collection mode"),
        paths: z.array(z.string()).max(50).optional().describe("Extra file paths to include"),
        password: z.string().optional().describe("Password to encrypt the upload"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, expires, mode, paths, password, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { mode, expires };
      if (paths) body.paths = paths;
      if (password !== undefined) body.password = password;

      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/forensic-logs`,
        { method: "POST", body }
      );
      return jsonResult(data);
    })
  );

  // --- Get Forensic Log Status ---
  server.registerTool(
    "sophos_get_forensic_log_status",
    {
      title: "Get Forensic Log Request Status",
      description: `Get the status of a forensic log upload request.

Check whether a previously requested forensic log upload has completed,
is still in progress, or has failed.

Args:
  - endpoint_id (string): The endpoint ID.
  - request_id (string): The forensic log request ID returned by sophos_request_forensic_logs.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID"),
        request_id: z
          .string()
          .uuid()
          .describe("Forensic log request ID"),
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
    withErrorHandling(async ({ endpoint_id, request_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/forensic-logs/${request_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Request Memory Dump ---
  server.registerTool(
    "sophos_request_memory_dump",
    {
      title: "Request Memory Dump",
      description: `Request a memory dump of a process or the kernel from a specific endpoint.

The dump is uploaded to the customer's configured Amazon S3 bucket. Use
sophos_get_memory_dump_status to track progress.

Args:
  - endpoint_id (string): The endpoint ID.
  - mode (string): "process" or "kernel".
  - expires (string): How long the request stays valid, as an ISO 8601 duration of
    5 minutes to 7 days in days, hours, minutes and seconds only, for example "PT1H".
  - pid (number, optional): Process ID. For mode "process", give pid or image_name.
  - image_name (string, optional): Process image name, used when pid is not given.
  - password (string, optional): Password for AES-256 ZIP encryption of the upload.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Request ID and status for tracking the memory dump.`,
      inputSchema: {
        endpoint_id: z
          .string()
          .uuid()
          .describe("Endpoint ID to request memory dump from"),
        mode: z.enum(["process", "kernel"]).describe("Process or kernel memory dump"),
        expires: z
          .string()
          .regex(/^P(?!$)(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?$/, 'An ISO 8601 duration in days, hours, minutes and seconds, for example "PT1H"')
          .describe('How long the request stays valid, for example "PT1H"'),
        pid: z.number().int().min(0).optional().describe("Process ID"),
        image_name: z.string().optional().describe("Process image name"),
        password: z.string().optional().describe("Password to encrypt the upload"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ endpoint_id, mode, expires, pid, image_name, password, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      if (mode === "process" && pid === undefined && !image_name) {
        throw new Error('mode "process" needs pid or image_name. Nothing was sent.');
      }
      const body: Record<string, unknown> = { mode, expires };
      if (pid !== undefined) body.pid = pid;
      if (image_name) body.imageName = image_name;
      if (password !== undefined) body.password = password;

      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/memory-dumps`,
        { method: "POST", body }
      );
      return jsonResult(data);
    })
  );

  // --- Get Memory Dump Status ---
  server.registerTool(
    "sophos_get_memory_dump_status",
    {
      title: "Get Memory Dump Request Status",
      description: `Get the status of a memory dump request.

Check whether a previously requested memory dump has completed, is still
in progress, or has failed.

Args:
  - endpoint_id (string): The endpoint ID.
  - request_id (string): The memory dump request ID returned by sophos_request_memory_dump.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID"),
        request_id: z
          .string()
          .uuid()
          .describe("Memory dump request ID"),
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
    withErrorHandling(async ({ endpoint_id, request_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/memory-dumps/${request_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Bulk Isolate Endpoints ---
  server.registerTool(
    "sophos_bulk_isolate_endpoints",
    {
      title: "Bulk Isolate/Release Sophos Endpoints",
      description: `Bulk isolate or release multiple endpoints at once.

WARNING: When isolating, all targeted endpoints will lose network connectivity
except their management connection to Sophos Central.

Args:
  - enabled (boolean): true to isolate, false to release.
  - ids (string[]): Array of endpoint IDs to isolate/release.
  - comment (string, optional): Reason for isolation/release.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        enabled: z
          .boolean()
          .describe("true to isolate, false to release"),
        ids: z
          .array(z.string().uuid())
          .min(1)
          .describe("Array of endpoint IDs to isolate/release"),
        comment: z
          .string()
          .optional()
          .describe("Reason for isolation/release"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ enabled, ids, comment, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { enabled, ids };
      if (comment) body.comment = comment;

      const data = await client.tenantRequest(
        resolvedTenantId,
        "/endpoint/v1/endpoints/isolation",
        { method: "POST", body }
      );
      return jsonResult(data);
    })
  );

  // --- Get Endpoint Isolation Status ---
  server.registerTool(
    "sophos_get_endpoint_isolation_status",
    {
      title: "Get Endpoint Isolation Status",
      description: `Get the current isolation status of a specific endpoint.

Returns whether the endpoint is currently isolated, not isolated, or if
an isolation/release operation is in progress.

Args:
  - endpoint_id (string): The endpoint ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_id: z.string().uuid().describe("Endpoint ID"),
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
    withErrorHandling(async ({ endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoints/${endpoint_id}/isolation`
      );
      return jsonResult(data);
    })
  );

  // --- Bulk Scan Endpoints ---
  server.registerTool(
    "sophos_bulk_scan_endpoints",
    {
      title: "Bulk Scan Sophos Endpoints",
      description: `Ask up to 500 endpoints to run a scan in one request.

Each endpoint is accepted or rejected on its own. Accepted ones come back in
items with status "requested"; rejected ones come back in errors with an
errorCode (notFound, notSupported, conflict, permissionDenied, internalError)
and a message. The scans run asynchronously on the devices. Sophos answers 404
when none of the IDs is found.

Args:
  - ids (string[]): Endpoint IDs (1 to 500). Duplicates are dropped.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  requested, accepted and rejected counts, then items and errors as Sophos returned them.`,
      inputSchema: {
        ids: z
          .array(z.string().uuid())
          .min(1)
          .max(500)
          .describe("Endpoint IDs to scan (1 to 500)"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const unique = [...new Set(ids)];
      const data = await client.tenantRequest<BulkActionResponse>(
        resolvedTenantId,
        "/endpoint/v1/endpoints/scans",
        { method: "POST", body: { ids: unique } }
      );
      return jsonResult(bulkActionResult(unique.length, data));
    })
  );

  // --- Bulk Reset Endpoint Health ---
  server.registerTool(
    "sophos_bulk_reset_endpoint_health",
    {
      title: "Bulk Reset Sophos Endpoint Health",
      description: `Reset the health status to green and clear all alerts on up to 500 endpoints in one request.

WARNING: every alert on the targeted endpoints is cleared, and that cannot be
undone. Review or record the alerts first (sophos_list_alerts). Windows
computers, Windows servers and Linux only; other platforms come back in errors
as notSupported.

Each endpoint is accepted or rejected on its own. Accepted ones come back in
items with status "requested"; rejected ones in errors with an errorCode
(notFound, notSupported, conflict, permissionDenied, internalError). Sophos
answers 404 when none of the IDs is found. Accepted means requested: an
endpoint offline since 2023 was accepted and still read suspicious minutes
later (29/10/2026), so read health back with sophos_get_endpoint.

Args:
  - ids (string[]): Endpoint IDs (1 to 500). Duplicates are dropped.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  requested, accepted and rejected counts, then items and errors as Sophos returned them.`,
      inputSchema: {
        ids: z
          .array(z.string().uuid())
          .min(1)
          .max(500)
          .describe("Endpoint IDs to reset (1 to 500)"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const unique = [...new Set(ids)];
      const data = await client.tenantRequest<BulkActionResponse>(
        resolvedTenantId,
        "/endpoint/v1/endpoints/reset-health",
        { method: "POST", body: { ids: unique } }
      );
      return jsonResult(bulkActionResult(unique.length, data));
    })
  );

  // --- Bulk Update Tamper Protection ---
  server.registerTool(
    "sophos_bulk_update_tamper_protection",
    {
      title: "Bulk Update Tamper Protection",
      description: `Turn tamper protection on or off, or generate a new tamper protection password, for up to 200 endpoints in one request.

WARNING: turning tamper protection off lets anyone on those devices uninstall
or reconfigure the Sophos agent without a password. Turn it back on when the
work is done. Generating a new password replaces the current one on every
targeted endpoint.

Pass enabled, regenerate_password, or both. Each endpoint is accepted or
rejected on its own: accepted ones come back in items with status
"requested", rejected ones in errors with an errorCode (notFound,
notSupported, conflict, permissionDenied, internalError). Accepted means
requested, so read the result back with sophos_get_tamper_protection, which
also returns the new password. Sophos answers 404 when none of the IDs is
found.

Args:
  - ids (string[]): Endpoint IDs (1 to 200). Duplicates are dropped.
  - enabled (boolean, optional): true turns tamper protection on, false turns it off.
  - regenerate_password (boolean, optional): true generates a new tamper protection password.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  requested, accepted and rejected counts, then items and errors as Sophos returned them.`,
      inputSchema: {
        ids: z
          .array(z.string().uuid())
          .min(1)
          .max(200)
          .describe("Endpoint IDs (1 to 200)"),
        enabled: z
          .boolean()
          .optional()
          .describe("true turns tamper protection on, false turns it off"),
        regenerate_password: z
          .boolean()
          .optional()
          .describe("true generates a new tamper protection password"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ ids, enabled, regenerate_password, tenant_id }) => {
      if (enabled === undefined && regenerate_password === undefined) {
        throw new Error("Pass enabled, regenerate_password, or both.");
      }
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const unique = [...new Set(ids)];
      const body: Record<string, unknown> = { ids: unique };
      if (enabled !== undefined) body.enabled = enabled;
      if (regenerate_password !== undefined) body.regeneratePassword = regenerate_password;
      const data = await client.tenantRequest<BulkActionResponse>(
        resolvedTenantId,
        "/endpoint/v1/endpoints/tamper-protection",
        { method: "POST", body }
      );
      return jsonResult(
        bulkActionResult(
          unique.length,
          data,
          "Accepted means requested. Check each endpoint with sophos_get_tamper_protection."
        )
      );
    })
  );
}

function formatEndpoint(ep: SophosEndpoint) {
  return {
    id: ep.id,
    hostname: ep.hostname,
    type: ep.type,
    health: ep.health.overall,
    threat_status: ep.health.threats.status,
    os: `${ep.os.platform} ${ep.os.name} ${ep.os.majorVersion}.${ep.os.minorVersion}`,
    is_server: ep.os.isServer,
    ipv4: ep.ipv4Addresses ?? [],
    person: ep.associatedPerson?.name ?? null,
    tamper_protection: ep.tamperProtectionEnabled,
    group: ep.groupName ?? null,
    last_seen: ep.lastSeenAt ?? null,
    isolation: ep.isolation?.status ?? null,
  };
}

function formatEndpointDetailed(ep: SophosEndpoint) {
  return {
    ...formatEndpoint(ep),
    tenant_id: ep.tenant.id,
    group_id: ep.groupId ?? null,
    ipv6: ep.ipv6Addresses ?? [],
    mac_addresses: ep.macAddresses ?? [],
    person_login: ep.associatedPerson?.viaLogin ?? null,
    person_id: ep.associatedPerson?.id ?? null,
    service_details: ep.health.services.serviceDetails ?? [],
    services_status: ep.health.services.status,
    assigned_products:
      ep.assignedProducts?.map((p) => ({
        code: p.code,
        version: p.version,
        status: p.status,
      })) ?? [],
    lockdown_status: ep.lockdown?.status ?? null,
    os_build: ep.os.build ?? null,
  };
}
