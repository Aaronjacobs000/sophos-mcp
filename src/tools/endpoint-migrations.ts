/**
 * Tools: sophos_list_migrations, sophos_get_migration, sophos_create_migration,
 *        sophos_list_migration_endpoints,
 *        sophos_list_recommended_packages, sophos_list_static_packages
 * Interact with the Sophos Endpoint Migration and Software Package APIs.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerEndpointMigrationTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Migrations ---
  server.registerTool(
    "sophos_list_migrations",
    {
      title: "List Sophos Endpoint Migrations",
      description: `List endpoint migration jobs for a tenant.

Returns migration jobs with their status, name, and endpoint counts.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of migration jobs.`,
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
          .max(100)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Max results per page (default 50)"),
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

      const data = await client.tenantRequest<
        SophosPagedResponse<Record<string, unknown>>
      >(resolvedTenantId, "/endpoint/v1/migrations", {
        params: { pageSize: String(limit), page: String(page) },
      });

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        migrations: data.items,
      });
    })
  );

  // --- Get Migration ---
  server.registerTool(
    "sophos_get_migration",
    {
      title: "Get Sophos Migration Detail",
      description: `Get full details of a specific endpoint migration job.

Args:
  - migration_id (string): The migration job ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Migration job details including status, name, and endpoint information.`,
      inputSchema: {
        migration_id: z.string().guid().describe("Migration job ID"),
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
    withErrorHandling(async ({ migration_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/endpoint/v1/migrations/${migration_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create Migration ---
  server.registerTool(
    "sophos_create_migration",
    {
      title: "Create Sophos Migration Job",
      description: `Create or start an endpoint migration job that moves endpoints between tenants.

A migration takes two calls, one on each tenant:

1. side "receiving", on the destination tenant: from_tenant (the source tenant's
   ID) and endpoints (the device IDs). POST /endpoint/v1/migrations. The response
   has the job id and a "token".
2. side "sending", on the source tenant: migration_id (that same job id), token
   and endpoints. PUT /endpoint/v1/migrations/{id}. This starts the move; it does
   not create a second job.

Track progress with sophos_list_migration_endpoints on either tenant.

Args:
  - side (string): "receiving" or "sending".
  - endpoints (array): Endpoint IDs to migrate (1 to 1000).
  - from_tenant (string): Receiving side only: the source tenant's ID.
  - migration_id (string): Sending side only: the job id from the receiving side.
  - token (string): Sending side only: the token from the receiving side.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The migration job; on the receiving side it includes the "token".`,
      inputSchema: {
        side: z.enum(["receiving", "sending"]).describe("Which tenant this call is on"),
        endpoints: z
          .array(z.string().guid())
          .min(1)
          .max(1000)
          .describe("Endpoint IDs to migrate"),
        from_tenant: z.string().guid().optional().describe("Receiving side: the source tenant's ID"),
        migration_id: z.string().guid().optional().describe("Sending side: the job id from the receiving side"),
        token: z.string().optional().describe("Sending side: the token from the receiving side"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ side, endpoints, from_tenant, migration_id, token, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      if (side === "receiving") {
        if (!from_tenant) throw new Error('side "receiving" needs from_tenant (the source tenant ID). Nothing was sent.');
        const data = await client.tenantRequest<Record<string, unknown>>(
          resolvedTenantId,
          "/endpoint/v1/migrations",
          { method: "POST", body: { fromTenant: from_tenant, endpoints } }
        );
        return jsonResult({ status: "created", migration: data });
      }
      if (!migration_id || !token) {
        throw new Error('side "sending" needs migration_id and token from the receiving side. Nothing was sent.');
      }
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/endpoint/v1/migrations/${migration_id}`,
        { method: "PUT", body: { token, endpoints } }
      );
      return jsonResult({ status: "started", migration: data });
    })
  );

  // --- List Migration Endpoints ---
  server.registerTool(
    "sophos_list_migration_endpoints",
    {
      title: "List Sophos Migration Endpoints",
      description: `List endpoints in a specific migration job.

Args:
  - migration_id (string): The migration job ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of endpoints in the migration.`,
      inputSchema: {
        migration_id: z.string().guid().describe("Migration job ID"),
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Max results per page (default 50)"),
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
    withErrorHandling(async ({ migration_id, tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const data = await client.tenantRequest<
        SophosPagedResponse<Record<string, unknown>>
      >(resolvedTenantId, `/endpoint/v1/migrations/${migration_id}/endpoints`, {
        params: { pageSize: String(limit), page: String(page) },
      });

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        endpoints: data.items,
      });
    })
  );

  // --- List Recommended Packages ---
  server.registerTool(
    "sophos_list_recommended_packages",
    {
      title: "List Sophos Recommended Packages",
      description: `List the Sophos recommended software packages for the tenant.

The API returns every package in one response.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
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
    withErrorHandling(async ({ tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<{ items?: Record<string, unknown>[] }>(
        resolvedTenantId,
        "/endpoint/v1/software/packages/recommended"
      );
      const items = data.items ?? [];
      return jsonResult({ total: items.length, packages: items });
    })
  );

  // --- List Static Packages ---
  server.registerTool(
    "sophos_list_static_packages",
    {
      title: "List Sophos Static Packages",
      description: `List the static (fixed version) software packages available to the tenant.

The API returns every matching package in one response.

Args:
  - endpoint_type (string, optional): "computer" or "server".
  - platform (string, optional): "windows", "linux" or "macOS".
  - type (string, optional): "fixed", "special" or "lts".
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        endpoint_type: z.enum(["computer", "server"]).optional().describe("Endpoint type"),
        platform: z.enum(["windows", "linux", "macOS"]).optional().describe("Platform"),
        type: z.enum(["fixed", "special", "lts"]).optional().describe("Package type"),
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
    withErrorHandling(async ({ endpoint_type, platform, type, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = {};
      if (endpoint_type) params.endpointType = endpoint_type;
      if (platform) params.platform = platform;
      if (type) params.type = type;
      const data = await client.tenantRequest<{ items?: Record<string, unknown>[] }>(
        resolvedTenantId,
        "/endpoint/v1/software/packages/static",
        { params }
      );
      const items = data.items ?? [];
      return jsonResult({ total: items.length, packages: items });
    })
  );
}
