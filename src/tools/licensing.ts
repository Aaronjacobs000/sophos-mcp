/**
 * Tools: sophos_list_licenses, sophos_list_firewall_licenses
 * Interact with the Sophos Licensing API /licenses/v1/ (global host).
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerLicensingTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Licenses ---
  server.registerTool(
    "sophos_list_licenses",
    {
      title: "List Sophos Licenses",
      description: `List the product licenses of a tenant, including usage and entitlements.

Returns license IDs, product, type, start/end dates, and usage counts.
Useful for renewal conversations and entitlement checks.

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
      const data = await client.globalRequest<Record<string, unknown>>(
        "/licenses/v1/licenses",
        { headers: { "X-Tenant-ID": resolvedTenantId } }
      );
      return jsonResult(data);
    })
  );

  // --- List Firewall Licenses ---
  server.registerTool(
    "sophos_list_firewall_licenses",
    {
      title: "List Sophos Firewall Licenses",
      description: `List firewall license details.

Scoping: pass tenant_id for one tenant's firewalls, or omit it as a partner
caller to list across all managed tenants.

Args:
  - tenant_id (string, optional): Tenant ID. Omit for a partner-wide listing.
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).
  - sort (string, optional): Sort column.`,
      inputSchema: {
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Omit for a partner-wide listing."),
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
        sort: z.string().optional().describe("Sort column"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, limit, page, sort }) => {
      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
        pageTotal: "true",
      };
      if (sort) params.sort = sort;

      const data = await client.globalRequest<Record<string, unknown>>(
        "/licenses/v1/licenses/firewalls",
        {
          params,
          ...(tenant_id ? { headers: { "X-Tenant-ID": tenant_id } } : {}),
        }
      );
      return jsonResult(data);
    })
  );
}
