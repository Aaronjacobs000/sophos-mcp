/**
 * Tools: sophos_get_switch_mac_filtering, sophos_update_switch_mac_filtering,
 *        sophos_list_switch_tasks
 * Interact with the Sophos Switch Management API /switch/v1/ (regional host).
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerSwitchTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- Get MAC Filtering Settings ---
  server.registerTool(
    "sophos_get_switch_mac_filtering",
    {
      title: "Get Sophos Switch MAC Filtering",
      description: `Get the global MAC filtering settings for Sophos Switches in a tenant.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
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
    withErrorHandling(async ({ tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/switch/v1/settings/mac-filtering"
      );
      return jsonResult(data);
    })
  );

  // --- Update MAC Filtering Settings ---
  server.registerTool(
    "sophos_update_switch_mac_filtering",
    {
      title: "Update Sophos Switch MAC Filtering",
      description: `Replace the global MAC filtering address list for Sophos Switches.

WARNING: This replaces the full list; include every MAC address that should
remain filtered.

Args:
  - mac_addresses (array): The complete list of MAC addresses to filter.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mac_addresses: z
          .array(z.string())
          .describe("Complete list of MAC addresses to filter"),
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
    withErrorHandling(async ({ mac_addresses, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/switch/v1/settings/mac-filtering",
        { method: "PUT", body: { macAddresses: mac_addresses } }
      );
      return jsonResult({ status: "updated", settings: data });
    })
  );

  // --- List Switch Tasks ---
  server.registerTool(
    "sophos_list_switch_tasks",
    {
      title: "List Sophos Switch Tasks",
      description: `List configuration tasks for Sophos Switches in a tenant.

Args:
  - type (string, optional): Policy type to filter the tasks by.
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        type: z.string().optional().describe("Policy type to filter the tasks by"),
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
    withErrorHandling(async ({ type, limit, page, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
        pageTotal: "true",
      };
      if (type) params.type = type;

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/switch/v1/tasks",
        { params }
      );
      return jsonResult(data);
    })
  );
}
