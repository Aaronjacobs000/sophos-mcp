/**
 * Tools: sophos_list_siem_events, sophos_list_siem_alerts
 * Interact with the Sophos SIEM API /siem/v1/events and /siem/v1/alerts
 * Uses cursor-based pagination for streaming event retrieval.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosSiemResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";

export function registerSiemTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List SIEM Events ---
  server.registerTool(
    "sophos_list_siem_events",
    {
      title: "List Sophos SIEM Events",
      description: `Retrieve security events from the Sophos SIEM API.

Returns events from the last 24 hours by default. Uses cursor-based pagination —
pass the next_cursor from a previous response to continue from where you left off.
This is ideal for polling: store the cursor and pass it on subsequent calls to get only new events.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Events per page (200-1000, default 200).
  - cursor (string, optional): Pagination cursor from a previous response's next_cursor.
  - from_date (number, optional): Unix timestamp to start from (alternative to cursor).
  - exclude_types (string, optional): Comma-separated event types to exclude.

Returns:
  items (array of events), next_cursor (for next page), has_more (boolean).
  Each event: id, type, name, severity, when, source, location, data.`,
      inputSchema: {
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(200)
          .max(1000)
          .optional()
          .default(200)
          .describe("Events per page (200-1000, default 200)"),
        cursor: z
          .string()
          .optional()
          .describe("Pagination cursor from a previous response's next_cursor"),
        from_date: z
          .number()
          .int()
          .optional()
          .describe("Unix timestamp to start from (alternative to cursor)"),
        exclude_types: z
          .string()
          .optional()
          .describe("Comma-separated event types to exclude"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, limit, cursor, from_date, exclude_types }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = { limit: String(limit) };
      if (cursor) params.cursor = cursor;
      if (from_date !== undefined) params.from_date = String(from_date);
      if (exclude_types) params.exclude_types = exclude_types;

      const data = await client.tenantRequest<SophosSiemResponse>(
        resolvedTenantId,
        "/siem/v1/events",
        { params }
      );
      return jsonResult({
        count: data.items.length,
        has_more: data.has_more,
        next_cursor: data.next_cursor,
        events: data.items,
      });
    })
  );

  // --- List SIEM Alerts ---
  server.registerTool(
    "sophos_list_siem_alerts",
    {
      title: "List Sophos SIEM Alerts",
      description: `Retrieve security alerts from the Sophos SIEM API.

Returns alerts from the last 24 hours by default. Uses cursor-based pagination —
pass the next_cursor from a previous response to continue from where you left off.

Note: These are SIEM-stream alerts (for SIEM integrations), distinct from the
Common API alerts returned by sophos_list_alerts.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Alerts per page (200-1000, default 200).
  - cursor (string, optional): Pagination cursor from a previous response's next_cursor.
  - from_date (number, optional): Unix timestamp to start from (alternative to cursor).
  - exclude_types (string, optional): Comma-separated alert types to exclude.

Returns:
  items (array of alerts), next_cursor, has_more.
  Each alert: id, type, name, severity, when, description, product, location.`,
      inputSchema: {
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        limit: z
          .number()
          .int()
          .min(200)
          .max(1000)
          .optional()
          .default(200)
          .describe("Alerts per page (200-1000, default 200)"),
        cursor: z
          .string()
          .optional()
          .describe("Pagination cursor from a previous response's next_cursor"),
        from_date: z
          .number()
          .int()
          .optional()
          .describe("Unix timestamp to start from (alternative to cursor)"),
        exclude_types: z
          .string()
          .optional()
          .describe("Comma-separated alert types to exclude"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, limit, cursor, from_date, exclude_types }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = { limit: String(limit) };
      if (cursor) params.cursor = cursor;
      if (from_date !== undefined) params.from_date = String(from_date);
      if (exclude_types) params.exclude_types = exclude_types;

      const data = await client.tenantRequest<SophosSiemResponse>(
        resolvedTenantId,
        "/siem/v1/alerts",
        { params }
      );
      return jsonResult({
        count: data.items.length,
        has_more: data.has_more,
        next_cursor: data.next_cursor,
        alerts: data.items,
      });
    })
  );
}
