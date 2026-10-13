/**
 * Tools: sophos_list_alerts, sophos_get_alert, sophos_acknowledge_alert, sophos_search_alerts
 * Interact with the Sophos Common API /common/v1/alerts
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosAlertPage, SophosAlert } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerAlertTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Alerts ---
  server.registerTool(
    "sophos_list_alerts",
    {
      title: "List Sophos Alerts",
      description: `List alerts from a Sophos Central tenant with optional filtering.

Retrieves alerts from the Common API with filtering by severity, category,
product, and date range. Results are paginated.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - severity (string, optional): Filter by severity: "high", "medium", "low".
  - category (string, optional): Filter by category e.g. "malware", "policy", "runtimeDetections", "updating".
  - product (string, optional): Filter by product e.g. "endpoint", "server", "firewall", "email".
  - from_date (string, optional): ISO 8601 start date e.g. "2025-01-01T00:00:00Z".
  - limit (number, optional): Max results per page (1-100, default 50).
  - page_from_key (string, optional): next_page_from_key from the previous page.

Returns:
  A page of alerts with: id, severity, category, description, product, raisedAt,
  managedAgent, allowedActions, and next_page_from_key when there are more.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        severity: z
          .string()
          .optional()
          .describe('Filter by severity: "high", "medium", "low"'),
        category: z
          .string()
          .optional()
          .describe("Filter by alert category"),
        product: z
          .string()
          .optional()
          .describe('Filter by product: "endpoint", "server", etc.'),
        from_date: z
          .string()
          .optional()
          .describe("ISO 8601 start date filter"),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Max results per page (default 50)"),
        page_from_key: z
          .string()
          .optional()
          .describe("next_page_from_key from the previous page"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({ tenant_id, severity, category, product, from_date, limit, page_from_key }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        // The alerts API pages by key (pageFromKey); a page number is ignored
        const params: Record<string, string> = {
          pageSize: String(limit),
          pageTotal: "true",
        };
        if (page_from_key) params.pageFromKey = page_from_key;

        if (severity) params.severity = severity;
        if (category) params.category = category;
        if (product) params.product = product;
        if (from_date) params.from = from_date;

        const data = await client.tenantRequest<SophosAlertPage>(
          resolvedTenantId,
          "/common/v1/alerts",
          { params }
        );

        return jsonResult({
          total: data.pages.items ?? data.items.length,
          page_size: data.pages.size,
          next_page_from_key: data.pages.nextKey ?? null,
          alerts: data.items.map(formatAlert),
        });
      }
    )
  );

  // --- Get Alert ---
  server.registerTool(
    "sophos_get_alert",
    {
      title: "Get Sophos Alert Detail",
      description: `Get full details of a specific Sophos Central alert by ID.

Returns complete alert information including description, severity, category,
product, managed agent details, and allowed actions (e.g. acknowledge, cleanPua).

Args:
  - alert_id (string): The alert ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        alert_id: z.string().uuid().describe("Alert ID to retrieve"),
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
    withErrorHandling(async ({ alert_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const alert = await client.tenantRequest<SophosAlert>(
        resolvedTenantId,
        `/common/v1/alerts/${alert_id}`
      );
      return jsonResult(formatAlert(alert));
    })
  );

  // --- Acknowledge Alert ---
  server.registerTool(
    "sophos_acknowledge_alert",
    {
      title: "Acknowledge Sophos Alert",
      description: `Acknowledge a Sophos Central alert, marking it as reviewed.

This is a write action that changes the alert status. The alert must have
"acknowledge" in its allowedActions list. Use sophos_get_alert first to check.

Args:
  - alert_id (string): The alert ID to acknowledge.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        alert_id: z.string().uuid().describe("Alert ID to acknowledge"),
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
    withErrorHandling(async ({ alert_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/common/v1/alerts/${alert_id}/actions`,
        {
          method: "POST",
          body: { action: "acknowledge" },
        }
      );
      return jsonResult({
        status: "acknowledged",
        alert_id,
        message: `Alert ${alert_id} has been acknowledged.`,
      });
    })
  );

  // --- Search Alerts ---
  server.registerTool(
    "sophos_search_alerts",
    {
      title: "Search Sophos Alerts",
      description: `Search alerts with several values per filter (POST /common/v1/alerts/search).

Every filter is optional and takes a list. Results page by key: pass the
previous result's next_page_from_key as page_from_key.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - ids (array, optional): Alert IDs.
  - severity (array, optional): "high", "medium", "low".
  - category (array, optional): Alert categories, for example "malware", "policy", "runtimeDetections".
  - product (array, optional): Products, for example "endpoint", "server", "firewall".
  - group_key (string, optional): Alert group key.
  - from (string, optional): Raised on or after this time (ISO 8601).
  - to (string, optional): Raised before this time (ISO 8601).
  - sort (array, optional): Sort fields, each "field" or "field:asc|desc", for example "raisedAt:desc".
  - limit (number, optional): Max results (default 50).
  - page_from_key (string, optional): next_page_from_key from the previous page.`,
      inputSchema: {
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
        ids: z.array(z.string().uuid()).optional().describe("Alert IDs"),
        severity: z.array(z.enum(["high", "medium", "low"])).optional().describe("Severities"),
        category: z.array(z.string()).optional().describe("Alert categories"),
        product: z.array(z.string()).optional().describe("Products"),
        group_key: z.string().optional().describe("Alert group key"),
        from: z.string().optional().describe("Raised on or after this time (ISO 8601)"),
        to: z.string().optional().describe("Raised before this time (ISO 8601)"),
        sort: z
          .array(z.string().regex(/^[^:]+(:(asc|desc))?$/, 'Use "field" or "field:asc|desc"'))
          .optional()
          .describe('Sort fields, for example "raisedAt:desc"'),
        limit: z.coerce.number().int().min(1).max(100).optional().default(DEFAULT_PAGE_SIZE).describe("Max results per page (default 50)"),
        page_from_key: z.string().optional().describe("next_page_from_key from the previous page"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ tenant_id, ids, severity, category, product, group_key, from, to, sort, limit, page_from_key }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { pageSize: limit, pageTotal: true };
      if (ids) body.ids = ids;
      if (severity) body.severity = severity;
      if (category) body.category = category;
      if (product) body.product = product;
      if (group_key) body.groupKey = group_key;
      if (from) body.from = from;
      if (to) body.to = to;
      if (sort) body.sort = sort;
      if (page_from_key) body.pageFromKey = page_from_key;

      const data = await client.tenantRequest<SophosAlertPage>(
        resolvedTenantId,
        "/common/v1/alerts/search",
        { method: "POST", body }
      );
      return jsonResult({
        total: data.pages.items ?? data.items.length,
        next_page_from_key: data.pages.nextKey ?? null,
        alerts: data.items.map(formatAlert),
      });
    })
  );
}

function formatAlert(alert: SophosAlert) {
  return {
    id: alert.id,
    severity: alert.severity,
    category: alert.category,
    description: alert.description,
    type: alert.type,
    product: alert.product,
    raised_at: alert.raisedAt,
    managed_agent: alert.managedAgent
      ? { id: alert.managedAgent.id, type: alert.managedAgent.type }
      : null,
    person_id: alert.person?.id ?? null,
    tenant_id: alert.tenant.id,
    tenant_name: alert.tenant.name ?? null,
    allowed_actions: alert.allowedActions,
  };
}
