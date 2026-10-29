/**
 * Tools: Endpoint Settings: installer downloads, blocked addresses, web control,
 *        tamper protection, exploit mitigation, IPS/isolation exclusions,
 *        peripheral control, event journal, update management, MTR.
 *
 * 26 tools covering the Sophos Central /endpoint/v1/settings/* and /endpoint/v1/downloads APIs.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerEndpointSettingsTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // =========================================================================
  // INSTALLER DOWNLOADS
  // =========================================================================

  server.registerTool(
    "sophos_list_installer_downloads",
    {
      title: "List Sophos Installer Downloads",
      description: `List available Sophos endpoint installer packages for a tenant.

Returns download links for Windows, macOS, and Linux installers in various formats.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  List of available installer packages with download URLs.`,
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
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/downloads",
        {}
      );
      return jsonResult(data);
    })
  );

  // =========================================================================
  // BLOCKED NETWORK ADDRESSES
  // =========================================================================

  server.registerTool(
    "sophos_list_blocked_addresses",
    {
      title: "List Sophos Blocked Network Addresses",
      description: `List blocked network addresses (IPs and domains) for a tenant.

These are network-level blocks applied across all endpoints.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of blocked addresses with type, value, and comment.`,
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
      >(resolvedTenantId, "/endpoint/v1/settings/blocked-addresses", {
        params: { pageSize: String(limit), page: String(page) },
      });
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? data.items.length,
        page: data.pages?.current ?? page,
        items: data.items,
      });
    })
  );

  server.registerTool(
    "sophos_add_blocked_address",
    {
      title: "Add Sophos Blocked Network Address",
      description: `Block IP addresses or IP ranges that every device in the tenant refuses to communicate with.

IP addresses and ranges only (IPv4 or IPv6; a range as CIDR). Up to 100 per call.

Args:
  - addresses (array): IP addresses or ranges to block.
  - comment (string, optional): Reason for blocking (up to 250 characters), applied to each.
  - expire_in_days (number, optional): Unblock after this many days (1 to 365).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        addresses: z.array(z.string()).min(1).max(100).describe("IP addresses or CIDR ranges to block"),
        comment: z.string().max(250).optional().describe("Reason for blocking"),
        expire_in_days: z.number().int().min(1).max(365).optional().describe("Unblock after this many days"),
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
    withErrorHandling(async ({ addresses, comment, expire_in_days, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const items = addresses.map((item) => ({
        item,
        ...(comment !== undefined ? { comment } : {}),
        ...(expire_in_days !== undefined ? { expireInDays: expire_in_days } : {}),
      }));
      const created = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/blocked-addresses/bulk",
        { method: "POST", body: { items } }
      );
      return jsonResult({ status: "created", result: created });
    })
  );

  server.registerTool(
    "sophos_delete_blocked_address",
    {
      title: "Delete Sophos Blocked Network Address",
      description: `Unblock IP addresses or ranges by their blocked-address record IDs.

sophos_list_blocked_addresses gives the IDs.

Args:
  - address_ids (array): Blocked address record IDs to remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        address_ids: z.array(z.string().guid()).min(1).describe("Blocked address record IDs to remove"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ address_ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/blocked-addresses/bulk/delete",
        { method: "POST", body: { ids: address_ids } }
      );
      return jsonResult({ status: "deleted", address_ids, result: data });
    })
  );

  // =========================================================================
  // WEB CONTROL - LOCAL SITES
  // =========================================================================

  server.registerTool(
    "sophos_list_local_sites",
    {
      title: "List Sophos Web Control Local Sites",
      description: `List local site definitions for web control.

Local sites allow you to categorize internal or custom URLs for web control policies.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of local sites with URL, category, and tags.`,
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
      >(resolvedTenantId, "/endpoint/v1/settings/web-control/local-sites", {
        params: { pageSize: String(limit), page: String(page) },
      });
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? data.items.length,
        page: data.pages?.current ?? page,
        items: data.items,
      });
    })
  );

  server.registerTool(
    "sophos_add_local_site",
    {
      title: "Add Sophos Web Control Local Site",
      description: `Add a local site definition for web control.

Assigns a URL to a web control category so policies can allow/block/warn on it.

Args:
  - url (string): The URL pattern to categorize.
  - categoryId (number): Web control category ID (use sophos_list_web_control_categories to find IDs).
  - comment (string, optional): Description or notes.
  - tags (string[], optional): Tags for organizing sites.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        url: z.string().describe("URL pattern to categorize"),
        categoryId: z.coerce.number().int().describe("Web control category ID"),
        comment: z.string().optional().describe("Description or notes"),
        tags: z.array(z.string()).optional().describe("Tags for organizing sites"),
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
    withErrorHandling(async ({ url, categoryId, comment, tags, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { url, categoryId };
      if (comment) body.comment = comment;
      if (tags) body.tags = tags;

      const created = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/web-control/local-sites",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", site: created });
    })
  );

  server.registerTool(
    "sophos_update_local_site",
    {
      title: "Update Sophos Web Control Local Site",
      description: `Update a local site definition for web control.

Modify the URL, category, comment, or tags of an existing local site.

Args:
  - site_id (string): Local site ID to update.
  - url (string, optional): Updated URL pattern.
  - categoryId (number, optional): Updated web control category ID.
  - comment (string, optional): Updated description.
  - tags (string[], optional): Updated tags.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_id: z.string().guid().describe("Local site ID to update"),
        url: z.string().optional().describe("Updated URL pattern"),
        categoryId: z.coerce.number().int().optional().describe("Updated web control category ID"),
        comment: z.string().optional().describe("Updated description"),
        tags: z.array(z.string()).optional().describe("Updated tags"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ site_id, url, categoryId, comment, tags, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {};
      if (url !== undefined) body.url = url;
      if (categoryId !== undefined) body.categoryId = categoryId;
      if (comment !== undefined) body.comment = comment;
      if (tags !== undefined) body.tags = tags;

      const updated = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/endpoint/v1/settings/web-control/local-sites/${site_id}`,
        { method: "PATCH", body }
      );
      return jsonResult({ status: "updated", site: updated });
    })
  );

  server.registerTool(
    "sophos_delete_local_site",
    {
      title: "Delete Sophos Web Control Local Site",
      description: `Delete a local site definition from web control.

Args:
  - site_id (string): Local site ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_id: z.string().guid().describe("Local site ID to delete"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ site_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/settings/web-control/local-sites/${site_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        site_id,
        message: `Local site ${site_id} deleted.`,
      });
    })
  );

  // =========================================================================
  // WEB CONTROL - CATEGORIES
  // =========================================================================

  server.registerTool(
    "sophos_list_web_control_categories",
    {
      title: "List Sophos Web Control Categories",
      description: `List all web control categories available for classifying websites.

Returns category IDs and names used when adding local sites or configuring web policies.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  List of web control categories with IDs and names.`,
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
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/web-control/categories",
        {}
      );
      return jsonResult(data);
    })
  );

  // =========================================================================
  // WEB CONTROL - TLS DECRYPTION
  // =========================================================================

  server.registerTool(
    "sophos_get_tls_decryption_settings",
    {
      title: "Get Sophos TLS Decryption Settings",
      description: `Get the current TLS decryption settings for web control.

Returns whether TLS decryption is enabled and any configured rules/exclusions.

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
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/web-control/tls-decryption",
        {}
      );
      return jsonResult(data);
    })
  );

  server.registerTool(
    "sophos_update_tls_decryption_settings",
    {
      title: "Update Sophos TLS Decryption Settings",
      description: `Turn SSL/TLS decryption on or off for the web categories that support a setting.

The API takes up to five categories by ID: 10, 14, 20, 27 and 54 (see
sophos_get_tls_decryption_settings for their names). Categories you leave out
keep their setting.

Args:
  - categories (array): Each {id, decryption_enabled}.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        categories: z
          .array(
            z.object({
              id: z.union([z.literal(10), z.literal(14), z.literal(20), z.literal(27), z.literal(54)]).describe("Web category ID"),
              decryption_enabled: z.boolean().describe("Decrypt websites in this category"),
            })
          )
          .min(1)
          .max(5)
          .describe("Categories to change"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ categories, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const updated = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/web-control/tls-decryption",
        {
          method: "PATCH",
          body: { categories: categories.map((c) => ({ id: c.id, decryptionEnabled: c.decryption_enabled })) },
        }
      );
      return jsonResult({ status: "updated", settings: updated });
    })
  );

  // =========================================================================
  // GLOBAL TAMPER PROTECTION
  // =========================================================================

  server.registerTool(
    "sophos_get_global_tamper_protection",
    {
      title: "Get Sophos Global Tamper Protection",
      description: `Get the global tamper protection settings for a tenant.

Returns whether tamper protection is globally enabled or disabled.

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
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/tamper-protection",
        {}
      );
      return jsonResult(data);
    })
  );

  // =========================================================================
  // EXPLOIT MITIGATION - DETECTED EXPLOITS
  // =========================================================================

  server.registerTool(
    "sophos_list_detected_exploits",
    {
      title: "List Sophos Detected Exploits",
      description: `List detected exploits across endpoints in the tenant.

Returns exploit events that have been detected and mitigated by exploit protection.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of detected exploits with details.`,
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
      >(
        resolvedTenantId,
        "/endpoint/v1/settings/exploit-mitigation/detected-exploits",
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? data.items.length,
        page: data.pages?.current ?? page,
        items: data.items,
      });
    })
  );

  server.registerTool(
    "sophos_get_detected_exploit",
    {
      title: "Get Sophos Detected Exploit",
      description: `Get details of a specific detected exploit by ID.

Args:
  - exploit_id (string): Detected exploit ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        exploit_id: z.string().guid().describe("Detected exploit ID"),
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
    withErrorHandling(async ({ exploit_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/endpoint/v1/settings/exploit-mitigation/detected-exploits/${exploit_id}`,
        {}
      );
      return jsonResult(data);
    })
  );

  // =========================================================================
  // EXPLOIT MITIGATION - CATEGORIES
  // =========================================================================

  server.registerTool(
    "sophos_list_exploit_mitigation_categories",
    {
      title: "List Sophos Exploit Mitigation Categories",
      description: `List exploit mitigation categories (for example java, browser, office) and their settings.

The API returns every category in one response.

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
        "/endpoint/v1/settings/exploit-mitigation/categories"
      );
      return jsonResult({ total: data.items?.length ?? 0, items: data.items ?? [] });
    })
  );

  server.registerTool(
    "sophos_get_exploit_mitigation_category",
    {
      title: "Get Sophos Exploit Mitigation Category",
      description: `Get one exploit mitigation category and its settings.

Category IDs are names such as "java" or "browser", as
sophos_list_exploit_mitigation_categories returns them.

Args:
  - category_id (string): Category ID, for example "java".
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        category_id: z.string().regex(/^[A-Za-z0-9_-]+$/, "A category ID such as java").describe('Category ID, for example "java"'),
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
    withErrorHandling(async ({ category_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/endpoint/v1/settings/exploit-mitigation/categories/${category_id}`
      );
      return jsonResult(data);
    })
  );

  // =========================================================================
  // EXPLOIT MITIGATION - APPLICATIONS
  // =========================================================================

  server.registerTool(
    "sophos_list_exploit_mitigation_apps",
    {
      title: "List Sophos Exploit Mitigation Applications",
      description: `List applications configured for exploit mitigation.

Returns applications that have exploit mitigation protection applied.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of exploit mitigation applications.`,
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
      >(
        resolvedTenantId,
        "/endpoint/v1/settings/exploit-mitigation/applications",
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? data.items.length,
        page: data.pages?.current ?? page,
        items: data.items,
      });
    })
  );

  server.registerTool(
    "sophos_get_exploit_mitigation_app",
    {
      title: "Get Sophos Exploit Mitigation Application",
      description: `Get details of a specific exploit mitigation application by ID.

Args:
  - app_id (string): Exploit mitigation application ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        app_id: z.string().guid().describe("Exploit mitigation application ID"),
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
    withErrorHandling(async ({ app_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/endpoint/v1/settings/exploit-mitigation/applications/${app_id}`,
        {}
      );
      return jsonResult(data);
    })
  );

  server.registerTool(
    "sophos_add_exploit_mitigation_app",
    {
      title: "Add Sophos Exploit Mitigation Application",
      description: `Add an application to exploit mitigation protection.

Specify one or more executable paths to protect with exploit mitigation.

Args:
  - paths (string[]): Array of executable paths to protect.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        paths: z
          .array(z.string())
          .describe("Array of executable paths to protect"),
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
    withErrorHandling(async ({ paths, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const created = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/exploit-mitigation/applications",
        { method: "POST", body: { paths } }
      );
      return jsonResult({ status: "created", application: created });
    })
  );

  server.registerTool(
    "sophos_update_exploit_mitigation_app",
    {
      title: "Update Sophos Exploit Mitigation Application",
      description: `Update an exploit mitigation application configuration.

Modify paths or settings for an application under exploit mitigation.

Args:
  - app_id (string): Exploit mitigation application ID to update.
  - paths (string[], optional): Updated executable paths.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        app_id: z.string().guid().describe("Exploit mitigation application ID to update"),
        paths: z
          .array(z.string())
          .optional()
          .describe("Updated executable paths"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ app_id, paths, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {};
      if (paths !== undefined) body.paths = paths;

      const updated = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/endpoint/v1/settings/exploit-mitigation/applications/${app_id}`,
        { method: "PATCH", body }
      );
      return jsonResult({ status: "updated", application: updated });
    })
  );

  // =========================================================================
  // IPS EXCLUSIONS (INTRUSION PREVENTION)
  // =========================================================================

  server.registerTool(
    "sophos_list_ips_exclusions",
    {
      title: "List Sophos IPS Exclusions",
      description: `List intrusion prevention system (IPS) exclusions.

Returns addresses excluded from IPS inspection. Use sparingly as exclusions
reduce network protection.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of IPS exclusions with direction, address, and comment.`,
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
      >(
        resolvedTenantId,
        "/endpoint/v1/settings/exclusions/intrusion-prevention",
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? data.items.length,
        page: data.pages?.current ?? page,
        items: data.items,
      });
    })
  );

  server.registerTool(
    "sophos_add_ips_exclusion",
    {
      title: "Add Sophos IPS Exclusion",
      description: `Add an intrusion prevention system (IPS) exclusion.

Each exclusion takes one remote address, one local port and one remote port at
most, plus a direction.

Args:
  - direction (string): "inbound", "outbound" or "both".
  - remote_address (string, optional): Remote IP address or range.
  - local_port (number, optional): Local protected port.
  - remote_port (number, optional): Remote protected port.
  - comment (string, optional): Reason for the exclusion.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        direction: z.enum(["inbound", "outbound", "both"]).describe("Traffic direction"),
        remote_address: z.string().optional().describe("Remote IP address or range"),
        local_port: z.number().int().min(1).max(65535).optional().describe("Local protected port"),
        remote_port: z.number().int().min(1).max(65535).optional().describe("Remote protected port"),
        comment: z.string().optional().describe("Reason for the exclusion"),
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
    withErrorHandling(async ({ direction, remote_address, local_port, remote_port, comment, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { direction };
      if (remote_address) body.remoteAddresses = [remote_address];
      if (local_port !== undefined) body.localPorts = [local_port];
      if (remote_port !== undefined) body.remotePorts = [remote_port];
      if (comment) body.comment = comment;
      const created = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/exclusions/intrusion-prevention",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", exclusion: created });
    })
  );

  server.registerTool(
    "sophos_delete_ips_exclusion",
    {
      title: "Delete Sophos IPS Exclusion",
      description: `Delete an IPS exclusion by ID, restoring IPS inspection for that address.

Args:
  - exclusion_id (string): IPS exclusion ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        exclusion_id: z.string().guid().describe("IPS exclusion ID to delete"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ exclusion_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/settings/exclusions/intrusion-prevention/${exclusion_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        exclusion_id,
        message: `IPS exclusion ${exclusion_id} deleted.`,
      });
    })
  );

  // =========================================================================
  // ISOLATION EXCLUSIONS
  // =========================================================================

  server.registerTool(
    "sophos_list_isolation_exclusions",
    {
      title: "List Sophos Isolation Exclusions",
      description: `List isolation exclusions — addresses that remain reachable when an endpoint is isolated.

These allow critical services (e.g. domain controllers, update servers) to remain
accessible even when an endpoint is network-isolated.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of isolation exclusions.`,
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
      >(resolvedTenantId, "/endpoint/v1/settings/exclusions/isolation", {
        params: { pageSize: String(limit), page: String(page) },
      });
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? data.items.length,
        page: data.pages?.current ?? page,
        items: data.items,
      });
    })
  );

  server.registerTool(
    "sophos_add_isolation_exclusion",
    {
      title: "Add Sophos Isolation Exclusion",
      description: `Add an isolation exclusion so traffic to or from given addresses or ports keeps flowing while an endpoint is isolated.

Args:
  - direction (string): "inbound", "outbound" or "both".
  - remote_addresses (array, optional): Remote IP addresses or ranges.
  - local_ports (array, optional): Local ports to allow.
  - remote_ports (array, optional): Remote ports to allow.
  - comment (string, optional): Reason for the exclusion.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        direction: z.enum(["inbound", "outbound", "both"]).describe("Traffic direction"),
        remote_addresses: z.array(z.string()).optional().describe("Remote IP addresses or ranges"),
        local_ports: z.array(z.number().int().min(1).max(65535)).optional().describe("Local ports to allow"),
        remote_ports: z.array(z.number().int().min(1).max(65535)).optional().describe("Remote ports to allow"),
        comment: z.string().optional().describe("Reason for the exclusion"),
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
    withErrorHandling(async ({ direction, remote_addresses, local_ports, remote_ports, comment, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { direction };
      if (remote_addresses) body.remoteAddresses = remote_addresses;
      if (local_ports) body.localPorts = local_ports;
      if (remote_ports) body.remotePorts = remote_ports;
      if (comment) body.comment = comment;
      const created = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/endpoint/v1/settings/exclusions/isolation",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", exclusion: created });
    })
  );

  server.registerTool(
    "sophos_delete_isolation_exclusion",
    {
      title: "Delete Sophos Isolation Exclusion",
      description: `Delete an isolation exclusion by ID.

Args:
  - exclusion_id (string): Isolation exclusion ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        exclusion_id: z.string().guid().describe("Isolation exclusion ID to delete"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ exclusion_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/settings/exclusions/isolation/${exclusion_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        exclusion_id,
        message: `Isolation exclusion ${exclusion_id} deleted.`,
      });
    })
  );

  // =========================================================================
}
