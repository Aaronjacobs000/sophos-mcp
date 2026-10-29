/**
 * Tools: sophos_list_exclusions, sophos_add_exclusion, sophos_delete_exclusion,
 *        sophos_list_allowed_items, sophos_add_allowed_item, sophos_delete_allowed_item,
 *        sophos_list_blocked_items, sophos_add_blocked_item, sophos_delete_blocked_item
 * Interact with the Sophos Endpoint API /endpoint/v1/settings/
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

interface SophosScanningExclusion {
  id: string;
  type: string;
  value: string;
  description?: string;
  comment?: string;
  scanMode?: string;
  createdAt?: string;
  updatedAt?: string;
  lockedByManagingAccount?: boolean;
}

interface SophosAllowedBlockedItem {
  id: string;
  type: string;
  comment?: string;
  properties: {
    fileName?: string;
    path?: string;
    sha256?: string;
    certificateSigner?: string;
  };
  createdAt?: string;
  updatedAt?: string;
  createdBy?: { id: string; name?: string };
  originEndpointId?: string;
  originPersonId?: string;
}

export function registerExclusionTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // =========================================================================
  // SCANNING EXCLUSIONS
  // =========================================================================

  server.registerTool(
    "sophos_list_exclusions",
    {
      title: "List Sophos Scanning Exclusions",
      description: `List global scanning exclusions configured for a tenant.

Returns all file/folder, process, website, PUA, exploit mitigation, and AMSI 
exclusions. These apply globally across all endpoints in the tenant.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - type (string, optional): Filter by exclusion type.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of exclusions with: id, type, value, description, scan mode.`,
      inputSchema: {
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        type: z
          .string()
          .optional()
          .describe("Filter by exclusion type"),
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
    withErrorHandling(async ({ tenant_id, type, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };
      if (type) params.type = type;

      const data = await client.tenantRequest<
        SophosPagedResponse<SophosScanningExclusion>
      >(resolvedTenantId, "/endpoint/v1/settings/exclusions/scanning", {
        params,
      });

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        exclusions: data.items.map(formatExclusion),
      });
    })
  );

  server.registerTool(
    "sophos_add_exclusion",
    {
      title: "Add Sophos Scanning Exclusion",
      description: `Add a new global scanning exclusion.

WARNING: Scanning exclusions reduce protection. Only add exclusions that are 
necessary for application compatibility. Overly broad exclusions (e.g. entire 
drives) are a security risk.

Supported exclusion types and their value formats:
  - "path": File or folder path (e.g. "C:\\MyApp\\", "/opt/myapp/")
  - "process": Process path (e.g. "C:\\MyApp\\app.exe")
  - "web": Website address (e.g. "example.com")
  - "pua": PUA application name
  - "amsi": AMSI protection exclusion
  - "detectedExploit": A detected exploit, by its ID
  - also "posixPath", "virtualPath", "behavioral", "journalHashingProcess", "journalHashingPath"

Args:
  - type (string): Exclusion type.
  - value (string): The value to exclude (path, process, website, etc.)
  - scan_mode (string, optional): "onDemandAndOnAccess", "onDemand" or "onAccess". Sophos
    picks the default by type.
  - comment (string, optional): Why this exclusion exists (up to 100 characters).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        type: z
          .enum(["path", "posixPath", "virtualPath", "process", "web", "pua", "detectedExploit", "amsi", "behavioral", "journalHashingProcess", "journalHashingPath"])
          .describe("Exclusion type"),
        value: z.string().describe("Value to exclude"),
        scan_mode: z
          .enum(["onDemandAndOnAccess", "onDemand", "onAccess"])
          .optional()
          .describe("Scan mode; Sophos picks the default by type"),
        comment: z.string().max(100).optional().describe("Why this exclusion exists"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ type, value, scan_mode, comment, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = { type, value };
      if (scan_mode) body.scanMode = scan_mode;
      if (comment) body.comment = comment;

      const created = await client.tenantRequest<SophosScanningExclusion>(
        resolvedTenantId,
        "/endpoint/v1/settings/exclusions/scanning",
        { method: "POST", body }
      );

      return jsonResult({ status: "created", exclusion: formatExclusion(created) });
    })
  );

  server.registerTool(
    "sophos_delete_exclusion",
    {
      title: "Delete Sophos Scanning Exclusion",
      description: `Delete a global scanning exclusion by ID.

Args:
  - exclusion_id (string): Exclusion ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        exclusion_id: z.string().guid().describe("Exclusion ID to delete"),
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
        `/endpoint/v1/settings/exclusions/scanning/${exclusion_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        exclusion_id,
        message: `Scanning exclusion ${exclusion_id} deleted.`,
      });
    })
  );

  // =========================================================================
  // ALLOWED ITEMS
  // =========================================================================

  server.registerTool(
    "sophos_list_allowed_items",
    {
      title: "List Sophos Allowed Items",
      description: `List globally allowed items (applications/files permitted despite detections).

Returns items that have been explicitly allowed across all endpoints.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).`,
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
        SophosPagedResponse<SophosAllowedBlockedItem>
      >(resolvedTenantId, "/endpoint/v1/settings/allowed-items", {
        params: { pageSize: String(limit), page: String(page) },
      });

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        items: data.items.map(formatAllowedBlockedItem),
      });
    })
  );

  server.registerTool(
    "sophos_add_allowed_item",
    {
      title: "Add Sophos Allowed Item",
      description: `Add a globally allowed item (permit an application/file despite detections).

WARNING: Allowing items bypasses security detections. Only allow items you 
have verified as safe. Commonly used after PUA or false positive detections.

Args:
  - type (string): Item type: "sha256", "path", "posixPath" or "certificateSigner".
  - properties (object): Item properties. Must include one of:
    - sha256: SHA-256 hash of the file
    - path: File path
    - certificateSigner: Certificate signer name
  - comment (string): Reason for allowing (required by the API).
  - origin_endpoint_id (string, optional): Endpoint where item was first detected.
  - origin_person_id (string, optional): Person associated with the detection.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        type: z.enum(["sha256", "path", "posixPath", "certificateSigner"]).describe("Item type"),
        properties: z
          .object({
            sha256: z.string().optional().describe("SHA-256 hash"),
            path: z.string().optional().describe("File path"),
            fileName: z.string().optional().describe("File name"),
            certificateSigner: z.string().optional().describe("Certificate signer"),
          })
          .describe("Item identification properties"),
        comment: z.string().describe("Reason for allowing"),
        origin_endpoint_id: z.string().guid().optional().describe("Source endpoint ID"),
        origin_person_id: z.string().guid().optional().describe("Source person ID"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(
      async ({ type, properties, comment, origin_endpoint_id, origin_person_id, tenant_id }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        const body: Record<string, unknown> = { type, properties, comment };
        if (origin_endpoint_id) body.originEndpointId = origin_endpoint_id;
        if (origin_person_id) body.originPersonId = origin_person_id;

        const created = await client.tenantRequest<SophosAllowedBlockedItem>(
          resolvedTenantId,
          "/endpoint/v1/settings/allowed-items",
          { method: "POST", body }
        );

        return jsonResult({
          status: "created",
          item: formatAllowedBlockedItem(created),
        });
      }
    )
  );

  server.registerTool(
    "sophos_delete_allowed_item",
    {
      title: "Delete Sophos Allowed Item",
      description: `Remove a globally allowed item, restoring normal detection behaviour.

Args:
  - item_id (string): Allowed item ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        item_id: z.string().guid().describe("Allowed item ID to delete"),
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
    withErrorHandling(async ({ item_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/settings/allowed-items/${item_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        item_id,
        message: `Allowed item ${item_id} deleted.`,
      });
    })
  );

  // =========================================================================
  // BLOCKED ITEMS
  // =========================================================================

  server.registerTool(
    "sophos_list_blocked_items",
    {
      title: "List Sophos Blocked Items",
      description: `List globally blocked items (applications/files blocked on all endpoints).

Returns items that have been explicitly blocked from running.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).`,
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
        SophosPagedResponse<SophosAllowedBlockedItem>
      >(resolvedTenantId, "/endpoint/v1/settings/blocked-items", {
        params: { pageSize: String(limit), page: String(page) },
      });

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        items: data.items.map(formatAllowedBlockedItem),
      });
    })
  );

  server.registerTool(
    "sophos_add_blocked_item",
    {
      title: "Add Sophos Blocked Item",
      description: `Add a globally blocked item to prevent an application/file from running.

This blocks the item across all endpoints in the tenant.

Args:
  - type (string): "sha256", the only type the API blocks by.
  - properties (object): Item identification properties (same as allowed items).
  - comment (string): Reason for blocking (required by the API).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        type: z.enum(["sha256"]).default("sha256").describe("Item type: sha256"),
        properties: z
          .object({
            sha256: z.string().optional().describe("SHA-256 hash"),
            path: z.string().optional().describe("File path"),
            fileName: z.string().optional().describe("File name"),
            certificateSigner: z.string().optional().describe("Certificate signer"),
          })
          .describe("Item identification properties"),
        comment: z.string().describe("Reason for blocking"),
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
    withErrorHandling(async ({ type, properties, comment, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = { type, properties, comment };

      const created = await client.tenantRequest<SophosAllowedBlockedItem>(
        resolvedTenantId,
        "/endpoint/v1/settings/blocked-items",
        { method: "POST", body }
      );

      return jsonResult({
        status: "created",
        item: formatAllowedBlockedItem(created),
      });
    })
  );

  server.registerTool(
    "sophos_delete_blocked_item",
    {
      title: "Delete Sophos Blocked Item",
      description: `Remove a globally blocked item, allowing it to run again.

Args:
  - item_id (string): Blocked item ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        item_id: z.string().guid().describe("Blocked item ID to delete"),
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
    withErrorHandling(async ({ item_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/settings/blocked-items/${item_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        item_id,
        message: `Blocked item ${item_id} deleted.`,
      });
    })
  );
}

function formatExclusion(e: SophosScanningExclusion) {
  return {
    id: e.id,
    type: e.type,
    value: e.value,
    description: e.description ?? null,
    comment: e.comment ?? null,
    scan_mode: e.scanMode ?? null,
    locked_by_partner: e.lockedByManagingAccount ?? false,
    created_at: e.createdAt ?? null,
    updated_at: e.updatedAt ?? null,
  };
}

function formatAllowedBlockedItem(item: SophosAllowedBlockedItem) {
  return {
    id: item.id,
    type: item.type,
    comment: item.comment ?? null,
    properties: {
      file_name: item.properties.fileName ?? null,
      path: item.properties.path ?? null,
      sha256: item.properties.sha256 ?? null,
      certificate_signer: item.properties.certificateSigner ?? null,
    },
    created_at: item.createdAt ?? null,
    updated_at: item.updatedAt ?? null,
    created_by: item.createdBy
      ? { id: item.createdBy.id, name: item.createdBy.name ?? null }
      : null,
    origin_endpoint_id: item.originEndpointId ?? null,
    origin_person_id: item.originPersonId ?? null,
  };
}
