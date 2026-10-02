/**
 * Tools: sophos_list_firewalls, sophos_update_firewall,
 *        sophos_delete_firewall, sophos_firewall_action,
 *        sophos_check_firmware_upgrade, sophos_start_firmware_upgrade,
 *        sophos_cancel_firmware_upgrade,
 *        sophos_list_firewall_groups, sophos_get_firewall_group,
 *        sophos_create_firewall_group, sophos_update_firewall_group,
 *        sophos_delete_firewall_group,
 *        sophos_get_firewall_sync_status,
 *        sophos_get_threat_feed_settings, sophos_update_threat_feed_settings,
 *        sophos_search_threat_feed_indicators,
 *        sophos_get_firewall_transaction,
 *        sophos_export_firewall_config, sophos_get_firewall_import_export_transaction,
 *        sophos_download_firewall_backup, sophos_import_firewall_config
 * Interact with the Sophos Firewall Management API /firewall/v1/
 * Paths verified against the firewall-v1 OpenAPI spec (Aug 2026).
 */

import { z } from "zod";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve as resolvePath } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerFirewallTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // ===== Firewalls =====

  // --- List Firewalls ---
  server.registerTool(
    "sophos_list_firewalls",
    {
      title: "List Sophos Firewalls",
      description: `List managed firewalls in a Sophos Central tenant.

Supports filtering by group and search string. Uses offset-based pagination.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - group_id (string, optional): Filter by firewall group ID.
  - search (string, optional): Search by firewall name or serial number.
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        group_id: z
          .string()
          .optional()
          .describe("Filter by firewall group ID"),
        search: z
          .string()
          .optional()
          .describe("Search by firewall name or serial number"),
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
    withErrorHandling(async ({ tenant_id, group_id, search, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      if (group_id) params.groupId = group_id;
      if (search) params.search = search;

      const data = await client.tenantRequest<SophosPagedResponse<Record<string, unknown>>>(
        resolvedTenantId,
        "/firewall/v1/firewalls",
        { params }
      );

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        firewalls: data.items,
      });
    })
  );

  // NOTE: There is intentionally no sophos_get_firewall tool. The Firewall
  // Management API does not document GET /firewalls/{firewallId} (verified
  // against the API spec and live API, which returns 404). Use
  // sophos_list_firewalls and filter by ID instead.

  // --- Update Firewall ---
  server.registerTool(
    "sophos_update_firewall",
    {
      title: "Update Sophos Firewall",
      description: `Update a managed firewall's name or group assignment.

Args:
  - firewall_id (string): The firewall ID to update.
  - name (string, optional): New firewall name.
  - group_id (string, optional): New group ID to assign the firewall to.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID to update"),
        name: z.string().optional().describe("New firewall name"),
        group_id: z
          .string()
          .uuid()
          .optional()
          .describe("New group ID to assign the firewall to"),
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
    withErrorHandling(async ({ firewall_id, name, group_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = {};
      if (name !== undefined) body.name = name;
      if (group_id !== undefined) body.groupId = group_id;

      if (Object.keys(body).length === 0) {
        return jsonResult({
          error: "No fields to update. Provide at least one of: name, group_id.",
        });
      }

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewalls/${firewall_id}`,
        { method: "PATCH", body }
      );
      return jsonResult({ status: "updated", firewall: data });
    })
  );

  // --- Delete Firewall ---
  server.registerTool(
    "sophos_delete_firewall",
    {
      title: "Delete Sophos Firewall",
      description: `Delete a managed firewall from Sophos Central.

WARNING: This permanently removes the firewall record. The device will need
to be re-registered if you want to manage it again.

Args:
  - firewall_id (string): The firewall ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID to delete"),
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
    withErrorHandling(async ({ firewall_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/firewall/v1/firewalls/${firewall_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        firewall_id,
        message: `Firewall ${firewall_id} has been deleted from Sophos Central.`,
      });
    })
  );

  // ===== Firewall Actions =====

  // --- Firewall Action ---
  server.registerTool(
    "sophos_firewall_action",
    {
      title: "Perform Sophos Firewall Action",
      description: `Perform an action on a managed firewall.

The API currently supports exactly one action: "approveManagement", which
approves the firewall being managed from Sophos Central. Firmware upgrades
have their own tools (sophos_check_firmware_upgrade,
sophos_start_firmware_upgrade, sophos_cancel_firmware_upgrade).

Args:
  - firewall_id (string): The firewall ID.
  - action (string): Action to perform. Only "approveManagement" is supported.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID"),
        action: z
          .enum(["approveManagement"])
          .describe("Action to perform on the firewall (only approveManagement is supported)"),
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
    withErrorHandling(async ({ firewall_id, action, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewalls/${firewall_id}/action`,
        { method: "POST", body: { action } }
      );
      return jsonResult({
        status: "action_submitted",
        firewall_id,
        action,
        result: data,
      });
    })
  );

  // ===== Firmware =====

  // --- Check Firmware Upgrade ---
  server.registerTool(
    "sophos_check_firmware_upgrade",
    {
      title: "Check Sophos Firewall Firmware Upgrade",
      description: `Check if firmware upgrades are available for one or more managed firewalls.

Args:
  - firewall_ids (array): Firewall IDs to check (at least one).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_ids: z
          .array(z.string().uuid())
          .min(1)
          .describe("Firewall IDs to check (at least one)"),
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
    withErrorHandling(async ({ firewall_ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/firewall/v1/firewalls/actions/firmware-upgrade-check",
        { method: "POST", body: { firewalls: firewall_ids } }
      );
      return jsonResult(data);
    })
  );

  // --- Start Firmware Upgrade ---
  server.registerTool(
    "sophos_start_firmware_upgrade",
    {
      title: "Start Sophos Firewall Firmware Upgrade",
      description: `Start (or schedule) a firmware upgrade on one or more managed firewalls.

WARNING: This will upgrade firewall firmware which may cause a brief
service interruption during reboot.

Args:
  - firewalls (array): Firewalls to upgrade. Each item: {id (required), upgrade_to_version (optional), upgrade_at (optional ISO 8601 datetime)}.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewalls: z
          .array(
            z.object({
              id: z.string().uuid().describe("Firewall ID"),
              upgrade_to_version: z
                .string()
                .optional()
                .describe("Target firmware version (omit for latest)"),
              upgrade_at: z
                .string()
                .optional()
                .describe("ISO 8601 datetime to schedule the upgrade"),
            })
          )
          .min(1)
          .describe("Firewalls to upgrade (at least one)"),
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
    withErrorHandling(async ({ firewalls, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body = {
        firewalls: firewalls.map((fw) => {
          const item: Record<string, unknown> = { id: fw.id };
          if (fw.upgrade_to_version) item.upgradeToVersion = fw.upgrade_to_version;
          if (fw.upgrade_at) item.upgradeAt = fw.upgrade_at;
          return item;
        }),
      };

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/firewall/v1/firewalls/actions/firmware-upgrade",
        { method: "POST", body }
      );
      return jsonResult({
        status: "firmware_upgrade_initiated",
        firewalls: firewalls.map((fw) => fw.id),
        result: data,
      });
    })
  );

  // --- Cancel Firmware Upgrade ---
  server.registerTool(
    "sophos_cancel_firmware_upgrade",
    {
      title: "Cancel Sophos Firewall Firmware Upgrade",
      description: `Cancel scheduled firmware upgrades on one or more managed firewalls.

Args:
  - firewall_ids (array): Firewall IDs whose scheduled upgrades should be cancelled.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_ids: z
          .array(z.string().uuid())
          .min(1)
          .describe("Firewall IDs whose scheduled upgrades should be cancelled"),
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
    withErrorHandling(async ({ firewall_ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        "/firewall/v1/firewalls/actions/firmware-upgrade",
        { method: "DELETE", params: { ids: firewall_ids.join(",") } }
      );
      return jsonResult({
        status: "firmware_upgrade_cancelled",
        firewall_ids,
        message: "Scheduled firmware upgrades cancelled.",
      });
    })
  );

  // ===== Firewall Groups =====

  // --- List Firewall Groups ---
  server.registerTool(
    "sophos_list_firewall_groups",
    {
      title: "List Sophos Firewall Groups",
      description: `List firewall groups in a Sophos Central tenant.

Firewall groups organise managed firewalls for policy and configuration management.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).`,
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

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      const data = await client.tenantRequest<SophosPagedResponse<Record<string, unknown>>>(
        resolvedTenantId,
        "/firewall/v1/firewall-groups",
        { params }
      );

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        groups: data.items,
      });
    })
  );

  // --- Get Firewall Group ---
  server.registerTool(
    "sophos_get_firewall_group",
    {
      title: "Get Sophos Firewall Group Detail",
      description: `Get full details of a firewall group by ID.

Returns group information including name, description, and member firewalls.

Args:
  - group_id (string): The firewall group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("Firewall group ID"),
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
    withErrorHandling(async ({ group_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-groups/${group_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create Firewall Group ---
  server.registerTool(
    "sophos_create_firewall_group",
    {
      title: "Create Sophos Firewall Group",
      description: `Create a new firewall group for organising managed firewalls.

Args:
  - name (string): Group name.
  - description (string, optional): Group description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        name: z.string().describe("Firewall group name"),
        description: z
          .string()
          .optional()
          .describe("Firewall group description"),
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
    withErrorHandling(async ({ name, description, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = { name };
      if (description) body.description = description;

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/firewall/v1/firewall-groups",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", group: data });
    })
  );

  // --- Update Firewall Group ---
  server.registerTool(
    "sophos_update_firewall_group",
    {
      title: "Update Sophos Firewall Group",
      description: `Update an existing firewall group's name or description.

Args:
  - group_id (string): Group ID to update.
  - name (string, optional): New group name.
  - description (string, optional): New group description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("Firewall group ID to update"),
        name: z.string().optional().describe("New group name"),
        description: z.string().optional().describe("New group description"),
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
    withErrorHandling(async ({ group_id, name, description, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = {};
      if (name !== undefined) body.name = name;
      if (description !== undefined) body.description = description;

      if (Object.keys(body).length === 0) {
        return jsonResult({
          error: "No fields to update. Provide at least one of: name, description.",
        });
      }

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-groups/${group_id}`,
        { method: "PATCH", body }
      );
      return jsonResult({ status: "updated", group: data });
    })
  );

  // --- Delete Firewall Group ---
  server.registerTool(
    "sophos_delete_firewall_group",
    {
      title: "Delete Sophos Firewall Group",
      description: `Delete a firewall group.

WARNING: This removes the group. Firewalls in the group are NOT deleted
but will no longer be members of this group.

Args:
  - group_id (string): Group ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("Firewall group ID to delete"),
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
    withErrorHandling(async ({ group_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/firewall/v1/firewall-groups/${group_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        group_id,
        message: `Firewall group ${group_id} has been deleted.`,
      });
    })
  );

  // ===== Firewall Sync Status =====

  // --- Get Firewall Sync Status ---
  server.registerTool(
    "sophos_get_firewall_sync_status",
    {
      title: "Get Sophos Firewall Group Sync Status",
      description: `Get the configuration sync status of the firewalls in a firewall group.

Returns whether each firewall's configuration is in sync with Sophos Central.

Args:
  - group_id (string): The firewall group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("Firewall group ID"),
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
    withErrorHandling(async ({ group_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-groups/${group_id}/firewalls/sync-status`
      );
      return jsonResult(data);
    })
  );

  // ===== MDR Threat Feed (per-firewall, /firewall-config) =====

  // --- Get Threat Feed Settings ---
  server.registerTool(
    "sophos_get_threat_feed_settings",
    {
      title: "Get MDR Threat Feed",
      description: `Get the MDR threat feed configuration and status for a managed firewall.

Returns the current configuration for how MDR threat indicators are pushed
to the firewall.

Args:
  - firewall_id (string): The firewall ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID"),
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
    withErrorHandling(async ({ firewall_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-config/firewalls/${firewall_id}/mdr-threat-feed`
      );
      return jsonResult(data);
    })
  );

  // --- Update Threat Feed Settings ---
  server.registerTool(
    "sophos_update_threat_feed_settings",
    {
      title: "Update MDR Threat Feed Settings",
      description: `Update the MDR threat feed settings on a managed firewall.

Asynchronous: returns a transaction ID. Poll it with
sophos_get_firewall_transaction.

Args:
  - firewall_id (string): The firewall ID.
  - settings (object): Settings object to update (passed directly to the API).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID"),
        settings: z
          .record(z.unknown())
          .describe("Settings object to update"),
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
    withErrorHandling(async ({ firewall_id, settings, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-config/firewalls/${firewall_id}/mdr-threat-feed/settings`,
        { method: "PATCH", body: settings }
      );
      return jsonResult({
        status: "update_submitted",
        firewall_id,
        result: data,
        next_step:
          "Poll sophos_get_firewall_transaction with the returned transactionId for the outcome.",
      });
    })
  );

  // --- Search Threat Feed Indicators ---
  server.registerTool(
    "sophos_search_threat_feed_indicators",
    {
      title: "Search MDR Threat Feed Indicators",
      description: `Search the MDR threat feed indicators on a managed firewall.

Asynchronous: returns a transaction ID. Poll it with
sophos_get_firewall_transaction; the finished transaction carries the
matching indicators.

Args:
  - firewall_id (string): The firewall ID.
  - filter (object, optional): Filter criteria object.
  - sort (array, optional): Sort criteria array.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID"),
        filter: z
          .record(z.unknown())
          .optional()
          .describe("Filter criteria object"),
        sort: z
          .array(z.unknown())
          .optional()
          .describe("Sort criteria array"),
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
    withErrorHandling(async ({ firewall_id, filter, sort, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = {};
      if (filter) body.filter = filter;
      if (sort) body.sort = sort;

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-config/firewalls/${firewall_id}/mdr-threat-feed/indicators/search`,
        { method: "POST", body }
      );
      return jsonResult(data);
    })
  );

  // --- Get Firewall Transaction (per-firewall operations) ---
  server.registerTool(
    "sophos_get_firewall_transaction",
    {
      title: "Get Sophos Firewall Transaction",
      description: `Poll a per-firewall transaction (MDR threat feed operations).

For configuration import/export transactions use
sophos_get_firewall_import_export_transaction instead; those are polled on a
shared endpoint without a firewall ID.

Args:
  - firewall_id (string): The firewall ID the transaction belongs to.
  - transaction_id (string): The transaction ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID"),
        transaction_id: z.string().describe("Transaction ID"),
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
    withErrorHandling(async ({ firewall_id, transaction_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-config/firewalls/${firewall_id}/transactions/${transaction_id}`
      );
      return jsonResult(data);
    })
  );

  // ===== Configuration Import/Export (Backups) =====

  // --- Export Firewall Configuration ---
  server.registerTool(
    "sophos_export_firewall_config",
    {
      title: "Export Sophos Firewall Configuration (Backup)",
      description: `Start a configuration export (backup) of a managed firewall.

The export is asynchronous: this call returns a transaction ID. Poll it with
sophos_get_firewall_import_export_transaction until finished, or use
sophos_download_firewall_backup to poll and save the archive in one step.

Export the full configuration (default) or a subset of entities such as
FirewallRule, NATRule, WebFilterPolicy, VPNIPSecConnection, Certificate.
See the ExportableEntity list in the Firewall Management API guide for all
valid entity names.

On a firewall running as an HA pair, target the PRIMARY node. The auxiliary
node rejects exports with "Configuration not allowed on auxiliary firewall".

Args:
  - firewall_id (string): The firewall ID to export.
  - full_export (boolean, optional): Export the full configuration (default true).
  - export_entities (array, optional): Entity names to export. Required when
    full_export is false; must be omitted when full_export is true.
  - include_dependency (boolean, optional): Include dependent entities. Only
    valid when full_export is false.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_id: z.string().uuid().describe("Firewall ID to export"),
        full_export: z
          .boolean()
          .optional()
          .default(true)
          .describe("Export the full configuration (default true)"),
        export_entities: z
          .array(z.string())
          .optional()
          .describe(
            "Entity names to export (e.g. FirewallRule, NATRule). Required when full_export is false"
          ),
        include_dependency: z
          .boolean()
          .optional()
          .describe("Include dependent entities (only when full_export is false)"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({ firewall_id, full_export, export_entities, include_dependency, tenant_id }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        if (full_export && (export_entities?.length || include_dependency !== undefined)) {
          return jsonResult({
            error:
              "When full_export is true, export_entities and include_dependency must be omitted. Set full_export to false for a selective export.",
          });
        }
        if (!full_export && !export_entities?.length) {
          return jsonResult({
            error:
              "When full_export is false, export_entities must contain at least one entity name.",
          });
        }

        const body: Record<string, unknown> = { fullExport: full_export };
        if (!full_export) {
          body.exportEntities = export_entities;
          if (include_dependency !== undefined) body.includeDependency = include_dependency;
        }

        const data = await client.tenantRequest<{ transactionId: string }>(
          resolvedTenantId,
          `/firewall/v1/firewall-config/firewalls/${firewall_id}/export`,
          { method: "POST", body }
        );

        return jsonResult({
          status: "export_initiated",
          firewall_id,
          transaction_id: data.transactionId,
          next_step:
            "Poll sophos_get_firewall_import_export_transaction (or run sophos_download_firewall_backup) with this transaction_id. When finished, the transaction response contains a pre-signed download URL.",
        });
      }
    )
  );

  // --- Get Import/Export Transaction ---
  server.registerTool(
    "sophos_get_firewall_import_export_transaction",
    {
      title: "Get Sophos Firewall Import/Export Transaction",
      description: `Poll the status of a firewall configuration export or import transaction.

Transactions move through states: pending, started, finished. A finished
export carries a pre-signed download URL (valid for a limited time) in its
response. A finished import carries per-firewall import results. Transactions
are retained for 30 days.

Args:
  - transaction_id (string): The transaction ID returned by the export or import call.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        transaction_id: z
          .string()
          .describe("Transaction ID from the export or import call"),
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
    withErrorHandling(async ({ transaction_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/firewall/v1/firewall-config/firewalls/transactions/${transaction_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Download Firewall Backup ---
  server.registerTool(
    "sophos_download_firewall_backup",
    {
      title: "Download Sophos Firewall Backup",
      description: `Download a finished firewall configuration export (backup) to a local file.

Checks the export transaction; if the export has finished, downloads the
archive from its pre-signed URL and saves it to output_path. If the export
is still running, returns the current status so you can retry shortly.

The archive can appear in storage up to a couple of minutes AFTER the
transaction reports finished; this tool retries the download automatically
for about 3 minutes before failing, so a single call normally suffices.

Typical flow: sophos_export_firewall_config, then call this tool with the
returned transaction_id.

Args:
  - transaction_id (string): The export transaction ID.
  - output_path (string): Local file path to save the backup archive to.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        transaction_id: z
          .string()
          .describe("Export transaction ID from sophos_export_firewall_config"),
        output_path: z
          .string()
          .describe("Local file path to save the backup archive to"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      // Writes output_path on this machine, replacing any file already there
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ transaction_id, output_path, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const txn = await client.tenantRequest<{
        status?: string;
        result?: string;
        response?: { url?: string; method?: string; expiresAt?: string; firewallId?: string };
      }>(resolvedTenantId, `/firewall/v1/firewall-config/firewalls/transactions/${transaction_id}`);

      if (txn.status !== "finished") {
        return jsonResult({
          status: "not_ready",
          transaction_status: txn.status,
          message: "Export has not finished yet. Retry in a few seconds.",
        });
      }

      const downloadUrl = txn.response?.url;
      if (txn.result !== "success" || !downloadUrl) {
        return jsonResult({
          status: "export_failed",
          transaction: txn,
          message: "Export finished without a downloadable archive.",
        });
      }

      // Pre-signed URL: plain fetch, no Sophos auth headers.
      // The storage object can lag the "finished" transaction status by a
      // couple of minutes, so a 404 from an unexpired URL means "not there
      // yet", not "expired". Retry before failing.
      const RETRY_DELAY_MS = 15_000;
      const MAX_ATTEMPTS = 13;
      const expiresAt = txn.response?.expiresAt;
      const urlExpired = () =>
        expiresAt !== undefined && Date.now() > Date.parse(expiresAt);
      let dl = await fetch(downloadUrl);
      for (
        let attempt = 1;
        !dl.ok && dl.status === 404 && !urlExpired() && attempt < MAX_ATTEMPTS;
        attempt++
      ) {
        await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
        dl = await fetch(downloadUrl);
      }
      if (!dl.ok) {
        throw new Error(
          dl.status === 404 && !urlExpired()
            ? `Backup download failed (404): the transaction reports finished but the archive has not appeared in storage yet, even after retrying for ~${Math.round((RETRY_DELAY_MS * (MAX_ATTEMPTS - 1)) / 60000)} minutes. Retry this tool shortly; the pre-signed URL is valid until ${expiresAt}.`
            : `Backup download failed (${dl.status}). The pre-signed URL may have expired (expiresAt: ${expiresAt}). Re-run sophos_export_firewall_config.`
        );
      }
      const bytes = Buffer.from(await dl.arrayBuffer());

      const savePath = resolvePath(output_path);
      await mkdir(dirname(savePath), { recursive: true });
      await writeFile(savePath, bytes);

      return jsonResult({
        status: "downloaded",
        transaction_id,
        firewall_id: txn.response?.firewallId,
        file_path: savePath,
        file_size_bytes: bytes.length,
        checksum_md5: createHash("md5").update(bytes).digest("hex"),
      });
    })
  );

  // --- Import Firewall Configuration ---
  server.registerTool(
    "sophos_import_firewall_config",
    {
      title: "Import Sophos Firewall Configuration",
      description: `Import a previously exported configuration archive into one or more firewalls.

WARNING: This changes the configuration of the target firewalls.

Runs the full import flow in one call: requests a pre-signed upload URL,
uploads the archive from file_path, then notifies Sophos Central with the
target firewalls and archive checksum. Returns the import transaction; poll
it with sophos_get_firewall_import_export_transaction for per-firewall results.

Args:
  - firewall_ids (array): Target firewall IDs (at least one).
  - file_path (string): Local path of the configuration archive to import.
  - secure_master_key (string, optional): Secure master key associated with the import.
  - perform_partial_import (boolean, optional): Allow partial success per firewall (default true).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        firewall_ids: z
          .array(z.string().uuid())
          .min(1)
          .describe("Target firewall IDs (at least one)"),
        file_path: z
          .string()
          .describe("Local path of the configuration archive to import"),
        secure_master_key: z
          .string()
          .optional()
          .describe("Secure master key associated with the import"),
        perform_partial_import: z
          .boolean()
          .optional()
          .default(true)
          .describe("Allow partial success per firewall (default true)"),
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
    withErrorHandling(
      async ({ firewall_ids, file_path, secure_master_key, perform_partial_import, tenant_id }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        const archive = await readFile(resolvePath(file_path));

        // Step 1: request the pre-signed upload URL.
        const init = await client.tenantRequest<{
          transactionId: string;
          url: string;
          method?: string;
          expiresAt?: string;
        }>(resolvedTenantId, "/firewall/v1/firewall-config/firewalls/import", { method: "POST" });

        // Step 2: upload the archive to the pre-signed URL (plain fetch, no Sophos auth headers).
        const upload = await fetch(init.url, {
          method: init.method || "PUT",
          body: archive,
        });
        if (!upload.ok) {
          throw new Error(
            `Archive upload failed (${upload.status}). The pre-signed URL may have expired (expiresAt: ${init.expiresAt}).`
          );
        }

        // Step 3: notify upload completion with target firewalls and archive metadata.
        const body: Record<string, unknown> = {
          firewallIds: firewall_ids,
          checksumMd5: createHash("md5").update(archive).digest("hex"),
          fileSizeBytes: archive.length,
          performPartialImport: perform_partial_import,
        };
        if (secure_master_key) body.secureMasterKey = secure_master_key;

        const txn = await client.tenantRequest<Record<string, unknown>>(
          resolvedTenantId,
          `/firewall/v1/firewall-config/firewalls/import/${init.transactionId}/upload-complete`,
          { method: "POST", body }
        );

        return jsonResult({
          status: "import_initiated",
          transaction_id: init.transactionId,
          firewall_ids,
          file_size_bytes: archive.length,
          transaction: txn,
          next_step:
            "Poll sophos_get_firewall_import_export_transaction with this transaction_id for per-firewall import results.",
        });
      }
    )
  );
}
