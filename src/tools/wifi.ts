/**
 * Tools: sophos_list_wifi_mac_filters, sophos_add_wifi_mac_filter,
 *        sophos_delete_wifi_mac_filter
 * Interact with the Sophos Wi-Fi Management API /wifi/v1/
 *
 * The API holds MAC filtering as one tenant-wide list (GET and PUT
 * /settings/mac-filtering, at most 256 addresses). There are no per-entry
 * routes, so add and delete read the list, change it, and PUT it back.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";

const PATH = "/wifi/v1/settings/mac-filtering";
const MAX_ADDRESSES = 256;

interface MacFilterSettings {
  macAddresses?: string[];
  updatedAt?: string | null;
  updatedBy?: unknown;
}

const tenantIdSchema = z
  .string()
  .uuid()
  .optional()
  .describe("Tenant ID. Required for partner/org callers.");

const macSchema = z
  .string()
  .regex(/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/, "A MAC address such as 00:11:22:33:44:55")
  .describe("MAC address");

/** Case-insensitive, separator-insensitive comparison key for a MAC address. */
const macKey = (mac: string) => mac.toLowerCase().replace(/-/g, ":");

export function registerWifiTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Wi-Fi MAC Filters ---
  server.registerTool(
    "sophos_list_wifi_mac_filters",
    {
      title: "List Wi-Fi MAC Filtering Entries",
      description: `Get the tenant's Wi-Fi MAC filtering list.

The API keeps one list for the whole tenant (up to 256 addresses) and returns
it in one response.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { tenant_id: tenantIdSchema },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<MacFilterSettings>(resolvedTenantId, PATH);
      return jsonResult({ total: data.macAddresses?.length ?? 0, ...data });
    })
  );

  // --- Add Wi-Fi MAC Filter ---
  server.registerTool(
    "sophos_add_wifi_mac_filter",
    {
      title: "Add Wi-Fi MAC Filter Entry",
      description: `Add MAC addresses to the tenant's Wi-Fi MAC filtering list.

The tool reads the list, adds the addresses that are not there yet, and writes
the whole list back (the API has no per-entry add). The list holds at most 256.

Args:
  - mac_addresses (array): MAC addresses to add, for example "00:11:22:33:44:55".
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mac_addresses: z.array(macSchema).min(1).describe("MAC addresses to add"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ mac_addresses, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const current = (await client.tenantRequest<MacFilterSettings>(resolvedTenantId, PATH)).macAddresses ?? [];
      const have = new Set(current.map(macKey));
      const added = mac_addresses.filter((m, i) => !have.has(macKey(m)) && mac_addresses.findIndex((x) => macKey(x) === macKey(m)) === i);
      if (added.length === 0) {
        return jsonResult({ status: "unchanged", message: "Every address is already in the list.", total: current.length });
      }
      const next = [...current, ...added];
      if (next.length > MAX_ADDRESSES) {
        throw new Error(`The list would hold ${next.length} addresses; the API allows ${MAX_ADDRESSES}. Nothing was written.`);
      }
      const data = await client.tenantRequest<MacFilterSettings>(resolvedTenantId, PATH, {
        method: "PUT",
        body: { macAddresses: next },
      });
      return jsonResult({ status: "updated", added, total: data.macAddresses?.length ?? next.length, settings: data });
    })
  );

  // --- Delete Wi-Fi MAC Filter ---
  server.registerTool(
    "sophos_delete_wifi_mac_filter",
    {
      title: "Delete Wi-Fi MAC Filter Entry",
      description: `Remove MAC addresses from the tenant's Wi-Fi MAC filtering list.

The tool reads the list, drops the addresses given, and writes the whole list
back (the API has no per-entry delete). Addresses not in the list are reported
in not_found.

Args:
  - mac_addresses (array): MAC addresses to remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        mac_addresses: z.array(macSchema).min(1).describe("MAC addresses to remove"),
        tenant_id: tenantIdSchema,
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
      const current = (await client.tenantRequest<MacFilterSettings>(resolvedTenantId, PATH)).macAddresses ?? [];
      const drop = new Set(mac_addresses.map(macKey));
      const next = current.filter((m) => !drop.has(macKey(m)));
      const have = new Set(current.map(macKey));
      const notFound = mac_addresses.filter((m) => !have.has(macKey(m)));
      if (next.length === current.length) {
        return jsonResult({ status: "unchanged", not_found: notFound, total: current.length });
      }
      const data = await client.tenantRequest<MacFilterSettings>(resolvedTenantId, PATH, {
        method: "PUT",
        body: { macAddresses: next },
      });
      return jsonResult({
        status: "updated",
        removed: current.length - next.length,
        ...(notFound.length ? { not_found: notFound } : {}),
        total: data.macAddresses?.length ?? next.length,
        settings: data,
      });
    })
  );
}
