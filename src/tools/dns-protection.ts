/**
 * Tools: sophos_list_dns_locations, sophos_get_dns_location,
 *        sophos_create_dns_location, sophos_update_dns_location,
 *        sophos_delete_dns_location
 * Interact with the Sophos DNS Protection API /dns-protection/v2/
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerDnsProtectionTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List DNS Locations ---
  server.registerTool(
    "sophos_list_dns_locations",
    {
      title: "List DNS Protection Locations",
      description: `List DNS protection locations configured for a tenant.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of DNS protection locations.`,
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
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/dns-protection/v2/locations",
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult(data);
    })
  );

  // --- Get DNS Location ---
  server.registerTool(
    "sophos_get_dns_location",
    {
      title: "Get DNS Protection Location",
      description: `Get details of a specific DNS protection location.

Args:
  - location_id (string): The location ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        location_id: z.string().describe("DNS location ID"),
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
    withErrorHandling(async ({ location_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/dns-protection/v2/locations/${location_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create DNS Location ---
  server.registerTool(
    "sophos_create_dns_location",
    {
      title: "Create DNS Protection Location",
      description: `Create a DNS Protection location (at most 50 per account).

A location is identified by its public IP addresses or domain names; together
at most 100.

Args:
  - name (string): Location name (letters, digits, spaces, hyphens, underscores; up to 100).
  - ip_addresses (string[], optional): Public IPv4 or IPv6 addresses.
  - domain_names (string[], optional): Domain names.
  - description (string, optional): Up to 250 characters.
  - policy_id (string, optional): DNS Protection policy to apply.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9\-_ ]+$/, "Letters, digits, spaces, hyphens and underscores only").describe("Location name"),
        ip_addresses: z.array(z.string()).max(100).optional().describe("Public IP addresses"),
        domain_names: z.array(z.string()).max(100).optional().describe("Domain names"),
        description: z.string().max(250).optional().describe("Location description"),
        policy_id: z.string().uuid().optional().describe("DNS Protection policy ID"),
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
    withErrorHandling(async ({ name, ip_addresses, domain_names, description, policy_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { name };
      if (ip_addresses) body.ipAddresses = ip_addresses;
      if (domain_names) body.domainNames = domain_names;
      if (description !== undefined) body.description = description;
      if (policy_id) body.policyId = policy_id;

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/dns-protection/v2/locations",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", location: data });
    })
  );

  // --- Update DNS Location ---
  server.registerTool(
    "sophos_update_dns_location",
    {
      title: "Update DNS Protection Location",
      description: `Update a DNS Protection location.

ip_addresses and domain_names replace the stored lists. To change a few
entries without restating the rest, use the add_* and remove_* arguments
instead (one form per list).

Args:
  - location_id (string): The location ID to update.
  - name (string, optional): New name.
  - description (string, optional): New description.
  - ip_addresses (string[], optional): The complete new IP address list.
  - add_ip_addresses, remove_ip_addresses (string[], optional): IPs to add or remove.
  - domain_names (string[], optional): The complete new domain name list.
  - add_domain_names, remove_domain_names (string[], optional): Domains to add or remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        location_id: z.string().uuid().describe("DNS location ID to update"),
        name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9\-_ ]+$/, "Letters, digits, spaces, hyphens and underscores only").optional().describe("New location name"),
        description: z.string().max(250).optional().describe("New description"),
        ip_addresses: z.array(z.string()).max(100).optional().describe("The complete new IP address list"),
        add_ip_addresses: z.array(z.string()).max(100).optional().describe("IP addresses to add"),
        remove_ip_addresses: z.array(z.string()).max(100).optional().describe("IP addresses to remove"),
        domain_names: z.array(z.string()).max(100).optional().describe("The complete new domain name list"),
        add_domain_names: z.array(z.string()).max(100).optional().describe("Domain names to add"),
        remove_domain_names: z.array(z.string()).max(100).optional().describe("Domain names to remove"),
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
    withErrorHandling(async (args) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const list = (full: string[] | undefined, add: string[] | undefined, remove: string[] | undefined, what: string) => {
        if (full && (add || remove)) {
          throw new Error(`Pass ${what} or add_${what}/remove_${what}, not both. Nothing was sent.`);
        }
        if (full) return full;
        if (add || remove) return { ...(add ? { add } : {}), ...(remove ? { remove } : {}) };
        return undefined;
      };
      const body: Record<string, unknown> = {};
      if (args.name !== undefined) body.name = args.name;
      if (args.description !== undefined) body.description = args.description;
      const ips = list(args.ip_addresses, args.add_ip_addresses, args.remove_ip_addresses, "ip_addresses");
      if (ips) body.ipAddresses = ips;
      const domains = list(args.domain_names, args.add_domain_names, args.remove_domain_names, "domain_names");
      if (domains) body.domainNames = domains;
      if (Object.keys(body).length === 0) {
        throw new Error("No fields to update. Nothing was sent.");
      }

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/dns-protection/v2/locations/${args.location_id}`,
        { method: "PATCH", body }
      );
      return jsonResult({ status: "updated", location: data });
    })
  );

  // --- Delete DNS Location ---
  server.registerTool(
    "sophos_delete_dns_location",
    {
      title: "Delete DNS Protection Location",
      description: `Delete a DNS protection location.

WARNING: This permanently removes the DNS protection location.

Args:
  - location_id (string): The location ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        location_id: z.string().describe("DNS location ID to delete"),
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
    withErrorHandling(async ({ location_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/dns-protection/v2/locations/${location_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        location_id,
        message: `DNS location ${location_id} deleted.`,
      });
    })
  );
}
