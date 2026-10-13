/**
 * Tools: sophos_list_web_filtering_profiles, sophos_get_web_filtering_profile,
 *        sophos_create_web_filtering_profile, sophos_update_web_filtering_profile,
 *        sophos_delete_web_filtering_profile, sophos_clone_web_filtering_profile,
 *        sophos_get_web_filtering_metadata,
 *        sophos_list_site_lists, sophos_get_site_list, sophos_create_site_list,
 *        sophos_update_site_list, sophos_delete_site_list, sophos_clone_site_list,
 *        sophos_list_sites, sophos_add_site, sophos_delete_site
 * Interact with the Sophos Web Filtering API /web-filters/v1/ (regional host).
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

const categoryActionSchema = z.object({
  name: z.string().describe("Category or category group name"),
  action: z.enum(["allow", "block", "warn"]).describe("Action"),
});

const siteListActionSchema = z.object({
  id: z.string().describe("Site list ID"),
  action: z.enum(["allow", "block", "warn"]).describe("Action"),
  priority: z.coerce.number().int().describe("Priority"),
});

const tenantIdSchema = z
  .string()
  .uuid()
  .optional()
  .describe("Tenant ID. Required for partner/org callers.");

const pageSchema = z
  .number()
  .int()
  .min(1)
  .optional()
  .default(1)
  .describe("Page number (default 1)");

const limitSchema = z
  .number()
  .int()
  .min(1)
  .max(100)
  .optional()
  .default(DEFAULT_PAGE_SIZE)
  .describe("Max results per page (default 50)");

function buildProfileBody(args: {
  name: string;
  description?: string;
  filter_by_category?: boolean;
  preset?: string;
  category_group_actions?: { name: string; action: "allow" | "block" | "warn" }[];
  category_actions?: { name: string; action: "allow" | "block" | "warn" }[];
  filter_by_site_list?: boolean;
  site_list_actions?: { id: string; action: "allow" | "block" | "warn"; priority: number }[];
}): Record<string, unknown> {
  const body: Record<string, unknown> = { name: args.name };
  if (args.description !== undefined) body.description = args.description;
  if (args.filter_by_category !== undefined) body.filterByCategory = args.filter_by_category;
  if (args.preset !== undefined) body.preset = args.preset;
  if (args.category_group_actions) body.categoryGroupActions = args.category_group_actions;
  if (args.category_actions) body.categoryActions = args.category_actions;
  if (args.filter_by_site_list !== undefined) body.filterBySiteList = args.filter_by_site_list;
  if (args.site_list_actions) body.siteListActions = args.site_list_actions;
  return body;
}

export function registerWebFilteringTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // ===== Profiles =====

  // --- List Profiles ---
  server.registerTool(
    "sophos_list_web_filtering_profiles",
    {
      title: "List Web Filtering Profiles",
      description: `List web filtering profiles in a tenant.

Args:
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: { limit: limitSchema, page: pageSchema, tenant_id: tenantIdSchema },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ limit, page, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/web-filters/v1/profiles",
        { params: { pageSize: String(limit), page: String(page), pageTotal: "true" } }
      );
      return jsonResult(data);
    })
  );

  // --- Get Profile ---
  server.registerTool(
    "sophos_get_web_filtering_profile",
    {
      title: "Get Web Filtering Profile",
      description: `Get a web filtering profile by ID.

Args:
  - profile_id (string): Web filtering profile ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        profile_id: z.string().describe("Web filtering profile ID"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ profile_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/profiles/${profile_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create Profile ---
  server.registerTool(
    "sophos_create_web_filtering_profile",
    {
      title: "Create Web Filtering Profile",
      description: `Create a web filtering profile.

A profile is linked to a policy from the policy side only: set
endpoint.web-control.web-profile-id in a web control policy's settings with
sophos_update_policy or sophos_create_policy. Sophos ignores consumers on a
profile write (accepted, nothing linked; measured 13/10/2026), so this tool
does not send it. The profile's consumers list is read-only.

Args:
  - name (string): Profile name.
  - description (string, optional): Profile description.
  - filter_by_category (boolean, optional): Enable category filtering.
  - preset (string, optional): Category preset name.
  - category_group_actions (array, optional): [{name, action: allow|block|warn}].
  - category_actions (array, optional): [{name, action: allow|block|warn}].
  - filter_by_site_list (boolean, optional): Enable site list filtering.
  - site_list_actions (array, optional): [{id, action: allow|block|warn, priority}].
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        name: z.string().describe("Profile name"),
        description: z.string().optional().describe("Profile description"),
        filter_by_category: z.boolean().optional().describe("Enable category filtering"),
        preset: z.string().optional().describe("Category preset name"),
        category_group_actions: z
          .array(categoryActionSchema)
          .optional()
          .describe("Category group actions"),
        category_actions: z
          .array(categoryActionSchema)
          .optional()
          .describe("Category actions"),
        filter_by_site_list: z
          .boolean()
          .optional()
          .describe("Enable site list filtering"),
        site_list_actions: z
          .array(siteListActionSchema)
          .optional()
          .describe("Site list actions"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, ...profileArgs }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/web-filters/v1/profiles",
        { method: "POST", body: buildProfileBody(profileArgs) }
      );
      return jsonResult({ status: "created", profile: data });
    })
  );

  // --- Update Profile ---
  server.registerTool(
    "sophos_update_web_filtering_profile",
    {
      title: "Update Web Filtering Profile",
      description: `Update (replace) a web filtering profile.

PUT semantics: the supplied fields replace the stored profile, so fetch the
profile first and send the complete desired state. consumers is not sent:
Sophos ignores it on a profile write, and policies link to a profile through
their own web-profile-id setting (sophos_update_policy).

Args: same as sophos_create_web_filtering_profile, plus:
  - profile_id (string): Web filtering profile ID.`,
      inputSchema: {
        profile_id: z.string().describe("Web filtering profile ID"),
        name: z.string().describe("Profile name"),
        description: z.string().optional().describe("Profile description"),
        filter_by_category: z.boolean().optional().describe("Enable category filtering"),
        preset: z.string().optional().describe("Category preset name"),
        category_group_actions: z
          .array(categoryActionSchema)
          .optional()
          .describe("Category group actions"),
        category_actions: z
          .array(categoryActionSchema)
          .optional()
          .describe("Category actions"),
        filter_by_site_list: z
          .boolean()
          .optional()
          .describe("Enable site list filtering"),
        site_list_actions: z
          .array(siteListActionSchema)
          .optional()
          .describe("Site list actions"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ profile_id, tenant_id, ...profileArgs }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/profiles/${profile_id}`,
        { method: "PUT", body: buildProfileBody(profileArgs) }
      );
      return jsonResult({ status: "updated", profile: data });
    })
  );

  // --- Delete Profile ---
  server.registerTool(
    "sophos_delete_web_filtering_profile",
    {
      title: "Delete Web Filtering Profile",
      description: `Delete a web filtering profile.

Args:
  - profile_id (string): Web filtering profile ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        profile_id: z.string().describe("Web filtering profile ID"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ profile_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/web-filters/v1/profiles/${profile_id}`,
        { method: "DELETE" }
      );
      return jsonResult({ status: "deleted", profile_id });
    })
  );

  // --- Clone Profile ---
  server.registerTool(
    "sophos_clone_web_filtering_profile",
    {
      title: "Clone Web Filtering Profile",
      description: `Clone a web filtering profile under a new name.

Args:
  - profile_id (string): Source profile ID.
  - name (string): Name for the cloned profile.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        profile_id: z.string().describe("Source profile ID"),
        name: z.string().describe("Name for the cloned profile"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ profile_id, name, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/profiles/${profile_id}/clone`,
        { method: "POST", body: { name } }
      );
      return jsonResult({ status: "cloned", profile: data });
    })
  );

  // --- Profile Metadata ---
  server.registerTool(
    "sophos_get_web_filtering_metadata",
    {
      title: "Get Web Filtering Metadata",
      description: `Get web filtering profile metadata (available categories, groups, presets).

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
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/web-filters/v1/profiles/metadata",
        // Accept-Language must be absent or a bare language tag such as "en" or "fr"
        // (labels come back in that language). "*", "en-US" and lists get a 400
        // "Invalid format of argument" (measured 13/10/2026), and Node's fetch sends
        // "*" when no header is set, so "en" is sent explicitly.
        { headers: { "Accept-Language": "en" } }
      );
      return jsonResult(data);
    })
  );

  // ===== Site Lists =====

  // --- List Site Lists ---
  server.registerTool(
    "sophos_list_site_lists",
    {
      title: "List Web Filtering Site Lists",
      description: `List site lists in a tenant.

Args:
  - search (string, optional): Filter lists whose name or sites contain the term.
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        search: z
          .string()
          .optional()
          .describe("Filter lists whose name or sites contain the term"),
        limit: limitSchema,
        page: pageSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ search, limit, page, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
        pageTotal: "true",
      };
      if (search) params.search = search;
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/web-filters/v1/site-lists",
        { params }
      );
      return jsonResult(data);
    })
  );

  // --- Get Site List ---
  server.registerTool(
    "sophos_get_site_list",
    {
      title: "Get Web Filtering Site List",
      description: `Get a site list by ID.

Args:
  - site_list_id (string): Site list ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_list_id: z.string().describe("Site list ID"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ site_list_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/site-lists/${site_list_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create Site List ---
  server.registerTool(
    "sophos_create_site_list",
    {
      title: "Create Web Filtering Site List",
      description: `Create a site list.

Args:
  - name (string): Site list name.
  - sites (array): Sites (domains, URLs, IPs, CIDRs) in the list.
  - description (string, optional): Site list description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        name: z.string().describe("Site list name"),
        sites: z
          .array(z.string())
          .describe("Sites (domains, URLs, IPs, CIDRs) in the list"),
        description: z.string().optional().describe("Site list description"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ name, sites, description, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { name, sites };
      if (description !== undefined) body.description = description;
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/web-filters/v1/site-lists",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", site_list: data });
    })
  );

  // --- Update Site List ---
  server.registerTool(
    "sophos_update_site_list",
    {
      title: "Update Web Filtering Site List",
      description: `Update (replace) a site list.

PUT semantics: name and sites replace the stored list, so fetch it first
and send the complete desired state.

Args:
  - site_list_id (string): Site list ID.
  - name (string): Site list name.
  - sites (array): Complete list of sites.
  - description (string, optional): Site list description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_list_id: z.string().describe("Site list ID"),
        name: z.string().describe("Site list name"),
        sites: z.array(z.string()).describe("Complete list of sites"),
        description: z.string().optional().describe("Site list description"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ site_list_id, name, sites, description, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { name, sites };
      if (description !== undefined) body.description = description;
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/site-lists/${site_list_id}`,
        { method: "PUT", body }
      );
      return jsonResult({ status: "updated", site_list: data });
    })
  );

  // --- Delete Site List ---
  server.registerTool(
    "sophos_delete_site_list",
    {
      title: "Delete Web Filtering Site List",
      description: `Delete a site list.

Args:
  - site_list_id (string): Site list ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_list_id: z.string().describe("Site list ID"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ site_list_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/web-filters/v1/site-lists/${site_list_id}`,
        { method: "DELETE" }
      );
      return jsonResult({ status: "deleted", site_list_id });
    })
  );

  // --- Clone Site List ---
  server.registerTool(
    "sophos_clone_site_list",
    {
      title: "Clone Web Filtering Site List",
      description: `Clone a site list under a new name.

Args:
  - site_list_id (string): Source site list ID.
  - name (string): Name for the cloned list.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_list_id: z.string().describe("Source site list ID"),
        name: z.string().describe("Name for the cloned list"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ site_list_id, name, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/site-lists/${site_list_id}/clone`,
        { method: "POST", body: { name } }
      );
      return jsonResult({ status: "cloned", site_list: data });
    })
  );

  // --- List Sites ---
  server.registerTool(
    "sophos_list_sites",
    {
      title: "List Sites in a Site List",
      description: `List the sites in a site list.

Args:
  - site_list_id (string): Site list ID.
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_list_id: z.string().describe("Site list ID"),
        limit: limitSchema,
        page: pageSchema,
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ site_list_id, limit, page, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/site-lists/${site_list_id}/sites`,
        { params: { pageSize: String(limit), page: String(page), pageTotal: "true" } }
      );
      return jsonResult(data);
    })
  );

  // --- Add Site ---
  server.registerTool(
    "sophos_add_site",
    {
      title: "Add Site to a Site List",
      description: `Add a single site to a site list.

Args:
  - site_list_id (string): Site list ID.
  - site (string): The site (domain, URL, URL pattern, TLD, IP, or CIDR).
  - site_type (string, optional): One of domain, url, urlPattern, tld, ipv4, ipv6, ipv4Cidr, ipv6Cidr.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_list_id: z.string().describe("Site list ID"),
        site: z.string().describe("The site to add"),
        site_type: z
          .enum(["domain", "url", "urlPattern", "tld", "ipv4", "ipv6", "ipv4Cidr", "ipv6Cidr"])
          .optional()
          .describe("Site type"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ site_list_id, site, site_type, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { site };
      if (site_type) body.siteType = site_type;
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/web-filters/v1/site-lists/${site_list_id}/sites`,
        { method: "POST", body }
      );
      return jsonResult({ status: "added", site: data });
    })
  );

  // --- Delete Site ---
  server.registerTool(
    "sophos_delete_site",
    {
      title: "Delete Site from a Site List",
      description: `Delete a single site from a site list.

Args:
  - site_list_id (string): Site list ID.
  - site_id (string): Site ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        site_list_id: z.string().describe("Site list ID"),
        site_id: z.string().describe("Site ID to delete"),
        tenant_id: tenantIdSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ site_list_id, site_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/web-filters/v1/site-lists/${site_list_id}/sites/${site_id}`,
        { method: "DELETE" }
      );
      return jsonResult({ status: "deleted", site_list_id, site_id });
    })
  );
}
