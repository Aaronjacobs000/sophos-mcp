/**
 * Tools: sophos_list_cloud_security_profiles, sophos_list_cloud_security_default_contents,
 *        sophos_get_cloud_security_profile,
 *        sophos_create_cloud_security_profile, sophos_update_cloud_security_profile,
 *        sophos_delete_cloud_security_profile
 * Interact with the Sophos Cloud Security API /cloud-security/v1/ (runtime detection
 * profiles), shaped by its published spec 1.0.0
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerCloudSecurityTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Cloud Security Profiles ---
  server.registerTool(
    "sophos_list_cloud_security_profiles",
    {
      title: "List Cloud Security Profiles",
      description: `List cloud security profiles configured for a tenant.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of cloud security profiles.`,
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
        "/cloud-security/v1/profiles",
        { params: { pageSize: String(limit), page: String(page) } }
      );
      return jsonResult(data);
    })
  );

  // --- List Cloud Security Default Contents ---
  server.registerTool(
    "sophos_list_cloud_security_default_contents",
    {
      title: "List Cloud Security Default Contents",
      description: `List the default detection contents for runtime detection profiles (Cloud Security API).

Each item has an id and a version. Pass a version as content_version to
sophos_create_cloud_security_profile.

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
      const data = await client.tenantRequest<{ items?: Array<{ id: string; version: string }> }>(
        resolvedTenantId,
        "/cloud-security/v1/profiles/default-contents"
      );
      const items = data.items ?? [];
      return jsonResult({ total: items.length, contents: items });
    })
  );

  // --- Get Cloud Security Profile ---
  server.registerTool(
    "sophos_get_cloud_security_profile",
    {
      title: "Get Cloud Security Profile",
      description: `Get details of a specific cloud security profile.

Args:
  - profile_id (string): The profile ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        profile_id: z.string().describe("Cloud security profile ID"),
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
    withErrorHandling(async ({ profile_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/cloud-security/v1/profiles/${profile_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create Cloud Security Profile ---
  server.registerTool(
    "sophos_create_cloud_security_profile",
    {
      title: "Create Cloud Security Profile",
      description: `Create a runtime detection profile, or a new version of an existing one (Cloud Security API).

content_version and settings are required. sophos_list_cloud_security_default_contents
lists the content versions. Pass profile_id to add a new version to that profile
instead of creating another. sophos_get_cloud_security_profile shows an existing
profile's contentVersion and settings to start from.

Args:
  - content_version (string): Detection content version, for example "5.8.0.8".
  - settings (object): Overrides of the default content: {rules?: [{name, enabled}],
    lists?: [{name, operations: [{behavior: "add"|"remove", list: [items]}]}]}.
    {} or empty arrays keep the defaults.
  - name (string, optional): Profile name (1 to 50 characters).
  - profile_description (string, optional): Profile description.
  - profile_id (string, optional): Existing profile to add a version to.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The profile's id and version.`,
      inputSchema: {
        content_version: z.string().describe('Detection content version, for example "5.8.0.8"'),
        settings: z
          .object({
            rules: z
              .array(z.object({ name: z.string().describe("Rule name"), enabled: z.boolean().describe("Whether the rule is on") }))
              .optional()
              .describe("Rule overrides"),
            lists: z
              .array(
                z.object({
                  name: z.string().describe("Allow or block list name"),
                  operations: z
                    .array(
                      z.object({
                        behavior: z.enum(["add", "remove"]).describe("Add or remove the items"),
                        list: z.array(z.string()).describe("Items"),
                      })
                    )
                    .describe("Changes to the list"),
                })
              )
              .optional()
              .describe("Allow and block list overrides"),
          })
          .describe("Overrides of the default content settings"),
        name: z.string().min(1).max(50).optional().describe("Profile name"),
        profile_description: z.string().optional().describe("Profile description"),
        profile_id: z.string().uuid().optional().describe("Existing profile to add a version to"),
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
    withErrorHandling(async ({ content_version, settings, name, profile_description, profile_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { contentVersion: content_version, settings };
      if (name !== undefined) body.name = name;
      if (profile_description !== undefined) body.profileDescription = profile_description;
      if (profile_id !== undefined) body.profileId = profile_id;
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/cloud-security/v1/profiles",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", profile: data });
    })
  );

  // --- Update Cloud Security Profile ---
  server.registerTool(
    "sophos_update_cloud_security_profile",
    {
      title: "Rename Cloud Security Profile",
      description: `Rename a runtime detection profile (Cloud Security API).

The API's update changes only the name; nothing else about the profile is
touched. To change settings, add a new version with
sophos_create_cloud_security_profile and profile_id. The name is read back
after the write.

Args:
  - profile_id (string): The profile ID.
  - name (string): New profile name (1 to 50 characters).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        profile_id: z.string().uuid().describe("Cloud security profile ID to rename"),
        name: z.string().min(1).max(50).describe("New profile name"),
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
    withErrorHandling(async ({ profile_id, name, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const path = `/cloud-security/v1/profiles/${profile_id}`;
      await client.tenantRequest(resolvedTenantId, path, { method: "PUT", params: { name } });
      const profile = await client.tenantRequest<Record<string, unknown>>(resolvedTenantId, path);
      return jsonResult({
        status: profile.name === name ? "renamed" : "not_renamed",
        profile_id,
        name_sent: name,
        name_stored: profile.name ?? null,
      });
    })
  );

  // --- Delete Cloud Security Profile ---
  server.registerTool(
    "sophos_delete_cloud_security_profile",
    {
      title: "Delete Cloud Security Profile",
      description: `Delete a runtime detection profile (Cloud Security API).

WARNING: This permanently removes the profile. Sophos may skip a profile it
cannot delete; the result says whether this one was deleted or skipped.

Args:
  - profile_id (string): The profile ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        profile_id: z.string().uuid().describe("Cloud security profile ID to delete"),
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
    withErrorHandling(async ({ profile_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<{ skippedProfiles?: unknown[] }>(
        resolvedTenantId,
        "/cloud-security/v1/profiles",
        { method: "DELETE", params: { profileIds: profile_id } }
      );
      const skipped = (data?.skippedProfiles ?? []).filter((s) =>
        JSON.stringify(s).includes(profile_id)
      );
      return jsonResult(
        skipped.length
          ? { status: "skipped", profile_id, skipped }
          : { status: "deleted", profile_id, message: `Cloud security profile ${profile_id} deleted.` }
      );
    })
  );

}
