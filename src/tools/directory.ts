/**
 * Tools: sophos_list_users, sophos_list_admins, sophos_list_roles,
 *        sophos_get_user, sophos_create_user, sophos_update_user, sophos_delete_user,
 *        sophos_list_user_groups, sophos_get_user_group,
 *        sophos_create_user_group, sophos_update_user_group, sophos_delete_user_group,
 *        sophos_list_user_group_members, sophos_add_users_to_group,
 *        sophos_remove_user_from_group, sophos_list_user_group_policies
 * Interact with the Sophos Common API for directory and admin management.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

interface SophosUser {
  id: string;
  name: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  exchangeLogin?: string;
  groupIds?: string[];
  groupNames?: string[];
}

interface SophosAdmin {
  id: string;
  name?: string;
  roleAssignments?: Array<{
    roleId: string;
    roleName?: string;
  }>;
}

export function registerDirectoryTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Users ---
  server.registerTool(
    "sophos_list_users",
    {
      title: "List Sophos Directory Users",
      description: `List directory users in a Sophos Central tenant.

Returns user records from the Sophos Central directory, which maps users to 
their devices and group memberships.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - search (string, optional): Search by name or email.
  - group_id (string, optional): Filter by group ID.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of users with: id, name, email, group memberships.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        search: z
          .string()
          .optional()
          .describe("Search by name or email substring"),
        group_id: z
          .string()
          .optional()
          .describe("Filter by directory group ID"),
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
    withErrorHandling(async ({ tenant_id, search, group_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      if (search) params.search = search;
      if (group_id) params.groupId = group_id;

      const data = await client.tenantRequest<SophosPagedResponse<SophosUser>>(
        resolvedTenantId,
        "/common/v1/directory/users",
        { params }
      );

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        users: data.items.map((u) => ({
          id: u.id,
          name: u.name,
          first_name: u.firstName ?? null,
          last_name: u.lastName ?? null,
          email: u.email ?? null,
          exchange_login: u.exchangeLogin ?? null,
          groups: u.groupNames ?? [],
        })),
      });
    })
  );

  // --- List Admins ---
  server.registerTool(
    "sophos_list_admins",
    {
      title: "List Sophos Admins",
      description: `List administrator accounts in a Sophos Central tenant.

Returns admin users and their role assignments.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
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

      const data = await client.tenantRequest<SophosPagedResponse<SophosAdmin>>(
        resolvedTenantId,
        "/common/v1/admins",
        { params }
      );

      const items = data.items ?? [];
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? items.length,
        page: data.pages?.current ?? page,
        admins: items.map((a) => ({
          id: a.id,
          name: a.name ?? null,
          roles: a.roleAssignments ?? [],
        })),
      });
    })
  );

  // --- List Roles ---
  server.registerTool(
    "sophos_list_roles",
    {
      title: "List Sophos Admin Roles",
      description: `List available admin roles in a Sophos Central tenant.

Returns all role definitions that can be assigned to admins, in one response.

Args:
  - type (string, optional): "predefined" or "custom".
  - principal_type (string, optional): "user" or "service".
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        type: z.enum(["predefined", "custom"]).optional().describe("Role type"),
        principal_type: z.enum(["user", "service"]).optional().describe("Principal type"),
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
    withErrorHandling(async ({ type, principal_type, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = {};
      if (type) params.type = type;
      if (principal_type) params.principalType = principal_type;

      const data = await client.tenantRequest<{ items?: Record<string, unknown>[] }>(
        resolvedTenantId,
        "/common/v1/roles",
        { params }
      );
      const items = data.items ?? [];
      return jsonResult({ total: items.length, roles: items });
    })
  );

  // --- Get User ---
  server.registerTool(
    "sophos_get_user",
    {
      title: "Get Sophos Directory User Detail",
      description: `Get full details of a specific directory user.

Args:
  - user_id (string): The user ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  User details including name, email, group memberships, and associated endpoints.`,
      inputSchema: {
        user_id: z.string().uuid().describe("User ID"),
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
    withErrorHandling(async ({ user_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<SophosUser>(
        resolvedTenantId,
        `/common/v1/directory/users/${user_id}`
      );
      return jsonResult({
        id: data.id,
        name: data.name,
        first_name: data.firstName ?? null,
        last_name: data.lastName ?? null,
        email: data.email ?? null,
        exchange_login: data.exchangeLogin ?? null,
        groups: data.groupNames ?? [],
        group_ids: data.groupIds ?? [],
      });
    })
  );

  // --- Create User ---
  server.registerTool(
    "sophos_create_user",
    {
      title: "Create Sophos Directory User",
      description: `Create a new directory user in a Sophos Central tenant.

Args:
  - name (string): User display name.
  - first_name (string, optional): First name.
  - last_name (string, optional): Last name.
  - email (string, optional): Email address.
  - exchange_login (string, optional): Exchange login / UPN.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The created user record.`,
      inputSchema: {
        name: z.string().describe("User display name"),
        first_name: z.string().optional().describe("First name"),
        last_name: z.string().optional().describe("Last name"),
        email: z.string().optional().describe("Email address"),
        exchange_login: z.string().optional().describe("Exchange login / UPN"),
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
    withErrorHandling(
      async ({ name, first_name, last_name, email, exchange_login, tenant_id }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        const body: Record<string, unknown> = { name };
        if (first_name) body.firstName = first_name;
        if (last_name) body.lastName = last_name;
        if (email) body.email = email;
        if (exchange_login) body.exchangeLogin = exchange_login;

        const data = await client.tenantRequest<SophosUser>(
          resolvedTenantId,
          "/common/v1/directory/users",
          { method: "POST", body }
        );

        return jsonResult({
          status: "created",
          user: {
            id: data.id,
            name: data.name,
            first_name: data.firstName ?? null,
            last_name: data.lastName ?? null,
            email: data.email ?? null,
            exchange_login: data.exchangeLogin ?? null,
          },
        });
      }
    )
  );

  // --- Update User ---
  server.registerTool(
    "sophos_update_user",
    {
      title: "Update Sophos Directory User",
      description: `Update an existing directory user's details.

Args:
  - user_id (string): User ID to update.
  - name (string, optional): New display name.
  - first_name (string, optional): New first name.
  - last_name (string, optional): New last name.
  - email (string, optional): New email address.
  - exchange_login (string, optional): New Exchange login / UPN.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        user_id: z.string().uuid().describe("User ID to update"),
        name: z.string().optional().describe("New display name"),
        first_name: z.string().optional().describe("New first name"),
        last_name: z.string().optional().describe("New last name"),
        email: z.string().optional().describe("New email address"),
        exchange_login: z.string().optional().describe("New Exchange login / UPN"),
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
    withErrorHandling(
      async ({ user_id, name, first_name, last_name, email, exchange_login, tenant_id }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        const body: Record<string, unknown> = {};
        if (name !== undefined) body.name = name;
        if (first_name !== undefined) body.firstName = first_name;
        if (last_name !== undefined) body.lastName = last_name;
        if (email !== undefined) body.email = email;
        if (exchange_login !== undefined) body.exchangeLogin = exchange_login;

        if (Object.keys(body).length === 0) {
          return jsonResult({
            error: "No fields to update. Provide at least one of: name, first_name, last_name, email, exchange_login.",
          });
        }

        const data = await client.tenantRequest<SophosUser>(
          resolvedTenantId,
          `/common/v1/directory/users/${user_id}`,
          { method: "PATCH", body }
        );

        return jsonResult({
          status: "updated",
          user: {
            id: data.id,
            name: data.name,
            first_name: data.firstName ?? null,
            last_name: data.lastName ?? null,
            email: data.email ?? null,
            exchange_login: data.exchangeLogin ?? null,
          },
        });
      }
    )
  );

  // --- Delete User ---
  server.registerTool(
    "sophos_delete_user",
    {
      title: "Delete Sophos Directory User",
      description: `Delete a directory user from a Sophos Central tenant.

WARNING: This permanently removes the user from the directory. Their device
associations and group memberships will be removed.

Args:
  - user_id (string): User ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        user_id: z.string().uuid().describe("User ID to delete"),
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
    withErrorHandling(async ({ user_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/common/v1/directory/users/${user_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        user_id,
        message: `User ${user_id} has been deleted.`,
      });
    })
  );

  // --- List User Groups ---
  server.registerTool(
    "sophos_list_user_groups",
    {
      title: "List Sophos Directory User Groups",
      description: `List directory user groups in a Sophos Central tenant.

User groups organise users for policy assignment. Different from endpoint groups.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - search (string, optional): Search by group name.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of user groups with: id, name, description.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        search: z.string().optional().describe("Search by group name"),
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
    withErrorHandling(async ({ tenant_id, search, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      if (search) params.search = search;

      const data = await client.tenantRequest<
        SophosPagedResponse<Record<string, unknown>>
      >(resolvedTenantId, "/common/v1/directory/user-groups", { params });

      const items = data.items ?? [];
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? items.length,
        page: data.pages?.current ?? page,
        user_groups: items,
      });
    })
  );

  // --- Get User Group ---
  server.registerTool(
    "sophos_get_user_group",
    {
      title: "Get Sophos Directory User Group Detail",
      description: `Get full details of a specific directory user group.

Args:
  - group_id (string): User group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  User group details including name, description, and member count.`,
      inputSchema: {
        group_id: z.string().uuid().describe("User group ID"),
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
        `/common/v1/directory/user-groups/${group_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create User Group ---
  server.registerTool(
    "sophos_create_user_group",
    {
      title: "Create Sophos Directory User Group",
      description: `Create a new directory user group in a Sophos Central tenant.

User groups organise users for policy assignment and management.
Assign a policy to a user group with sophos_set_policy_assignments (user_groups).

Args:
  - name (string): Group name.
  - description (string, optional): Group description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The created user group.`,
      inputSchema: {
        name: z.string().describe("Group name"),
        description: z.string().optional().describe("Group description"),
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
        "/common/v1/directory/user-groups",
        { method: "POST", body }
      );

      return jsonResult({ status: "created", user_group: data });
    })
  );

  // --- Update User Group ---
  server.registerTool(
    "sophos_update_user_group",
    {
      title: "Update Sophos Directory User Group",
      description: `Update an existing directory user group's name or description.

Args:
  - group_id (string): User group ID to update.
  - name (string, optional): New group name.
  - description (string, optional): New group description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("User group ID to update"),
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
        `/common/v1/directory/user-groups/${group_id}`,
        { method: "PATCH", body }
      );

      return jsonResult({ status: "updated", user_group: data });
    })
  );

  // --- Delete User Group ---
  server.registerTool(
    "sophos_delete_user_group",
    {
      title: "Delete Sophos Directory User Group",
      description: `Delete a directory user group from a Sophos Central tenant.

WARNING: This removes the group. Users in the group are NOT deleted but will
no longer be members of this group. Policies assigned to this group will no
longer apply to those users.

Args:
  - group_id (string): User group ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("User group ID to delete"),
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
        `/common/v1/directory/user-groups/${group_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        group_id,
        message: `User group ${group_id} has been deleted.`,
      });
    })
  );

  // --- List User Group Members ---
  server.registerTool(
    "sophos_list_user_group_members",
    {
      title: "List Members of Sophos User Group",
      description: `List the users that are members of a specific directory user group.

Args:
  - group_id (string): User group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of users in the group.`,
      inputSchema: {
        group_id: z.string().uuid().describe("User group ID"),
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
    withErrorHandling(async ({ group_id, tenant_id, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      const data = await client.tenantRequest<
        SophosPagedResponse<SophosUser>
      >(resolvedTenantId, `/common/v1/directory/user-groups/${group_id}/users`, {
        params,
      });

      const items = data.items ?? [];
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? items.length,
        page: data.pages?.current ?? page,
        users: items.map((u) => ({
          id: u.id,
          name: u.name,
          first_name: u.firstName ?? null,
          last_name: u.lastName ?? null,
          email: u.email ?? null,
        })),
      });
    })
  );

  // --- Add Users to Group ---
  server.registerTool(
    "sophos_add_users_to_group",
    {
      title: "Add Users to Sophos User Group",
      description: `Add one or more users to an existing directory user group.

Args:
  - group_id (string): User group ID.
  - user_ids (array): Array of user IDs to add.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("User group ID"),
        user_ids: z
          .array(z.string().uuid())
          .min(1)
          .describe("User IDs to add to the group"),
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
    withErrorHandling(async ({ group_id, user_ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      await client.tenantRequest(
        resolvedTenantId,
        `/common/v1/directory/user-groups/${group_id}/users`,
        { method: "POST", body: { ids: user_ids } }
      );

      return jsonResult({
        status: "added",
        group_id,
        users_added: user_ids.length,
        message: `Added ${user_ids.length} user(s) to group ${group_id}.`,
      });
    })
  );

  // --- Remove User from Group ---
  server.registerTool(
    "sophos_remove_user_from_group",
    {
      title: "Remove User from Sophos User Group",
      description: `Remove a single user from a directory user group.

The user is not deleted, only removed from the group.

Args:
  - group_id (string): User group ID.
  - user_id (string): User ID to remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().uuid().describe("User group ID"),
        user_id: z.string().uuid().describe("User ID to remove"),
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
    withErrorHandling(async ({ group_id, user_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      await client.tenantRequest(
        resolvedTenantId,
        `/common/v1/directory/user-groups/${group_id}/users/${user_id}`,
        { method: "DELETE" }
      );

      return jsonResult({
        status: "removed",
        group_id,
        user_id,
        message: `User ${user_id} removed from group ${group_id}.`,
      });
    })
  );

  // --- List User Group Policies ---
  server.registerTool(
    "sophos_list_user_group_policies",
    {
      title: "List Policies for Sophos User Group",
      description: `List the endpoint policies assigned to a directory user group.

There is no API for this directly, so the tool reads every endpoint policy and
keeps the ones whose assignment includes the group. The policy list can lag a
change by about 25 seconds.

Args:
  - group_id (string): User group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The policies that name the group: id, name, type, enabled, priority.`,
      inputSchema: {
        group_id: z.string().uuid().describe("User group ID"),
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
      type Policy = { id: string; name: string; type: string; enabled: boolean; priority: number; appliesTo?: { userGroups?: unknown[] } };
      const matches: Array<Omit<Policy, "appliesTo">> = [];
      for (let page = 1; page <= 50; page++) {
        const data = await client.tenantRequest<SophosPagedResponse<Policy>>(
          resolvedTenantId,
          "/endpoint/v1/policies",
          { params: { page: String(page), pageSize: "100", pageTotal: "true" } }
        );
        for (const p of data.items ?? []) {
          const groups = (p.appliesTo?.userGroups ?? []).map((g) => (typeof g === "string" ? g : (g as { id?: string }).id));
          if (groups.includes(group_id)) {
            matches.push({ id: p.id, name: p.name, type: p.type, enabled: p.enabled, priority: p.priority });
          }
        }
        if (!data.pages?.total || page >= data.pages.total) break;
      }
      return jsonResult({ group_id, total: matches.length, policies: matches });
    })
  );
}
