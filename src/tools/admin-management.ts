/**
 * Tools: sophos_get_admin, sophos_create_admin, sophos_delete_admin,
 *        sophos_list_admin_role_assignments, sophos_add_admin_role_assignment,
 *        sophos_delete_admin_role_assignment, sophos_get_admin_role_assignment,
 *        sophos_create_role, sophos_get_role, sophos_update_role, sophos_delete_role,
 *        sophos_list_permission_sets
 * Interact with the Sophos Common API for admin and role management.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerAdminManagementTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- Get Admin ---
  server.registerTool(
    "sophos_get_admin",
    {
      title: "Get Sophos Admin Detail",
      description: `Get full details of a specific administrator account.

Args:
  - admin_id (string): The admin ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Admin details including name, email, and role assignments.`,
      inputSchema: {
        admin_id: z.string().uuid().describe("Admin ID"),
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
    withErrorHandling(async ({ admin_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/common/v1/admins/${admin_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create Admin ---
  server.registerTool(
    "sophos_create_admin",
    {
      title: "Create Sophos Admin",
      description: `Make an existing directory user an administrator of a Sophos Central tenant.

The API creates a tenant admin from a directory user (sophos_list_users gives the
ID) with exactly one role (sophos_list_roles gives role IDs).

Args:
  - user_id (string): Directory user ID.
  - role_id (string): Role to assign.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The created admin record.`,
      inputSchema: {
        user_id: z.string().uuid().describe("Directory user ID"),
        role_id: z.string().uuid().describe("Role to assign"),
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
      async ({ user_id, role_id, tenant_id }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        const body = { userId: user_id, roleAssignments: [{ roleId: role_id }] };

        const data = await client.tenantRequest<Record<string, unknown>>(
          resolvedTenantId,
          "/common/v1/admins",
          { method: "POST", body }
        );

        return jsonResult({ status: "created", admin: data });
      }
    )
  );

  // --- Delete Admin ---
  server.registerTool(
    "sophos_delete_admin",
    {
      title: "Delete Sophos Admin",
      description: `Delete an administrator account from a Sophos Central tenant.

WARNING: This permanently removes the admin. They will lose all access.

Args:
  - admin_id (string): Admin ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        admin_id: z.string().uuid().describe("Admin ID to delete"),
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
    withErrorHandling(async ({ admin_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/common/v1/admins/${admin_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        admin_id,
        message: `Admin ${admin_id} has been deleted.`,
      });
    })
  );

  // --- List Admin Role Assignments ---
  server.registerTool(
    "sophos_list_admin_role_assignments",
    {
      title: "List Admin Role Assignments",
      description: `List role assignments for a specific administrator.

Args:
  - admin_id (string): Admin ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  List of role assignments for the admin.`,
      inputSchema: {
        admin_id: z.string().uuid().describe("Admin ID"),
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
    withErrorHandling(async ({ admin_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<
        SophosPagedResponse<Record<string, unknown>>
      >(
        resolvedTenantId,
        `/common/v1/admins/${admin_id}/role-assignments`
      );

      const items = data.items ?? [];
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? items.length,
        role_assignments: items,
      });
    })
  );

  // --- Add Admin Role Assignment ---
  server.registerTool(
    "sophos_add_admin_role_assignment",
    {
      title: "Add Role Assignment to Admin",
      description: `Add a role assignment to an administrator.

Args:
  - admin_id (string): Admin ID.
  - role_id (string): Role ID to assign.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The created role assignment.`,
      inputSchema: {
        admin_id: z.string().uuid().describe("Admin ID"),
        role_id: z.string().uuid().describe("Role ID to assign"),
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
    withErrorHandling(async ({ admin_id, role_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/common/v1/admins/${admin_id}/role-assignments`,
        { method: "POST", body: { roleId: role_id } }
      );
      return jsonResult({ status: "added", role_assignment: data });
    })
  );

  // --- Delete Admin Role Assignment ---
  server.registerTool(
    "sophos_delete_admin_role_assignment",
    {
      title: "Delete Admin Role Assignment",
      description: `Remove a role assignment from an administrator.

Args:
  - admin_id (string): Admin ID.
  - assignment_id (string): Role assignment ID to remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        admin_id: z.string().uuid().describe("Admin ID"),
        assignment_id: z.string().uuid().describe("Role assignment ID to remove"),
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
    withErrorHandling(async ({ admin_id, assignment_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/common/v1/admins/${admin_id}/role-assignments/${assignment_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        admin_id,
        assignment_id,
        message: `Role assignment ${assignment_id} removed from admin ${admin_id}.`,
      });
    })
  );

  // --- Get Admin Role Assignment ---
  server.registerTool(
    "sophos_get_admin_role_assignment",
    {
      title: "Get Admin Role Assignment Detail",
      description: `Get details of a specific role assignment for an administrator.

Args:
  - admin_id (string): Admin ID.
  - assignment_id (string): Role assignment ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Role assignment details.`,
      inputSchema: {
        admin_id: z.string().uuid().describe("Admin ID"),
        assignment_id: z.string().uuid().describe("Role assignment ID"),
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
    withErrorHandling(async ({ admin_id, assignment_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/common/v1/admins/${admin_id}/role-assignments/${assignment_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Create Role ---
  server.registerTool(
    "sophos_create_role",
    {
      title: "Create Sophos Admin Role",
      description: `Create a new admin role in a Sophos Central tenant.

Args:
  - name (string): Role name.
  - principal_type (string): "user" (for admins) or "service" (for API credentials).
  - permission_sets (array): Permission set IDs (sophos_list_permission_sets). A
    user role needs at least one set of type base and one of type product.
  - description (string, optional): Role description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The created role.`,
      inputSchema: {
        name: z.string().describe("Role name"),
        principal_type: z.enum(["user", "service"]).describe("Who the role is for"),
        permission_sets: z
          .array(z.string())
          .min(1)
          .describe("Permission set IDs to include in the role"),
        description: z.string().optional().describe("Role description"),
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
    withErrorHandling(async ({ name, principal_type, permission_sets, description, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = { name, principalType: principal_type, permissionSets: permission_sets };
      if (description) body.description = description;

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/common/v1/roles",
        { method: "POST", body }
      );

      return jsonResult({ status: "created", role: data });
    })
  );

  // --- Get Role ---
  server.registerTool(
    "sophos_get_role",
    {
      title: "Get Sophos Admin Role Detail",
      description: `Get full details of a specific admin role.

Args:
  - role_id (string): Role ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Role details including name, description, and permission sets.`,
      inputSchema: {
        role_id: z.string().uuid().describe("Role ID"),
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
    withErrorHandling(async ({ role_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/common/v1/roles/${role_id}`
      );
      return jsonResult(data);
    })
  );

  // --- Update Role ---
  server.registerTool(
    "sophos_update_role",
    {
      title: "Update Sophos Admin Role",
      description: `Update an existing admin role.

Args:
  - role_id (string): Role ID to update.
  - name (string, optional): New role name.
  - description (string, optional): New role description.
  - permission_sets (array, optional): The complete new list of permission set IDs
    (replaces the current list; measured 13/10/2026).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        role_id: z.string().uuid().describe("Role ID to update"),
        name: z.string().optional().describe("New role name"),
        description: z.string().optional().describe("New role description"),
        permission_sets: z
          .array(z.string())
          .optional()
          .describe("Updated permission set IDs"),
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
      async ({ role_id, name, description, permission_sets, tenant_id }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

        const body: Record<string, unknown> = {};
        if (name !== undefined) body.name = name;
        if (description !== undefined) body.description = description;
        if (permission_sets !== undefined) body.permissionSets = permission_sets;

        if (Object.keys(body).length === 0) {
          return jsonResult({
            error:
              "No fields to update. Provide at least one of: name, description, permission_sets.",
          });
        }

        const data = await client.tenantRequest<Record<string, unknown>>(
          resolvedTenantId,
          `/common/v1/roles/${role_id}`,
          { method: "PATCH", body }
        );

        return jsonResult({ status: "updated", role: data });
      }
    )
  );

  // --- Delete Role ---
  server.registerTool(
    "sophos_delete_role",
    {
      title: "Delete Sophos Admin Role",
      description: `Delete an admin role from a Sophos Central tenant.

WARNING: This permanently removes the role. Admins assigned this role will lose
the associated permissions.

Args:
  - role_id (string): Role ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        role_id: z.string().uuid().describe("Role ID to delete"),
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
    withErrorHandling(async ({ role_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/common/v1/roles/${role_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        role_id,
        message: `Role ${role_id} has been deleted.`,
      });
    })
  );

  // --- List Permission Sets ---
  server.registerTool(
    "sophos_list_permission_sets",
    {
      title: "List Sophos Permission Sets",
      description: `List available permission sets that can be assigned to roles.

Permission sets define granular access levels. Use this to discover what
permissions are available when creating or updating roles.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  List of available permission sets with their IDs and descriptions.`,
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
      const data = await client.tenantRequest<
        { items?: Record<string, unknown>[]; pages?: { current?: number; total?: number; items?: number } }
      >(resolvedTenantId, "/common/v1/roles/permission-sets");

      const items = data.items ?? [];
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? items.length,
        permission_sets: items,
      });
    })
  );

}
