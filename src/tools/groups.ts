/**
 * Tools: sophos_list_endpoint_groups, sophos_get_endpoint_group,
 *        sophos_create_endpoint_group, sophos_update_endpoint_group,
 *        sophos_delete_endpoint_group, sophos_add_endpoints_to_group,
 *        sophos_remove_endpoint_from_group
 * Interact with the Sophos Endpoint API /endpoint/v1/endpoint-groups
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

interface SophosEndpointGroup {
  id: string;
  name: string;
  description?: string;
  type: string;
  createdAt?: string;
  updatedAt?: string;
  endpoints?: {
    total: number;
    itemsCount?: number;
    items?: Array<{ id: string; hostname?: string; type?: string }>;
  };
}

export function registerGroupTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Endpoint Groups ---
  server.registerTool(
    "sophos_list_endpoint_groups",
    {
      title: "List Sophos Endpoint Groups",
      description: `List endpoint groups in a Sophos Central tenant.

Endpoint groups organise devices for policy assignment. Returns group names,
types, descriptions, and endpoint counts.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - search (string, optional): Search by group name.
  - group_type (string, optional): Filter by group type: "computer", "server".
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of groups with: id, name, type, description, endpoint count.`,
      inputSchema: {
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        search: z.string().optional().describe("Search by group name"),
        group_type: z
          .string()
          .optional()
          .describe('Filter by group type: "computer", "server"'),
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
    withErrorHandling(async ({ tenant_id, search, group_type, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      if (search) params.search = search;
      if (group_type) params.groupType = group_type;

      const data = await client.tenantRequest<
        SophosPagedResponse<SophosEndpointGroup>
      >(resolvedTenantId, "/endpoint/v1/endpoint-groups", { params });

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        groups: data.items.map(formatGroup),
      });
    })
  );

  // --- Get Endpoint Group ---
  server.registerTool(
    "sophos_get_endpoint_group",
    {
      title: "Get Sophos Endpoint Group Detail",
      description: `Get full details of an endpoint group including its member endpoints.

Args:
  - group_id (string): The group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - include_endpoints (boolean, optional): Include list of member endpoints (default false).`,
      inputSchema: {
        group_id: z.string().guid().describe("Endpoint group ID"),
        tenant_id: z
          .string()
          .guid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        include_endpoints: z
          .boolean()
          .optional()
          .default(false)
          .describe("Include member endpoint list (default false)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ group_id, tenant_id, include_endpoints }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const group = await client.tenantRequest<SophosEndpointGroup>(
        resolvedTenantId,
        `/endpoint/v1/endpoint-groups/${group_id}`
      );

      const result = formatGroup(group);

      if (include_endpoints) {
        const endpoints = await client.tenantRequest<
          SophosPagedResponse<{ id: string; hostname?: string; type?: string }>
        >(
          resolvedTenantId,
          `/endpoint/v1/endpoint-groups/${group_id}/endpoints`,
          { params: { pageSize: "100" } }
        );

        return jsonResult({
          ...result,
          endpoints: endpoints.items.map((e) => ({
            id: e.id,
            hostname: e.hostname ?? null,
            type: e.type ?? null,
          })),
          endpoints_total: endpoints.pages.total ?? endpoints.items.length,
        });
      }

      return jsonResult(result);
    })
  );

  // --- Create Endpoint Group ---
  server.registerTool(
    "sophos_create_endpoint_group",
    {
      title: "Create Sophos Endpoint Group",
      description: `Create a new endpoint group.

Groups are used to organise devices and assign policies at the group level.
Assign a policy to a group with sophos_set_policy_assignments (endpoint_groups).

Args:
  - name (string): Group name.
  - type (string): Group type: "computer" or "server".
  - description (string, optional): Group description.
  - endpoint_ids (array, optional): Initial endpoint IDs to add to the group.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        name: z.string().describe("Group name"),
        type: z.string().describe('Group type: "computer" or "server"'),
        description: z.string().optional().describe("Group description"),
        endpoint_ids: z
          .array(z.string())
          .optional()
          .describe("Initial endpoint IDs to add"),
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
    withErrorHandling(async ({ name, type, description, endpoint_ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const body: Record<string, unknown> = { name, type };
      if (description) body.description = description;
      if (endpoint_ids?.length) body.endpointIds = endpoint_ids;

      const created = await client.tenantRequest<SophosEndpointGroup>(
        resolvedTenantId,
        "/endpoint/v1/endpoint-groups",
        { method: "POST", body }
      );

      return jsonResult({
        status: "created",
        group: formatGroup(created),
      });
    })
  );

  // --- Update Endpoint Group ---
  server.registerTool(
    "sophos_update_endpoint_group",
    {
      title: "Update Sophos Endpoint Group",
      description: `Update an existing endpoint group's name or description.

Args:
  - group_id (string): Group ID to update.
  - name (string, optional): New group name.
  - description (string, optional): New group description.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().guid().describe("Group ID to update"),
        name: z.string().optional().describe("New group name"),
        description: z.string().optional().describe("New description"),
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

      const updated = await client.tenantRequest<SophosEndpointGroup>(
        resolvedTenantId,
        `/endpoint/v1/endpoint-groups/${group_id}`,
        { method: "PATCH", body }
      );

      return jsonResult({ status: "updated", group: formatGroup(updated) });
    })
  );

  // --- Delete Endpoint Group ---
  server.registerTool(
    "sophos_delete_endpoint_group",
    {
      title: "Delete Sophos Endpoint Group",
      description: `Delete an endpoint group.

WARNING: This removes the group. Endpoints in the group are NOT deleted but 
will no longer be members of this group. Policies assigned to this group 
will no longer apply.

Args:
  - group_id (string): Group ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().guid().describe("Group ID to delete"),
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
    withErrorHandling(async ({ group_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoint-groups/${group_id}`,
        { method: "DELETE" }
      );
      return jsonResult({
        status: "deleted",
        group_id,
        message: `Endpoint group ${group_id} has been deleted.`,
      });
    })
  );

  // --- Add Endpoints to Group ---
  server.registerTool(
    "sophos_add_endpoints_to_group",
    {
      title: "Add Endpoints to Sophos Group",
      description: `Add one or more endpoints to an existing endpoint group.

Args:
  - group_id (string): Group ID.
  - endpoint_ids (array): Array of endpoint IDs to add.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().guid().describe("Group ID"),
        endpoint_ids: z
          .array(z.string().guid())
          .min(1)
          .describe("Endpoint IDs to add"),
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
    withErrorHandling(async ({ group_id, endpoint_ids, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoint-groups/${group_id}/endpoints`,
        {
          method: "POST",
          body: { ids: endpoint_ids },
        }
      );

      return jsonResult({
        status: "added",
        group_id,
        endpoints_added: endpoint_ids.length,
        message: `Added ${endpoint_ids.length} endpoint(s) to group ${group_id}.`,
      });
    })
  );

  // --- Remove Endpoint from Group ---
  server.registerTool(
    "sophos_remove_endpoint_from_group",
    {
      title: "Remove Endpoint from Sophos Group",
      description: `Remove a single endpoint from an endpoint group.

The endpoint is not deleted, only removed from the group.

Args:
  - group_id (string): Group ID.
  - endpoint_id (string): Endpoint ID to remove.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        group_id: z.string().guid().describe("Group ID"),
        endpoint_id: z.string().guid().describe("Endpoint ID to remove"),
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
    withErrorHandling(async ({ group_id, endpoint_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      await client.tenantRequest(
        resolvedTenantId,
        `/endpoint/v1/endpoint-groups/${group_id}/endpoints/${endpoint_id}`,
        { method: "DELETE" }
      );

      return jsonResult({
        status: "removed",
        group_id,
        endpoint_id,
        message: `Endpoint ${endpoint_id} removed from group ${group_id}.`,
      });
    })
  );
}

function formatGroup(g: SophosEndpointGroup) {
  return {
    id: g.id,
    name: g.name,
    type: g.type,
    description: g.description ?? null,
    endpoint_count: g.endpoints?.total ?? g.endpoints?.itemsCount ?? 0,
    created_at: g.createdAt ?? null,
    updated_at: g.updatedAt ?? null,
  };
}
