/**
 * Tools: sophos_list_endpoint_groups, sophos_get_endpoint_group,
 *        sophos_create_endpoint_group, sophos_update_endpoint_group,
 *        sophos_delete_endpoint_group, sophos_add_endpoints_to_group,
 *        sophos_bulk_change_endpoint_group, sophos_remove_endpoint_from_group
 * Interact with the Sophos Endpoint API /endpoint/v1/endpoint-groups
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { bulkActionResult, itemTotal, jsonResult, withErrorHandling } from "./helpers.js";
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

/**
 * The 201 body of POST /endpoint/v1/endpoint-groups/{groupId}/endpoints. The
 * Endpoint API reference gives addedEndpoints as { id, hostname } objects; the
 * endpoint groups guide shows bare IDs, so both are read. Endpoints already in
 * the group are in neither list.
 */
interface AddEndpointsToGroupResponse {
  addedEndpoints?: Array<{ id: string; hostname?: string } | string>;
  errors?: {
    endpointsNotFound?: string[];
    endpointsOfWrongType?: string[];
  };
}

/**
 * The 200 body of POST /endpoint/v1/endpoint-groups/endpoints (Endpoint API
 * reference, "Change group membership"): the endpoints whose group changed,
 * and the ones that could not be changed with an errorCode (notFound,
 * notSupported, conflict, permissionDenied, internalError).
 */
interface BulkChangeGroupResponse {
  items?: Array<{ id: string; hostname?: string }>;
  errors?: Array<{ id: string; errorCode: string; endpointErrorCode?: string; errorMessage: string }>;
}

/** The API takes at most 500 endpoint IDs per request. */
const BULK_CHANGE_GROUP_BATCH = 500;
/** The most IDs one tool call takes: ten requests. */
const BULK_CHANGE_GROUP_MAX = 5000;

type NotAddedReason = "not_found" | "wrong_type" | "not_in_response";

const NOT_ADDED_LABELS: Record<NotAddedReason, string> = {
  not_found: "not found",
  wrong_type: "of the wrong type for the group",
  not_in_response: "not in the response (most likely already in the group)",
};

/** The request's distinct IDs, compared without case, in the caller's spelling. */
function distinctIds(ids: string[]): string[] {
  const seen = new Map<string, string>();
  for (const id of ids) if (!seen.has(id.toLowerCase())) seen.set(id.toLowerCase(), id);
  return [...seen.values()];
}

/** What Sophos added, what it did not and why, and a status that says which. */
function addEndpointsResult(groupId: string, requested: string[], data: AddEndpointsToGroupResponse) {
  const added = (data?.addedEndpoints ?? []).map((e) =>
    typeof e === "string" ? { id: e } : { id: e.id, hostname: e.hostname }
  );
  const notAdded: Array<{ id: string; reason: NotAddedReason }> = [
    ...(data?.errors?.endpointsNotFound ?? []).map((id) => ({ id, reason: "not_found" as const })),
    ...(data?.errors?.endpointsOfWrongType ?? []).map((id) => ({ id, reason: "wrong_type" as const })),
  ];
  const reported = new Set([...added, ...notAdded].map((e) => e.id.toLowerCase()));
  for (const id of requested) {
    if (!reported.has(id.toLowerCase())) notAdded.push({ id, reason: "not_in_response" });
  }

  const status = added.length === 0 ? "none_added" : notAdded.length === 0 ? "added" : "partially_added";
  const counts = (Object.keys(NOT_ADDED_LABELS) as NotAddedReason[])
    .map((reason) => [notAdded.filter((e) => e.reason === reason).length, NOT_ADDED_LABELS[reason]] as const)
    .filter(([n]) => n > 0)
    .map(([n, label]) => `${n} ${label}`);
  const message =
    status === "added"
      ? `Added ${added.length} endpoint(s) to group ${groupId}.`
      : `Added ${added.length === 0 ? "none" : added.length} of ${requested.length} endpoint(s) to group ${groupId}. Not added: ${counts.join(", ")}.`;

  return {
    status,
    group_id: groupId,
    requested: requested.length,
    endpoints_added: added.length,
    added,
    not_added: notAdded,
    message,
    ...(notAdded.some((e) => e.reason === "not_in_response")
      ? {
          note: "Sophos leaves endpoints that are already in the group out of its answer. Check membership with sophos_get_endpoint_group and include_endpoints true.",
        }
      : {}),
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
        pageTotal: "true",
      };

      if (search) params.search = search;
      if (group_type) params.groupType = group_type;

      const data = await client.tenantRequest<
        SophosPagedResponse<SophosEndpointGroup>
      >(resolvedTenantId, "/endpoint/v1/endpoint-groups", { params });

      return jsonResult({
        total: itemTotal(data.pages),
        total_pages: data.pages.total,
        page: data.pages.current ?? page,
        groups: data.items.map(formatGroup),
      }, { page, limit });
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
          { params: { pageSize: "100", pageTotal: "true" } }
        );

        return jsonResult({
          ...result,
          endpoints: endpoints.items.map((e) => ({
            id: e.id,
            hostname: e.hostname ?? null,
            type: e.type ?? null,
          })),
          endpoints_total: itemTotal(endpoints.pages),
          endpoints_total_pages: endpoints.pages.total,
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

Endpoints must match the group type (computer or server). Sophos adds the ones
it can and lists the rest: IDs it could not find and endpoints of the wrong
type. It leaves endpoints that are already in the group out of its answer.

Args:
  - group_id (string): Group ID.
  - endpoint_ids (array): Array of endpoint IDs to add. Duplicates are dropped.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status ("added", "partially_added" or "none_added"), requested and
  endpoints_added counts, added (id and hostname), and not_added with a reason
  for each ID: not_found, wrong_type, or not_in_response (most likely already
  in the group).`,
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
      // The API requires unique IDs.
      const ids = distinctIds(endpoint_ids);

      const data = await client.tenantRequest<AddEndpointsToGroupResponse>(
        resolvedTenantId,
        `/endpoint/v1/endpoint-groups/${group_id}/endpoints`,
        {
          method: "POST",
          body: { ids },
        }
      );

      return jsonResult(addEndpointsResult(group_id, ids, data));
    })
  );

  // --- Bulk Change Endpoint Group ---
  server.registerTool(
    "sophos_bulk_change_endpoint_group",
    {
      title: "Bulk Change Sophos Endpoint Group",
      description: `Move endpoints into one endpoint group, or take them out of their current group, in bulk.

group_id is the target group. Pass null to remove the endpoints from whatever
group they are in, leaving them in no group. An endpoint leaves its old group
when it moves. Sophos refuses groups synced from Active Directory, and
endpoints synced from it, with a 409.

Each endpoint succeeds or fails on its own. Changed ones come back in items
(id, hostname); the rest come back in errors with an errorCode (notFound,
notSupported, conflict, permissionDenied, internalError) and a message. The
API takes 500 IDs per request, so a longer list goes in batches of 500, in
order. If a batch fails after an earlier one went through, the tool stops and
reports the IDs it could not confirm and the ones it did not send.

Args:
  - endpoint_ids (string[]): Endpoint IDs (1 to 5000). Duplicates are dropped.
  - group_id (string or null): Target group ID, or null to remove the endpoints from their group.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  requested, accepted and rejected counts, then items and errors as Sophos returned them.`,
      inputSchema: {
        endpoint_ids: z
          .array(z.string().guid())
          .min(1)
          .max(BULK_CHANGE_GROUP_MAX)
          .describe("Endpoint IDs to move (1 to 5000)"),
        group_id: z
          .string()
          .guid()
          .nullable()
          .describe("Target group ID, or null to remove the endpoints from their current group"),
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
    withErrorHandling(async ({ endpoint_ids, group_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const ids = distinctIds(endpoint_ids);
      const batches = Math.ceil(ids.length / BULK_CHANGE_GROUP_BATCH);
      const items: NonNullable<BulkChangeGroupResponse["items"]> = [];
      const errors: NonNullable<BulkChangeGroupResponse["errors"]> = [];

      for (let start = 0; start < ids.length; start += BULK_CHANGE_GROUP_BATCH) {
        const batch = ids.slice(start, start + BULK_CHANGE_GROUP_BATCH);
        let data: BulkChangeGroupResponse;
        try {
          data = await client.tenantRequest<BulkChangeGroupResponse>(
            resolvedTenantId,
            "/endpoint/v1/endpoint-groups/endpoints",
            { method: "POST", body: { ids: batch, groupId: group_id } }
          );
        } catch (error) {
          // Nothing went through yet: an ordinary error.
          if (start === 0) throw error;
          const notSent = ids.slice(start + BULK_CHANGE_GROUP_BATCH);
          return jsonResult({
            group_id,
            stopped: true,
            stopped_error: error instanceof Error ? error.message : String(error),
            ...bulkActionResult(
              ids.length,
              { items, errors },
              `Stopped at batch ${start / BULK_CHANGE_GROUP_BATCH + 1} of ${batches}. The first ${start} endpoint(s) were processed as items and errors show. The ${batch.length} in unconfirmed may or may not have moved; the ${notSent.length} in not_sent were not sent. Check before retrying them.`
            ),
            unconfirmed: batch,
            not_sent: notSent,
          });
        }
        items.push(...(data?.items ?? []));
        errors.push(...(data?.errors ?? []));
      }

      return jsonResult({ group_id, ...bulkActionResult(ids.length, { items, errors }) });
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
