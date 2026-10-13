/**
 * Tools: sophos_list_policies, sophos_get_policy, sophos_update_policy, sophos_clone_policy,
 *        sophos_create_policy, sophos_delete_policy, sophos_set_policy_assignments
 * Interact with the Sophos Endpoint API /endpoint/v1/policies
 *
 * Assignment (appliesTo) rules measured on a live tenant, 13/10/2026:
 * - appliesTo holds plain ID arrays under users and userGroups (a user policy)
 *   or endpoints and endpointGroups (a device policy). There is no type field;
 *   the kind follows which keys appliesTo carries. {id} objects get a 400.
 * - Mixing user and device keys gets a 400. Server policies take device keys only.
 * - endpointGroups without an endpoints key gets a 500 "Error processing data"
 *   on POST and PATCH; {endpoints: [], endpointGroups: [id]} works.
 * - PATCH replaces the whole assignment: a family key left out comes back empty.
 * - A new policy reaches the list 1.6 to 21.8 s after creation; GET by ID works at once.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { SophosPagedResponse } from "../types/sophos.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

interface SophosPolicy {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  priority: number;
  enforced: boolean;
  createdAt?: string;
  updatedAt?: string;
  appliesTo?: Record<string, unknown>;
  settings?: Record<string, unknown>;
  lockedByManagingAccount?: boolean;
}

/** A policy's assignment in one family, as the tools name the keys. */
export type PolicyAssignment =
  | { kind: "user"; users: string[]; user_groups: string[] }
  | { kind: "device"; endpoints: string[]; endpoint_groups: string[] };

export interface AssignmentArgs {
  users?: string[];
  user_groups?: string[];
  endpoints?: string[];
  endpoint_groups?: string[];
}

const assignmentInputSchema = {
  users: z
    .array(z.string().uuid())
    .optional()
    .describe("User IDs (makes it a user policy). Plain ID strings."),
  user_groups: z
    .array(z.string().uuid())
    .optional()
    .describe("Directory user group IDs (makes it a user policy). Plain ID strings."),
  endpoints: z
    .array(z.string().uuid())
    .optional()
    .describe("Endpoint IDs (makes it a device policy). Plain ID strings."),
  endpoint_groups: z
    .array(z.string().uuid())
    .optional()
    .describe("Endpoint group IDs (makes it a device policy). Plain ID strings."),
};

const uniq = (ids: string[] | undefined): string[] => [...new Set(ids ?? [])];

/**
 * The family the caller's assignment keys belong to, or undefined when none
 * was passed. Throws, before anything is sent, when user and device keys are
 * mixed (Sophos answers 400) or user keys are aimed at a server policy.
 */
export function requestedAssignmentKind(
  args: AssignmentArgs,
  policyType?: string
): "user" | "device" | undefined {
  const user = args.users !== undefined || args.user_groups !== undefined;
  const device = args.endpoints !== undefined || args.endpoint_groups !== undefined;
  if (user && device) {
    throw new Error(
      "A policy applies either to users and user groups (a user policy) or to endpoints and endpoint groups (a device policy), never both. Pass users/user_groups or endpoints/endpoint_groups, not a mix. Nothing was sent."
    );
  }
  if (user) {
    assertUserAssignable(policyType);
    return "user";
  }
  return device ? "device" : undefined;
}

/** Server policies apply only to endpoints and endpoint groups. */
export function assertUserAssignable(policyType: string | undefined): void {
  if (policyType?.startsWith("server-")) {
    throw new Error(
      `Policy type ${policyType} applies only to endpoints and endpoint groups. Use endpoints or endpoint_groups, not users or user_groups. Nothing was written.`
    );
  }
}

/** The whole assignment the caller asked for; keys left out are empty. */
export function assignmentFromArgs(kind: "user" | "device", args: AssignmentArgs): PolicyAssignment {
  return kind === "user"
    ? { kind, users: uniq(args.users), user_groups: uniq(args.user_groups) }
    : { kind, endpoints: uniq(args.endpoints), endpoint_groups: uniq(args.endpoint_groups) };
}

export function emptyAssignment(kind: "user" | "device"): PolicyAssignment {
  return assignmentFromArgs(kind, {});
}

/**
 * The appliesTo body for an assignment. Both keys of the family are always
 * sent, so endpointGroups never travels without endpoints (that shape gets a
 * 500), and the body says exactly what the stored assignment will be.
 */
export function toAppliesTo(a: PolicyAssignment): Record<string, string[]> {
  return a.kind === "user"
    ? { users: a.users, userGroups: a.user_groups }
    : { endpoints: a.endpoints, endpointGroups: a.endpoint_groups };
}

/**
 * Reads a policy's stored appliesTo. Sophos returns plain ID arrays; an
 * {id} object is read too. Returns null when appliesTo carries neither family.
 */
export function storedAssignment(appliesTo: unknown): PolicyAssignment | null {
  if (!appliesTo || typeof appliesTo !== "object") return null;
  const raw = appliesTo as Record<string, unknown>;
  const ids = (key: string): string[] => {
    const value = raw[key];
    if (!Array.isArray(value)) return [];
    return value
      .map((e) => (typeof e === "string" ? e : (e as { id?: unknown } | null)?.id))
      .filter((id): id is string => typeof id === "string");
  };
  const hasUser = "users" in raw || "userGroups" in raw;
  const hasDevice = "endpoints" in raw || "endpointGroups" in raw;
  const device: PolicyAssignment = {
    kind: "device",
    endpoints: ids("endpoints"),
    endpoint_groups: ids("endpointGroups"),
  };
  if (hasDevice && (!hasUser || device.endpoints.length + device.endpoint_groups.length > 0)) {
    return device;
  }
  return hasUser ? { kind: "user", users: ids("users"), user_groups: ids("userGroups") } : null;
}

function assignmentLists(a: PolicyAssignment): string[][] {
  return a.kind === "user" ? [a.users, a.user_groups] : [a.endpoints, a.endpoint_groups];
}

export function sameAssignment(a: PolicyAssignment | null, b: PolicyAssignment | null): boolean {
  if (!a || !b || a.kind !== b.kind) return false;
  const left = assignmentLists(a);
  const right = assignmentLists(b);
  return left.every((ids, i) => ids.length === right[i].length && ids.every((id) => right[i].includes(id)));
}

function assignmentSize(a: PolicyAssignment): number {
  return assignmentLists(a).reduce((n, ids) => n + ids.length, 0);
}

/** Per-key counts for list output. */
function assignmentCounts(a: PolicyAssignment | null) {
  if (!a) return { kind: null };
  return a.kind === "user"
    ? { kind: a.kind, users: a.users.length, user_groups: a.user_groups.length }
    : { kind: a.kind, endpoints: a.endpoints.length, endpoint_groups: a.endpoint_groups.length };
}

/**
 * Reads the policy back by ID (the list lags by up to about 22 s; GET by ID
 * does not) and reports what Sophos stored against what was sent.
 */
async function readBackAssignment(
  client: SophosClient,
  tenantId: string,
  policyId: string,
  sent: PolicyAssignment
) {
  try {
    const policy = await client.tenantRequest<SophosPolicy>(tenantId, `/endpoint/v1/policies/${policyId}`);
    const stored = storedAssignment(policy.appliesTo);
    const matches = sameAssignment(sent, stored);
    return {
      assignment_stored: stored,
      assignment_matches: matches,
      ...(matches
        ? {}
        : { warning: "The stored assignment differs from what was sent. assignment_stored is what Sophos holds." }),
    };
  } catch (error) {
    return {
      assignment_stored: null,
      assignment_matches: null,
      warning: `The write succeeded but the read-back failed: ${error instanceof Error ? error.message : String(error)}. Check with sophos_get_policy.`,
    };
  }
}

export function registerPolicyTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Policies ---
  server.registerTool(
    "sophos_list_policies",
    {
      title: "List Sophos Endpoint Policies",
      description: `List endpoint protection policies for a Sophos Central tenant.

Returns all configured policies including threat protection, peripheral control, 
application control, data loss prevention, web control, update management, and more.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - policy_type (string, optional): Filter by type e.g. "threat-protection", 
    "peripheral-control", "application-control", "data-loss-prevention", 
    "web-control", "update-management", "windows-firewall", "server-threat-protection",
    "server-lockdown".
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of policies with: id, name, type, enabled, priority, enforced,
  applies_to (kind plus counts). kind is user (users, user_groups) or device
  (endpoints, endpoint_groups); it follows which keys the assignment carries.

Listing lag: a policy created in the last 25 seconds or so may be missing here
(measured 1.6 to 21.8 s), and a deleted one can linger for as long. Use
sophos_get_policy by ID, which is current at once, rather than re-listing.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        policy_type: z
          .string()
          .optional()
          .describe(
            'Filter by policy type e.g. "threat-protection", "peripheral-control", "web-control"'
          ),
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
    withErrorHandling(async ({ tenant_id, policy_type, limit, page }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      if (policy_type) params.policyType = policy_type;

      const data = await client.tenantRequest<SophosPagedResponse<SophosPolicy>>(
        resolvedTenantId,
        "/endpoint/v1/policies",
        { params }
      );

      return jsonResult({
        total: data.pages.total ?? data.pages.items ?? data.items.length,
        page: data.pages.current ?? page,
        policies: data.items.map(formatPolicy),
      });
    })
  );

  // --- Get Policy ---
  server.registerTool(
    "sophos_get_policy",
    {
      title: "Get Sophos Policy Detail",
      description: `Get full details of a specific endpoint policy including all settings.

Returns the complete policy configuration, assignments, and individual settings.
applies_to_detail lists the assigned IDs and the kind: user (users, user_groups)
or device (endpoints, endpoint_groups). There is no type field; the kind follows
which keys the assignment carries. Current at once, unlike the policy list.

Args:
  - policy_id (string): The policy ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        policy_id: z.string().uuid().describe("Policy ID to retrieve"),
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
    withErrorHandling(async ({ policy_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const policy = await client.tenantRequest<SophosPolicy>(
        resolvedTenantId,
        `/endpoint/v1/policies/${policy_id}`
      );
      return jsonResult(formatPolicyDetailed(policy));
    })
  );

  // --- Update Policy ---
  server.registerTool(
    "sophos_update_policy",
    {
      title: "Update Sophos Policy",
      description: `Update an endpoint policy's properties or settings.

WARNING: This modifies the policy configuration which affects all assigned 
endpoints. Changes take effect on next agent check-in.

Supports updating: name, enabled state, priority, enforcement, individual
settings, and assignment. Pass only the fields you want to change.

Assignment: users, user_groups, endpoints and endpoint_groups (plain ID arrays)
REPLACE the policy's whole assignment. A key you leave out is emptied, and
device keys on a user policy turn it into a device policy (and back): the kind
follows which keys the assignment carries. To add or remove a few IDs without
restating the rest, use sophos_set_policy_assignments. Never mix user and
device keys; server policies (server-*) take only endpoints and
endpoint_groups. Both are refused before anything is written.
endpoint_groups is always sent with an endpoints key, because endpoint groups
on their own get a 500 from Sophos. After the write the policy is read back by
ID: assignment_stored is what Sophos holds and assignment_matches compares it
with assignment_sent.

Args:
  - policy_id (string): The policy ID to update.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string, optional): New policy name.
  - enabled (boolean, optional): Enable/disable the policy.
  - priority (number, optional): Policy priority (lower = higher priority).
  - enforced (boolean, optional): Whether policy settings are enforced (cannot be overridden by lower-priority policies).
  - settings (object, optional): Policy settings object to merge. Only include settings you want to change.
  - users, user_groups, endpoints, endpoint_groups (string arrays, optional): The new whole assignment.`,
      inputSchema: {
        policy_id: z.string().uuid().describe("Policy ID to update"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().optional().describe("New policy name"),
        enabled: z.boolean().optional().describe("Enable or disable the policy"),
        priority: z
          .number()
          .int()
          .optional()
          .describe("Policy priority (lower = higher priority)"),
        enforced: z
          .boolean()
          .optional()
          .describe("Whether policy settings are enforced"),
        settings: z
          .record(z.unknown())
          .optional()
          .describe("Policy settings to update (partial merge)"),
        ...assignmentInputSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({ policy_id, tenant_id, name, enabled, priority, enforced, settings, ...assignmentArgs }) => {
        const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
        const kind = requestedAssignmentKind(assignmentArgs);

        const body: Record<string, unknown> = {};
        if (name !== undefined) body.name = name;
        if (enabled !== undefined) body.enabled = enabled;
        if (priority !== undefined) body.priority = priority;
        if (enforced !== undefined) body.enforced = enforced;
        if (settings !== undefined) body.settings = settings;

        if (Object.keys(body).length === 0 && !kind) {
          return jsonResult({
            error:
              "No fields to update. Provide at least one of: name, enabled, priority, enforced, settings, users, user_groups, endpoints, endpoint_groups.",
          });
        }

        let sent: PolicyAssignment | undefined;
        if (kind) {
          if (kind === "user") {
            const current = await client.tenantRequest<SophosPolicy>(
              resolvedTenantId,
              `/endpoint/v1/policies/${policy_id}`
            );
            assertUserAssignable(current.type);
          }
          sent = assignmentFromArgs(kind, assignmentArgs);
          body.appliesTo = toAppliesTo(sent);
        }

        const updated = await client.tenantRequest<SophosPolicy>(
          resolvedTenantId,
          `/endpoint/v1/policies/${policy_id}`,
          { method: "PATCH", body }
        );

        return jsonResult({
          status: "updated",
          policy: formatPolicy(updated),
          ...(sent
            ? { assignment_sent: sent, ...(await readBackAssignment(client, resolvedTenantId, policy_id, sent)) }
            : {}),
        });
      }
    )
  );

  // --- Clone Policy ---
  server.registerTool(
    "sophos_clone_policy",
    {
      title: "Clone Sophos Policy",
      description: `Create a new policy by cloning an existing one.

Creates a copy of the source policy with a new name. The cloned policy starts 
as disabled and inherits all settings from the source. Useful for creating 
variants of existing policies.

Args:
  - source_policy_id (string): The policy ID to clone.
  - name (string): Name for the new cloned policy.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        source_policy_id: z.string().uuid().describe("Policy ID to clone from"),
        name: z.string().describe("Name for the cloned policy"),
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
    withErrorHandling(async ({ source_policy_id, name, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);

      const created = await client.tenantRequest<SophosPolicy>(
        resolvedTenantId,
        `/endpoint/v1/policies/${source_policy_id}/clone`,
        { method: "POST", body: { name } }
      );

      return jsonResult({
        status: "cloned",
        policy: formatPolicy(created),
      });
    })
  );

  // --- Create Policy ---
  server.registerTool(
    "sophos_create_policy",
    {
      title: "Create Sophos Policy",
      description: `Create a new endpoint policy in Sophos Central.

Assignment (optional): users, user_groups, endpoints and endpoint_groups take
plain ID arrays. A policy applies either to users and user groups (a user
policy) or to endpoints and endpoint groups (a device policy), never both.
There is no type field: the kind follows which keys you send. A computer policy
created with no assignment is an unassigned user policy. Server policies
(server-*) take only endpoints and endpoint_groups. A mix, or user keys on a
server policy, is refused before anything is sent. endpoint_groups is always
sent with an endpoints key, because endpoint groups on their own get a 500 from
Sophos. With an assignment, the new policy is read back by ID: assignment_stored
is what Sophos holds and assignment_matches compares it with assignment_sent.

Listing lag: the new policy can take up to about 25 seconds to appear in
sophos_list_policies (measured 1.6 to 21.8 s). sophos_get_policy by ID works at
once, so check by ID rather than re-listing or creating it again.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string): Policy name.
  - type (string): Policy type e.g. "threat-protection", "peripheral-control", "web-control".
  - enabled (boolean, optional): Whether the policy is enabled (default true).
  - priority (number, optional): Policy priority (lower = higher priority).
  - settings (object, optional): Policy settings object.
  - users, user_groups, endpoints, endpoint_groups (string arrays, optional): Who or what the policy applies to.`,
      inputSchema: {
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
        name: z.string().describe("Policy name"),
        type: z.string().describe('Policy type e.g. "threat-protection", "peripheral-control", "web-control"'),
        enabled: z.boolean().optional().describe("Whether the policy is enabled (default true)"),
        priority: z.coerce.number().int().optional().describe("Policy priority (lower = higher priority)"),
        settings: z.record(z.unknown()).optional().describe("Policy settings object"),
        ...assignmentInputSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    withErrorHandling(async ({ tenant_id, name, type, enabled, priority, settings, ...assignmentArgs }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const kind = requestedAssignmentKind(assignmentArgs, type);
      const body: Record<string, unknown> = { name, type };
      if (enabled !== undefined) body.enabled = enabled;
      if (priority !== undefined) body.priority = priority;
      if (settings !== undefined) body.settings = settings;
      const sent = kind ? assignmentFromArgs(kind, assignmentArgs) : undefined;
      if (sent) body.appliesTo = toAppliesTo(sent);

      const created = await client.tenantRequest<SophosPolicy>(
        resolvedTenantId,
        "/endpoint/v1/policies",
        { method: "POST", body }
      );
      return jsonResult({
        status: "created",
        policy: formatPolicy(created),
        ...(sent
          ? { assignment_sent: sent, ...(await readBackAssignment(client, resolvedTenantId, created.id, sent)) }
          : {}),
      });
    })
  );

  // --- Delete Policy ---
  server.registerTool(
    "sophos_delete_policy",
    {
      title: "Delete Sophos Policy",
      description: `Delete an endpoint policy from Sophos Central.

WARNING: This permanently removes the policy. Endpoints assigned to this policy will
fall back to the next applicable policy in the priority chain.

Args:
  - policy_id (string): Policy ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        policy_id: z.string().uuid().describe("Policy ID to delete"),
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ policy_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.tenantRequest(resolvedTenantId, `/endpoint/v1/policies/${policy_id}`, { method: "DELETE" });
      return jsonResult({ status: "deleted", policy_id, message: `Policy ${policy_id} deleted.` });
    })
  );

  // --- Set Policy Assignments ---
  server.registerTool(
    "sophos_set_policy_assignments",
    {
      title: "Set Sophos Policy Assignments",
      description: `Change only which users, user groups, endpoints or endpoint groups a policy applies to.

mode:
  - replace: the IDs you pass become the whole assignment. Keys you leave out are emptied.
  - add: the IDs are added to what the policy holds now.
  - remove: the IDs are taken out. IDs that were not assigned are listed in not_assigned.

A policy is either a user policy (users, user_groups) or a device policy
(endpoints, endpoint_groups). There is no type field: the kind follows which
keys the assignment carries, so replace with device keys turns a user policy
into a device policy, and back. Never mix user and device keys in one call.
add refuses a kind change while the policy still has assignments of the other
kind; use replace for that. Server policies (server-*) take only endpoints and
endpoint_groups. Refusals happen before anything is written.

The policy is read first, written with one PATCH (none when nothing would
change), then read back by ID. The result shows assignment_before,
assignment_sent, assignment_stored (what Sophos holds) and assignment_matches.
endpoint_groups is always sent with an endpoints key, because endpoint groups
on their own get a 500 from Sophos. The policy list can lag a write by up to
about 25 seconds; sophos_get_policy by ID is current at once.

Args:
  - policy_id (string): The policy ID.
  - mode (string): "replace", "add" or "remove".
  - users, user_groups, endpoints, endpoint_groups (string arrays, optional): IDs. At least one is required.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        policy_id: z.string().uuid().describe("Policy ID"),
        mode: z
          .enum(["replace", "add", "remove"])
          .describe("replace sets the whole assignment; add and remove change only the IDs passed"),
        ...assignmentInputSchema,
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    withErrorHandling(async ({ policy_id, mode, tenant_id, ...assignmentArgs }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const kind = requestedAssignmentKind(assignmentArgs);
      if (!kind) {
        throw new Error("Pass at least one of users, user_groups, endpoints or endpoint_groups. Nothing was sent.");
      }

      const policy = await client.tenantRequest<SophosPolicy>(
        resolvedTenantId,
        `/endpoint/v1/policies/${policy_id}`
      );
      if (kind === "user") assertUserAssignable(policy.type);
      const before =
        storedAssignment(policy.appliesTo) ?? emptyAssignment(policy.type?.startsWith("server-") ? "device" : "user");
      const request = assignmentFromArgs(kind, assignmentArgs);
      const requestLists = assignmentLists(request);
      const beforeLists = before.kind === kind ? assignmentLists(before) : [[], []];

      let target: PolicyAssignment;
      let notAssigned: PolicyAssignment | undefined;
      if (mode === "replace") {
        target = request;
      } else if (mode === "add") {
        if (before.kind !== kind && assignmentSize(before) > 0) {
          throw new Error(
            `Policy ${policy_id} is a ${before.kind} policy with ${assignmentSize(before)} assignment(s), and a policy cannot mix user and device assignments. Use mode "replace" to make it a ${kind} policy, which drops the current assignments. Nothing was written.`
          );
        }
        const [a, b] = requestLists.map((ids, i) => uniq([...beforeLists[i], ...ids]));
        target = kind === "user" ? { kind, users: a, user_groups: b } : { kind, endpoints: a, endpoint_groups: b };
      } else {
        if (before.kind !== kind) {
          target = before;
          notAssigned = request;
        } else {
          const [a, b] = beforeLists.map((ids, i) => ids.filter((id) => !requestLists[i].includes(id)));
          target = kind === "user" ? { kind, users: a, user_groups: b } : { kind, endpoints: a, endpoint_groups: b };
          const [x, y] = requestLists.map((ids, i) => ids.filter((id) => !beforeLists[i].includes(id)));
          if (x.length + y.length > 0) {
            notAssigned =
              kind === "user" ? { kind, users: x, user_groups: y } : { kind, endpoints: x, endpoint_groups: y };
          }
        }
      }

      const summary = {
        policy_id,
        name: policy.name,
        type: policy.type,
        mode,
        assignment_before: before,
        ...(notAssigned ? { not_assigned: notAssigned } : {}),
      };
      if (sameAssignment(target, before)) {
        return jsonResult({ status: "unchanged", ...summary, message: "Nothing to change, so nothing was written." });
      }

      await client.tenantRequest<SophosPolicy>(resolvedTenantId, `/endpoint/v1/policies/${policy_id}`, {
        method: "PATCH",
        body: { appliesTo: toAppliesTo(target) },
      });
      return jsonResult({
        status: "updated",
        ...summary,
        assignment_sent: target,
        ...(await readBackAssignment(client, resolvedTenantId, policy_id, target)),
      });
    })
  );
}

function formatPolicy(p: SophosPolicy) {
  return {
    id: p.id,
    name: p.name,
    type: p.type,
    enabled: p.enabled,
    priority: p.priority,
    enforced: p.enforced,
    locked_by_partner: p.lockedByManagingAccount ?? false,
    created_at: p.createdAt ?? null,
    updated_at: p.updatedAt ?? null,
    applies_to: assignmentCounts(storedAssignment(p.appliesTo)),
  };
}

function formatPolicyDetailed(p: SophosPolicy) {
  return {
    ...formatPolicy(p),
    applies_to_detail: storedAssignment(p.appliesTo),
    settings: p.settings ?? {},
  };
}
