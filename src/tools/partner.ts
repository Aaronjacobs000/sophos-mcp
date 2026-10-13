/**
 * Tools: sophos_create_tenant, sophos_get_managed_tenant,
 *        sophos_list_partner_roles, sophos_get_partner_role,
 *        sophos_create_partner_role, sophos_delete_partner_role,
 *        sophos_list_partner_permission_sets,
 *        sophos_list_partner_admins, sophos_get_partner_admin,
 *        sophos_create_partner_admin, sophos_delete_partner_admin,
 *        sophos_list_partner_admin_role_assignments,
 *        sophos_add_partner_admin_role_assignment,
 *        sophos_delete_partner_admin_role_assignment,
 *        sophos_get_billing_usage, sophos_get_billing_summary
 * Partner/organization-level tools using globalRequest.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

const partnerRoleAssignmentSchema = z.object({
  role_id: z.string().uuid().describe("Role ID"),
  scope_type: z
    .enum(["tenant", "allManagedTenants", "self", "tenantGroup"])
    .describe("What the role applies to"),
  scope_id: z
    .string()
    .uuid()
    .optional()
    .describe("Tenant or tenant group ID; not used for allManagedTenants or self"),
});

function toPartnerRoleAssignment(a: z.infer<typeof partnerRoleAssignmentSchema>) {
  return {
    roleId: a.role_id,
    scope: { type: a.scope_type, ...(a.scope_id ? { id: a.scope_id } : {}) },
  };
}

export function registerPartnerTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // =========================================================================
  // TENANT MANAGEMENT
  // =========================================================================

  server.registerTool(
    "sophos_create_tenant",
    {
      title: "Create Managed Tenant",
      description: `Create a new managed tenant under this partner account.

The API needs a billing type and a contact with a phone number and a postal
address. The name cannot be changed after creation.

Args:
  - name (string): Tenant name (permanent).
  - billing_type (string): "trial", "usage" or "ordered".
  - data_geography (string, optional): "US", "IE", "DE", "CA", "AU", "JP", "IN", "BR" or "AE".
  - contact_first_name, contact_last_name, contact_phone (string): Primary contact.
  - contact_email (string, optional): Primary contact email.
  - address1, city, country_code, postal_code (string): Contact address.
  - address2, state (string, optional): More of the address.

Returns:
  Created tenant details including id, name, apiHost.`,
      inputSchema: {
        name: z.string().describe("Tenant name (cannot be changed later)"),
        billing_type: z.enum(["trial", "usage", "ordered"]).describe("Billing type"),
        data_geography: z
          .enum(["US", "IE", "DE", "CA", "AU", "JP", "IN", "BR", "AE"])
          .optional()
          .describe("Data residency geography"),
        contact_first_name: z.string().describe("Primary contact first name"),
        contact_last_name: z.string().describe("Primary contact last name"),
        contact_phone: z.string().describe("Primary contact phone number"),
        contact_email: z.string().email().optional().describe("Primary contact email address"),
        address1: z.string().describe("Address line 1"),
        address2: z.string().optional().describe("Address line 2"),
        city: z.string().describe("City"),
        state: z.string().optional().describe("State"),
        country_code: z.string().describe('Country code, for example "AU"'),
        postal_code: z.string().describe("Postal code"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async (args) => {
      const address: Record<string, unknown> = {
        address1: args.address1,
        city: args.city,
        countryCode: args.country_code,
        postalCode: args.postal_code,
      };
      if (args.address2) address.address2 = args.address2;
      if (args.state) address.state = args.state;
      const contact: Record<string, unknown> = {
        firstName: args.contact_first_name,
        lastName: args.contact_last_name,
        phone: args.contact_phone,
        address,
      };
      if (args.contact_email) contact.email = args.contact_email;
      const body: Record<string, unknown> = { name: args.name, billingType: args.billing_type, contact };
      if (args.data_geography) body.dataGeography = args.data_geography;

      const data = await client.globalRequest<Record<string, unknown>>(
        "/partner/v1/tenants",
        { method: "POST", body }
      );

      return jsonResult({ status: "created", tenant: data });
    })
  );

  server.registerTool(
    "sophos_get_managed_tenant",
    {
      title: "Get Managed Tenant Details",
      description: `Get detailed information about a specific managed tenant.

Returns full tenant details including name, data geography, API host,
billing type, status, and contact information.

Args:
  - tenant_id (string): The tenant ID to retrieve.

Returns:
  Full tenant details.`,
      inputSchema: {
        tenant_id: z.string().describe("Tenant ID to retrieve"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id }) => {
      const data = await client.globalRequest<Record<string, unknown>>(
        `/partner/v1/tenants/${tenant_id}`
      );

      return jsonResult(data);
    })
  );

  // =========================================================================
  // PARTNER ROLES
  // =========================================================================

  server.registerTool(
    "sophos_list_partner_roles",
    {
      title: "List Partner Roles",
      description: `List partner-level admin roles.

Returns all role definitions available at the partner level, in one response.
These roles can be assigned to partner administrators.

Args:
  - type (string, optional): "predefined" or "custom".
  - principal_type (string, optional): "user" or "service".

Returns:
  The partner roles.`,
      inputSchema: {
        type: z.enum(["predefined", "custom"]).optional().describe("Role type"),
        principal_type: z.enum(["user", "service"]).optional().describe("Principal type"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ type, principal_type }) => {
      const params: Record<string, string> = {};
      if (type) params.type = type;
      if (principal_type) params.principalType = principal_type;

      const data = await client.globalRequest<{
        items?: Record<string, unknown>[];
        pages?: { current?: number; total?: number; items?: number };
      }>("/partner/v1/roles", { params });

      const items = data.items ?? [];
      return jsonResult({ total: items.length, roles: items });
    })
  );

  server.registerTool(
    "sophos_get_partner_role",
    {
      title: "Get Partner Role",
      description: `Get details of a specific partner-level role.

Args:
  - role_id (string): Role ID to retrieve.

Returns:
  Role details including name, description, and permission sets.`,
      inputSchema: {
        role_id: z.string().describe("Role ID to retrieve"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ role_id }) => {
      const data = await client.globalRequest<Record<string, unknown>>(
        `/partner/v1/roles/${role_id}`
      );

      return jsonResult(data);
    })
  );

  server.registerTool(
    "sophos_create_partner_role",
    {
      title: "Create Partner Role",
      description: `Create a new partner-level admin role.

Creates a custom role that can be assigned to partner administrators.
Use sophos_list_partner_permission_sets to see available permissions.

Args:
  - name (string): Role name.
  - principal_type (string): "user" (for admins) or "service" (for API credentials).
  - permission_sets (string[]): Permission set IDs to include (at least one).
  - description (string, optional): Role description.

Returns:
  Created role details.`,
      inputSchema: {
        name: z.string().describe("Role name"),
        principal_type: z.enum(["user", "service"]).describe("Who the role is for"),
        permission_sets: z.array(z.string()).min(1).describe("Permission set IDs to include"),
        description: z.string().optional().describe("Role description"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ name, principal_type, permission_sets, description }) => {
      const body: Record<string, unknown> = { name, principalType: principal_type, permissionSets: permission_sets };
      if (description) body.description = description;

      const data = await client.globalRequest<Record<string, unknown>>(
        "/partner/v1/roles",
        { method: "POST", body }
      );

      return jsonResult({ status: "created", role: data });
    })
  );

  server.registerTool(
    "sophos_delete_partner_role",
    {
      title: "Delete Partner Role",
      description: `Delete a partner-level admin role.

Removes the role definition. Any admins currently assigned this role will
lose the associated permissions.

Args:
  - role_id (string): Role ID to delete.

Returns:
  Confirmation of deletion.`,
      inputSchema: {
        role_id: z.string().describe("Role ID to delete"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ role_id }) => {
      await client.globalRequest(
        `/partner/v1/roles/${role_id}`,
        { method: "DELETE" }
      );

      return jsonResult({
        status: "deleted",
        role_id,
        message: `Partner role ${role_id} deleted.`,
      });
    })
  );

  // =========================================================================
  // PARTNER PERMISSION SETS
  // =========================================================================

  server.registerTool(
    "sophos_list_partner_permission_sets",
    {
      title: "List Partner Permission Sets",
      description: `List available partner-level permission sets.

Returns all permission sets that can be assigned to partner roles.
Use these IDs when creating or updating partner roles.

Returns:
  List of available permission sets with IDs and descriptions.`,
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async () => {
      const data = await client.globalRequest<Record<string, unknown>>(
        "/partner/v1/roles/permission-sets"
      );

      return jsonResult(data);
    })
  );

  // =========================================================================
  // PARTNER ADMINS
  // =========================================================================

  server.registerTool(
    "sophos_list_partner_admins",
    {
      title: "List Partner Admins",
      description: `List partner-level administrator accounts.

Returns all administrators at the partner/organization level with their
role assignments.

Args:
  - limit (number, optional): Max results per page (default 50).
  - page (number, optional): Page number (default 1).

Returns:
  Paginated list of partner admins.`,
      inputSchema: {
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
    withErrorHandling(async ({ limit, page }) => {
      const params: Record<string, string> = {
        pageSize: String(limit),
        page: String(page),
      };

      const data = await client.globalRequest<{
        items?: Record<string, unknown>[];
        pages?: { current?: number; total?: number; items?: number };
      }>("/partner/v1/admins", { params });

      const items = data.items ?? [];
      return jsonResult({
        total: data.pages?.total ?? data.pages?.items ?? items.length,
        page: data.pages?.current ?? page,
        admins: items,
      });
    })
  );

  server.registerTool(
    "sophos_get_partner_admin",
    {
      title: "Get Partner Admin",
      description: `Get details of a specific partner-level administrator.

Args:
  - admin_id (string): Admin ID to retrieve.

Returns:
  Admin details including name, email, and role assignments.`,
      inputSchema: {
        admin_id: z.string().describe("Admin ID to retrieve"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ admin_id }) => {
      const data = await client.globalRequest<Record<string, unknown>>(
        `/partner/v1/admins/${admin_id}`
      );

      return jsonResult(data);
    })
  );

  server.registerTool(
    "sophos_create_partner_admin",
    {
      title: "Create Partner Admin",
      description: `Create a new partner-level administrator.

The admin receives an invitation email at the username address.

Args:
  - username (string): The admin's email address, which is the username.
  - first_name (string): Admin's first name.
  - last_name (string): Admin's last name.
  - name (string, optional): Full name; first and last name when omitted.
  - phone, mobile (string, optional): Phone numbers.
  - role_assignments (array, optional): Each {role_id, scope_type, scope_id?}.
    scope_type is "tenant", "allManagedTenants", "self" or "tenantGroup";
    scope_id is the tenant or tenant group ID (not used for allManagedTenants or self).

Returns:
  Created admin details.`,
      inputSchema: {
        username: z.string().email().describe("Admin email address (the username)"),
        first_name: z.string().describe("Admin's first name"),
        last_name: z.string().describe("Admin's last name"),
        name: z.string().optional().describe("Full name"),
        phone: z.string().optional().describe("Phone number"),
        mobile: z.string().optional().describe("Mobile number"),
        role_assignments: z
          .array(partnerRoleAssignmentSchema)
          .optional()
          .describe("Role assignments"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ username, first_name, last_name, name, phone, mobile, role_assignments }) => {
      const profile: Record<string, unknown> = {
        name: name ?? `${first_name} ${last_name}`,
        firstName: first_name,
        lastName: last_name,
      };
      if (phone) profile.phone = phone;
      if (mobile) profile.mobile = mobile;
      const body: Record<string, unknown> = { username, profile };
      if (role_assignments) body.roleAssignments = role_assignments.map(toPartnerRoleAssignment);

      const data = await client.globalRequest<Record<string, unknown>>(
        "/partner/v1/admins",
        { method: "POST", body }
      );

      return jsonResult({ status: "created", admin: data });
    })
  );

  server.registerTool(
    "sophos_delete_partner_admin",
    {
      title: "Delete Partner Admin",
      description: `Delete a partner-level administrator account.

Permanently removes the admin's access to the partner dashboard and
all managed tenants.

Args:
  - admin_id (string): Admin ID to delete.

Returns:
  Confirmation of deletion.`,
      inputSchema: {
        admin_id: z.string().describe("Admin ID to delete"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ admin_id }) => {
      await client.globalRequest(
        `/partner/v1/admins/${admin_id}`,
        { method: "DELETE" }
      );

      return jsonResult({
        status: "deleted",
        admin_id,
        message: `Partner admin ${admin_id} deleted.`,
      });
    })
  );

  // =========================================================================
  // PARTNER ADMIN ROLE ASSIGNMENTS
  // =========================================================================

  server.registerTool(
    "sophos_list_partner_admin_role_assignments",
    {
      title: "List Partner Admin Role Assignments",
      description: `List role assignments for a specific partner administrator.

Returns all roles currently assigned to the specified admin.

Args:
  - admin_id (string): Admin ID whose role assignments to list.

Returns:
  List of role assignments for the admin.`,
      inputSchema: {
        admin_id: z.string().describe("Admin ID whose role assignments to list"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ admin_id }) => {
      const data = await client.globalRequest<Record<string, unknown>>(
        `/partner/v1/admins/${admin_id}/role-assignments`
      );

      return jsonResult(data);
    })
  );

  server.registerTool(
    "sophos_add_partner_admin_role_assignment",
    {
      title: "Add Partner Admin Role Assignment",
      description: `Add a role assignment to a partner administrator.

Grants the role's permissions to the admin over a scope.

Args:
  - admin_id (string): Admin ID to assign the role to.
  - role_id (string): Role ID to assign.
  - scope_type (string): "tenant", "allManagedTenants", "self" or "tenantGroup".
  - scope_id (string, optional): Tenant or tenant group ID; not used for
    allManagedTenants or self.

Returns:
  Created role assignment details.`,
      inputSchema: {
        admin_id: z.string().uuid().describe("Admin ID to assign the role to"),
        role_id: z.string().uuid().describe("Role ID to assign"),
        scope_type: partnerRoleAssignmentSchema.shape.scope_type,
        scope_id: partnerRoleAssignmentSchema.shape.scope_id,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ admin_id, role_id, scope_type, scope_id }) => {
      const data = await client.globalRequest<Record<string, unknown>>(
        `/partner/v1/admins/${admin_id}/role-assignments`,
        { method: "POST", body: toPartnerRoleAssignment({ role_id, scope_type, scope_id }) }
      );

      return jsonResult({ status: "created", assignment: data });
    })
  );

  server.registerTool(
    "sophos_delete_partner_admin_role_assignment",
    {
      title: "Delete Partner Admin Role Assignment",
      description: `Remove a role assignment from a partner administrator.

Revokes the specified role's permissions from the admin.

Args:
  - admin_id (string): Admin ID to remove the role from.
  - assignment_id (string): Role assignment ID to remove.

Returns:
  Confirmation of deletion.`,
      inputSchema: {
        admin_id: z.string().describe("Admin ID to remove the role from"),
        assignment_id: z.string().describe("Role assignment ID to remove"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ admin_id, assignment_id }) => {
      await client.globalRequest(
        `/partner/v1/admins/${admin_id}/role-assignments/${assignment_id}`,
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

  // =========================================================================
  // BILLING USAGE
  // =========================================================================

  server.registerTool(
    "sophos_get_billing_usage",
    {
      title: "Get Billing Usage",
      description: `Get billing usage for a specific month.

Returns billing usage data across all managed tenants for the given year and month.
Supports pagination and optional client-side tenant filtering.

When tenant_id is provided, results are filtered client-side by matching the
accountId field in each billing line item. Items without an accountId (e.g.
standalone device subscriptions) are excluded from filtered results. The
pages metadata reflects the unfiltered totals from the API.

Args:
  - year (number): The year (e.g. 2026).
  - month (number): The month (1-12).
  - tenant_id (string, optional): Filter results to a specific tenant by accountId.
  - page_size (number, optional): Items per page (default 50).
  - cursor (string, optional): pages.nextKey from the previous response.

Returns:
  Billing usage details for the specified month.`,
      inputSchema: {
        year: z.coerce.number().int().min(2000).max(2100).describe("Year (e.g. 2026)"),
        month: z.coerce.number().int().min(1).max(12).describe("Month (1-12)"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Filter results to a specific tenant by accountId"),
        page_size: z
          .number()
          .int()
          .min(1)
          .max(1000)
          .optional()
          .describe("Items per page (default 50)"),
        cursor: z
          .string()
          .optional()
          .describe("pages.nextKey from the previous response"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ year, month, tenant_id, page_size, cursor }) => {
      const params: Record<string, string> = { pageTotal: "true" };
      if (page_size) params.pageSize = String(page_size);
      if (cursor) params.pageFromKey = cursor;

      const data = await client.globalRequest<{
        items?: Array<Record<string, unknown>>;
        pages?: Record<string, unknown>;
      }>(
        `/partner/v1/billing/usage/${year}/${month}`,
        { params }
      );

      if (tenant_id && Array.isArray(data.items)) {
        const filtered = data.items.filter(
          (item) => item.accountId === tenant_id || item.externalId === tenant_id
        );
        return jsonResult({
          items: filtered,
          filteredCount: filtered.length,
          unfilteredCount: data.items.length,
          tenantFilter: tenant_id,
          pages: data.pages,
        });
      }

      return jsonResult(data);
    })
  );

  // =========================================================================
  // BILLING SUMMARY (aggregated)
  // =========================================================================

  server.registerTool(
    "sophos_get_billing_summary",
    {
      title: "Get Billing Summary by Customer",
      description: `Get an aggregated billing summary for a specific month, ranked by customer revenue.

Auto-paginates through ALL billing line items and aggregates by customer.
Returns per-customer totals with product breakdown, sorted by monthly revenue descending.

Monthly cost per line item is calculated as: billableQuantity * unitPrice.
The netPrice field in raw billing data is the total order line value shared across
all customers on that line — NOT the per-customer cost.

Use compact=true to get a smaller response with coverage flags (hasMDR, mdrTier,
hasFirewall, firewallModels) instead of full product arrays. This fits all customers
in a single response without hitting the character limit.

Args:
  - year (number): The year (e.g. 2026).
  - month (number): The month (1-12).
  - limit (number, optional): Return only the top N customers (default: all).
  - compact (boolean, optional): Return coverage flags instead of full product arrays (default: false).

Returns:
  Ranked list of customers with monthly cost, product breakdown, and estate totals.`,
      inputSchema: {
        year: z.coerce.number().int().min(2000).max(2100).describe("Year (e.g. 2026)"),
        month: z.coerce.number().int().min(1).max(12).describe("Month (1-12)"),
        limit: z
          .number()
          .int()
          .min(1)
          .optional()
          .describe("Return only the top N customers (default: all)"),
        compact: z
          .boolean()
          .optional()
          .describe("Return coverage flags instead of full product arrays (default: false)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ year, month, limit, compact }) => {
      // Auto-paginate to collect ALL billing line items
      const allItems: Array<Record<string, unknown>> = [];
      let cursor: string | undefined;
      let pageCount = 0;
      const maxPages = 20; // Safety limit

      do {
        const params: Record<string, string> = {
          pageTotal: "true",
          pageSize: "1000",
        };
        // The usage report pages by key; a "cursor" parameter is ignored, which
        // made every loop re-read the first page and count it again.
        if (cursor) params.pageFromKey = cursor;

        const data = await client.globalRequest<{
          items?: Array<Record<string, unknown>>;
          pages?: { nextKey?: string; items?: number };
        }>(`/partner/v1/billing/usage/${year}/${month}`, { params });

        if (Array.isArray(data.items)) {
          allItems.push(...data.items);
        }
        const next = data.pages?.nextKey ?? undefined;
        cursor = next && next !== cursor ? next : undefined;
        pageCount++;
      } while (cursor && pageCount < maxPages);

      // Aggregate by customer
      const customers = new Map<
        string,
        {
          name: string;
          accountId: string | null;
          monthlyTotal: number;
          products: Map<string, { description: string; quantity: number; monthlyCost: number; productGroup: string }>;
          totalUsers: number;
          totalServers: number;
          totalDevices: number;
          hasMDR: boolean;
          mdrTier: string | null;
          hasFirewall: boolean;
          firewallModels: Set<string>;
        }
      >();

      for (const item of allItems) {
        const name = String(item.assignedAccountIdentifier ?? "Unknown");
        const accountId = (item.accountId as string) ?? null;
        const quantity = Number(item.billableQuantity ?? 0);
        const unitPrice = Number(item.unitPrice ?? 0);
        const monthlyCost = quantity * unitPrice;
        const productGroup = String(item.productGroup ?? "Other");
        const productDesc = String(item.productDescription ?? "Unknown");
        const productCode = String(item.productCode ?? "unknown");

        if (!customers.has(name)) {
          customers.set(name, {
            name,
            accountId,
            monthlyTotal: 0,
            products: new Map(),
            totalUsers: 0,
            totalServers: 0,
            totalDevices: 0,
            hasMDR: false,
            mdrTier: null,
            hasFirewall: false,
            firewallModels: new Set(),
          });
        }

        const cust = customers.get(name)!;
        cust.monthlyTotal += monthlyCost;

        // Track product breakdown
        const key = productCode;
        if (!cust.products.has(key)) {
          cust.products.set(key, { description: productDesc, quantity: 0, monthlyCost: 0, productGroup });
        }
        const prod = cust.products.get(key)!;
        prod.quantity += quantity;
        prod.monthlyCost += monthlyCost;

        // Track seat/device counts
        if (productGroup === "User") cust.totalUsers += quantity;
        else if (productGroup === "Server") cust.totalServers += quantity;
        else if (productGroup === "Device") cust.totalDevices += quantity;

        // Track MDR coverage
        const descLower = productDesc.toLowerCase();
        if (descLower.includes("mdr complete")) {
          cust.hasMDR = true;
          cust.mdrTier = "Complete";
        } else if (descLower.includes("mdr essentials") && cust.mdrTier !== "Complete") {
          cust.hasMDR = true;
          cust.mdrTier = "Essentials";
        }

        // Track firewall coverage
        if (productGroup === "Device" && (
          descLower.includes("xgs") || descLower.includes("xg ") ||
          descLower.includes("sf sw") || descLower.includes("sf virtual") ||
          descLower.includes("xstream protection") || descLower.includes("standard protection")
        )) {
          cust.hasFirewall = true;
          // Extract model from description
          const modelMatch = productDesc.match(/^(XGS \d+|XG \d+|SF SW\/Virtual[^-]*)/i);
          if (modelMatch) cust.firewallModels.add(modelMatch[1].trim());
        }
      }

      // Sort by monthly total descending
      const sorted = [...customers.values()]
        .sort((a, b) => b.monthlyTotal - a.monthlyTotal)
        .slice(0, limit ?? customers.size);

      // Build summary
      const grandTotal = [...customers.values()].reduce((sum, c) => sum + c.monthlyTotal, 0);
      const totalCustomers = customers.size;

      if (compact) {
        const compactSummary = sorted.map((c, i) => ({
          rank: i + 1,
          customer: c.name,
          accountId: c.accountId,
          monthlyAUD: Math.round(c.monthlyTotal * 100) / 100,
          users: c.totalUsers,
          servers: c.totalServers,
          devices: c.totalDevices,
          hasMDR: c.hasMDR,
          mdrTier: c.mdrTier,
          hasFirewall: c.hasFirewall,
          firewallModels: [...c.firewallModels],
        }));

        return jsonResult({
          period: `${year}-${String(month).padStart(2, "0")}`,
          currency: "AUD",
          totalCustomers,
          totalLineItems: allItems.length,
          grandTotalMonthlyAUD: Math.round(grandTotal * 100) / 100,
          returnedCustomers: compactSummary.length,
          customers: compactSummary,
        });
      }

      const summary = sorted.map((c, i) => ({
        rank: i + 1,
        customer: c.name,
        accountId: c.accountId,
        monthlyAUD: Math.round(c.monthlyTotal * 100) / 100,
        users: c.totalUsers,
        servers: c.totalServers,
        devices: c.totalDevices,
        hasMDR: c.hasMDR,
        mdrTier: c.mdrTier,
        hasFirewall: c.hasFirewall,
        firewallModels: [...c.firewallModels],
        products: [...c.products.values()].map((p) => ({
          product: p.description,
          group: p.productGroup,
          quantity: p.quantity,
          monthlyAUD: Math.round(p.monthlyCost * 100) / 100,
        })),
      }));

      return jsonResult({
        period: `${year}-${String(month).padStart(2, "0")}`,
        currency: "AUD",
        totalCustomers,
        totalLineItems: allItems.length,
        grandTotalMonthlyAUD: Math.round(grandTotal * 100) / 100,
        returnedCustomers: summary.length,
        customers: summary,
      });
    })
  );

}
