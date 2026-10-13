/**
 * Tools: sophos_get_mobile_auto_enrollment, sophos_update_mobile_auto_enrollment,
 *        sophos_list_mobile_os, sophos_list_mobile_devices, sophos_get_mobile_device,
 *        sophos_create_mobile_device, sophos_update_mobile_device, sophos_delete_mobile_device,
 *        sophos_list_mobile_device_properties, sophos_get_mobile_device_compliance,
 *        sophos_get_mobile_device_scans, sophos_get_mobile_device_policies,
 *        sophos_get_mobile_device_apps, sophos_get_mobile_device_location,
 *        sophos_list_mobile_device_groups, sophos_get_mobile_device_group,
 *        sophos_create_mobile_device_group, sophos_update_mobile_device_group,
 *        sophos_delete_mobile_device_group, sophos_sync_mobile_device,
 *        sophos_request_mobile_device_logs, sophos_scan_mobile_device,
 *        sophos_unenroll_mobile_device, sophos_send_mobile_device_message,
 *        sophos_locate_mobile_device, sophos_lock_mobile_device, sophos_wipe_mobile_device,
 *        sophos_list_mobile_app_groups, sophos_get_mobile_app_group,
 *        sophos_create_mobile_app_group, sophos_update_mobile_app_group,
 *        sophos_delete_mobile_app_group
 * Interact with the Sophos Mobile API /mobile/v1
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

// Field names and enums follow the Sophos Mobile API spec (mobile-v1 1.0.13).
const ownershipTypeSchema = z.enum(["corporate", "employee"]);
const platformSchema = z.enum(["iOS", "macOS", "android", "chrome", "windows"]);
const logLevelSchema = z.enum(["error", "warn", "info", "debug", "trace"]);
const appSchema = z.object({
  name: z.string().describe("App name"),
  identifier: z.string().describe("App identifier (bundle ID or package name)"),
  link: z.string().optional().describe("Link to the app"),
});
const iosAutoEnrollmentSchema = z
  .object({
    enabled: z.boolean().describe("Assign this group to iOS devices that auto-enroll"),
    install_smc_app: z.boolean().optional().describe("Install the Sophos Mobile Control app through MDM during enrollment"),
  })
  .describe("iOS auto-enrollment settings for the group");

function toIosAutoEnrollment(
  value: { enabled: boolean; install_smc_app?: boolean } | undefined
): Record<string, unknown> | undefined {
  return value === undefined ? undefined : compact({ enabled: value.enabled, installSmcApp: value.install_smc_app });
}

/** The id of a {id, name} reference the API returns, if there is one. */
function idOf(value: unknown): string | undefined {
  const id = value && typeof value === "object" ? (value as { id?: unknown }).id : undefined;
  return typeof id === "string" ? id : undefined;
}

/** Drops undefined and null, so a value the API left empty is not sent back. */
function compact(object: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(object).filter(([, v]) => v !== undefined && v !== null));
}

export function registerMobileTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // =====================================================================
  // Auto-Enrollment
  // =====================================================================

  // --- Get Auto-Enrollment Settings ---
  server.registerTool(
    "sophos_get_mobile_auto_enrollment",
    {
      title: "Get Mobile Auto-Enrollment Settings",
      description: `Get the Intercept X for Mobile auto-enrollment settings.

Returns the device group, ownership type, Android and iOS policies and the
connection code. Sophos answers 404 ixmAutoEnrollmentNotConfigured when
auto-enrollment is not set up for the tenant.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Auto-enrollment configuration for the tenant.`,
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
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/settings/ixm-auto-enrollment"
      );
      return jsonResult(data);
    })
  );

  // --- Update Auto-Enrollment Settings ---
  server.registerTool(
    "sophos_update_mobile_auto_enrollment",
    {
      title: "Update Mobile Auto-Enrollment Settings",
      description: `Update the Intercept X for Mobile auto-enrollment settings.

Sophos replaces the whole setting on update (PUT), so the tool reads the
current setting first and sends it back with your changes: anything you leave
out keeps its value. rotate_connection_code true issues a new connection code,
and the old one stops working. Auto-enrollment must already be set up; Sophos
answers 404 ixmAutoEnrollmentNotConfigured otherwise.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - device_group_id (string, optional): Device group for auto-enrolled devices.
  - ownership_type (string, optional): "corporate" or "employee".
  - android_policy_id (string, optional): Android security policy ID.
  - ios_policy_id (string, optional): iOS security policy ID.
  - rotate_connection_code (boolean, optional): Issue a new connection code.

Returns:
  What was sent and the updated configuration.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        device_group_id: z.string().uuid().optional().describe("Device group for auto-enrolled devices"),
        ownership_type: ownershipTypeSchema.optional().describe("Ownership type of auto-enrolled devices"),
        android_policy_id: z.string().uuid().optional().describe("Android security policy ID"),
        ios_policy_id: z.string().uuid().optional().describe("iOS security policy ID"),
        rotate_connection_code: z.boolean().optional().describe("Issue a new connection code; the old one stops working"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({ tenant_id, device_group_id, ownership_type, android_policy_id, ios_policy_id, rotate_connection_code }) => {
        const tenantId = tenantResolver.resolveTenantId(tenant_id);
        const path = "/mobile/v1/settings/ixm-auto-enrollment";
        const current = await client.tenantRequest<Record<string, unknown>>(tenantId, path);
        const body = compact({
          deviceGroupId: device_group_id ?? idOf(current.deviceGroup),
          ownershipType: ownership_type ?? current.ownershipType,
          androidPolicyId: android_policy_id ?? idOf(current.androidPolicy),
          iosPolicyId: ios_policy_id ?? idOf(current.iosPolicy),
          rotateConnectionCode: rotate_connection_code,
        });
        const data = await client.tenantRequest<Record<string, unknown>>(tenantId, path, { method: "PUT", body });
        return jsonResult({ status: "updated", sent: body, settings: data });
      }
    )
  );

  // =====================================================================
  // Operating Systems
  // =====================================================================

  // --- List Operating Systems ---
  server.registerTool(
    "sophos_list_mobile_os",
    {
      title: "List Mobile Operating Systems",
      description: `List supported mobile operating systems in Sophos Mobile.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  List of supported mobile operating systems.`,
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
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/operating-systems"
      );
      return jsonResult(data);
    })
  );

  // =====================================================================
  // Devices CRUD
  // =====================================================================

  // --- List Mobile Devices ---
  server.registerTool(
    "sophos_list_mobile_devices",
    {
      title: "List Mobile Devices",
      description: `List mobile devices managed by Sophos Mobile.

Supports filtering by search term, platform and compliance.
Uses page-based pagination.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - search (string, optional): Search term to filter devices.
  - platform (string, optional): "iOS", "macOS", "android", "chrome" or "windows".
  - compliant (boolean, optional): Only compliant (true) or non-compliant (false) devices.
  - page (number, optional): Page number (default 1).
  - page_size (number, optional): Results per page (1-100, default 50).

Returns:
  Paginated list of mobile devices.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        search: z
          .string()
          .optional()
          .describe("Search term to filter devices"),
        platform: platformSchema.optional().describe("Device platform"),
        compliant: z.boolean().optional().describe("Compliant (true) or non-compliant (false)"),
        page: z
          .number()
          .int()
          .min(1)
          .optional()
          .default(1)
          .describe("Page number (default 1)"),
        page_size: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results per page (default 50)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(
      async ({ tenant_id, search, platform, compliant, page, page_size }) => {
        const tenantId = tenantResolver.resolveTenantId(tenant_id);
        const params: Record<string, string> = {
          page: String(page),
          pageSize: String(page_size),
        };
        if (search) params.search = search;
        if (platform) params.platform = platform;
        if (compliant !== undefined) params.compliant = String(compliant);

        const data = await client.tenantRequest<Record<string, unknown>>(
          tenantId,
          "/mobile/v1/devices",
          { params }
        );
        return jsonResult(data);
      }
    )
  );

  // --- Get Mobile Device ---
  server.registerTool(
    "sophos_get_mobile_device",
    {
      title: "Get Mobile Device Detail",
      description: `Get full details of a specific mobile device by ID.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Complete device details (the API's full view) including OS, compliance,
  ownership, device group and enrollment status.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}`,
        { params: { view: "full" } }
      );
      return jsonResult(data);
    })
  );

  // --- Create Mobile Device ---
  server.registerTool(
    "sophos_create_mobile_device",
    {
      title: "Create Mobile Device",
      description: `Create a mobile device in Sophos Mobile.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string): Device name.
  - platform (string): "iOS", "macOS", "android", "chrome" or "windows".
  - ownership_type (string): "corporate" or "employee".
  - group_id (string, optional): Device group ID.
  - description (string, optional): Device description.
  - phone_number (string, optional): Phone number of the assigned user.
  - email (string, optional): Email address for the device when no user is assigned.
  - assigned_person_id (string, optional): ID of the user assigned to the device.
  - log_level (string, optional): "error", "warn", "info", "debug" or "trace".

Returns:
  The newly created device.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().describe("Device name"),
        platform: platformSchema.describe("Device platform"),
        ownership_type: ownershipTypeSchema.describe("Ownership type"),
        group_id: z.string().uuid().optional().describe("Device group ID"),
        description: z.string().optional().describe("Device description"),
        phone_number: z.string().optional().describe("Phone number of the assigned user"),
        email: z.string().optional().describe("Email address for the device when no user is assigned"),
        assigned_person_id: z.string().uuid().optional().describe("ID of the user assigned to the device"),
        log_level: logLevelSchema.optional().describe("Sophos Mobile app log level"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, ...args }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body = compact({
        name: args.name,
        platform: args.platform,
        ownershipType: args.ownership_type,
        groupId: args.group_id,
        description: args.description,
        phoneNumber: args.phone_number,
        email: args.email,
        assignedPersonId: args.assigned_person_id,
        logLevel: args.log_level,
      });
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/devices",
        { method: "POST", body }
      );
      return jsonResult(data);
    })
  );

  // --- Update Mobile Device ---
  server.registerTool(
    "sophos_update_mobile_device",
    {
      title: "Update Mobile Device",
      description: `Update a mobile device in Sophos Mobile.

Sophos replaces the whole device record on update (PUT, with name, ownership
type and group required), so the tool reads the device first (full view) and
sends it back with your changes: fields you leave out keep their values.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string, optional): New device name.
  - group_id (string, optional): Device group ID to move it to.
  - ownership_type (string, optional): "corporate" or "employee".
  - description (string, optional): Device description.
  - phone_number (string, optional): Phone number of the assigned user.
  - email (string, optional): Email address for the device when no user is assigned.
  - assigned_person_id (string, optional): ID of the user assigned to the device.
  - log_level (string, optional): "error", "warn", "info", "debug" or "trace".

Returns:
  What was sent and the updated device record.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().optional().describe("New device name"),
        group_id: z.string().uuid().optional().describe("Device group ID to move it to"),
        ownership_type: ownershipTypeSchema.optional().describe("Ownership type"),
        description: z.string().optional().describe("Device description"),
        phone_number: z.string().optional().describe("Phone number of the assigned user"),
        email: z.string().optional().describe("Email address for the device when no user is assigned"),
        assigned_person_id: z.string().uuid().optional().describe("ID of the user assigned to the device"),
        log_level: logLevelSchema.optional().describe("Sophos Mobile app log level"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ device_id, tenant_id, ...args }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const path = `/mobile/v1/devices/${device_id}`;
      const current = await client.tenantRequest<Record<string, unknown>>(tenantId, path, {
        params: { view: "full" },
      });
      const assignedPersonId = args.assigned_person_id ?? idOf(current.assignedPerson);
      const body = compact({
        name: args.name ?? current.name,
        description: args.description ?? current.description,
        phoneNumber: args.phone_number ?? current.phoneNumber,
        // email is for a device with no assigned user, so the stored one is kept only then
        email: args.email ?? (assignedPersonId ? undefined : current.email),
        assignedPersonId,
        ownershipType: args.ownership_type ?? current.ownershipType,
        logLevel: args.log_level ?? current.logLevel,
        groupId: args.group_id ?? idOf(current.deviceGroup),
      });
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, path, { method: "PUT", body });
      return jsonResult({ status: "updated", sent: body, device: data });
    })
  );

  // --- Delete Mobile Device ---
  server.registerTool(
    "sophos_delete_mobile_device",
    {
      title: "Delete Mobile Device",
      description: `Delete (unenroll) a mobile device from Sophos Mobile.

This permanently removes the device from management.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation of deletion.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID to delete"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}`,
        { method: "DELETE" }
      );
      return jsonResult(data ?? { deleted: true });
    })
  );

  // --- List Mobile Device Properties ---
  server.registerTool(
    "sophos_list_mobile_device_properties",
    {
      title: "Get Mobile Device Properties",
      description: `Get the properties of a specific mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Device property key-value pairs.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}/properties`
      );
      return jsonResult(data);
    })
  );

  // =====================================================================
  // Device Details
  // =====================================================================

  // --- Get Device Compliance ---
  server.registerTool(
    "sophos_get_mobile_device_compliance",
    {
      title: "Get Mobile Device Compliance",
      description: `Get the compliance status of a specific mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Compliance status and any violations.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}/compliance-violations`
      );
      return jsonResult(data);
    })
  );

  // --- Get Device Scans ---
  server.registerTool(
    "sophos_get_mobile_device_scans",
    {
      title: "Get Mobile Device Scans",
      description: `Get scan results for a specific mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Scan history and results.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}/scan-results`
      );
      return jsonResult(data);
    })
  );

  // --- Get Device Policies ---
  server.registerTool(
    "sophos_get_mobile_device_policies",
    {
      title: "Get Mobile Device Policies",
      description: `Get policies assigned to a specific mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  List of policies assigned to the device.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}/policies`
      );
      return jsonResult(data);
    })
  );

  // --- Get Device Apps ---
  server.registerTool(
    "sophos_get_mobile_device_apps",
    {
      title: "Get Mobile Device Apps",
      description: `Get installed apps on a specific mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  List of installed applications.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}/installed-apps`
      );
      return jsonResult(data);
    })
  );

  // =====================================================================
  // Device Location
  // =====================================================================

  // --- Get Device Location ---
  server.registerTool(
    "sophos_get_mobile_device_location",
    {
      title: "Get Mobile Device Location",
      description: `Get the last known location of a specific mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Device location coordinates and timestamp.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/devices/${device_id}/location`
      );
      return jsonResult(data);
    })
  );

  // =====================================================================
  // Device Groups CRUD
  // =====================================================================

  // --- List Device Groups ---
  server.registerTool(
    "sophos_list_mobile_device_groups",
    {
      title: "List Mobile Device Groups",
      description: `List mobile device groups in Sophos Mobile.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - page (number, optional): Page number (default 1).
  - page_size (number, optional): Results per page (1-100, default 50).

Returns:
  Paginated list of device groups.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        page: z
          .number()
          .int()
          .min(1)
          .optional()
          .default(1)
          .describe("Page number (default 1)"),
        page_size: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results per page (default 50)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, page, page_size }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = {
        page: String(page),
        pageSize: String(page_size),
      };
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/device-groups",
        { params }
      );
      return jsonResult(data);
    })
  );

  // --- Get Device Group ---
  server.registerTool(
    "sophos_get_mobile_device_group",
    {
      title: "Get Mobile Device Group",
      description: `Get details of a specific mobile device group.

Returns the API's full view, including the employee and corporate compliance
policy IDs, which sophos_create_mobile_device_group needs.

Args:
  - group_id (string): The device group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Device group details including name, description, compliance policies and
  iOS auto-enrollment settings.`,
      inputSchema: {
        group_id: z.string().describe("Device group ID"),
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
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/device-groups/${group_id}`,
        { params: { view: "full" } }
      );
      return jsonResult(data);
    })
  );

  // --- Create Device Group ---
  server.registerTool(
    "sophos_create_mobile_device_group",
    {
      title: "Create Mobile Device Group",
      description: `Create a new mobile device group in Sophos Mobile.

Both compliance policy IDs are required. sophos_get_mobile_device_group shows
the ones an existing group uses.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string): Group name.
  - employee_compliance_policy_id (string): Compliance policy for devices the user owns.
  - corporate_compliance_policy_id (string): Compliance policy for devices the organization owns.
  - description (string, optional): Group description.
  - ios_auto_enrollment (object, optional): {enabled, install_smc_app}.

Returns:
  The newly created device group.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().describe("Group name"),
        employee_compliance_policy_id: z.string().uuid().describe("Compliance policy for devices the user owns"),
        corporate_compliance_policy_id: z.string().uuid().describe("Compliance policy for devices the organization owns"),
        description: z.string().optional().describe("Group description"),
        ios_auto_enrollment: iosAutoEnrollmentSchema.optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, ...args }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body = compact({
        name: args.name,
        description: args.description,
        employeeCompliancePolicyId: args.employee_compliance_policy_id,
        corporateCompliancePolicyId: args.corporate_compliance_policy_id,
        iosAutoEnrollment: toIosAutoEnrollment(args.ios_auto_enrollment),
      });
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/device-groups",
        { method: "POST", body }
      );
      return jsonResult(data);
    })
  );

  // --- Update Device Group ---
  server.registerTool(
    "sophos_update_mobile_device_group",
    {
      title: "Update Mobile Device Group",
      description: `Update a mobile device group in Sophos Mobile.

Sophos replaces the whole group on update (PUT, with name and both compliance
policy IDs required), so the tool reads the group first (full view) and sends
it back with your changes: fields you leave out keep their values.

Args:
  - group_id (string): The device group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string, optional): New group name.
  - description (string, optional): New group description.
  - employee_compliance_policy_id (string, optional): Compliance policy for devices the user owns.
  - corporate_compliance_policy_id (string, optional): Compliance policy for devices the organization owns.
  - ios_auto_enrollment (object, optional): {enabled, install_smc_app}.

Returns:
  What was sent and the updated device group.`,
      inputSchema: {
        group_id: z.string().describe("Device group ID"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().optional().describe("New group name"),
        description: z.string().optional().describe("New group description"),
        employee_compliance_policy_id: z.string().uuid().optional().describe("Compliance policy for devices the user owns"),
        corporate_compliance_policy_id: z.string().uuid().optional().describe("Compliance policy for devices the organization owns"),
        ios_auto_enrollment: iosAutoEnrollmentSchema.optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ group_id, tenant_id, ...args }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const path = `/mobile/v1/device-groups/${group_id}`;
      const current = await client.tenantRequest<Record<string, unknown>>(tenantId, path, {
        params: { view: "full" },
      });
      const storedIos = current.iosAutoEnrollment as { enabled?: boolean; installSmcApp?: boolean } | undefined;
      const body = compact({
        name: args.name ?? current.name,
        description: args.description ?? current.description,
        employeeCompliancePolicyId: args.employee_compliance_policy_id ?? idOf(current.employeeCompliancePolicy),
        corporateCompliancePolicyId: args.corporate_compliance_policy_id ?? idOf(current.corporateCompliancePolicy),
        iosAutoEnrollment:
          toIosAutoEnrollment(args.ios_auto_enrollment) ??
          (storedIos?.enabled === undefined ? undefined : compact({ enabled: storedIos.enabled, installSmcApp: storedIos.installSmcApp })),
      });
      const data = await client.tenantRequest<Record<string, unknown>>(tenantId, path, { method: "PUT", body });
      return jsonResult({ status: "updated", sent: body, group: data });
    })
  );

  // --- Delete Device Group ---
  server.registerTool(
    "sophos_delete_mobile_device_group",
    {
      title: "Delete Mobile Device Group",
      description: `Delete a mobile device group from Sophos Mobile.

Args:
  - group_id (string): The device group ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation of deletion.`,
      inputSchema: {
        group_id: z.string().describe("Device group ID to delete"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ group_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/device-groups/${group_id}`,
        { method: "DELETE" }
      );
      return jsonResult(data ?? { deleted: true });
    })
  );

  // =====================================================================
  // Device Actions
  // =====================================================================

  // --- Sync Device ---
  server.registerTool(
    "sophos_sync_mobile_device",
    {
      title: "Sync Mobile Device",
      description: `Trigger a sync on a mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation that sync was initiated.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/sync",
        { method: "POST", body: { endpoints: [device_id] } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // --- Request Device Logs ---
  server.registerTool(
    "sophos_request_mobile_device_logs",
    {
      title: "Request Mobile Device Logs",
      description: `Request logs from a mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation that log request was initiated.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/get-logs",
        { method: "POST", body: { endpoints: [device_id] } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // --- Scan Device ---
  server.registerTool(
    "sophos_scan_mobile_device",
    {
      title: "Scan Mobile Device",
      description: `Trigger a security scan on a mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation that scan was initiated.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
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
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/scan",
        { method: "POST", body: { endpoints: [device_id] } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // --- Unenroll Device ---
  server.registerTool(
    "sophos_unenroll_mobile_device",
    {
      title: "Unenroll Mobile Device",
      description: `Unenroll a mobile device from Sophos Mobile management.

This removes the device from active management.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation that unenroll was initiated.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ device_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/unenroll",
        { method: "POST", body: { endpoints: [device_id] } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // --- Send Message to Device ---
  server.registerTool(
    "sophos_send_mobile_device_message",
    {
      title: "Send Message to Mobile Device",
      description: `Send a message to a mobile device.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - message (string): The message text (up to 500 characters).

Returns:
  Confirmation that message was sent.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        message: z.string().max(500).describe("Message text to send to the device"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ device_id, tenant_id, message }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/send-message",
        { method: "POST", body: { endpoints: [device_id], arguments: { message } } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // --- Locate Device ---
  server.registerTool(
    "sophos_locate_mobile_device",
    {
      title: "Locate Mobile Device",
      description: `Request a location update from a mobile device.

This triggers the device to report its current location.
Use sophos_get_mobile_device_location to retrieve the result.

Args:
  - device_id (string): The mobile device ID.
  - reason (string): Why the device is being located; Sophos Mobile writes it to its
    privacy log (up to 255 characters).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation that locate request was sent.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
        reason: z.string().max(255).describe("Why the device is being located (privacy log)"),
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
    withErrorHandling(async ({ device_id, reason, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/locate",
        { method: "POST", body: { endpoints: [device_id], arguments: { reason } } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // --- Lock Device ---
  server.registerTool(
    "sophos_lock_mobile_device",
    {
      title: "Lock Mobile Device",
      description: `Remotely lock a mobile device.

This sends a lock command to the device, preventing access until unlocked.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - message (string, optional): Lock screen message (Android and iOS, up to 500 characters).
  - pin (string, optional): Six-digit lock code; required for Macs only.
  - phone_number (string, optional): Phone number shown on a locked iPhone.

Returns:
  Confirmation that lock command was sent.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        message: z.string().max(500).optional().describe("Lock screen message (Android and iOS)"),
        pin: z.string().regex(/^[0-9]{6}$/, "Six digits").optional().describe("Six-digit lock code (Macs)"),
        phone_number: z.string().max(50).regex(/^\+?\d*$/, "Digits with an optional leading +").optional().describe("Phone number shown on a locked iPhone"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ device_id, tenant_id, message, pin, phone_number }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const args: Record<string, unknown> = {};
      if (message !== undefined) args.lockScreenMessage = message;
      if (pin !== undefined) args.lockCode = pin;
      if (phone_number !== undefined) args.phoneNumber = phone_number;

      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/lock",
        { method: "POST", body: { endpoints: [device_id], arguments: args } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // --- Wipe Device ---
  server.registerTool(
    "sophos_wipe_mobile_device",
    {
      title: "Wipe Mobile Device",
      description: `Remotely wipe a mobile device.

WARNING: This will erase ALL data on the device. This action cannot be undone.
Use with extreme caution. The device will be factory-reset.

Args:
  - device_id (string): The mobile device ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - wipe_code (string, optional): Six-digit code; required for Macs only.
  - preserve_data_plan (boolean, optional): Keep data plans such as eSIM (iOS only).
  - disallow_proximity_setup (boolean, optional): Block proximity setup after the wipe (iOS only).

Returns:
  Confirmation that wipe command was sent.`,
      inputSchema: {
        device_id: z.string().describe("Mobile device ID"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        wipe_code: z.string().regex(/^[0-9]{6}$/, "Six digits").optional().describe("Six-digit wipe code (Macs)"),
        preserve_data_plan: z.boolean().optional().describe("Keep data plans such as eSIM (iOS)"),
        disallow_proximity_setup: z.boolean().optional().describe("Block proximity setup after the wipe (iOS)"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ device_id, tenant_id, wipe_code, preserve_data_plan, disallow_proximity_setup }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const args: Record<string, unknown> = {};
      if (wipe_code !== undefined) args.wipeCode = wipe_code;
      if (preserve_data_plan !== undefined) args.preserveDataPlan = preserve_data_plan;
      if (disallow_proximity_setup !== undefined) args.disallowProximitySetup = disallow_proximity_setup;

      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/actions/wipe",
        { method: "POST", body: { endpoints: [device_id], arguments: args } }
      );
      return jsonResult(data ?? { actionInitiated: true });
    })
  );

  // =====================================================================
  // App Groups
  // =====================================================================

  // --- List App Groups ---
  server.registerTool(
    "sophos_list_mobile_app_groups",
    {
      title: "List Mobile App Groups",
      description: `List mobile app groups in Sophos Mobile.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - page (number, optional): Page number (default 1).
  - page_size (number, optional): Results per page (1-100, default 50).

Returns:
  Paginated list of app groups.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        page: z
          .number()
          .int()
          .min(1)
          .optional()
          .default(1)
          .describe("Page number (default 1)"),
        page_size: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results per page (default 50)"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, page, page_size }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const params: Record<string, string> = {
        page: String(page),
        pageSize: String(page_size),
      };
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/app-groups",
        { params }
      );
      return jsonResult(data);
    })
  );

  // --- Get App Group ---
  server.registerTool(
    "sophos_get_mobile_app_group",
    {
      title: "Get Mobile App Group",
      description: `Get details of a specific mobile app group, including its apps (the API's full view).

Args:
  - group_id (string): The app group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  App group details including name, type, and apps.`,
      inputSchema: {
        group_id: z.string().describe("App group ID"),
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
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/app-groups/${group_id}`,
        { params: { view: "full" } }
      );
      return jsonResult(data);
    })
  );

  // --- Create App Group ---
  server.registerTool(
    "sophos_create_mobile_app_group",
    {
      title: "Create Mobile App Group",
      description: `Create a new mobile app group in Sophos Mobile.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string): App group name.
  - platform (string): "iOS", "macOS", "android", "chrome" or "windows".
  - apps (array): Apps in the group, each {name, identifier, link?}.

Returns:
  The newly created app group.`,
      inputSchema: {
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().describe("App group name"),
        platform: platformSchema.describe("Device platform the group is for"),
        apps: z.array(appSchema).describe("Apps in the group"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, name, platform, apps }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        "/mobile/v1/app-groups",
        { method: "POST", body: { name, platform, apps } }
      );
      return jsonResult(data);
    })
  );

  // --- Update App Group ---
  server.registerTool(
    "sophos_update_mobile_app_group",
    {
      title: "Update Mobile App Group",
      description: `Update a mobile app group's name or apps in Sophos Mobile (PATCH).

Fields you leave out keep their values. apps replaces the group's whole app
list, so include every app that should stay. The platform cannot be changed.

Args:
  - group_id (string): The app group ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string, optional): New app group name.
  - apps (array, optional): The complete new app list, each {name, identifier, link?}.

Returns:
  The updated app group.`,
      inputSchema: {
        group_id: z.string().describe("App group ID"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
        name: z.string().optional().describe("New app group name"),
        apps: z.array(appSchema).optional().describe("The complete new app list"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ group_id, tenant_id, name, apps }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const body = compact({ name, apps });
      if (Object.keys(body).length === 0) {
        throw new Error("Pass name, apps or both. Nothing was sent.");
      }
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/app-groups/${group_id}`,
        { method: "PATCH", body }
      );
      return jsonResult(data);
    })
  );

  // --- Delete App Group ---
  server.registerTool(
    "sophos_delete_mobile_app_group",
    {
      title: "Delete Mobile App Group",
      description: `Delete a mobile app group from Sophos Mobile.

Args:
  - group_id (string): The app group ID to delete.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Confirmation of deletion.`,
      inputSchema: {
        group_id: z.string().describe("App group ID to delete"),
        tenant_id: z
          .string()
          .uuid()
          .optional()
          .describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ group_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        tenantId,
        `/mobile/v1/app-groups/${group_id}`,
        { method: "DELETE" }
      );
      return jsonResult(data ?? { deleted: true });
    })
  );

}
