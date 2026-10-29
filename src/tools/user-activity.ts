/**
 * Tools: sophos_create_attestation, sophos_get_attestation
 * Interact with the Sophos User Activity Verification API /user-activity-verification/v1/
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";

export function registerUserActivityTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- Create Attestation ---
  server.registerTool(
    "sophos_create_attestation",
    {
      title: "Create User Attestation",
      description: `Ask a user to attest to something through Intercept X for Mobile (User Activity Verification API).

The user sees the title and question in the app and picks an answer; read the
result with sophos_get_attestation. Without options the answers are yes and no.

Args:
  - user_id (string): The user to ask.
  - title (string): Title shown to the user (up to 100 characters).
  - question (string): The question (up to 500 characters).
  - options (array, optional): Up to 5 answers, each {key, text, action?}. key is
    returned when chosen; action is a URI the app opens.
  - reference (string, optional): Your own reference, returned with the attestation.
  - timeout_in_seconds (number, optional): Expiry, 60 to 86400 seconds.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        user_id: z.string().guid().describe("User ID"),
        title: z.string().max(100).describe("Title shown to the user"),
        question: z.string().max(500).describe("The question"),
        options: z
          .array(
            z.object({
              key: z.string().max(36).describe("Returned when the user picks this answer"),
              text: z.string().max(100).describe("Answer text"),
              action: z.string().max(2048).optional().describe("URI the app opens for this answer"),
            })
          )
          .max(5)
          .optional()
          .describe("Up to 5 answers; yes and no when omitted"),
        reference: z.string().max(256).optional().describe("Your own reference"),
        timeout_in_seconds: z.number().int().min(60).max(86400).optional().describe("Expiry in seconds"),
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
    withErrorHandling(async ({ user_id, title, question, options, reference, timeout_in_seconds, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {
        userId: user_id,
        title: { text: title },
        question: { text: question },
      };
      if (options) {
        body.options = options.map((o) => ({
          key: o.key,
          value: { text: o.text },
          ...(o.action !== undefined ? { action: o.action } : {}),
        }));
      }
      if (reference !== undefined) body.reference = reference;
      if (timeout_in_seconds !== undefined) body.timeoutInSeconds = timeout_in_seconds;

      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        "/user-activity-verification/v1/attestations",
        { method: "POST", body }
      );
      return jsonResult({ status: "created", attestation: data });
    })
  );

  // --- Get Attestation ---
  server.registerTool(
    "sophos_get_attestation",
    {
      title: "Get Attestation Detail",
      description: `Get details of a specific user attestation.

Args:
  - attestation_id (string): The attestation ID.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        attestation_id: z.string().describe("Attestation ID"),
        tenant_id: z
          .string()
          .guid()
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
    withErrorHandling(async ({ attestation_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        `/user-activity-verification/v1/attestations/${attestation_id}`
      );
      return jsonResult(data);
    })
  );
}
