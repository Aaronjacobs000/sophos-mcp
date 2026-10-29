/**
 * Tools: sophos_list_access_tokens, sophos_create_access_token,
 *        sophos_update_access_token, sophos_revoke_access_token
 * Interact with the Sophos Accounts API /accounts/v1/ (global host).
 * Manages repository access tokens (e.g. for the Sophos Linux Sensor).
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";
import { DEFAULT_PAGE_SIZE } from "../config/config.js";

export function registerAccountsTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  // --- List Access Tokens ---
  server.registerTool(
    "sophos_list_access_tokens",
    {
      title: "List Sophos Access Tokens",
      description: `List a tenant's repository access tokens (e.g. Sophos Linux Sensor package tokens).

Args:
  - limit (number, optional): Max results per page (1-100, default 50).
  - page (number, optional): Page number (default 1).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
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
    withErrorHandling(async ({ limit, page, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.globalRequest<Record<string, unknown>>(
        "/accounts/v1/access-tokens",
        {
          params: { pageSize: String(limit), page: String(page), pageTotal: "true" },
          headers: { "X-Tenant-ID": resolvedTenantId },
        }
      );
      return jsonResult(data);
    })
  );

  // --- Create Access Token ---
  server.registerTool(
    "sophos_create_access_token",
    {
      title: "Create Sophos Access Token",
      description: `Create a repository access token for a tenant.

Args:
  - label (string): Human-readable token label.
  - type (string): Token type. Only "sophosLinuxSensor" is supported.
  - expires_at (string, optional): Expiry (ISO 8601 datetime).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        label: z.string().describe("Human-readable token label"),
        type: z
          .enum(["sophosLinuxSensor"])
          .describe("Token type (only sophosLinuxSensor is supported)"),
        expires_at: z.string().optional().describe("Expiry (ISO 8601 datetime)"),
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
    withErrorHandling(async ({ label, type, expires_at, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = { label, type };
      if (expires_at) body.expiresAt = expires_at;

      const data = await client.globalRequest<Record<string, unknown>>(
        "/accounts/v1/access-tokens",
        { method: "POST", body, headers: { "X-Tenant-ID": resolvedTenantId } }
      );
      return jsonResult({ status: "created", token: data });
    })
  );

  // --- Update Access Token ---
  server.registerTool(
    "sophos_update_access_token",
    {
      title: "Update Sophos Access Token",
      description: `Update a repository access token's label or expiry.

Args:
  - token_id (string): The token ID.
  - label (string, optional): New label.
  - expires_at (string, optional): New expiry (ISO 8601 datetime).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        token_id: z.string().describe("Token ID"),
        label: z.string().optional().describe("New label"),
        expires_at: z.string().optional().describe("New expiry (ISO 8601 datetime)"),
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
    withErrorHandling(async ({ token_id, label, expires_at, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const body: Record<string, unknown> = {};
      if (label !== undefined) body.label = label;
      if (expires_at !== undefined) body.expiresAt = expires_at;

      if (Object.keys(body).length === 0) {
        return jsonResult({
          error: "No fields to update. Provide at least one of: label, expires_at.",
        });
      }

      const data = await client.globalRequest<Record<string, unknown>>(
        `/accounts/v1/access-tokens/${token_id}`,
        { method: "PATCH", body, headers: { "X-Tenant-ID": resolvedTenantId } }
      );
      return jsonResult({ status: "updated", token: data });
    })
  );

  // --- Revoke Access Token ---
  server.registerTool(
    "sophos_revoke_access_token",
    {
      title: "Revoke Sophos Access Token",
      description: `Revoke a repository access token.

WARNING: Systems using this token lose repository access.

Args:
  - token_id (string): The token ID to revoke.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.`,
      inputSchema: {
        token_id: z.string().describe("Token ID to revoke"),
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
    withErrorHandling(async ({ token_id, tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      await client.globalRequest(`/accounts/v1/access-tokens/${token_id}`, {
        method: "DELETE",
        headers: { "X-Tenant-ID": resolvedTenantId },
      });
      return jsonResult({ status: "revoked", token_id });
    })
  );
}
