/**
 * Environment-based configuration for Sophos Central MCP Server.
 * Credentials are read from environment variables only.
 */

export interface SophosConfig {
  clientId: string;
  clientSecret: string;
  tenantId?: string;
  port: number;
  transport: "http" | "stdio";
}

export function loadConfig(): SophosConfig {
  const clientId = process.env.SOPHOS_CLIENT_ID;
  const clientSecret = process.env.SOPHOS_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error(
      "Missing required environment variables: SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET must be set."
    );
  }

  const rawPort = parseInt(process.env.PORT || "3100", 10);
  if (!Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
    throw new Error(
      `Invalid PORT value "${process.env.PORT}". Must be an integer between 1 and 65535.`
    );
  }

  return {
    clientId,
    clientSecret,
    tenantId: process.env.SOPHOS_TENANT_ID || undefined,
    port: rawPort,
    transport: (process.env.TRANSPORT as "http" | "stdio") || "http",
  };
}

// Sophos Central global API endpoints
export const SOPHOS_AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token";
export const SOPHOS_GLOBAL_API = "https://api.central.sophos.com";

// Sophos Fusion GraphQL endpoint. One host for every tenant, no regional
// lookup. The env override exists so the Fusion branded hostnames expected in
// November 2026 need no code change.
export const SOPHOS_FUSION_GRAPHQL_URL =
  process.env.SOPHOS_FUSION_GRAPHQL_URL || "https://api.taegis.sophos.com/graphql";

// Response size limits (CHARACTER_LIMIT configurable via env var)
export const CHARACTER_LIMIT = Math.max(
  10000,
  parseInt(process.env.CHARACTER_LIMIT || "50000", 10) || 50000
);
export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 100;
