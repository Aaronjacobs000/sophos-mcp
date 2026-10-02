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
  /** Address the HTTP transport binds to. 127.0.0.1 unless MCP_HTTP_HOST says otherwise. */
  httpHost: string;
  /** When set, every /mcp request must send it as a bearer token. */
  httpToken?: string;
  /** Browser origins allowed besides loopback ones, from MCP_ALLOWED_ORIGINS. */
  allowedOrigins: string[];
}

export function loadConfig(): SophosConfig {
  const clientId = process.env.SOPHOS_CLIENT_ID;
  const clientSecret = process.env.SOPHOS_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error(
      "Missing required environment variables: SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET must be set."
    );
  }

  checkFusionGraphQLUrl(SOPHOS_FUSION_GRAPHQL_URL);

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
    httpHost: process.env.MCP_HTTP_HOST || "127.0.0.1",
    httpToken: process.env.MCP_HTTP_TOKEN || undefined,
    allowedOrigins: parseAllowedOrigins(process.env.MCP_ALLOWED_ORIGINS),
  };
}

/**
 * MCP_ALLOWED_ORIGINS is a comma separated list of browser origins, such as
 * "https://inspector.example.com,http://10.0.0.5:6274". Each entry is reduced
 * to its origin (scheme, host and port) so it compares equal to the Origin
 * header a browser sends.
 */
export function parseAllowedOrigins(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "")
    .map((entry) => {
      let url: URL;
      try {
        url = new URL(entry);
      } catch {
        throw new Error(`Invalid MCP_ALLOWED_ORIGINS entry "${entry}": not a URL such as https://host:port.`);
      }
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new Error(`Invalid MCP_ALLOWED_ORIGINS entry "${entry}": it must be an http or https origin.`);
      }
      return url.origin;
    });
}

// Sophos Central global API endpoints
export const SOPHOS_AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token";
export const SOPHOS_GLOBAL_API = "https://api.central.sophos.com";

// Sophos Fusion GraphQL endpoint. One host for every tenant, no regional
// lookup. The env override exists so the Fusion branded hostnames expected in
// November 2026 need no code change.
export const SOPHOS_FUSION_GRAPHQL_URL =
  process.env.SOPHOS_FUSION_GRAPHQL_URL || "https://api.taegis.sophos.com/graphql";

/**
 * The bearer token is sent to SOPHOS_FUSION_GRAPHQL_URL, and dotenv fills that
 * from a .env in the working directory, which for a stdio server is whatever
 * directory the client was started in (a cloned repo, say). So the override
 * must be an https URL on a sophos.com host, or the server refuses to start.
 */
export function checkFusionGraphQLUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid SOPHOS_FUSION_GRAPHQL_URL "${value}": not a URL.`);
  }
  const host = url.hostname;
  if (url.protocol !== "https:" || (host !== "sophos.com" && !host.endsWith(".sophos.com"))) {
    throw new Error(
      `Invalid SOPHOS_FUSION_GRAPHQL_URL "${value}": it must be an https URL on a sophos.com host, because the Sophos bearer token is sent to it.`
    );
  }
  return value;
}

// Response size limits (CHARACTER_LIMIT configurable via env var)
export const CHARACTER_LIMIT = Math.max(
  10000,
  parseInt(process.env.CHARACTER_LIMIT || "50000", 10) || 50000
);
export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 100;

// Migration awareness for the Classic Cases and Detections REST tools. A
// tenant that has moved to Sophos Fusion is refused on those tools and pointed
// at the sophos_fusion_* equivalent, because for such a tenant the Classic
// APIs answer from the pre-migration Sophos Central objects. Set
// SOPHOS_CLASSIC_MIGRATION_CHECK=off to skip the check.
export const CLASSIC_MIGRATION_CHECK =
  (process.env.SOPHOS_CLASSIC_MIGRATION_CHECK || "on").toLowerCase() !== "off";
