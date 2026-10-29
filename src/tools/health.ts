/**
 * Tools: sophos_get_account_health, sophos_list_account_health, sophos_partner_gap_analysis
 * Interact with the Sophos Account Health Check API /account-health-check/v1/health-check
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { jsonResult, withErrorHandling } from "./helpers.js";

const HEALTH_PATH = "/account-health-check/v1/health-check";
const CONCURRENCY = 10;

/**
 * Extracts the minimum overall score from a health check response.
 * Checks both endpoint and server protection globalDetail scores.
 * Returns null if no health data is available.
 */
function extractOverallScore(data: Record<string, unknown> | null): number | null {
  if (!data) return null;
  const scores: number[] = [];
  // Health response structure: data.endpoint.protection.computer.score / .server.score
  const endpoint = data["endpoint"] as Record<string, unknown> | undefined;
  const protection = endpoint?.["protection"] as Record<string, unknown> | undefined;
  for (const deviceType of ["computer", "server"]) {
    const deviceProtection = protection?.[deviceType] as Record<string, unknown> | undefined;
    if (typeof deviceProtection?.["score"] === "number") {
      scores.push(deviceProtection["score"] as number);
    }
  }
  return scores.length > 0 ? Math.min(...scores) : null;
}

/**
 * Extracts a score from a health section for a specific device type.
 * Returns null if the section or device data is absent.
 */
function extractDeviceScore(
  section: Record<string, unknown> | undefined,
  deviceType: string
): number | null {
  if (!section) return null;
  const device = section[deviceType] as Record<string, unknown> | undefined;
  if (typeof device?.["score"] === "number") return device["score"] as number;
  return null;
}

type GapItem = {
  type: string;
  detail: string;
  score?: number;
};

/**
 * Analyses a health check response and returns a list of gaps/opportunities.
 */
function analyseGaps(
  data: Record<string, unknown> | null,
  threshold: number,
  flagMissingServerProtection: boolean
): GapItem[] {
  if (!data) {
    return [
      {
        type: "no_products_enrolled",
        detail: "No health data — no Sophos products enrolled or no endpoints reporting",
      },
    ];
  }

  const gaps: GapItem[] = [];
  const endpoint = data["endpoint"] as Record<string, unknown> | undefined;
  const protection = endpoint?.["protection"] as Record<string, unknown> | undefined;
  const tamperProtection = endpoint?.["tamperProtection"] as Record<string, unknown> | undefined;
  const policy = endpoint?.["policy"] as Record<string, unknown> | undefined;

  // Computer protection score
  const computerScore = extractDeviceScore(protection, "computer");
  if (computerScore !== null && computerScore < threshold) {
    gaps.push({
      type: "low_computer_protection",
      detail: `Computer protection at ${computerScore}% (below ${threshold}% threshold)`,
      score: computerScore,
    });
  }

  // Server protection — absent means not enrolled
  const serverProtectionPresent =
    protection?.["server"] !== undefined && protection?.["server"] !== null;
  if (!serverProtectionPresent) {
    if (flagMissingServerProtection) {
      gaps.push({
        type: "no_server_protection",
        detail: "Server protection not enrolled — potential upsell for Sophos Server Protection",
      });
    }
  } else {
    const serverScore = extractDeviceScore(protection, "server");
    if (serverScore !== null && serverScore < threshold) {
      gaps.push({
        type: "low_server_protection",
        detail: `Server protection at ${serverScore}% (below ${threshold}% threshold)`,
        score: serverScore,
      });
    }
  }

  // Tamper protection — computers
  const computerTamperScore = extractDeviceScore(tamperProtection, "computer");
  if (computerTamperScore !== null && computerTamperScore < 100) {
    gaps.push({
      type: "tamper_protection_partial",
      detail: `Tamper protection enabled on only ${computerTamperScore}% of computers`,
      score: computerTamperScore,
    });
  }

  // Tamper protection — servers
  const serverTamperScore = extractDeviceScore(tamperProtection, "server");
  if (serverTamperScore !== null && serverTamperScore < 100) {
    gaps.push({
      type: "tamper_protection_partial_servers",
      detail: `Tamper protection enabled on only ${serverTamperScore}% of servers`,
      score: serverTamperScore,
    });
  }

  // Policy compliance — computers
  const computerPolicyScore = extractDeviceScore(policy, "computer");
  if (computerPolicyScore !== null && computerPolicyScore < 100) {
    gaps.push({
      type: "policy_non_compliance",
      detail: `Computer policy compliance at ${computerPolicyScore}%`,
      score: computerPolicyScore,
    });
  }

  // Policy compliance — servers
  const serverPolicyScore = extractDeviceScore(policy, "server");
  if (serverPolicyScore !== null && serverPolicyScore < 100) {
    gaps.push({
      type: "policy_non_compliance_servers",
      detail: `Server policy compliance at ${serverPolicyScore}%`,
      score: serverPolicyScore,
    });
  }

  return gaps;
}

export function registerHealthTools(
  server: McpServer,
  client: SophosClient,
  tenantResolver: TenantResolver
): void {
  server.registerTool(
    "sophos_get_account_health",
    {
      title: "Get Sophos Account Health",
      description: `Get the account health check scores for a single Sophos Central tenant.

Returns protection percentages and status for endpoints and servers,
including policy compliance, exclusion health, and tamper protection status.

For partner/org callers who need to compare health across multiple tenants,
use sophos_list_account_health instead — it fetches all tenants in parallel.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Health check object with endpoint/server protection scores and status.`,
      inputSchema: {
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
    withErrorHandling(async ({ tenant_id }) => {
      const resolvedTenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await client.tenantRequest<Record<string, unknown>>(
        resolvedTenantId,
        HEALTH_PATH
      );
      return jsonResult(data);
    })
  );

  // Bulk tools: only useful for partner/org callers who manage multiple tenants
  if (tenantResolver.getIdentity().idType !== "tenant") {
    server.registerTool(
      "sophos_list_account_health",
      {
        title: "List Account Health for All Tenants",
        description: `Fetch account health scores for all managed tenants in parallel and return a ranked summary.

Use this when you need to compare health across tenants or find tenants with the lowest
scores. Much faster than calling sophos_get_account_health per tenant — fetches all
tenants concurrently server-side in a single tool call.

Results are sorted by overall score ascending (lowest/worst first).
Tenants with no health data (no enrolled products) are listed last.

Args:
  - limit (number, optional): Return only the N lowest-scoring tenants. Useful for
    "show me the 10 worst tenants". Omit to return all tenants.

Returns:
  Array of tenants with their health scores and full health detail, sorted worst-first.`,
        inputSchema: {
          limit: z
            .number()
            .int()
            .min(1)
            .max(500)
            .optional()
            .describe("Return only the N lowest-scoring tenants (default: all)."),
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
      },
      withErrorHandling(async ({ limit }) => {
        const tenants = tenantResolver.getCachedTenants();

        // Fetch health for all tenants in parallel batches
        type HealthEntry = {
          tenant_id: string;
          tenant_name: string;
          overall_score: number | null;
          health: Record<string, unknown> | null;
        };

        const results: HealthEntry[] = [];

        for (let i = 0; i < tenants.length; i += CONCURRENCY) {
          const batch = tenants.slice(i, i + CONCURRENCY);
          const batchResults = await Promise.all(
            batch.map(async (tenant) => {
              try {
                const data = await client.tenantRequest<Record<string, unknown>>(
                  tenant.id,
                  HEALTH_PATH
                );
                return {
                  tenant_id: tenant.id,
                  tenant_name: tenant.name,
                  overall_score: extractOverallScore(data),
                  health: data,
                };
              } catch {
                return {
                  tenant_id: tenant.id,
                  tenant_name: tenant.name,
                  overall_score: null,
                  health: null,
                };
              }
            })
          );
          results.push(...batchResults);
        }

        // Sort: lowest score first, null (no data) last
        results.sort((a, b) => {
          if (a.overall_score === null && b.overall_score === null) return 0;
          if (a.overall_score === null) return 1;
          if (b.overall_score === null) return -1;
          return a.overall_score - b.overall_score;
        });

        const limited = limit !== undefined ? results.slice(0, limit) : results;

        return jsonResult({
          total_tenants: tenants.length,
          returned: limited.length,
          tenants: limited,
        });
      })
    );

    server.registerTool(
      "sophos_partner_gap_analysis",
      {
        title: "Partner Gap Analysis — Sales Opportunities",
        description: `Identify security gaps and upsell opportunities across all managed tenants in a single call.

Fetches account health for every tenant in parallel and distils the results into a compact,
actionable list of gaps per tenant — designed for partner sales and advisory conversations.

Gaps detected:
  - no_products_enrolled: tenant has no Sophos products or no endpoints reporting
  - low_computer_protection: computer protection score below threshold
  - low_server_protection: server protection score below threshold
  - tamper_protection_partial: tamper protection not enabled on all computers/servers
  - policy_non_compliance: policy compliance below 100%
  - no_server_protection: server protection not enrolled (only if flag_missing_server_protection=true)

Results are sorted by gap count descending (most opportunities first).
Includes a summary breakdown of gap types across the estate.

Args:
  - protection_threshold (number, optional): Minimum acceptable protection score %. Default: 80.
  - flag_missing_server_protection (boolean, optional): Flag tenants with no server protection
    enrolled as an upsell opportunity. Default: false (avoids noise for SMB-heavy partners).
  - limit (number, optional): Return only the top N tenants (by gap count). Omit for all.

Returns:
  summary with gap type counts + per-tenant gap list sorted worst-first.`,
        inputSchema: {
          protection_threshold: z
            .number()
            .int()
            .min(1)
            .max(100)
            .optional()
            .describe("Minimum acceptable protection score % (default: 80)."),
          flag_missing_server_protection: z
            .boolean()
            .optional()
            .describe(
              "Include tenants with no server protection enrolled as a gap (default: false)."
            ),
          limit: z
            .number()
            .int()
            .min(1)
            .max(500)
            .optional()
            .describe("Return only the top N tenants by gap count (default: all)."),
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
      },
      withErrorHandling(
        async ({ protection_threshold, flag_missing_server_protection, limit }) => {
          const threshold = protection_threshold ?? 80;
          const flagServerGap = flag_missing_server_protection ?? false;
          const tenants = tenantResolver.getCachedTenants();

          type TenantGapResult = {
            tenant_id: string;
            tenant_name: string;
            gap_count: number;
            gaps: GapItem[];
            error?: string;
          };

          const allResults: TenantGapResult[] = [];

          for (let i = 0; i < tenants.length; i += CONCURRENCY) {
            const batch = tenants.slice(i, i + CONCURRENCY);
            const batchResults = await Promise.all(
              batch.map(async (tenant) => {
                try {
                  const data = await client.tenantRequest<Record<string, unknown>>(
                    tenant.id,
                    HEALTH_PATH
                  );
                  const gaps = analyseGaps(data, threshold, flagServerGap);
                  return {
                    tenant_id: tenant.id,
                    tenant_name: tenant.name,
                    gap_count: gaps.length,
                    gaps,
                  };
                } catch {
                  return {
                    tenant_id: tenant.id,
                    tenant_name: tenant.name,
                    gap_count: 0,
                    gaps: [],
                    error: "Failed to retrieve health data",
                  };
                }
              })
            );
            allResults.push(...batchResults);
          }

          // Only include tenants that have at least one gap (or an error)
          const withGaps = allResults.filter((r) => r.gap_count > 0 || r.error);

          // Sort: most gaps first; ties broken by lowest gap score
          withGaps.sort((a, b) => b.gap_count - a.gap_count);

          const limited = limit !== undefined ? withGaps.slice(0, limit) : withGaps;

          // Aggregate gap type counts across all tenants
          const gapTypeCounts: Record<string, number> = {};
          for (const r of allResults) {
            for (const g of r.gaps) {
              gapTypeCounts[g.type] = (gapTypeCounts[g.type] ?? 0) + 1;
            }
          }
          const gapBreakdown = Object.entries(gapTypeCounts)
            .sort(([, a], [, b]) => b - a)
            .map(([type, count]) => ({ type, affected_tenants: count }));

          return jsonResult({
            summary: {
              total_tenants: tenants.length,
              tenants_with_gaps: withGaps.filter((r) => !r.error).length,
              tenants_with_errors: allResults.filter((r) => r.error).length,
              tenants_no_issues: allResults.filter(
                (r) => r.gap_count === 0 && !r.error
              ).length,
              protection_threshold_used: threshold,
              gap_type_breakdown: gapBreakdown,
            },
            tenants_with_gaps: limited,
          });
        }
      )
    );
  }
}
