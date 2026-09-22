/**
 * Tools: sophos_fusion_search_detections
 * Sophos Fusion Detections GraphQL API v2 on https://api.taegis.sophos.com/graphql.
 *
 * The Fusion side of the Classic run, poll, results detection tools in
 * detections.ts, which are refused for a tenant that has migrated to Fusion.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { FusionClient } from "../client/fusion-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../config/config.js";
import { formatDetection } from "../fusion/format.js";
import { DETECTION_SEARCH } from "../fusion/queries/detections.js";
import type { FusionDetectionSearchResponse } from "../fusion/types.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";

/** The query verified against a live tenant on 22/09/2026. */
export const DEFAULT_DETECTION_QUERY = "from alert severity >= 0.1 EARLIEST=-90d";

export function registerFusionDetectionTools(
  server: McpServer,
  client: FusionClient,
  tenantResolver: TenantResolver
): void {
  server.registerTool(
    "sophos_fusion_search_detections",
    {
      title: "Search Fusion Detections",
      description: `Search detections in Sophos Fusion with a Fusion Query Language (QL) query. One call replaces the Classic run, poll, results triple (sophos_run_detections_query and friends), which are refused for a tenant that has migrated to Fusion.

The QL source keyword is alert. Working example: "from alert severity >= 0.1 EARLIEST=-90d". Detection severity is a 0 to 1 float; it is not the Classic REST 0 to 10 scale and not the case 2 to 10 scale, so never convert between them. Detection IDs are six section resource names like alert://priv:event-filter:123456:1789526908712:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, and are exactly what sophos_fusion_add_case_evidence and sophos_fusion_create_case take as detection_ids.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - query (string, optional): QL query. Default "${DEFAULT_DETECTION_QUERY}".
  - limit (number, optional, 1-100, default 50) and offset (number, optional, default 0).
  - search_id (string, optional): Continuation handle the API returns for large result sets; pass it back with the next offset.

Returns:
  status, total_results, next_offset, search_id, and detections (id, title, severity_0_to_1, confidence, status, detector, entities, event_count, MITRE technique IDs, timestamps).`,
      inputSchema: {
        tenant_id: z.string().uuid().optional().describe("Tenant ID. Required for partner/org callers."),
        query: z.string().optional().default(DEFAULT_DETECTION_QUERY).describe("QL query, source keyword alert"),
        limit: z
          .number()
          .int()
          .min(1)
          .max(MAX_PAGE_SIZE)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results to return (max 100)"),
        offset: z.number().int().min(0).optional().default(0).describe("Result offset"),
        search_id: z.string().optional().describe("Continuation handle from a previous search"),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ tenant_id, query, limit, offset, search_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const input: Record<string, unknown> = { cql_query: query, limit, offset };
      if (search_id) input.search_id = search_id;

      const { data, warnings } = await client.query<FusionDetectionSearchResponse>(
        tenantId,
        DETECTION_SEARCH,
        { in: input }
      );
      const result = data.detectionSearch;
      if (!result) {
        throw new Error("detectionSearch returned no result.");
      }
      const list = result.alerts?.list ?? [];
      return jsonResult(
        withWarnings(
          {
            tenant_id: tenantId,
            ql_query: query,
            status: result.status ?? null,
            reason: result.reason ?? null,
            total_results: result.alerts?.total_results ?? null,
            returned: list.length,
            offset,
            next_offset: result.alerts?.next_offset ?? null,
            search_id: result.search_id ?? null,
            detections: list.map((record) => formatDetection(record)),
          },
          warnings
        )
      );
    })
  );
}
