/**
 * Tools: sophos_fusion_list_cases, sophos_fusion_get_case, sophos_fusion_get_case_evidence,
 *        sophos_fusion_get_case_summary, sophos_fusion_list_case_reference_data,
 *        sophos_fusion_create_case, sophos_fusion_update_case,
 *        sophos_fusion_list_case_comments, sophos_fusion_add_case_comment,
 *        sophos_fusion_add_case_evidence, sophos_fusion_remove_case_evidence,
 *        sophos_fusion_create_case_link
 * Sophos Fusion Cases GraphQL API v2 on https://api.taegis.sophos.com/graphql.
 *
 * These sit beside the Classic REST case tools in cases.ts. The two APIs hold
 * separate case sets: a Classic ID like 1-598868 never resolves here, and a
 * Fusion UUID or CSE##### never resolves there.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { FusionClient } from "../client/fusion-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { CaseReferenceDataCache } from "../fusion/case-reference-data.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../config/config.js";
import { buildCasesQl } from "../fusion/cases-ql.js";
import {
  CASE_SEVERITY_NAMES,
  caseSeverityLabel,
  isCaseShortId,
  isLegacyCaseId,
  isUuid,
  looksLikeEmail,
  normaliseCaseSeverity,
  qlString,
  timestampToIso,
} from "../fusion/format.js";
import {
  ADD_CASE_COMMENT,
  ADD_EVIDENCE_TO_CASE,
  CASE_PRIMARY_VERDICTS_FOR,
  CREATE_CASE,
  CREATE_CASE_LINK,
  GET_CASE,
  GET_CASE_EVIDENCE,
  GET_CASE_WITH_EVIDENCE,
  LIST_CASES,
  LIST_CASE_COMMENTS,
  REMOVE_EVIDENCE_FROM_CASE,
  UPDATE_CASE,
} from "../fusion/queries/cases.js";
import { DETECTIONS_BY_ID } from "../fusion/queries/detections.js";
import type {
  FusionAddCaseCommentResponse,
  FusionAddEvidenceResponse,
  FusionCaseCommentsResponse,
  FusionCaseDetail,
  FusionCaseEvidence,
  FusionCaseEvidenceResponse,
  FusionCasePrimaryVerdictsResponse,
  FusionCaseResponse,
  FusionCaseSummary,
  FusionCaseWithEvidenceResponse,
  FusionCasesResponse,
  FusionCreateCaseLinkResponse,
  FusionCreateCaseResponse,
  FusionDetectionEntity,
  FusionDetectionRecord,
  FusionDetectionsByIdResponse,
  FusionRemoveEvidenceResponse,
  FusionUpdateCaseResponse,
} from "../fusion/types.js";
import { jsonResult, withErrorHandling } from "./helpers.js";

const ID_NOTE =
  "Fusion case UUID or short ID (e.g. 'CSE00001'). Classic IDs like '1-598868' do not resolve here.";

const tenantIdField = z
  .string()
  .uuid()
  .optional()
  .describe("Tenant ID. Required for partner/org callers.");

const severityField = z
  .union([z.number().int().min(2).max(10), z.enum(CASE_SEVERITY_NAMES)])
  .describe("Case severity: 2 informational, 4 low, 6 medium, 8 high, 10 critical (or the label)");

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export function registerFusionCaseTools(
  server: McpServer,
  client: FusionClient,
  tenantResolver: TenantResolver,
  referenceData: CaseReferenceDataCache
): void {
  // --- List Cases ---
  server.registerTool(
    "sophos_fusion_list_cases",
    {
      title: "List Fusion Cases",
      description: `List cases from the Sophos Fusion Cases GraphQL API, with filters that compile to a Fusion Query Language (QL) string.

Type, status and verdict are resolved to the tenant's own IDs at runtime (they depend on licensed services), so pass the name shown by sophos_fusion_list_case_reference_data or a UUID. Case severity is an integer: 2 informational, 4 low, 6 medium, 8 high, 10 critical. Legacy Sophos Central cases (IDs like '1-598868') are a separate case set and are not listed here; use sophos_list_cases for those.

Raw QL example for the query parameter: "severity >= 8 and closedAt is null | sort updatedAt desc". Searchable fields: id, shortId, title, severity, riskScore, tags, assigneeId, createdAt, updatedAt, closedAt, closeReason, archivedAt, managedBy, typeId, primaryStatusId. Names are not searchable, only IDs.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - query (string, optional): Raw QL. Combined with the filters below using "and".
  - type (string, optional): Case type name or UUID.
  - status (string[], optional): Primary status names or UUIDs (any of).
  - verdict (string, optional): Primary verdict name or UUID.
  - severity (number|string, optional): Exact severity. severity_min (optional): severity >= value.
  - open_only (boolean, optional): Only cases with no closedAt.
  - assignee_id (string, optional): Subject ID. unassigned (boolean, optional): assigneeId is null.
  - title_contains, tag, created_after, created_before, updated_after (optional): further predicates. Timestamps are ISO 8601.
  - sort (string, optional): "<field> asc|desc", default createdAt desc.
  - page (number, optional, default 1) and per_page (number, optional, 1-100, default 50), or after (string, optional): the endCursor from a previous page for cursor pagination.

Returns:
  total, page info (has_next_page, end_cursor), the QL string used, and cases with id, short_id, title, severity, type, status, tags, assignee_id, timestamps.`,
      inputSchema: {
        tenant_id: tenantIdField,
        query: z.string().optional().describe("Raw QL predicate, optionally with | sort"),
        type: z.string().optional().describe("Case type name or UUID"),
        status: z.array(z.string()).optional().describe("Primary status names or UUIDs"),
        verdict: z.string().optional().describe("Primary verdict name or UUID"),
        severity: severityField.optional(),
        severity_min: severityField.optional().describe("Minimum severity (inclusive)"),
        open_only: z.boolean().optional().describe("Only open cases (closedAt is null)"),
        assignee_id: z.string().optional().describe("Assignee Subject ID (not an email)"),
        unassigned: z.boolean().optional().describe("Only unassigned cases"),
        title_contains: z.string().optional().describe("Substring of the title"),
        tag: z.string().optional().describe("A tag the case must carry"),
        created_after: z.string().optional().describe("ISO 8601 timestamp, createdAt >="),
        created_before: z.string().optional().describe("ISO 8601 timestamp, createdAt <="),
        updated_after: z.string().optional().describe("ISO 8601 timestamp, updatedAt >="),
        sort: z.string().optional().describe('e.g. "severity desc"'),
        page: z.number().int().min(1).optional().default(1).describe("Page number (offset mode)"),
        per_page: z
          .number()
          .int()
          .min(1)
          .max(MAX_PAGE_SIZE)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results per page (max 100)"),
        after: z.string().optional().describe("endCursor from a previous page (cursor mode)"),
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);

      const typeId = args.type ? await referenceData.resolveTypeId(tenantId, args.type) : undefined;
      const statusIds = args.status
        ? await Promise.all(args.status.map((s) => referenceData.resolveStatusId(tenantId, s)))
        : undefined;
      const verdictId = args.verdict
        ? await referenceData.resolveVerdictId(tenantId, args.verdict)
        : undefined;

      const ql = buildCasesQl({
        query: args.query,
        typeId,
        statusIds,
        verdictId,
        severity: args.severity !== undefined ? normaliseCaseSeverity(args.severity) : undefined,
        severityMin:
          args.severity_min !== undefined ? normaliseCaseSeverity(args.severity_min) : undefined,
        openOnly: args.open_only,
        assigneeId: args.assignee_id,
        unassigned: args.unassigned,
        titleContains: args.title_contains,
        tag: args.tag,
        createdAfter: args.created_after,
        createdBefore: args.created_before,
        updatedAfter: args.updated_after,
        sort: args.sort,
      });

      const pagination = args.after
        ? { cursor: { first: args.per_page, after: args.after } }
        : { offset: { page: args.page, perPage: args.per_page } };

      const { data, warnings } = await client.query<FusionCasesResponse>(tenantId, LIST_CASES, {
        arguments: { ...(ql ? { query: ql } : {}), pagination },
      });

      return jsonResult(
        withWarnings(
          {
            total: data.cases.totalCount,
            page: args.after ? null : args.page,
            per_page: args.per_page,
            has_next_page: data.cases.pageInfo.hasNextPage,
            end_cursor: data.cases.pageInfo.endCursor,
            ql_query: ql ?? null,
            cases: data.cases.cases.map(formatCaseSummary),
          },
          warnings
        )
      );
    })
  );

  // --- Get Case ---
  server.registerTool(
    "sophos_fusion_get_case",
    {
      title: "Get Fusion Case",
      description: `Get full details of one Sophos Fusion case, including key findings (the REST "overview"), verdicts, links, processing status and evidence counts.

Accepts the case UUID or the short ID (CSE00001); a short ID costs one extra lookup. Legacy Sophos Central case IDs ('1-598868') are a separate case set and do not resolve here.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  The case with id, short_id, title, severity (2-10), type, status, verdict, assignee_id (a Subject ID), key_findings, tags, links, timestamps and evidence counts.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ case_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const { data, warnings } = await client.query<FusionCaseResponse>(tenantId, GET_CASE, {
        arguments: { id: resolved.id },
      });
      if (!data.case) {
        throw new Error(`Fusion case ${case_id} not found in tenant ${tenantId}.`);
      }
      return jsonResult(withWarnings(formatCaseDetail(data.case), [...resolved.warnings, ...warnings]));
    })
  );

  // --- Get Case Evidence ---
  server.registerTool(
    "sophos_fusion_get_case_evidence",
    {
      title: "Get Fusion Case Evidence",
      description: `List the evidence attached to a Sophos Fusion case: detection IDs, event IDs, asset IDs and saved-search IDs, with when and by whom each was attached and whether it was genesis evidence (what the case was opened on).

This is linkage only. Use sophos_fusion_get_case_summary to resolve the detections to full records in one batched call.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  Counts and ID lists for detections, events, assets and search queries.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ case_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const { data, warnings } = await client.query<FusionCaseEvidenceResponse>(
        tenantId,
        GET_CASE_EVIDENCE,
        { arguments: { id: resolved.id } }
      );
      if (!data.caseEvidence) {
        throw new Error(`Fusion case ${case_id} not found in tenant ${tenantId}.`);
      }
      return jsonResult(
        withWarnings(formatEvidence(data.caseEvidence), [...resolved.warnings, ...warnings])
      );
    })
  );

  // --- Get Case Summary (case + evidence + detections + MITRE roll-up) ---
  server.registerTool(
    "sophos_fusion_get_case_summary",
    {
      title: "Get Fusion Case Summary",
      description: `One-call investigation summary of a Sophos Fusion case: the case, its evidence counts, the attached detections resolved to full records in a single batched Detections API call, and a MITRE ATT&CK roll-up (tactics and techniques with detection counts) assembled from those records.

This replaces what sophos_get_case plus sophos_list_case_detections plus sophos_get_case_mitre_summary gave for Classic cases; Fusion has no server-side MITRE summary. Detection severity here is a 0 to 1 float. It is a different scale from the case's 2 to 10 severity and from the Classic REST 0 to 10 detection severity; do not convert between them.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - include_detections (boolean, optional, default true): Resolve detection records and build the MITRE roll-up.
  - max_detections (number, optional, 1-100, default 50): Cap on detections resolved (one API call regardless).

Returns:
  case, evidence counts, detections (id, title, severity_0_to_1, status, detector, entities, timestamps), detections_resolved vs detections_total, and mitre_summary.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        include_detections: z
          .boolean()
          .optional()
          .default(true)
          .describe("Resolve detection records and MITRE roll-up (default true)"),
        max_detections: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .default(50)
          .describe("Maximum detections to resolve (default 50)"),
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ case_id, tenant_id, include_detections, max_detections }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const warnings = [...resolved.warnings];

      const caseResult = await client.query<FusionCaseWithEvidenceResponse>(
        tenantId,
        GET_CASE_WITH_EVIDENCE,
        { caseArguments: { id: resolved.id }, evidenceArguments: { id: resolved.id } }
      );
      warnings.push(...caseResult.warnings);
      if (!caseResult.data.case) {
        throw new Error(`Fusion case ${case_id} not found in tenant ${tenantId}.`);
      }

      const evidence = caseResult.data.caseEvidence;
      const attached = evidence?.detectionsEvidence ?? [];
      const detectionIds = attached.map((e) => e.detectionId);
      const toResolve = detectionIds.slice(0, max_detections);

      let detections: ReturnType<typeof formatDetection>[] = [];
      let mitreSummary: ReturnType<typeof buildMitreSummary> | null = null;

      if (include_detections && toResolve.length > 0) {
        const detResult = await client.query<FusionDetectionsByIdResponse>(
          tenantId,
          DETECTIONS_BY_ID,
          { in: { iDs: toResolve } }
        );
        warnings.push(...detResult.warnings);
        const records = detResult.data.detectionRetrieveById?.alerts?.list ?? [];
        const genesis = new Map(attached.map((e) => [e.detectionId, e]));
        detections = records.map((r) => formatDetection(r, genesis.get(r.id)));
        mitreSummary = buildMitreSummary(records);
      }

      return jsonResult(
        withWarnings(
          {
            case: formatCaseDetail(caseResult.data.case),
            evidence: evidence
              ? {
                  detections: evidence.detectionsEvidenceCount,
                  events: evidence.eventsEvidenceCount,
                  assets: evidence.assetsEvidenceCount,
                  search_queries: evidence.searchQueriesEvidenceCount,
                  event_ids: (evidence.eventsEvidence ?? []).map((e) => e.eventId),
                  asset_ids: (evidence.assetsEvidence ?? []).map((a) => a.assetId),
                }
              : null,
            detections_total: detectionIds.length,
            detections_resolved: detections.length,
            detections,
            mitre_summary: mitreSummary,
          },
          warnings
        )
      );
    })
  );

  // --- List Case Reference Data ---
  server.registerTool(
    "sophos_fusion_list_case_reference_data",
    {
      title: "List Fusion Case Reference Data",
      description: `List the case types, primary statuses and primary verdicts this tenant can use in Sophos Fusion. These are not fixed enums: the set depends on the tenant's licensed services, and every filter or write uses their IDs.

Cached per tenant for 15 minutes. Pass refresh to bypass the cache after a licensing change.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - refresh (boolean, optional): Ignore the cache and fetch again.

Returns:
  types (id, name, title, managed_by, supported status and verdict IDs), primary_statuses (id, name, title, is_closed), primary_verdicts (id, name, title), fetched_at.`,
      inputSchema: {
        tenant_id: tenantIdField,
        refresh: z.boolean().optional().describe("Bypass the 15 minute cache"),
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ tenant_id, refresh }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const data = await referenceData.get(tenantId, { refresh });
      return jsonResult({
        tenant_id: tenantId,
        fetched_at: data.fetchedAt,
        cache_ttl_minutes: 15,
        types: data.types.map((t) => ({
          id: t.id,
          name: t.name,
          title: t.title,
          managed_by: t.managedBy,
          supported_primary_status_ids: t.supportedPrimaryStatusIds,
          supported_primary_verdict_ids: t.supportedPrimaryVerdictIds,
        })),
        primary_statuses: data.primaryStatuses.map((s) => ({
          id: s.id,
          name: s.name,
          title: s.title,
          is_closed: s.isClosed,
        })),
        primary_verdicts: data.primaryVerdicts.map((v) => ({
          id: v.id,
          name: v.name,
          title: v.title,
        })),
      });
    })
  );

  // --- Create Case ---
  server.registerTool(
    "sophos_fusion_create_case",
    {
      title: "Create Fusion Case",
      description: `Create a case in Sophos Fusion.

Type and status are resolved from the tenant's reference data (name or UUID). When status is omitted the first non-closed status is used, preferring one named NEW or OPEN. Severity is an integer 2, 4, 6, 8 or 10 (or its label). assignee_id is a Subject ID or an @mention (for example @customer or @sophos), never an email address. key_findings is Markdown and becomes the case's typed key findings document (the REST "overview"). Evidence attached at creation is recorded as genesis evidence.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - title (string): Case title, max 256 characters.
  - type (string): Case type name or UUID (see sophos_fusion_list_case_reference_data).
  - severity (number|string): 2 informational, 4 low, 6 medium, 8 high, 10 critical.
  - status (string, optional): Initial primary status name or UUID.
  - assignee_id (string, optional): Subject ID or @mention.
  - key_findings (string, optional): Markdown body.
  - tags (string[], optional): Labels.
  - detection_ids, event_ids, host_ids (string[], optional): Evidence to attach as genesis evidence.

Returns:
  The created case (id, short_id, title, severity, type, status, ...).`,
      inputSchema: {
        tenant_id: tenantIdField,
        title: z.string().min(1).max(256).describe("Case title (max 256 characters)"),
        type: z.string().describe("Case type name or UUID"),
        severity: severityField,
        status: z.string().optional().describe("Initial primary status name or UUID"),
        assignee_id: z.string().optional().describe("Subject ID or @mention, never an email"),
        key_findings: z.string().optional().describe("Key findings, Markdown"),
        tags: z.array(z.string()).optional().describe("Tags"),
        detection_ids: z.array(z.string()).optional().describe("Detection IDs to attach"),
        event_ids: z.array(z.string()).optional().describe("Event IDs to attach"),
        host_ids: z.array(z.string()).optional().describe("Host IDs whose assets to attach"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      assertAssignee(args.assignee_id);

      const typeId = await referenceData.resolveTypeId(tenantId, args.type);
      const primaryStatusId = args.status
        ? await referenceData.resolveStatusId(tenantId, args.status)
        : await defaultOpenStatusId(referenceData, tenantId);

      const input: Record<string, unknown> = {
        title: args.title,
        typeId,
        severity: normaliseCaseSeverity(args.severity),
        primaryStatusId,
      };
      if (args.assignee_id) input.assigneeId = args.assignee_id;
      if (args.key_findings !== undefined) input.keyFindings = keyFindingsInput(args.key_findings);
      if (args.tags) input.tags = args.tags;
      if (args.detection_ids?.length) input.detectionIds = args.detection_ids;
      if (args.event_ids?.length) input.eventIds = args.event_ids;
      if (args.host_ids?.length) input.hostIds = args.host_ids;

      const { data, warnings } = await client.query<FusionCreateCaseResponse>(
        tenantId,
        CREATE_CASE,
        { input }
      );
      if (!data.createCase) {
        throw new Error("createCase returned no case.");
      }
      return jsonResult(withWarnings(formatCaseDetail(data.createCase), warnings));
    })
  );

  // --- Update Case ---
  server.registerTool(
    "sophos_fusion_update_case",
    {
      title: "Update Fusion Case",
      description: `Update a Sophos Fusion case. PATCH style: only the fields supplied change.

Closing: set status to a closed status (see is_closed in sophos_fusion_list_case_reference_data). If the case type supports verdicts, a verdict is required to close and this tool refuses the call with the valid verdict names when none is given. Archiving is separate from closing and only allowed on a closed case; there is no delete in Fusion, so close then archive. assignee_id is a Subject ID or @mention; an empty string clears the assignee. tags replace the existing list.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - title (string, optional), severity (number|string, optional): 2, 4, 6, 8, 10 or label.
  - status (string, optional): Primary status name or UUID.
  - verdict (string, optional): Primary verdict name or UUID (required when closing a type that supports verdicts).
  - close_reason (string, optional): Free text recorded with a close.
  - assignee_id (string, optional): Subject ID or @mention; "" clears.
  - key_findings (string, optional): Markdown; replaces the key findings document.
  - tags (string[], optional): Replaces the tag list.
  - archived (boolean, optional): true archives a closed case, false unarchives.

Returns:
  The updated case.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        title: z.string().min(1).max(256).optional().describe("New title"),
        severity: severityField.optional(),
        status: z.string().optional().describe("Primary status name or UUID"),
        verdict: z.string().optional().describe("Primary verdict name or UUID"),
        close_reason: z.string().optional().describe("Reason recorded when closing"),
        assignee_id: z.string().optional().describe('Subject ID or @mention; "" clears'),
        key_findings: z.string().optional().describe("Key findings, Markdown (replaces)"),
        tags: z.array(z.string()).optional().describe("Tags (replaces the list)"),
        archived: z.boolean().optional().describe("Archive (true) or unarchive (false)"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, args.case_id);
      const warnings = [...resolved.warnings];
      if (args.assignee_id) assertAssignee(args.assignee_id);

      const input: Record<string, unknown> = { id: resolved.id };
      if (args.title !== undefined) input.title = args.title;
      if (args.severity !== undefined) input.severity = normaliseCaseSeverity(args.severity);
      if (args.close_reason !== undefined) input.closeReason = args.close_reason;
      if (args.assignee_id !== undefined) input.assigneeId = args.assignee_id;
      if (args.key_findings !== undefined) input.keyFindings = keyFindingsInput(args.key_findings);
      if (args.tags !== undefined) input.tags = args.tags;
      if (args.archived !== undefined) input.isArchived = args.archived;

      const status = args.status
        ? await referenceData.resolveStatus(tenantId, args.status)
        : undefined;
      if (status) input.primaryStatusId = status.id;
      if (args.verdict !== undefined) {
        input.primaryVerdictId = await referenceData.resolveVerdictId(tenantId, args.verdict);
      }

      if (Object.keys(input).length === 1) {
        throw new Error("Nothing to update: supply at least one field to change.");
      }

      // Verdict-on-close: Fusion rejects a close without a verdict when the
      // case type supports verdicts. Check first so the error names the options.
      if (status?.isClosed && args.verdict === undefined) {
        const current = await client.query<FusionCaseResponse>(tenantId, GET_CASE, {
          arguments: { id: resolved.id },
        });
        warnings.push(...current.warnings);
        const typeId = current.data.case?.type.id;
        if (typeId) {
          const verdicts = await client.query<FusionCasePrimaryVerdictsResponse>(
            tenantId,
            CASE_PRIMARY_VERDICTS_FOR,
            { arguments: { typeId, primaryStatusId: status.id } }
          );
          const options = verdicts.data.casePrimaryVerdicts?.primaryVerdicts ?? [];
          if (options.length > 0) {
            throw new Error(
              `Closing this case requires a verdict. Valid verdicts for its type: ${options
                .map((v) => `${v.name}${v.title ? ` (${v.title})` : ""}`)
                .join(", ")}. Re-run with verdict set.`
            );
          }
        }
      }

      const { data, warnings: updateWarnings } = await client.query<FusionUpdateCaseResponse>(
        tenantId,
        UPDATE_CASE,
        { input }
      );
      warnings.push(...updateWarnings);
      if (!data.updateCase) {
        throw new Error("updateCase returned no case.");
      }
      return jsonResult(withWarnings(formatCaseDetail(data.updateCase), warnings));
    })
  );

  // --- List Case Comments ---
  server.registerTool(
    "sophos_fusion_list_case_comments",
    {
      title: "List Fusion Case Comments",
      description: `List the comments on a Sophos Fusion case. Comments had no REST equivalent.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - order (string, optional): "asc" or "desc" by createdAt (API default).
  - visibility (string, optional): "ALL" (default), "INTERNAL" (partner-only comments) or "NOT_INTERNAL".
  - page (number, optional, default 1), per_page (number, optional, 1-100, default 25).

Returns:
  total, total_unread, comments (id, author_id, comment, is_internal, mentions, timestamps).`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        order: z.enum(["asc", "desc"]).optional().describe("Sort by createdAt"),
        visibility: z
          .enum(["ALL", "INTERNAL", "NOT_INTERNAL"])
          .optional()
          .default("ALL")
          .describe("Comment visibility filter"),
        page: z.number().int().min(1).optional().default(1).describe("Page number"),
        per_page: z
          .number()
          .int()
          .min(1)
          .max(MAX_PAGE_SIZE)
          .optional()
          .default(25)
          .describe("Results per page (max 100)"),
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ case_id, tenant_id, order, visibility, page, per_page }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const { data, warnings } = await client.query<FusionCaseCommentsResponse>(
        tenantId,
        LIST_CASE_COMMENTS,
        {
          arguments: {
            caseId: resolved.id,
            visibility,
            page,
            perPage: per_page,
            ...(order ? { orderBy: order === "asc" ? "ASCENDING" : "DESCENDING" } : {}),
          },
        }
      );
      return jsonResult(
        withWarnings(
          {
            case_id: resolved.id,
            total: data.caseComments.totalCount,
            total_unread: data.caseComments.totalUnreadCount,
            page,
            per_page,
            comments: data.caseComments.comments.map(formatComment),
          },
          [...resolved.warnings, ...warnings]
        )
      );
    })
  );

  // --- Add Case Comment ---
  server.registerTool(
    "sophos_fusion_add_case_comment",
    {
      title: "Add Fusion Case Comment",
      description: `Add a comment to a Sophos Fusion case. The text may contain @mentions to notify users.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - comment (string): Comment text.
  - internal (boolean, optional): Mark internal (visible to partner users only). Partner credentials only.

Returns:
  The created comment.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        comment: z.string().min(1).describe("Comment text"),
        internal: z.boolean().optional().describe("Internal (partner-only) comment"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ case_id, tenant_id, comment, internal }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const { data, warnings } = await client.query<FusionAddCaseCommentResponse>(
        tenantId,
        ADD_CASE_COMMENT,
        { input: { caseId: resolved.id, comment, ...(internal !== undefined ? { isInternal: internal } : {}) } }
      );
      if (!data.addCaseComment) {
        throw new Error("addCaseComment returned no comment.");
      }
      return jsonResult(
        withWarnings(formatComment(data.addCaseComment), [...resolved.warnings, ...warnings])
      );
    })
  );

  // --- Add Case Evidence ---
  server.registerTool(
    "sophos_fusion_add_case_evidence",
    {
      title: "Add Fusion Case Evidence",
      description: `Attach detections, events, hosts (assets) or saved searches to an existing Sophos Fusion case. Asynchronous: the API accepts the request and processes it in the background; check processing_status on sophos_fusion_get_case before expecting the evidence to appear. Evidence added this way is not genesis evidence.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - detection_ids, event_ids, host_ids, search_queries (string[], optional): At least one list required.

Returns:
  What the service accepted for attachment.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        detection_ids: z.array(z.string()).optional().describe("Detection IDs"),
        event_ids: z.array(z.string()).optional().describe("Event IDs"),
        host_ids: z.array(z.string()).optional().describe("Host IDs (attaches their assets)"),
        search_queries: z.array(z.string()).optional().describe("Saved search IDs"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, args.case_id);
      const input: Record<string, unknown> = { caseId: resolved.id };
      if (args.detection_ids?.length) input.detectionIds = args.detection_ids;
      if (args.event_ids?.length) input.eventIds = args.event_ids;
      if (args.host_ids?.length) input.hostIds = args.host_ids;
      if (args.search_queries?.length) input.searchQueries = args.search_queries;
      if (Object.keys(input).length === 1) {
        throw new Error("Supply at least one of detection_ids, event_ids, host_ids or search_queries.");
      }
      const { data, warnings } = await client.query<FusionAddEvidenceResponse>(
        tenantId,
        ADD_EVIDENCE_TO_CASE,
        { input }
      );
      const result = data.addEvidenceToCase;
      if (!result) {
        throw new Error("addEvidenceToCase returned no result.");
      }
      return jsonResult(
        withWarnings(
          {
            status: "accepted",
            note: "Evidence is attached asynchronously. Check processing_status on the case.",
            case_id: result.caseId,
            detection_ids: result.detectionIds ?? [],
            event_ids: result.eventIds ?? [],
            host_ids: result.hostIds ?? [],
            search_queries: result.searchQueries ?? [],
          },
          [...resolved.warnings, ...warnings]
        )
      );
    })
  );

  // --- Remove Case Evidence ---
  server.registerTool(
    "sophos_fusion_remove_case_evidence",
    {
      title: "Remove Fusion Case Evidence",
      description: `Detach detections, events, assets or saved searches from a Sophos Fusion case. Asynchronous, like adding evidence. Assets are removed by asset ID (as returned by sophos_fusion_get_case_evidence), not host ID.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - detection_ids, event_ids, asset_ids, search_queries (string[], optional): At least one list required.

Returns:
  What the service accepted for removal.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        detection_ids: z.array(z.string()).optional().describe("Detection IDs"),
        event_ids: z.array(z.string()).optional().describe("Event IDs"),
        asset_ids: z.array(z.string()).optional().describe("Asset IDs"),
        search_queries: z.array(z.string()).optional().describe("Saved search IDs"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, args.case_id);
      const input: Record<string, unknown> = { caseId: resolved.id };
      if (args.detection_ids?.length) input.detectionIds = args.detection_ids;
      if (args.event_ids?.length) input.eventIds = args.event_ids;
      if (args.asset_ids?.length) input.assetIds = args.asset_ids;
      if (args.search_queries?.length) input.searchQueries = args.search_queries;
      if (Object.keys(input).length === 1) {
        throw new Error("Supply at least one of detection_ids, event_ids, asset_ids or search_queries.");
      }
      const { data, warnings } = await client.query<FusionRemoveEvidenceResponse>(
        tenantId,
        REMOVE_EVIDENCE_FROM_CASE,
        { input }
      );
      const result = data.removeEvidenceFromCase;
      if (!result) {
        throw new Error("removeEvidenceFromCase returned no result.");
      }
      return jsonResult(
        withWarnings(
          {
            status: "accepted",
            note: "Evidence is removed asynchronously. Check processing_status on the case.",
            case_id: result.caseId,
            detection_ids: result.detectionIds ?? [],
            event_ids: result.eventIds ?? [],
            asset_ids: result.assetIds ?? [],
            search_queries: result.searchQueries ?? [],
          },
          [...resolved.warnings, ...warnings]
        )
      );
    })
  );

  // --- Create Case Link ---
  server.registerTool(
    "sophos_fusion_create_case_link",
    {
      title: "Create Fusion Case Link",
      description: `Attach an external link (a ServiceNow ticket, a runbook, a report) to a Sophos Fusion case. Links had no REST equivalent.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - url (string): The link.
  - title (string, optional): Display title.
  - type (string, optional): System name, e.g. "ServiceNow".
  - reference (string, optional): The ID in the other system, e.g. an incident number.
  - internal (boolean, optional): Visible to internal users only (default false).

Returns:
  The created link.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        url: z.string().url().describe("Link URL"),
        title: z.string().optional().describe("Display title"),
        type: z.string().optional().describe("Linked system, e.g. ServiceNow"),
        reference: z.string().optional().describe("ID in the linked system"),
        internal: z.boolean().optional().describe("Internal-only link"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ case_id, tenant_id, url, title, type, reference, internal }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const input: Record<string, unknown> = { caseId: resolved.id, url };
      if (title !== undefined) input.title = title;
      if (type !== undefined) input.type = type;
      if (reference !== undefined) input.reference = reference;
      if (internal !== undefined) input.isInternal = internal;
      const { data, warnings } = await client.query<FusionCreateCaseLinkResponse>(
        tenantId,
        CREATE_CASE_LINK,
        { input }
      );
      if (!data.createCaseLink) {
        throw new Error("createCaseLink returned no link.");
      }
      const link = data.createCaseLink;
      return jsonResult(
        withWarnings(
          {
            id: link.id,
            case_id: resolved.id,
            url: link.url,
            title: link.title,
            type: link.type,
            reference: link.reference,
            is_internal: link.isInternal,
            created_at: link.createdAt,
          },
          [...resolved.warnings, ...warnings]
        )
      );
    })
  );
}

// --- Helpers ---

function withWarnings<T extends object>(result: T, warnings: string[]): T | (T & { warnings: string[] }) {
  return warnings.length > 0 ? { ...result, warnings } : result;
}

/**
 * Turns whatever the caller passed as a case ID into the Fusion UUID. Short
 * IDs cost one search; legacy IDs are refused with a pointer to the Classic tool.
 */
async function resolveCaseUuid(
  client: FusionClient,
  tenantId: string,
  caseRef: string
): Promise<{ id: string; warnings: string[] }> {
  const value = caseRef.trim();
  if (isUuid(value)) return { id: value, warnings: [] };

  if (isCaseShortId(value)) {
    const { data, warnings } = await client.query<FusionCasesResponse>(tenantId, LIST_CASES, {
      arguments: {
        query: `shortId = ${qlString(value.toUpperCase())}`,
        pagination: { offset: { page: 1, perPage: 1 } },
      },
    });
    const found = data.cases.cases[0];
    if (!found) {
      throw new Error(`No Fusion case with short ID ${value.toUpperCase()} in tenant ${tenantId}.`);
    }
    return { id: found.id, warnings };
  }

  if (isLegacyCaseId(value)) {
    throw new Error(
      `${value} looks like a Classic (legacy) Sophos Central case ID. Fusion holds a separate case set and legacy IDs do not resolve here. Use sophos_get_case for legacy cases.`
    );
  }

  throw new Error(
    `Unrecognised case ID ${JSON.stringify(value)}. Expected a Fusion case UUID or a short ID like CSE00001.`
  );
}

function assertAssignee(assigneeId: string | undefined): void {
  if (assigneeId && looksLikeEmail(assigneeId)) {
    throw new Error(
      `assignee_id must be a Subject ID or an @mention, not an email address (got ${assigneeId}). Look the user up first; the developer portal points at the Users API (sophos_list_users) for tenant user IDs.`
    );
  }
}

async function defaultOpenStatusId(
  referenceData: CaseReferenceDataCache,
  tenantId: string
): Promise<string> {
  const { primaryStatuses } = await referenceData.get(tenantId);
  const open = primaryStatuses.filter((s) => !s.isClosed);
  const preferred =
    open.find((s) => s.name.toUpperCase() === "NEW") ??
    open.find((s) => s.name.toUpperCase() === "OPEN") ??
    open[0];
  if (!preferred) {
    throw new Error(
      "This tenant exposes no open case status; pass status explicitly (see sophos_fusion_list_case_reference_data)."
    );
  }
  return preferred.id;
}

function keyFindingsInput(content: string) {
  return { documentType: "MARKDOWN", documentVersion: "1.0", content };
}

function formatCaseSummary(c: FusionCaseSummary) {
  return {
    id: c.id,
    short_id: c.shortId,
    title: c.title,
    severity: c.severity,
    severity_label: caseSeverityLabel(c.severity),
    type: c.type ? { id: c.type.id, name: c.type.name, title: c.type.title } : null,
    status: c.primaryStatus
      ? {
          id: c.primaryStatus.id,
          name: c.primaryStatus.name,
          title: c.primaryStatus.title,
          is_closed: c.primaryStatus.isClosed,
        }
      : null,
    secondary_status: c.secondaryStatus
      ? { id: c.secondaryStatus.id, name: c.secondaryStatus.name, title: c.secondaryStatus.title }
      : null,
    tags: c.tags ?? [],
    assignee_id: c.assigneeId ?? null,
    managed_by: c.managedBy ?? null,
    tenant_id: c.tenantId,
    created_at: c.createdAt,
    updated_at: c.updatedAt,
    closed_at: c.closedAt ?? null,
    archived_at: c.archivedAt ?? null,
    risk_score: c.riskScore ?? null,
  };
}

function formatCaseDetail(c: FusionCaseDetail) {
  return {
    ...formatCaseSummary(c),
    key_findings: c.keyFindings
      ? { document_type: c.keyFindings.documentType, content: c.keyFindings.content }
      : null,
    verdict: c.primaryVerdict
      ? { id: c.primaryVerdict.id, name: c.primaryVerdict.name, title: c.primaryVerdict.title }
      : null,
    secondary_verdict: c.secondaryVerdict
      ? { id: c.secondaryVerdict.id, name: c.secondaryVerdict.name, title: c.secondaryVerdict.title }
      : null,
    secondary_status_reason: c.secondaryStatusReason ?? [],
    close_reason: c.closeReason ?? null,
    closed_by_id: c.closedById ?? null,
    created_by_id: c.createdById,
    updated_by_id: c.updatedById,
    contributor_ids: c.contributorIds ?? [],
    incident_advisor_id: c.incidentAdvisorId ?? null,
    rule_id: c.ruleId ?? null,
    source: c.source ? { id: c.source.id, name: c.source.name, title: c.source.title } : null,
    links: (c.links ?? []).map((l) => ({
      id: l.id,
      url: l.url,
      title: l.title,
      type: l.type,
      reference: l.reference,
      is_internal: l.isInternal,
      created_at: l.createdAt,
    })),
    processing_status: c.processingStatus ?? null,
    created_by_partner: c.isCreatedByPartner,
    created_by_mdr_provider: c.isCreatedByMDRProvider,
    evidence_counts: {
      detections: c.detectionsCount,
      events: c.eventsCount,
      assets: c.assetsCount,
    },
  };
}

function formatEvidence(e: FusionCaseEvidence) {
  return {
    case_id: e.id,
    counts: {
      detections: e.detectionsEvidenceCount,
      events: e.eventsEvidenceCount,
      assets: e.assetsEvidenceCount,
      search_queries: e.searchQueriesEvidenceCount,
    },
    detections: (e.detectionsEvidence ?? []).map((d) => ({
      detection_id: d.detectionId,
      attached_at: d.createdAt,
      attached_by: d.createdBy ?? null,
      is_genesis: d.isGenesis,
    })),
    events: (e.eventsEvidence ?? []).map((ev) => ({
      event_id: ev.eventId,
      attached_at: ev.createdAt,
      attached_by: ev.createdBy,
      is_genesis: ev.isGenesis,
    })),
    assets: (e.assetsEvidence ?? []).map((a) => ({
      asset_id: a.assetId,
      attached_at: a.createdAt,
      attached_by: a.createdBy ?? null,
    })),
    search_queries: (e.searchQueriesEvidence ?? []).map((s) => ({
      search_query_id: s.searchQueryId,
      attached_at: s.createdAt,
      is_genesis: s.isGenesis,
    })),
  };
}

function formatComment(c: {
  id: string;
  authorId: string;
  comment: string;
  createdAt: string;
  updatedAt: string;
  isInternal: boolean;
  mentionsIds: string[];
}) {
  return {
    id: c.id,
    author_id: c.authorId,
    comment: c.comment,
    is_internal: c.isInternal,
    mentions: c.mentionsIds ?? [],
    created_at: c.createdAt,
    updated_at: c.updatedAt,
  };
}

function formatEntity(e: FusionDetectionEntity) {
  return { name: e.display_name, subtype: e.subtype, identifiers: e.identifiers ?? [] };
}

function formatDetection(
  r: FusionDetectionRecord,
  attachment?: { createdAt: string; isGenesis: boolean }
) {
  const m = r.metadata;
  return {
    id: r.id,
    title: m?.title ?? null,
    description: m?.description ?? null,
    severity_0_to_1: m?.severity ?? null,
    confidence: m?.confidence ?? null,
    status: r.status ?? null,
    resolution_reason: r.resolution_reason ?? null,
    origin: m?.origin ?? null,
    detector: m?.creator?.detector?.detector_name ?? null,
    detector_id: m?.creator?.detector?.detector_id ?? null,
    created_at: timestampToIso(m?.created_at),
    first_seen_at: timestampToIso(m?.first_seen_at),
    sensor_types: r.sensor_types ?? [],
    tags: r.tags ?? [],
    attack_technique_ids: r.attack_technique_ids ?? [],
    source_entities: (r.source_entities ?? []).map(formatEntity),
    target_entities: (r.target_entities ?? []).map(formatEntity),
    event_count: r.event_ids?.length ?? 0,
    is_genesis: attachment?.isGenesis ?? null,
    attached_at: attachment?.createdAt ?? null,
  };
}

/**
 * Client-side replacement for the Classic mitre-attack-summary endpoint:
 * tactics and techniques across the resolved detections, with counts.
 */
export function buildMitreSummary(records: FusionDetectionRecord[]) {
  const techniques = new Map<
    string,
    { technique_id: string; technique: string | null; tactics: Set<string>; detections: Set<string> }
  >();

  const touch = (id: string, name: string | null, tactics: string[] | null, detectionId: string) => {
    const entry = techniques.get(id) ?? {
      technique_id: id,
      technique: null,
      tactics: new Set<string>(),
      detections: new Set<string>(),
    };
    if (name && !entry.technique) entry.technique = name;
    for (const t of tactics ?? []) entry.tactics.add(t);
    entry.detections.add(detectionId);
    techniques.set(id, entry);
  };

  for (const r of records) {
    for (const d of r.enrichment_details ?? []) {
      const info = d.mitre_attack_info;
      if (info?.technique_id) touch(info.technique_id, info.technique, info.tactics, r.id);
    }
    for (const id of r.attack_technique_ids ?? []) touch(id, null, null, r.id);
  }

  const byTactic = new Map<string, Array<{ technique_id: string; technique: string | null; detection_count: number }>>();
  const withoutTactic: Array<{ technique_id: string; technique: string | null; detection_count: number }> = [];
  for (const entry of techniques.values()) {
    const row = {
      technique_id: entry.technique_id,
      technique: entry.technique,
      detection_count: entry.detections.size,
    };
    if (entry.tactics.size === 0) {
      withoutTactic.push(row);
      continue;
    }
    for (const tactic of entry.tactics) {
      const list = byTactic.get(tactic) ?? [];
      list.push(row);
      byTactic.set(tactic, list);
    }
  }

  return {
    detection_count: records.length,
    technique_count: techniques.size,
    tactics: [...byTactic.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([tactic, list]) => ({
        tactic,
        techniques: list.sort((a, b) => b.detection_count - a.detection_count),
      })),
    techniques_without_tactic: withoutTactic,
  };
}
