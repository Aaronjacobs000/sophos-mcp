/**
 * Tools: sophos_fusion_list_cases, sophos_fusion_get_case, sophos_fusion_get_case_evidence,
 *        sophos_fusion_get_case_summary, sophos_fusion_list_case_reference_data,
 *        sophos_fusion_create_case, sophos_fusion_update_case,
 *        sophos_fusion_split_case, sophos_fusion_merge_cases,
 *        sophos_fusion_list_case_comments, sophos_fusion_add_case_comment,
 *        sophos_fusion_update_case_comment, sophos_fusion_delete_case_comment,
 *        sophos_fusion_add_case_evidence, sophos_fusion_remove_case_evidence,
 *        sophos_fusion_list_case_files, sophos_fusion_upload_case_file,
 *        sophos_fusion_delete_case_file,
 *        sophos_fusion_create_case_link, sophos_fusion_update_case_link,
 *        sophos_fusion_delete_case_link
 * Sophos Fusion Cases GraphQL API v2 on https://api.taegis.sophos.com/graphql.
 *
 * These sit beside the Classic REST case tools in cases.ts. The two APIs hold
 * separate case sets: a Classic ID like 1-598868 never resolves here, and a
 * Fusion UUID or CSE##### never resolves there. For a tenant that has moved
 * to Fusion the Classic tools refuse and point here (fusion/migration.ts).
 *
 * Everything below about lag, expansion, source IDs, mentions and the
 * lifecycle rules was measured on a live tenant on 22/09/2026.
 */

import { readFile } from "node:fs/promises";
import { basename, extname } from "node:path";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { FusionGraphQLError, type FusionClient } from "../client/fusion-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import type { CaseReferenceDataCache } from "../fusion/case-reference-data.js";
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from "../config/config.js";
import { buildCasesQl } from "../fusion/cases-ql.js";
import {
  CASE_SEVERITY_NAMES,
  RESOURCE_NAME_EXAMPLE,
  caseSeverityLabel,
  formatDetection,
  isCaseShortId,
  isLegacyCaseId,
  isResourceName,
  isUuid,
  looksLikeEmail,
  mergeTags,
  normaliseCaseSeverity,
  parseMentionTokens,
  qlString,
} from "../fusion/format.js";
import {
  ADD_CASE_COMMENT,
  ADD_EVIDENCE_TO_CASE,
  CASE_PRIMARY_VERDICTS_FOR,
  CREATE_CASE,
  CREATE_CASE_LINK,
  DELETE_CASE_COMMENT,
  DELETE_CASE_FILE,
  DELETE_CASE_LINK,
  GET_CASE,
  GET_CASE_EVIDENCE,
  GET_CASE_FILE,
  LIST_CASES,
  LIST_CASE_COMMENTS,
  LIST_CASE_FILES,
  LIST_CASE_FILES_WITH_URLS,
  MERGE_CASES,
  REMOVE_EVIDENCE_FROM_CASE,
  SPLIT_CASE,
  START_CASE_FILE_UPLOAD,
  UPDATE_CASE,
  UPDATE_CASE_COMMENT,
  UPDATE_CASE_LINK,
} from "../fusion/queries/cases.js";
import { DETECTIONS_BY_ID } from "../fusion/queries/detections.js";
import type {
  FusionAddCaseCommentResponse,
  FusionAddEvidenceResponse,
  FusionCaseComment,
  FusionCaseCommentsResponse,
  FusionCaseDetail,
  FusionCaseEvidence,
  FusionCaseEvidenceResponse,
  FusionCaseFile,
  FusionCaseFileResponse,
  FusionCaseFilesResponse,
  FusionCaseLink,
  FusionCasePrimaryVerdictsResponse,
  FusionCaseResponse,
  FusionCaseSummary,
  FusionCasesResponse,
  FusionCreateCaseLinkResponse,
  FusionCreateCaseResponse,
  FusionDeleteCaseCommentResponse,
  FusionDeleteCaseFileResponse,
  FusionDeleteCaseLinkResponse,
  FusionDetectionRecord,
  FusionDetectionsByIdResponse,
  FusionMergeCaseResponse,
  FusionRemoveEvidenceResponse,
  FusionSplitCaseResponse,
  FusionStartCaseFileUploadResponse,
  FusionUpdateCaseCommentResponse,
  FusionUpdateCaseLinkResponse,
  FusionUpdateCaseResponse,
} from "../fusion/types.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";

const ID_NOTE =
  "Fusion case UUID or short ID (e.g. 'CSE00001'). Classic IDs like '1-598868' do not resolve here.";

const MANAGED_BY_NOTE =
  "PROVIDER hands the case to Sophos MDR, CUSTOMER keeps it self managed. Cannot be changed after creation.";

const RN_NOTE = `Six section resource names (e.g. ${RESOURCE_NAME_EXAMPLE}), never bare UUIDs`;

const LAG_NOTE =
  "Reads lag writes by a few seconds: an evidence count read straight after this call may still show the previous number.";

const KNOWN_MENTION_GROUPS = ["@authorized_contacts", "@customer", "@sophos"];

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const MAX_FILE_LIST_PAGES = 20;

const tenantIdField = z
  .string()
  .uuid()
  .optional()
  .describe("Tenant ID. Required for partner/org callers.");

const severityField = z
  .union([z.number().int().min(2).max(10), z.enum(CASE_SEVERITY_NAMES)])
  .describe("Case severity: 2 informational, 4 low, 6 medium, 8 high, 10 critical (or the label)");

const managedByField = z.enum(["PROVIDER", "CUSTOMER"]).describe(MANAGED_BY_NOTE);

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const WRITE = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

const DESTRUCTIVE = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
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

Type, status and verdict are resolved to the tenant's own IDs at runtime (they depend on licensed services), so pass the name shown by sophos_fusion_list_case_reference_data or a UUID. Case severity is an integer: 2 informational, 4 low, 6 medium, 8 high, 10 critical. Legacy Sophos Central cases (IDs like '1-598868') are a separate case set and are not listed here; use sophos_list_cases for those on a tenant that has not migrated.

Raw QL example for the query parameter: "severity >= 8 and closedAt is null | sort updatedAt desc". Searchable fields: id, shortId, title, severity, riskScore, tags, assigneeId, createdAt, updatedAt, closedAt, closeReason, archivedAt, managedBy, typeId, primaryStatusId, primaryVerdictId. Names are not searchable, only IDs. Unassigned cases carry assigneeId '' rather than null, so unassigned compiles to (assigneeId is null or assigneeId = '').

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
  total, page info (has_next_page, end_cursor), the QL string used, and cases with id, short_id, title, severity, type, status, tags, assignee_id, managed_by, timestamps.`,
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
  The case with id, short_id, title, severity (2-10), type, status, verdict, managed_by, assignee_id (a Subject ID), key_findings, tags, links (with link ids for sophos_fusion_update_case_link), timestamps and evidence counts.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ case_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const { data, warnings } = await client
        .query<FusionCaseResponse>(tenantId, GET_CASE, { arguments: { id: resolved.id } })
        .catch((error: unknown) => rethrowNotFound(error, case_id, tenantId));
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

The detection_id, event_id, asset_id and search_query_id values are the source IDs, which is what sophos_fusion_remove_case_evidence needs (removal by any other id succeeds silently and removes nothing). Detection and event IDs are six section resource names. This is linkage only; sophos_fusion_get_case_summary resolves the detections to full records in one batched call.

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
      const { data, warnings } = await client
        .query<FusionCaseEvidenceResponse>(tenantId, GET_CASE_EVIDENCE, {
          arguments: { id: resolved.id },
        })
        .catch((error: unknown) => rethrowNotFound(error, case_id, tenantId));
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
  case (key findings capped at 4000 characters here; sophos_fusion_get_case returns the full text), evidence counts, detections_resolved vs detections_total, mitre_summary, then detections (id, title, severity_0_to_1, status, detector, entities, timestamps).`,
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

      // Two calls on purpose: case and caseEvidence in one document fail with
      // "conn busy" from investigations-v2 (see queries/cases.ts).
      const caseResult = await client
        .query<FusionCaseResponse>(tenantId, GET_CASE, { arguments: { id: resolved.id } })
        .catch((error: unknown) => rethrowNotFound(error, case_id, tenantId));
      warnings.push(...caseResult.warnings);
      if (!caseResult.data.case) {
        throw new Error(`Fusion case ${case_id} not found in tenant ${tenantId}.`);
      }

      const evidenceResult = await client.query<FusionCaseEvidenceResponse>(
        tenantId,
        GET_CASE_EVIDENCE,
        { arguments: { id: resolved.id } }
      );
      warnings.push(...evidenceResult.warnings);

      const evidence = evidenceResult.data.caseEvidence;
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

      // Order and size matter here: the response is capped at CHARACTER_LIMIT
      // and a real case's key findings alone ran to 20 KB, which pushed the
      // MITRE roll-up (last key) past the cap. Key findings are capped with a
      // pointer to sophos_fusion_get_case, and the roll-up precedes the list.
      return jsonResult(
        withWarnings(
          {
            case: capKeyFindings(formatCaseDetail(caseResult.data.case)),
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
            mitre_summary: mitreSummary,
            detections,
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

A case can carry a primary status ID that is not in this list: a tenant credential sees six statuses while case types list eight supported ones, and the two extra are provider-side statuses on Sophos MDR managed cases. Such an ID is reported raw, not as an error. A type whose managed_by is set (health_check, threat_hunt) pins who manages every case of that type. Cached per tenant for 15 minutes; pass refresh to bypass the cache after a licensing change.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - refresh (boolean, optional): Ignore the cache and fetch again.

Returns:
  types (id, name, title, managed_by, supported status and verdict IDs), primary_statuses (id, name, title, is_closed, is_case_visible_to_customers), primary_verdicts (id, name, title), fetched_at.`,
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
          is_case_visible_to_customers: s.isCaseVisibleToCustomers ?? null,
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
      description: `Create a case in Sophos Fusion. managed_by is required and decides who works the case: PROVIDER hands it to Sophos MDR, CUSTOMER keeps it self managed. It cannot be changed after creation, and a case created without it would be unclaimed, so this tool never omits it.

Case types health_check and threat_hunt always use PROVIDER; investigation and other leave the choice free. A managed_by that contradicts the type is refused before any call is made. Type and status are resolved from the tenant's reference data (name or UUID). When status is omitted a CUSTOMER case starts in new (or the first open status) and a PROVIDER case starts in awaiting_sophos_assignment when the tenant exposes it. Severity is 2, 4, 6, 8 or 10 (or its label). assignee_id is a Subject ID or an @mention (for example @customer or @sophos), never an email address. key_findings is Markdown and becomes the case's typed key findings document (the REST "overview"). Evidence attached at creation is recorded as genesis evidence; detection_ids and event_ids are six section resource names (sophos_fusion_search_detections returns them), and attaching a detection also attaches its linked asset and events.

The API has an intermittent fault on this call (roughly one in two attempts, "not allowed" on partnerPreferences). The client retries it up to 8 times before giving up; a failure that names createCase in its path is a genuine input error and is not retried.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - title (string): Case title, max 256 characters.
  - type (string): Case type name or UUID (see sophos_fusion_list_case_reference_data).
  - severity (number|string): 2 informational, 4 low, 6 medium, 8 high, 10 critical.
  - managed_by (string): PROVIDER or CUSTOMER. Required, no default, irreversible.
  - status (string, optional): Initial primary status name or UUID.
  - assignee_id (string, optional): Subject ID or @mention.
  - key_findings (string, optional): Markdown body.
  - tags (string[], optional): Labels.
  - detection_ids, event_ids (string[], optional): ${RN_NOTE}.
  - detections_search_query (string, optional): QL query whose matching detections (first 50k) are attached.
  - search_queries (string[], optional): Saved search IDs to attach (not executed).
  - host_ids (string[], optional): Host IDs whose assets to attach.

Returns:
  The created case (id, short_id, title, severity, type, status, managed_by, ...).`,
      inputSchema: {
        tenant_id: tenantIdField,
        title: z.string().min(1).max(256).describe("Case title (max 256 characters)"),
        type: z.string().describe("Case type name or UUID"),
        severity: severityField,
        managed_by: managedByField,
        status: z.string().optional().describe("Initial primary status name or UUID"),
        assignee_id: z.string().optional().describe("Subject ID or @mention, never an email"),
        key_findings: z.string().optional().describe("Key findings, Markdown"),
        tags: z.array(z.string()).optional().describe("Tags"),
        detection_ids: z.array(z.string()).optional().describe(`Detection IDs to attach. ${RN_NOTE}`),
        detections_search_query: z.string().optional().describe("QL query whose detections are attached"),
        event_ids: z.array(z.string()).optional().describe(`Event IDs to attach. ${RN_NOTE}`),
        search_queries: z.array(z.string()).optional().describe("Saved search IDs to attach"),
        host_ids: z.array(z.string()).optional().describe("Host IDs whose assets to attach"),
      },
      annotations: WRITE,
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const input = await buildCreateCaseInput(referenceData, tenantId, args);

      const { data, warnings } = await client
        .query<FusionCreateCaseResponse>(tenantId, CREATE_CASE, { input })
        .catch(rethrowWithHint);
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

Tags: the API replaces the whole tag list on every write, so this tool reads the current tags and merges yours in; pass replace_tags true to replace the list instead (tags [] with replace_tags true clears it). Closing: set status to a closed status (see is_closed in sophos_fusion_list_case_reference_data); when the case type supports verdicts one is required and the tool refuses with the valid names if none is given. Reopening: a closed case that holds a verdict cannot move to an open status while the verdict stands, so the tool clears the verdict in the same update. Once a case has left new it cannot return to it. A closed case is frozen apart from status, verdicts, secondary status, archive and secondary reasons. An archived case refuses every update until unarchived; pass archived false (alone or with other changes, which are applied after the unarchive). Archiving is applied last, after every other change in the same call, because an archived case cannot be edited. There is no delete in Fusion: close, then archive. managed_by cannot be changed after creation and is not accepted here. assignee_id is a Subject ID or @mention; an empty string clears the assignee.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - title (string, optional), severity (number|string, optional): 2, 4, 6, 8, 10 or label.
  - status (string, optional): Primary status name or UUID.
  - verdict (string, optional): Primary verdict name or UUID (required when closing a type that supports verdicts).
  - close_reason (string, optional): Free text recorded with a close.
  - assignee_id (string, optional): Subject ID or @mention; "" clears.
  - key_findings (string, optional): Markdown; replaces the key findings document.
  - tags (string[], optional): Tags to add (merged with the current list unless replace_tags is true).
  - replace_tags (boolean, optional, default false): Replace the tag list with tags instead of merging.
  - archived (boolean, optional): true archives a closed case, false unarchives.

Returns:
  The updated case, plus notes on anything the tool did on your behalf (verdict cleared, tags merged, order of operations).`,
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
        tags: z.array(z.string()).optional().describe("Tags to add (merged unless replace_tags)"),
        replace_tags: z.boolean().optional().default(false).describe("Replace the tag list instead of merging"),
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
      const notes: string[] = [];
      if (args.assignee_id) assertAssignee(args.assignee_id);

      const fields: Record<string, unknown> = {};
      if (args.title !== undefined) fields.title = args.title;
      if (args.severity !== undefined) fields.severity = normaliseCaseSeverity(args.severity);
      if (args.close_reason !== undefined) fields.closeReason = args.close_reason;
      if (args.assignee_id !== undefined) fields.assigneeId = args.assignee_id;
      if (args.key_findings !== undefined) fields.keyFindings = keyFindingsInput(args.key_findings);

      const status = args.status
        ? await referenceData.resolveStatus(tenantId, args.status)
        : undefined;
      if (status) fields.primaryStatusId = status.id;
      if (args.verdict !== undefined) {
        fields.primaryVerdictId = await referenceData.resolveVerdictId(tenantId, args.verdict);
      }

      if (Object.keys(fields).length === 0 && args.tags === undefined && args.archived === undefined) {
        throw new Error("Nothing to update: supply at least one field to change.");
      }

      // One read serves the tag merge, the reopen verdict clear, the one way
      // door on new and the archived check.
      let current: FusionCaseDetail | null = null;
      if (status || args.tags !== undefined || args.archived !== undefined) {
        const read = await client
          .query<FusionCaseResponse>(tenantId, GET_CASE, { arguments: { id: resolved.id } })
          .catch((error: unknown) => rethrowNotFound(error, args.case_id, tenantId));
        warnings.push(...read.warnings);
        current = read.data.case;
        if (!current) {
          throw new Error(`Fusion case ${args.case_id} not found in tenant ${tenantId}.`);
        }
      }

      if (args.tags !== undefined) {
        if (args.replace_tags) {
          fields.tags = args.tags;
        } else {
          fields.tags = mergeTags(current?.tags, args.tags);
          notes.push(`Tags merged with the existing list (${(current?.tags ?? []).length} existing); pass replace_tags true to replace it.`);
        }
      }

      if (current?.archivedAt && args.archived !== false) {
        throw new Error(
          "This case is archived and refuses every update. Pass archived false first (it can be combined with the other changes in one call; the unarchive is applied before them)."
        );
      }

      if (status && current) {
        const currentName = current.primaryStatus.name.toLowerCase();
        if (status.name.toLowerCase() === "new" && currentName !== "new") {
          throw new Error(
            `Fusion cannot move a case back to new once it has left it (current status ${current.primaryStatus.name}). Choose another open status.`
          );
        }
        if (status.isClosed && args.verdict === undefined) {
          // Verdict-on-close: Fusion rejects a close without a verdict when
          // the case type supports verdicts. Check first so the error names
          // the options.
          const verdicts = await client.query<FusionCasePrimaryVerdictsResponse>(
            tenantId,
            CASE_PRIMARY_VERDICTS_FOR,
            { arguments: { typeId: current.type.id, primaryStatusId: status.id } }
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
        if (!status.isClosed && current.primaryStatus.isClosed && current.primaryVerdict && args.verdict === undefined) {
          // A verdict cannot ride along into an open status; clearing it in
          // the same update is what unblocks the transition.
          fields.primaryVerdictId = null;
          notes.push(`Cleared the verdict ${current.primaryVerdict.name} because Fusion refuses to reopen a case that still holds one.`);
        }
      }

      const send = async (input: Record<string, unknown>): Promise<FusionCaseDetail> => {
        const result = await client
          .query<FusionUpdateCaseResponse>(tenantId, UPDATE_CASE, { input: { id: resolved.id, ...input } })
          .catch(rethrowWithHint);
        warnings.push(...result.warnings);
        if (!result.data.updateCase) {
          throw new Error("updateCase returned no case.");
        }
        return result.data.updateCase;
      };

      // Order: unarchive first (an archived case refuses everything), then
      // the field changes, then archive last (an archived case is frozen, so
      // a retitle after the archive would fail).
      let updated: FusionCaseDetail | null = null;
      const hasFields = Object.keys(fields).length > 0;
      if (args.archived === false) {
        updated = await send({ isArchived: false });
        if (hasFields) notes.push("Unarchived first, then applied the other changes.");
      }
      if (hasFields) {
        updated = await send(fields);
      }
      if (args.archived === true) {
        updated = await send({ isArchived: true });
        if (hasFields) notes.push("Applied the other changes first, then archived.");
      }
      if (!updated) {
        throw new Error("Nothing to update: supply at least one field to change.");
      }

      return jsonResult(
        withWarnings(
          { ...formatCaseDetail(updated), ...(notes.length > 0 ? { notes } : {}) },
          warnings
        )
      );
    })
  );

  // --- Split Case ---
  server.registerTool(
    "sophos_fusion_split_case",
    {
      title: "Split Fusion Case",
      description: `Move some of a Sophos Fusion case's evidence into a new case created by the same call. Destructive and irreversible: the named detections, events, saved searches and files leave the source case, and there is no unsplit and no delete for the new case. Requires confirm_split true.

The new case takes the same inputs as sophos_fusion_create_case, including the required new_managed_by (PROVIDER hands it to Sophos MDR, CUSTOMER keeps it self managed; cannot be changed later). At least one evidence list is required. Detection and event IDs are the source IDs shown by sophos_fusion_get_case_evidence. Evidence reads on both cases can lag for a few seconds after the split.

Args:
  - case_id (string): ${ID_NOTE} The source case.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - confirm_split (boolean): Must be true.
  - new_title (string), new_type (string), new_severity (number|string), new_managed_by (string): The new case, as for sophos_fusion_create_case.
  - new_status, new_assignee_id, new_key_findings, new_tags (optional): As for sophos_fusion_create_case.
  - detection_ids, event_ids (string[], optional): ${RN_NOTE}.
  - search_queries, file_ids (string[], optional): Saved search IDs and case file IDs to move.

Returns:
  source_case_id, destination_case_id, the destination case summary, and the IDs that moved.`,
      inputSchema: {
        case_id: z.string().describe(`${ID_NOTE} The source case.`),
        tenant_id: tenantIdField,
        confirm_split: z.boolean().describe("Must be true: the split moves evidence to a new case and cannot be undone"),
        new_title: z.string().min(1).max(256).describe("Title of the new case"),
        new_type: z.string().describe("Case type name or UUID for the new case"),
        new_severity: severityField,
        new_managed_by: managedByField,
        new_status: z.string().optional().describe("Initial primary status name or UUID for the new case"),
        new_assignee_id: z.string().optional().describe("Subject ID or @mention for the new case"),
        new_key_findings: z.string().optional().describe("Key findings for the new case, Markdown"),
        new_tags: z.array(z.string()).optional().describe("Tags for the new case"),
        detection_ids: z.array(z.string()).optional().describe(`Detection IDs to move. ${RN_NOTE}`),
        event_ids: z.array(z.string()).optional().describe(`Event IDs to move. ${RN_NOTE}`),
        search_queries: z.array(z.string()).optional().describe("Saved search IDs to move"),
        file_ids: z.array(z.string()).optional().describe("Case file IDs to move"),
      },
      annotations: DESTRUCTIVE,
    },
    withErrorHandling(async (args) => {
      if (args.confirm_split !== true) {
        throw new Error(
          "sophos_fusion_split_case moves evidence to a new case and cannot be undone. Re-run with confirm_split true to proceed."
        );
      }
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, args.case_id);
      const warnings = [...resolved.warnings];
      assertResourceNames("detection_ids", args.detection_ids);
      assertResourceNames("event_ids", args.event_ids);

      const moved: Record<string, string[]> = {};
      if (args.detection_ids?.length) moved.detectionIds = args.detection_ids;
      if (args.event_ids?.length) moved.eventIds = args.event_ids;
      if (args.search_queries?.length) moved.searchQueries = args.search_queries;
      if (args.file_ids?.length) moved.fileIds = args.file_ids;
      if (Object.keys(moved).length === 0) {
        throw new Error("Supply at least one of detection_ids, event_ids, search_queries or file_ids to move.");
      }

      const newCase = await buildCreateCaseInput(referenceData, tenantId, {
        title: args.new_title,
        type: args.new_type,
        severity: args.new_severity,
        managed_by: args.new_managed_by,
        status: args.new_status,
        assignee_id: args.new_assignee_id,
        key_findings: args.new_key_findings,
        tags: args.new_tags,
      });

      const { data, warnings: splitWarnings } = await client
        .query<FusionSplitCaseResponse>(tenantId, SPLIT_CASE, {
          input: { caseId: resolved.id, newCase, ...moved },
        })
        .catch(rethrowWithHint);
      warnings.push(...splitWarnings);
      const result = data.splitCase;
      if (!result) {
        throw new Error("splitCase returned no result.");
      }

      // The split has happened; a failed read-back of the new case is a warning.
      let destination: ReturnType<typeof formatCaseSummary> | null = null;
      try {
        const read = await client.query<FusionCaseResponse>(tenantId, GET_CASE, {
          arguments: { id: result.destinationCaseId },
        });
        warnings.push(...read.warnings);
        destination = read.data.case ? formatCaseSummary(read.data.case) : null;
      } catch (error) {
        warnings.push(
          `Split succeeded but the new case could not be read back: ${error instanceof Error ? error.message : String(error)}`
        );
      }

      return jsonResult(
        withWarnings(
          {
            source_case_id: result.caseId,
            destination_case_id: result.destinationCaseId,
            destination_case: destination,
            moved: {
              detection_ids: result.detectionIds ?? [],
              event_ids: result.eventIds ?? [],
              search_queries: result.searchQueries ?? [],
              file_ids: result.fileIds ?? [],
            },
            note: `The moved evidence now belongs to the destination case; the source keeps the rest. ${LAG_NOTE}`,
          },
          warnings
        )
      );
    })
  );

  // --- Merge Cases ---
  server.registerTool(
    "sophos_fusion_merge_cases",
    {
      title: "Merge Fusion Cases",
      description: `Merge one or more Sophos Fusion cases into a target case. Destructive and irreversible: the source cases' evidence is associated with the target and the sources are closed (and archived too when archive_sources is true). There is no unmerge. Requires confirm_merge true.

Asynchronous: the API returns a processing_event_id job handle and the effect landed within about 4 seconds in testing. The source cases keep their own evidence rows, so their counts do not drop. Reads lag writes, so re-read the target after a few seconds rather than straight away.

Args:
  - target_case_id (string): ${ID_NOTE} The case that is kept.
  - source_case_ids (string[]): One or more cases to merge into it (UUIDs or short IDs).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - confirm_merge (boolean): Must be true.
  - archive_sources (boolean, optional, default false): Also archive the closed sources.

Returns:
  target_case_id, source_case_ids, processing_event_id and status accepted.`,
      inputSchema: {
        target_case_id: z.string().describe(`${ID_NOTE} The case that is kept.`),
        source_case_ids: z.array(z.string()).min(1).describe("Cases to merge into the target"),
        tenant_id: tenantIdField,
        confirm_merge: z.boolean().describe("Must be true: the merge closes the sources and cannot be undone"),
        archive_sources: z.boolean().optional().default(false).describe("Also archive the merged sources"),
      },
      annotations: DESTRUCTIVE,
    },
    withErrorHandling(async ({ target_case_id, source_case_ids, tenant_id, confirm_merge, archive_sources }) => {
      if (confirm_merge !== true) {
        throw new Error(
          "sophos_fusion_merge_cases closes the source cases and cannot be undone. Re-run with confirm_merge true to proceed."
        );
      }
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const target = await resolveCaseUuid(client, tenantId, target_case_id);
      const warnings = [...target.warnings];
      const sourceIds: string[] = [];
      for (const ref of source_case_ids) {
        const source = await resolveCaseUuid(client, tenantId, ref);
        warnings.push(...source.warnings);
        if (!sourceIds.includes(source.id)) sourceIds.push(source.id);
      }
      if (sourceIds.includes(target.id)) {
        throw new Error("The target case cannot also be a source.");
      }

      const { data, warnings: mergeWarnings } = await client
        .query<FusionMergeCaseResponse>(tenantId, MERGE_CASES, {
          input: { targetCaseId: target.id, sourceCaseIds: sourceIds, archiveSources: archive_sources },
        })
        .catch(rethrowWithHint);
      warnings.push(...mergeWarnings);
      const result = data.mergeCase;
      if (!result) {
        throw new Error("mergeCase returned no result.");
      }
      return jsonResult(
        withWarnings(
          {
            status: "accepted",
            target_case_id: result.targetCaseId,
            source_case_ids: result.sourceCaseIds ?? sourceIds,
            archive_sources,
            processing_event_id: result.processingEventId,
            note: `Asynchronous: the source evidence is associated with the target and the sources are closed${archive_sources ? " and archived" : ""} in the background (about 4 seconds in testing). The sources keep their own evidence rows. This cannot be undone.`,
          },
          warnings
        )
      );
    })
  );

  // --- List Case Comments ---
  server.registerTool(
    "sophos_fusion_list_case_comments",
    {
      title: "List Fusion Case Comments",
      description: `List the comments on a Sophos Fusion case. Comments are the two way channel with the Sophos MDR analyst on a PROVIDER managed case; they had no REST equivalent.

author_id is a raw user or client UUID: the API cannot resolve it to a name for an API credential, so the ID is shown as is. mentions lists the group mentions that fired (@authorized_contacts, @customer, @sophos), leading @ kept.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - order (string, optional): "asc" or "desc" by createdAt (API default).
  - visibility (string, optional): "ALL" (default), "INTERNAL" (partner-only comments) or "NOT_INTERNAL".
  - author_ids (string[], optional): Only comments by these author IDs.
  - page (number, optional, default 1), per_page (number, optional, 1-100, default 25).

Returns:
  total, total_unread, comments (id, author_id, comment, is_internal, mentions, read_by_ids, timestamps).`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        order: z.enum(["asc", "desc"]).optional().describe("Sort by createdAt"),
        visibility: z
          .enum(["ALL", "INTERNAL", "NOT_INTERNAL"])
          .optional()
          .default("ALL")
          .describe("Comment visibility filter"),
        author_ids: z.array(z.string()).optional().describe("Only comments by these author IDs"),
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
    withErrorHandling(async ({ case_id, tenant_id, order, visibility, author_ids, page, per_page }) => {
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
            // PaginationOrder is ASCENDING or DESCENDING; "ASC" is not accepted.
            ...(order ? { orderBy: order === "asc" ? "ASCENDING" : "DESCENDING" } : {}),
            ...(author_ids?.length ? { authorIds: author_ids } : {}),
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
      description: `Add a comment to a Sophos Fusion case. On a PROVIDER managed case this is how you talk to the Sophos MDR analyst.

Mentions: three group tokens resolve, @authorized_contacts, @customer and @sophos. Every one that appears in the text fires, including a token that only appears in explanatory prose, so do not name a token unless you mean to notify that group. Matching is case insensitive and word initial (an email address cannot misfire one). An unrecognised token is dropped silently by the API with no error, which is why this tool reads the stored mentions back and reports mentions_resolved and mentions_unresolved: an unresolved token notified nobody. internal comments need a partner or MDR provider credential.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - comment (string): Comment text, may contain @mentions.
  - internal (boolean, optional): Mark internal (visible to partner users only). Partner credentials only.

Returns:
  The created comment with mentions_resolved (what actually fired) and mentions_unresolved (tokens in the text that the API dropped).`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        comment: z.string().min(1).describe("Comment text; @mentions notify groups"),
        internal: z.boolean().optional().describe("Internal (partner-only) comment"),
      },
      annotations: WRITE,
    },
    withErrorHandling(async ({ case_id, tenant_id, comment, internal }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const { data, warnings } = await client
        .query<FusionAddCaseCommentResponse>(tenantId, ADD_CASE_COMMENT, {
          input: { caseId: resolved.id, comment, ...(internal !== undefined ? { isInternal: internal } : {}) },
        })
        .catch(rethrowWithHint);
      if (!data.addCaseComment) {
        throw new Error("addCaseComment returned no comment.");
      }
      const mentions = reportMentions(comment, data.addCaseComment);
      return jsonResult(
        withWarnings(
          { ...formatComment(data.addCaseComment), ...mentions.fields },
          [...resolved.warnings, ...warnings, ...mentions.warnings]
        )
      );
    })
  );

  // --- Update Case Comment ---
  server.registerTool(
    "sophos_fusion_update_case_comment",
    {
      title: "Update Fusion Case Comment",
      description: `Edit the text of a Sophos Fusion case comment, mark it read, or both. Marking read is an update, not its own call.

A new text is re-parsed for @mentions with the same rules as sophos_fusion_add_case_comment (every recognised token fires, unrecognised ones are dropped silently), so the resolved and unresolved mentions are reported back.

Args:
  - comment_id (string): The comment ID from sophos_fusion_list_case_comments.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - comment (string, optional): New text.
  - mark_as_read (boolean, optional): Mark the comment read for the calling user.

Returns:
  The updated comment.`,
      inputSchema: {
        comment_id: z.string().describe("Comment ID"),
        tenant_id: tenantIdField,
        comment: z.string().min(1).optional().describe("New comment text"),
        mark_as_read: z.boolean().optional().describe("Mark read for the caller"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ comment_id, tenant_id, comment, mark_as_read }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      if (comment === undefined && mark_as_read === undefined) {
        throw new Error("Supply comment, mark_as_read or both.");
      }
      const input: Record<string, unknown> = { commentId: comment_id };
      if (comment !== undefined) input.comment = comment;
      if (mark_as_read !== undefined) input.markAsRead = mark_as_read;
      const { data, warnings } = await client
        .query<FusionUpdateCaseCommentResponse>(tenantId, UPDATE_CASE_COMMENT, { input })
        .catch(rethrowWithHint);
      if (!data.updateCaseComment) {
        throw new Error("updateCaseComment returned no comment.");
      }
      const mentions = comment !== undefined ? reportMentions(comment, data.updateCaseComment) : null;
      return jsonResult(
        withWarnings(
          { ...formatComment(data.updateCaseComment), ...(mentions?.fields ?? {}) },
          [...warnings, ...(mentions?.warnings ?? [])]
        )
      );
    })
  );

  // --- Delete Case Comment ---
  server.registerTool(
    "sophos_fusion_delete_case_comment",
    {
      title: "Delete Fusion Case Comment",
      description: `Delete a comment from a Sophos Fusion case. Cannot be undone.

Args:
  - comment_id (string): The comment ID from sophos_fusion_list_case_comments.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status deleted and the comment as it was, when the API returns it.`,
      inputSchema: {
        comment_id: z.string().describe("Comment ID"),
        tenant_id: tenantIdField,
      },
      annotations: { ...DESTRUCTIVE, idempotentHint: true },
    },
    withErrorHandling(async ({ comment_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<FusionDeleteCaseCommentResponse>(tenantId, DELETE_CASE_COMMENT, {
          input: { commentId: comment_id },
        })
        .catch(rethrowWithHint);
      return jsonResult(
        withWarnings(
          {
            status: "deleted",
            comment_id,
            comment: data.deleteCaseComment ? formatComment(data.deleteCaseComment) : null,
          },
          warnings
        )
      );
    })
  );

  // --- Add Case Evidence ---
  server.registerTool(
    "sophos_fusion_add_case_evidence",
    {
      title: "Add Fusion Case Evidence",
      description: `Attach detections, events, hosts (assets) or saved searches to an existing Sophos Fusion case. Evidence added this way is not genesis evidence.

Detection and event IDs are six section resource names, for example ${RESOURCE_NAME_EXAMPLE}; bare UUIDs are refused here before any call. sophos_fusion_search_detections returns detection IDs in this form. Attaching one detection also attaches its linked asset and events (one detection added 1 asset and 2 events in testing), and removing the detection later does not retract them. ${LAG_NOTE} The case must be open: a closed case refuses evidence writes. The API has an intermittent fault on this call (roughly one in two attempts); the client retries it up to 8 times.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - detection_ids, event_ids (string[], optional): ${RN_NOTE}.
  - detections_search_query (string, optional): QL query whose matching detections are attached.
  - host_ids (string[], optional): Host IDs whose assets to attach.
  - search_queries (string[], optional): Saved search IDs to attach (not executed).
  At least one of these is required.

Returns:
  What the service accepted for attachment.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        detection_ids: z.array(z.string()).optional().describe(`Detection IDs. ${RN_NOTE}`),
        detections_search_query: z.string().optional().describe("QL query whose detections are attached"),
        event_ids: z.array(z.string()).optional().describe(`Event IDs. ${RN_NOTE}`),
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
      assertResourceNames("detection_ids", args.detection_ids);
      assertResourceNames("event_ids", args.event_ids);
      const input: Record<string, unknown> = { caseId: resolved.id };
      if (args.detection_ids?.length) input.detectionIds = args.detection_ids;
      if (args.detections_search_query) input.detectionsSearchQuery = args.detections_search_query;
      if (args.event_ids?.length) input.eventIds = args.event_ids;
      if (args.host_ids?.length) input.hostIds = args.host_ids;
      if (args.search_queries?.length) input.searchQueries = args.search_queries;
      if (Object.keys(input).length === 1) {
        throw new Error(
          "Supply at least one of detection_ids, detections_search_query, event_ids, host_ids or search_queries."
        );
      }
      const { data, warnings } = await client
        .query<FusionAddEvidenceResponse>(tenantId, ADD_EVIDENCE_TO_CASE, { input })
        .catch(rethrowWithHint);
      const result = data.addEvidenceToCase;
      if (!result) {
        throw new Error("addEvidenceToCase returned no result.");
      }
      return jsonResult(
        withWarnings(
          {
            status: "accepted",
            note: `Evidence is attached in the background. A detection brings its linked asset and events with it. ${LAG_NOTE} Check processing_status on sophos_fusion_get_case or re-read sophos_fusion_get_case_evidence after a few seconds.`,
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
      description: `Detach detections, events, assets or saved searches from a Sophos Fusion case, or everything with remove_all.

Pass the SOURCE IDs as shown by sophos_fusion_get_case_evidence (detection_id, event_id, asset_id, search_query_id). The API accepts any ID and reports success, but only source IDs remove anything: an evidence entry ID is a silent no-op. Detection and event source IDs are six section resource names and are checked here; asset IDs are plain UUIDs (asset_ids, not host IDs) and cannot be checked. Removing a detection does not retract the asset and events that were attached with it; remove_all enumerates the case evidence and removes every category explicitly, which is the reliable way to empty a case. ${LAG_NOTE} A closed case refuses evidence writes.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - detection_ids, event_ids (string[], optional): ${RN_NOTE}.
  - asset_ids (string[], optional): Asset source IDs from sophos_fusion_get_case_evidence.
  - search_queries (string[], optional): Saved search IDs.
  - remove_all (boolean, optional): Remove every piece of evidence on the case. Cannot be combined with the ID lists.

Returns:
  What the service accepted for removal.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        detection_ids: z.array(z.string()).optional().describe(`Detection source IDs. ${RN_NOTE}`),
        event_ids: z.array(z.string()).optional().describe(`Event source IDs. ${RN_NOTE}`),
        asset_ids: z.array(z.string()).optional().describe("Asset source IDs (asset_id from get_case_evidence)"),
        search_queries: z.array(z.string()).optional().describe("Saved search IDs"),
        remove_all: z.boolean().optional().describe("Remove every piece of evidence on the case"),
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
      const warnings = [...resolved.warnings];
      const input: Record<string, unknown> = { caseId: resolved.id };
      const explicit = [args.detection_ids, args.event_ids, args.asset_ids, args.search_queries].some(
        (list) => list && list.length > 0
      );

      if (args.remove_all) {
        if (explicit) {
          throw new Error("remove_all cannot be combined with detection_ids, event_ids, asset_ids or search_queries.");
        }
        const read = await client
          .query<FusionCaseEvidenceResponse>(tenantId, GET_CASE_EVIDENCE, { arguments: { id: resolved.id } })
          .catch((error: unknown) => rethrowNotFound(error, args.case_id, tenantId));
        warnings.push(...read.warnings);
        const evidence = read.data.caseEvidence;
        if (!evidence) {
          throw new Error(`Fusion case ${args.case_id} not found in tenant ${tenantId}.`);
        }
        const detectionIds = (evidence.detectionsEvidence ?? []).map((d) => d.detectionId);
        const eventIds = (evidence.eventsEvidence ?? []).map((e) => e.eventId);
        const assetIds = (evidence.assetsEvidence ?? []).map((a) => a.assetId);
        const searchQueries = (evidence.searchQueriesEvidence ?? []).map((s) => s.searchQueryId);
        if (detectionIds.length) input.detectionIds = detectionIds;
        if (eventIds.length) input.eventIds = eventIds;
        if (assetIds.length) input.assetIds = assetIds;
        if (searchQueries.length) input.searchQueries = searchQueries;
        if (Object.keys(input).length === 1) {
          return jsonResult(
            withWarnings({ status: "nothing_to_remove", case_id: resolved.id, note: "The case holds no evidence." }, warnings)
          );
        }
      } else {
        assertResourceNames("detection_ids", args.detection_ids);
        assertResourceNames("event_ids", args.event_ids);
        if (args.detection_ids?.length) input.detectionIds = args.detection_ids;
        if (args.event_ids?.length) input.eventIds = args.event_ids;
        if (args.asset_ids?.length) input.assetIds = args.asset_ids;
        if (args.search_queries?.length) input.searchQueries = args.search_queries;
        if (Object.keys(input).length === 1) {
          throw new Error(
            "Supply at least one of detection_ids, event_ids, asset_ids or search_queries, or remove_all."
          );
        }
      }

      const { data, warnings: removeWarnings } = await client
        .query<FusionRemoveEvidenceResponse>(tenantId, REMOVE_EVIDENCE_FROM_CASE, { input })
        .catch(rethrowWithHint);
      warnings.push(...removeWarnings);
      const result = data.removeEvidenceFromCase;
      if (!result) {
        throw new Error("removeEvidenceFromCase returned no result.");
      }
      return jsonResult(
        withWarnings(
          {
            status: "accepted",
            note: `Evidence is removed in the background. ${LAG_NOTE} Re-read sophos_fusion_get_case_evidence after a few seconds to confirm; removing a detection leaves the asset and events it brought in place unless they are removed too.`,
            case_id: result.caseId,
            detection_ids: result.detectionIds ?? (input.detectionIds as string[] | undefined) ?? [],
            event_ids: result.eventIds ?? (input.eventIds as string[] | undefined) ?? [],
            asset_ids: result.assetIds ?? (input.assetIds as string[] | undefined) ?? [],
            search_queries: result.searchQueries ?? (input.searchQueries as string[] | undefined) ?? [],
          },
          warnings
        )
      );
    })
  );

  // --- List Case Files ---
  server.registerTool(
    "sophos_fusion_list_case_files",
    {
      title: "List Fusion Case Files",
      description: `List the files attached to a Sophos Fusion case, or every file in the tenant when case_id is omitted.

The API lists files tenant wide with no case filter, so with case_id the tool walks the list (up to 2000 files) and keeps the rows for that case. Deleted files stay in the list with status DELETED because deletion is soft; they are hidden unless include_deleted is true. Download URLs are presigned and valid about 15 minutes, and requesting one on a non-embedded file writes an audit log entry, so they are only selected when include_download_urls is true.

Args:
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - case_id (string, optional): ${ID_NOTE}
  - include_deleted (boolean, optional, default false): Show soft-deleted files too.
  - include_download_urls (boolean, optional, default false): Select download_url on each file.
  - page (number, optional, default 1), per_page (number, optional, 1-100, default 50): Tenant-wide paging, used only when case_id is omitted.

Returns:
  files (id, case_id, name, size, status, content_type, is_embedded, uploader, timestamps, download_url on request), tenant_total_files, and how many deleted rows were hidden.`,
      inputSchema: {
        tenant_id: tenantIdField,
        case_id: z.string().optional().describe(ID_NOTE),
        include_deleted: z.boolean().optional().default(false).describe("Include soft-deleted files"),
        include_download_urls: z.boolean().optional().default(false).describe("Select presigned download URLs"),
        page: z.number().int().min(1).optional().default(1).describe("Page (tenant-wide listing only)"),
        per_page: z
          .number()
          .int()
          .min(1)
          .max(MAX_PAGE_SIZE)
          .optional()
          .default(DEFAULT_PAGE_SIZE)
          .describe("Results per page (tenant-wide listing only, max 100)"),
      },
      annotations: READ_ONLY,
    },
    withErrorHandling(async ({ tenant_id, case_id, include_deleted, include_download_urls, page, per_page }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const document = include_download_urls ? LIST_CASE_FILES_WITH_URLS : LIST_CASE_FILES;
      const warnings: string[] = [];
      const files: FusionCaseFile[] = [];
      let totalCount = 0;
      let scanned = 0;
      let caseUuid: string | null = null;

      if (case_id) {
        const resolved = await resolveCaseUuid(client, tenantId, case_id);
        warnings.push(...resolved.warnings);
        caseUuid = resolved.id;
        for (let p = 1; p <= MAX_FILE_LIST_PAGES; p++) {
          const { data, warnings: pageWarnings } = await client.query<FusionCaseFilesResponse>(
            tenantId,
            document,
            { arguments: { page: p, perPage: MAX_PAGE_SIZE } }
          );
          warnings.push(...pageWarnings);
          const rows = data.caseFiles?.files ?? [];
          totalCount = data.caseFiles?.totalCount ?? totalCount;
          scanned += rows.length;
          files.push(...rows.filter((f) => f.caseId === caseUuid));
          if (rows.length < MAX_PAGE_SIZE || scanned >= totalCount) break;
          if (p === MAX_FILE_LIST_PAGES) {
            warnings.push(
              `Stopped after ${scanned} of ${totalCount} tenant files; files for this case beyond that point are not shown.`
            );
          }
        }
      } else {
        const { data, warnings: pageWarnings } = await client.query<FusionCaseFilesResponse>(
          tenantId,
          document,
          { arguments: { page, perPage: per_page } }
        );
        warnings.push(...pageWarnings);
        files.push(...(data.caseFiles?.files ?? []));
        totalCount = data.caseFiles?.totalCount ?? 0;
        scanned = files.length;
      }

      const visible = include_deleted ? files : files.filter((f) => !isDeletedFile(f));
      return jsonResult(
        withWarnings(
          {
            tenant_id: tenantId,
            case_id: caseUuid,
            tenant_total_files: totalCount,
            scanned,
            returned: visible.length,
            deleted_hidden: files.length - visible.length,
            ...(caseUuid ? {} : { page, per_page }),
            files: visible.map(formatFile),
          },
          warnings
        )
      );
    })
  );

  // --- Upload Case File ---
  server.registerTool(
    "sophos_fusion_upload_case_file",
    {
      title: "Upload Fusion Case File",
      description: `Attach a file to a Sophos Fusion case: registers the upload, PUTs the bytes to the presigned URL the API returns, then polls until the file status leaves SCHEDULED (it reached UPLOADED within about 3 seconds in testing).

Supply exactly one of content (text, stored as UTF-8), content_base64 (binary) or file_path (a file on the machine running this MCP server). name is required unless file_path is given. content_type defaults from the file extension. Files are limited to 50 MB. Deleting a file later is a soft delete.

Args:
  - case_id (string): ${ID_NOTE}
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - name (string, optional): File name as it should appear on the case.
  - content (string, optional): Text content.
  - content_base64 (string, optional): Binary content, base64.
  - file_path (string, optional): Local path to read.
  - content_type (string, optional): MIME type; guessed from the name when omitted.
  - embedded (boolean, optional, default false): Mark the file as embedded content (for images used in key findings).

Returns:
  The file record (id, name, size, status, content_type) and upload_status.`,
      inputSchema: {
        case_id: z.string().describe(ID_NOTE),
        tenant_id: tenantIdField,
        name: z.string().min(1).optional().describe("File name on the case"),
        content: z.string().optional().describe("Text content (UTF-8)"),
        content_base64: z.string().optional().describe("Binary content, base64"),
        file_path: z.string().optional().describe("Local file path on the MCP server host"),
        content_type: z.string().optional().describe("MIME type (guessed from the name when omitted)"),
        embedded: z.boolean().optional().default(false).describe("Embedded content (images in key findings)"),
      },
      annotations: WRITE,
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const sources = [args.content, args.content_base64, args.file_path].filter((v) => v !== undefined).length;
      if (sources !== 1) {
        throw new Error("Supply exactly one of content, content_base64 or file_path.");
      }
      const name = args.name ?? (args.file_path ? basename(args.file_path) : undefined);
      if (!name) {
        throw new Error("name is required unless file_path is given.");
      }

      let bytes: Uint8Array;
      if (args.content !== undefined) {
        bytes = Buffer.from(args.content, "utf8");
      } else if (args.content_base64 !== undefined) {
        bytes = Buffer.from(args.content_base64, "base64");
      } else {
        bytes = await readFile(args.file_path!).catch((error: NodeJS.ErrnoException) => {
          throw new Error(`Could not read ${args.file_path}: ${error.message}`);
        });
      }
      if (bytes.byteLength === 0) {
        throw new Error("The file is empty; nothing to upload.");
      }
      if (bytes.byteLength > MAX_UPLOAD_BYTES) {
        throw new Error(`The file is ${bytes.byteLength} bytes; the limit here is ${MAX_UPLOAD_BYTES} bytes.`);
      }
      const contentType = args.content_type ?? guessContentType(name);

      const resolved = await resolveCaseUuid(client, tenantId, args.case_id);
      const warnings = [...resolved.warnings];
      const start = await client
        .query<FusionStartCaseFileUploadResponse>(tenantId, START_CASE_FILE_UPLOAD, {
          input: { caseId: resolved.id, name, size: bytes.byteLength, contentType, isEmbedded: args.embedded },
        })
        .catch(rethrowWithHint);
      warnings.push(...start.warnings);
      const upload = start.data.startCaseFileUpload;
      if (!upload) {
        throw new Error("startCaseFileUpload returned no upload.");
      }

      // The presigned URL is never returned or logged: it grants a write.
      await client.putPresigned(upload.presignedUrl, bytes, contentType);

      let file = upload.file;
      for (let i = 0; i < 5 && file.status === "SCHEDULED"; i++) {
        await sleep(1500);
        try {
          const read = await client.query<FusionCaseFileResponse>(tenantId, GET_CASE_FILE, {
            arguments: { fileId: file.id },
          });
          warnings.push(...read.warnings);
          if (read.data.caseFile) file = read.data.caseFile;
        } catch (error) {
          warnings.push(
            `Upload sent but the file status could not be read back: ${error instanceof Error ? error.message : String(error)}`
          );
          break;
        }
      }

      return jsonResult(
        withWarnings(
          {
            ...formatFile(file),
            upload_bytes: bytes.byteLength,
            upload_status: file.status,
            note:
              file.status === "UPLOADED"
                ? "Upload complete."
                : `The bytes were sent but the file status still read ${file.status}; re-check with sophos_fusion_list_case_files in a few seconds.`,
          },
          warnings
        )
      );
    })
  );

  // --- Delete Case File ---
  server.registerTool(
    "sophos_fusion_delete_case_file",
    {
      title: "Delete Fusion Case File",
      description: `Delete a file from a Sophos Fusion case. This is a SOFT delete: the row stays in the file list with status DELETED and a deleted_at, and the tenant file count does not drop. sophos_fusion_list_case_files hides deleted files unless include_deleted is true. Cannot be undone.

Args:
  - file_id (string): The file ID from sophos_fusion_list_case_files.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status deleted and the file record as returned by the API.`,
      inputSchema: {
        file_id: z.string().describe("Case file ID"),
        tenant_id: tenantIdField,
      },
      annotations: { ...DESTRUCTIVE, idempotentHint: true },
    },
    withErrorHandling(async ({ file_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<FusionDeleteCaseFileResponse>(tenantId, DELETE_CASE_FILE, { input: { fileId: file_id } })
        .catch(rethrowWithHint);
      return jsonResult(
        withWarnings(
          {
            status: "deleted",
            file_id,
            note: "Soft delete: the file remains listed with status DELETED (hidden by default in sophos_fusion_list_case_files) and the tenant file count does not drop.",
            file: data.deleteCaseFile ? formatFile(data.deleteCaseFile) : null,
          },
          warnings
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

internal true needs a partner or MDR provider credential; a tenant credential is refused. The link ID in the result is what sophos_fusion_update_case_link and sophos_fusion_delete_case_link take.

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
        internal: z.boolean().optional().describe("Internal-only link (partner credentials)"),
      },
      annotations: WRITE,
    },
    withErrorHandling(async ({ case_id, tenant_id, url, title, type, reference, internal }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const resolved = await resolveCaseUuid(client, tenantId, case_id);
      const input: Record<string, unknown> = { caseId: resolved.id, url };
      if (title !== undefined) input.title = title;
      if (type !== undefined) input.type = type;
      if (reference !== undefined) input.reference = reference;
      if (internal !== undefined) input.isInternal = internal;
      const { data, warnings } = await client
        .query<FusionCreateCaseLinkResponse>(tenantId, CREATE_CASE_LINK, { input })
        .catch(rethrowWithHint);
      if (!data.createCaseLink) {
        throw new Error("createCaseLink returned no link.");
      }
      return jsonResult(
        withWarnings(
          { ...formatLink(data.createCaseLink), case_id: resolved.id },
          [...resolved.warnings, ...warnings]
        )
      );
    })
  );

  // --- Update Case Link ---
  server.registerTool(
    "sophos_fusion_update_case_link",
    {
      title: "Update Fusion Case Link",
      description: `Change the URL, title, type, reference or internal flag of an existing Sophos Fusion case link. Only the fields supplied change.

Args:
  - link_id (string): The link ID (from sophos_fusion_get_case links or sophos_fusion_create_case_link).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.
  - url, title, type, reference (string, optional), internal (boolean, optional): New values. internal true needs a partner or MDR provider credential.

Returns:
  The updated link.`,
      inputSchema: {
        link_id: z.string().describe("Case link ID"),
        tenant_id: tenantIdField,
        url: z.string().url().optional().describe("New URL"),
        title: z.string().optional().describe("New display title"),
        type: z.string().optional().describe("New linked system name"),
        reference: z.string().optional().describe("New ID in the linked system"),
        internal: z.boolean().optional().describe("Internal-only link (partner credentials)"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async ({ link_id, tenant_id, url, title, type, reference, internal }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const input: Record<string, unknown> = { id: link_id };
      if (url !== undefined) input.url = url;
      if (title !== undefined) input.title = title;
      if (type !== undefined) input.type = type;
      if (reference !== undefined) input.reference = reference;
      if (internal !== undefined) input.isInternal = internal;
      if (Object.keys(input).length === 1) {
        throw new Error("Nothing to update: supply at least one of url, title, type, reference or internal.");
      }
      const { data, warnings } = await client
        .query<FusionUpdateCaseLinkResponse>(tenantId, UPDATE_CASE_LINK, { input })
        .catch(rethrowWithHint);
      if (!data.updateCaseLink) {
        throw new Error("updateCaseLink returned no link.");
      }
      return jsonResult(withWarnings(formatLink(data.updateCaseLink), warnings));
    })
  );

  // --- Delete Case Link ---
  server.registerTool(
    "sophos_fusion_delete_case_link",
    {
      title: "Delete Fusion Case Link",
      description: `Remove a link from a Sophos Fusion case. Cannot be undone.

Args:
  - link_id (string): The link ID (from sophos_fusion_get_case links).
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  status deleted and the link as it was, when the API returns it.`,
      inputSchema: {
        link_id: z.string().describe("Case link ID"),
        tenant_id: tenantIdField,
      },
      annotations: { ...DESTRUCTIVE, idempotentHint: true },
    },
    withErrorHandling(async ({ link_id, tenant_id }) => {
      const tenantId = tenantResolver.resolveTenantId(tenant_id);
      const { data, warnings } = await client
        .query<FusionDeleteCaseLinkResponse>(tenantId, DELETE_CASE_LINK, { input: { id: link_id } })
        .catch(rethrowWithHint);
      return jsonResult(
        withWarnings(
          { status: "deleted", link_id, link: data.deleteCaseLink ? formatLink(data.deleteCaseLink) : null },
          warnings
        )
      );
    })
  );
}

// --- Helpers ---

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
      `${value} looks like a Classic (legacy) Sophos Central case ID. Fusion holds a separate case set and legacy IDs do not resolve here. Use sophos_get_case for legacy cases on a tenant that has not migrated.`
    );
  }

  throw new Error(
    `Unrecognised case ID ${JSON.stringify(value)}. Expected a Fusion case UUID or a short ID like CSE00001.`
  );
}

/**
 * Fusion reports an unknown case as a GraphQL error ("record not found")
 * beside a null root field, so the client throws before the tool's own null
 * check runs. Translate it into the message the tool promises; rethrow
 * anything else untouched.
 */
function rethrowNotFound(error: unknown, caseRef: string, tenantId: string): never {
  if (error instanceof FusionGraphQLError && error.notFound) {
    throw new Error(`Fusion case ${caseRef} not found in tenant ${tenantId}.`);
  }
  throw error;
}

/**
 * Server-side lifecycle refusals, each with what to do about it. The API's
 * own wording is kept; the hint is appended.
 */
const CASE_WRITE_HINTS: Array<[RegExp, string]> = [
  [
    /closed primary status/i,
    "The case is closed: only status, verdicts, secondary status, secondary reasons and archive can change, and evidence writes are refused. Reopen it first (sophos_fusion_update_case with an open status).",
  ],
  [
    /archived investigations cannot be updated/i,
    "The case is archived and refuses every update. Unarchive it first (sophos_fusion_update_case with archived false), then retry.",
  ],
  [
    /primary verdict is not valid for provided case primary status/i,
    "A verdict cannot be carried into an open status. Omit verdict when reopening and the tool clears it for you.",
  ],
  [
    /invalid rn format/i,
    `Detection and event IDs are six section resource names like ${RESOURCE_NAME_EXAMPLE}, not bare UUIDs.`,
  ],
  [
    /only partner or MDR provider users can set isInternal/i,
    "internal true needs a partner or MDR provider credential; omit it or pass false.",
  ],
];

function rethrowWithHint(error: unknown): never {
  if (error instanceof Error) {
    const hint = CASE_WRITE_HINTS.find(([pattern]) => pattern.test(error.message))?.[1];
    if (hint) {
      const wrapped = new Error(`${error.message}. ${hint}`);
      wrapped.name = error.name;
      throw wrapped;
    }
  }
  throw error;
}

function assertAssignee(assigneeId: string | undefined): void {
  if (assigneeId && looksLikeEmail(assigneeId)) {
    throw new Error(
      `assignee_id must be a Subject ID or an @mention, not an email address (got ${assigneeId}). Look the user up first; the developer portal points at the Users API (sophos_list_users) for tenant user IDs.`
    );
  }
}

function assertResourceNames(field: string, values: string[] | undefined): void {
  const rejected = (values ?? []).filter((value) => !isResourceName(value));
  if (rejected.length > 0) {
    throw new Error(
      `${field} must be six section resource names (for example ${RESOURCE_NAME_EXAMPLE}), not bare UUIDs or evidence entry IDs. Rejected: ${rejected.join(", ")}. sophos_fusion_search_detections and sophos_fusion_get_case_evidence return IDs in the right form.`
    );
  }
}

interface NewCaseArgs {
  title: string;
  type: string;
  severity: number | string;
  managed_by: "PROVIDER" | "CUSTOMER";
  status?: string;
  assignee_id?: string;
  key_findings?: string;
  tags?: string[];
  detection_ids?: string[];
  detections_search_query?: string;
  event_ids?: string[];
  search_queries?: string[];
  host_ids?: string[];
}

/** CreateCaseInput for createCase and for splitCase's newCase. managedBy is always sent. */
async function buildCreateCaseInput(
  referenceData: CaseReferenceDataCache,
  tenantId: string,
  args: NewCaseArgs
): Promise<Record<string, unknown>> {
  assertAssignee(args.assignee_id);
  assertResourceNames("detection_ids", args.detection_ids);
  assertResourceNames("event_ids", args.event_ids);

  const typeId = await referenceData.resolveTypeId(tenantId, args.type);
  const { types } = await referenceData.get(tenantId);
  const type = types.find((t) => t.id === typeId);
  if (type?.managedBy && type.managedBy !== args.managed_by) {
    throw new Error(
      `Case type ${type.name} is always managed by ${type.managedBy}; managed_by ${args.managed_by} contradicts it and the API would refuse. Pass managed_by ${type.managedBy}, or use a type that leaves it free (investigation, other).`
    );
  }

  const primaryStatusId = args.status
    ? await referenceData.resolveStatusId(tenantId, args.status)
    : await defaultOpenStatusId(referenceData, tenantId, args.managed_by);

  const input: Record<string, unknown> = {
    title: args.title,
    typeId,
    severity: normaliseCaseSeverity(args.severity),
    primaryStatusId,
    managedBy: args.managed_by,
  };
  if (args.assignee_id) input.assigneeId = args.assignee_id;
  if (args.key_findings !== undefined) input.keyFindings = keyFindingsInput(args.key_findings);
  if (args.tags) input.tags = args.tags;
  if (args.detection_ids?.length) input.detectionIds = args.detection_ids;
  if (args.detections_search_query) input.detectionsSearchQuery = args.detections_search_query;
  if (args.event_ids?.length) input.eventIds = args.event_ids;
  if (args.search_queries?.length) input.searchQueries = args.search_queries;
  if (args.host_ids?.length) input.hostIds = args.host_ids;
  return input;
}

/**
 * Initial status when the caller gives none. A PROVIDER case goes to the
 * Sophos MDR queue, whose entry status is awaiting_sophos_assignment where the
 * tenant exposes it; otherwise, and for CUSTOMER cases, new (or open, or the
 * first open status).
 */
async function defaultOpenStatusId(
  referenceData: CaseReferenceDataCache,
  tenantId: string,
  managedBy: "PROVIDER" | "CUSTOMER"
): Promise<string> {
  const { primaryStatuses } = await referenceData.get(tenantId);
  const open = primaryStatuses.filter((s) => !s.isClosed);
  const byName = (name: string) => open.find((s) => s.name.toUpperCase() === name);
  const preferred =
    (managedBy === "PROVIDER" ? byName("AWAITING_SOPHOS_ASSIGNMENT") : undefined) ??
    byName("NEW") ??
    byName("OPEN") ??
    open[0];
  if (!preferred) {
    throw new Error(
      "This tenant exposes no open case status; pass status explicitly (see sophos_fusion_list_case_reference_data)."
    );
  }
  return preferred.id;
}

/** documentVersion must be exactly "1.0"; "1.0.0" is rejected. */
function keyFindingsInput(content: string) {
  return { documentType: "MARKDOWN", documentVersion: "1.0", content };
}

/**
 * Compares the tokens a comment would fire with what the API stored. An
 * unrecognised token is dropped silently by the API, so this is the only way
 * a caller learns that a mention notified nobody.
 */
function reportMentions(text: string, stored: FusionCaseComment) {
  const requested = parseMentionTokens(text);
  const resolved = (stored.mentionsIds ?? []).map((id) => id.toLowerCase());
  const unresolved = requested.filter((token) => !resolved.includes(token));
  const warnings =
    unresolved.length > 0
      ? [
          `These @mentions did not resolve and notified nobody: ${unresolved.join(", ")}. Known group tokens: ${KNOWN_MENTION_GROUPS.join(", ")}.`,
        ]
      : [];
  return {
    fields: { mentions_resolved: stored.mentionsIds ?? [], mentions_unresolved: unresolved },
    warnings,
  };
}

const CONTENT_TYPES: Record<string, string> = {
  ".txt": "text/plain",
  ".log": "text/plain",
  ".md": "text/markdown",
  ".csv": "text/csv",
  ".json": "application/json",
  ".xml": "application/xml",
  ".html": "text/html",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".zip": "application/zip",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

function guessContentType(name: string): string {
  return CONTENT_TYPES[extname(name).toLowerCase()] ?? "application/octet-stream";
}

function isDeletedFile(f: FusionCaseFile): boolean {
  return f.status === "DELETED" || Boolean(f.deletedAt);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const SUMMARY_KEY_FINDINGS_CHARS = 4000;

/** Caps key findings in the summary; sophos_fusion_get_case returns the full text. */
function capKeyFindings<T extends { key_findings: { document_type: string; content: string } | null }>(
  detail: T
): T & { key_findings_truncated?: boolean } {
  const content = detail.key_findings?.content;
  if (!content || content.length <= SUMMARY_KEY_FINDINGS_CHARS) return detail;
  return {
    ...detail,
    key_findings: {
      ...detail.key_findings!,
      content: `${content.slice(0, SUMMARY_KEY_FINDINGS_CHARS)}\n\n[truncated at ${SUMMARY_KEY_FINDINGS_CHARS} of ${content.length} characters; sophos_fusion_get_case returns the full key findings]`,
    },
    key_findings_truncated: true,
  };
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
    links: (c.links ?? []).map(formatLink),
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

function formatLink(l: FusionCaseLink) {
  return {
    id: l.id,
    url: l.url,
    title: l.title,
    type: l.type,
    reference: l.reference,
    is_internal: l.isInternal,
    created_at: l.createdAt,
  };
}

function formatFile(f: FusionCaseFile) {
  return {
    id: f.id,
    case_id: f.caseId,
    name: f.name,
    size: f.size,
    status: f.status,
    content_type: f.metadata?.contentType ?? null,
    content_md5: f.metadata?.contentMD5 ?? null,
    is_embedded: f.isEmbedded,
    uploaded_by_id: f.uploadedById,
    created_at: f.createdAt,
    updated_at: f.updatedAt,
    deleted_at: f.deletedAt ?? null,
    deleted_by_id: f.deletedById || null,
    ...(f.downloadURL !== undefined
      ? { download_url: f.downloadURL, download_url_note: "Presigned, valid about 15 minutes" }
      : {}),
  };
}

/** The source IDs on each entry are what removeEvidenceFromCase takes. */
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

function formatComment(c: FusionCaseComment) {
  return {
    id: c.id,
    author_id: c.authorId,
    comment: c.comment,
    is_internal: c.isInternal,
    mentions: c.mentionsIds ?? [],
    read_by_ids: c.readByIds ?? [],
    created_at: c.createdAt,
    updated_at: c.updatedAt,
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
