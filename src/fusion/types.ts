/**
 * Response types for the Sophos Fusion GraphQL APIs, limited to the fields the
 * query documents in src/fusion/queries/ select. The full schemas are vendored
 * under schemas/fusion/.
 */

// --- Cases v2 ---

export interface FusionReferenceItem {
  id: string;
  name: string;
  title: string | null;
}

export interface FusionCaseType extends FusionReferenceItem {
  managedBy: "PROVIDER" | "CUSTOMER" | null;
  supportedPrimaryStatusIds: string[];
  supportedPrimaryVerdictIds: string[];
}

export interface FusionCasePrimaryStatus extends FusionReferenceItem {
  isClosed: boolean;
}

export interface FusionCaseReferenceDataResponse {
  caseTypes: { types: FusionCaseType[] } | null;
  casePrimaryStatuses: { primaryStatuses: FusionCasePrimaryStatus[] } | null;
  casePrimaryVerdicts: { primaryVerdicts: FusionReferenceItem[] } | null;
}

export interface FusionCasePrimaryVerdictsResponse {
  casePrimaryVerdicts: { primaryVerdicts: FusionReferenceItem[] } | null;
}

export interface FusionKeyFindings {
  documentType: "MARKDOWN" | "RICH_TEXT";
  documentVersion: string;
  content: string;
}

export interface FusionCaseLink {
  id: string;
  url: string;
  title: string | null;
  type: string | null;
  reference: string | null;
  isInternal: boolean;
  createdAt: string;
}

/** Fields selected on every case, list and detail. */
export interface FusionCaseSummary {
  id: string;
  shortId: string;
  title: string;
  severity: number;
  type: FusionReferenceItem;
  primaryStatus: FusionCasePrimaryStatus;
  secondaryStatus: FusionReferenceItem | null;
  tags: string[] | null;
  assigneeId: string | null;
  managedBy: "PROVIDER" | "CUSTOMER" | null;
  tenantId: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  archivedAt: string | null;
  riskScore: number | null;
}

/** Extra fields selected only by the single-case query. */
export interface FusionCaseDetail extends FusionCaseSummary {
  keyFindings: FusionKeyFindings | null;
  primaryVerdict: FusionReferenceItem | null;
  secondaryVerdict: FusionReferenceItem | null;
  secondaryStatusReason: string[];
  closeReason: string | null;
  closedById: string | null;
  createdById: string;
  updatedById: string;
  contributorIds: string[];
  incidentAdvisorId: string | null;
  ruleId: string | null;
  source: FusionReferenceItem | null;
  links: FusionCaseLink[];
  processingStatus: {
    assets: string | null;
    events: string | null;
    detections: string | null;
  };
  isCreatedByPartner: boolean;
  isCreatedByMDRProvider: boolean;
  detectionsCount: number;
  eventsCount: number;
  assetsCount: number;
}

export interface FusionPageInfo {
  startCursor: string | null;
  endCursor: string | null;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}

export interface FusionCasesResponse {
  cases: {
    totalCount: number;
    pageInfo: FusionPageInfo;
    cases: FusionCaseSummary[];
  };
}

export interface FusionCaseResponse {
  case: FusionCaseDetail | null;
}

export interface FusionCaseEvidence {
  id: string;
  detectionsEvidenceCount: number;
  detectionsEvidence: Array<{
    detectionId: string;
    createdAt: string;
    createdBy: string | null;
    isGenesis: boolean;
  }> | null;
  eventsEvidenceCount: number;
  eventsEvidence: Array<{
    eventId: string;
    createdAt: string;
    createdBy: string;
    isGenesis: boolean;
  }> | null;
  assetsEvidenceCount: number;
  assetsEvidence: Array<{
    assetId: string;
    createdAt: string;
    createdBy: string | null;
  }> | null;
  searchQueriesEvidenceCount: number;
  searchQueriesEvidence: Array<{
    searchQueryId: string;
    createdAt: string;
    isGenesis: boolean;
  }> | null;
}

export interface FusionCaseEvidenceResponse {
  caseEvidence: FusionCaseEvidence | null;
}

export interface FusionCaseWithEvidenceResponse {
  case: FusionCaseDetail | null;
  caseEvidence: FusionCaseEvidence | null;
}

export interface FusionCaseComment {
  id: string;
  authorId: string;
  comment: string;
  createdAt: string;
  updatedAt: string;
  isInternal: boolean;
  mentionsIds: string[];
}

export interface FusionCaseCommentsResponse {
  caseComments: {
    totalCount: number;
    totalUnreadCount: number;
    comments: FusionCaseComment[];
  };
}

export interface FusionAddCaseCommentResponse {
  addCaseComment: FusionCaseComment | null;
}

export interface FusionCreateCaseResponse {
  createCase: FusionCaseDetail | null;
}

export interface FusionUpdateCaseResponse {
  updateCase: FusionCaseDetail | null;
}

export interface FusionEvidenceMutationResult {
  caseId: string;
  detectionIds: string[] | null;
  eventIds: string[] | null;
  hostIds?: string[] | null;
  assetIds?: string[] | null;
  searchQueries: string[] | null;
}

export interface FusionAddEvidenceResponse {
  addEvidenceToCase: FusionEvidenceMutationResult | null;
}

export interface FusionRemoveEvidenceResponse {
  removeEvidenceFromCase: FusionEvidenceMutationResult | null;
}

export interface FusionCreateCaseLinkResponse {
  createCaseLink: FusionCaseLink | null;
}

// --- Detections v2 (only what the case summary reads) ---

export interface FusionTimestamp {
  seconds: number;
  nanos: number;
}

export interface FusionDetectionEntity {
  display_name: string;
  subtype: string;
  identifiers: string[];
}

export interface FusionDetectionRecord {
  id: string;
  status: string | null;
  resolution_reason: string | null;
  attack_technique_ids: string[] | null;
  sensor_types: string[] | null;
  tags: string[] | null;
  metadata: {
    title: string | null;
    description: string | null;
    /** 0 to 1. Not the Classic REST 0 to 10 scale and not the case 2 to 10 scale. */
    severity: number | null;
    confidence: number | null;
    origin: string | null;
    created_at: FusionTimestamp | null;
    first_seen_at: FusionTimestamp | null;
    creator: {
      detector: { detector_id: string | null; detector_name: string | null } | null;
    } | null;
  } | null;
  enrichment_details: Array<{
    mitre_attack_info: {
      technique_id: string | null;
      technique: string | null;
      tactics: string[] | null;
    } | null;
  }> | null;
  source_entities: FusionDetectionEntity[] | null;
  target_entities: FusionDetectionEntity[] | null;
  event_ids: Array<{ id: string }> | null;
}

export interface FusionDetectionsByIdResponse {
  detectionRetrieveById: {
    alerts: {
      total_results: number | null;
      list: FusionDetectionRecord[] | null;
    } | null;
  } | null;
}
