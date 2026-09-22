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
  /** Provider-side statuses are never returned by casePrimaryStatuses; a case can still carry one. */
  isCaseVisibleToCustomers?: boolean;
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

export interface FusionCaseComment {
  id: string;
  authorId: string;
  comment: string;
  createdAt: string;
  updatedAt: string;
  isInternal: boolean;
  /** Group mentions the parser resolved, leading @ kept (for example "@authorized_contacts"). */
  mentionsIds: string[];
  readByIds: string[];
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

export interface FusionUpdateCaseCommentResponse {
  updateCaseComment: FusionCaseComment | null;
}

export interface FusionDeleteCaseCommentResponse {
  deleteCaseComment: FusionCaseComment | null;
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

export interface FusionUpdateCaseLinkResponse {
  updateCaseLink: FusionCaseLink | null;
}

export interface FusionDeleteCaseLinkResponse {
  deleteCaseLink: FusionCaseLink | null;
}

/** Case files. deleteCaseFile is a soft delete: the row stays with status DELETED and a deletedAt. */
export interface FusionCaseFile {
  id: string;
  caseId: string;
  name: string;
  size: number;
  /** SCHEDULED until the presigned PUT lands, then UPLOADED; DELETED after a soft delete. */
  status: string;
  isEmbedded: boolean;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
  uploadedById: string;
  deletedById: string | null;
  metadata: { contentType: string | null; contentMD5: string | null } | null;
  /** Presigned S3 GET, valid 15 minutes. Only selected when the caller asks for it. */
  downloadURL?: string | null;
}

export interface FusionCaseFilesResponse {
  caseFiles: { totalCount: number; files: FusionCaseFile[] } | null;
}

export interface FusionCaseFileResponse {
  caseFile: FusionCaseFile | null;
}

export interface FusionStartCaseFileUploadResponse {
  startCaseFileUpload: { file: FusionCaseFile; presignedUrl: string } | null;
}

export interface FusionDeleteCaseFileResponse {
  deleteCaseFile: FusionCaseFile | null;
}

export interface FusionSplitCaseResponse {
  splitCase: {
    caseId: string;
    destinationCaseId: string;
    detectionIds: string[];
    eventIds: string[];
    searchQueries: string[];
    fileIds: string[];
  } | null;
}

export interface FusionMergeCaseResponse {
  mergeCase: {
    targetCaseId: string;
    sourceCaseIds: string[];
    /** Job handle: the evidence association is asynchronous (landed within about 4 s in testing). */
    processingEventId: string;
  } | null;
}

// --- Detections v2 (the case summary's batched lookup and the QL search) ---

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

export interface FusionDetectionSearchResponse {
  detectionSearch: {
    status: string | null;
    reason: string | null;
    search_id: string | null;
    alerts: {
      total_results: number | null;
      next_offset: number | null;
      list: FusionDetectionRecord[] | null;
    } | null;
  } | null;
}
