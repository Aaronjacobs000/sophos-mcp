/**
 * Hand-written GraphQL documents for the Cases v2 API. Selection sets are kept
 * to what the tools return; every guide on the developer portal says request
 * only the fields you use. Schema: schemas/fusion/cases-v2.graphql.
 *
 * Federated `*Subject` fields are deliberately not selected: the vendored
 * schema declares Subject with `id` only, and a federated field that cannot
 * be resolved turns a clean response into a partial one.
 */

const CASE_SUMMARY_FIELDS = `
  id
  shortId
  title
  severity
  type { id name title }
  primaryStatus { id name title isClosed }
  secondaryStatus { id name title }
  tags
  assigneeId
  managedBy
  tenantId
  createdAt
  updatedAt
  closedAt
  archivedAt
  riskScore`;

const CASE_DETAIL_FIELDS = `${CASE_SUMMARY_FIELDS}
  keyFindings { documentType documentVersion content }
  primaryVerdict { id name title }
  secondaryVerdict { id name title }
  secondaryStatusReason
  closeReason
  closedById
  createdById
  updatedById
  contributorIds
  incidentAdvisorId
  ruleId
  source { id name title }
  links { id url title type reference isInternal createdAt }
  processingStatus { assets events detections }
  isCreatedByPartner
  isCreatedByMDRProvider
  detectionsCount
  eventsCount
  assetsCount`;

const CASE_EVIDENCE_FIELDS = `
  id
  detectionsEvidenceCount
  detectionsEvidence { detectionId createdAt createdBy isGenesis }
  eventsEvidenceCount
  eventsEvidence { eventId createdAt createdBy isGenesis }
  assetsEvidenceCount
  assetsEvidence { assetId createdAt createdBy }
  searchQueriesEvidenceCount
  searchQueriesEvidence { searchQueryId createdAt isGenesis }`;

const CASE_COMMENT_FIELDS = `
  id
  authorId
  comment
  createdAt
  updatedAt
  isInternal
  mentionsIds
  readByIds`;

const CASE_LINK_FIELDS = `
  id
  url
  title
  type
  reference
  isInternal
  createdAt`;

// downloadURL is not in the base selection: requesting it on a non-embedded
// file writes an audit log entry, so the list tool selects it only on request.
const CASE_FILE_FIELDS = `
  id
  caseId
  name
  size
  status
  isEmbedded
  createdAt
  updatedAt
  deletedAt
  uploadedById
  deletedById
  metadata { contentType contentMD5 }`;

export const LIST_CASES = `query FusionListCases($arguments: CasesArguments!) {
  cases(arguments: $arguments) {
    totalCount
    pageInfo { startCursor endCursor hasNextPage hasPreviousPage }
    cases {${CASE_SUMMARY_FIELDS}
    }
  }
}`;

export const GET_CASE = `query FusionGetCase($arguments: CaseArguments!) {
  case(arguments: $arguments) {${CASE_DETAIL_FIELDS}
  }
}`;

export const GET_CASE_EVIDENCE = `query FusionGetCaseEvidence($arguments: CaseEvidenceArguments!) {
  caseEvidence(arguments: $arguments) {${CASE_EVIDENCE_FIELDS}
  }
}`;

// There is no combined case-plus-evidence document on purpose. Two
// case-scoped root fields in one document (case + caseEvidence, or two aliased
// case fields) fail every time with "conn busy" from investigations-v2
// (verified against a live tenant on 21/09/2026). The summary tool runs
// GET_CASE and GET_CASE_EVIDENCE as two calls. CASE_REFERENCE_DATA below is
// unaffected: its three root fields are not case-scoped.

export const LIST_CASE_COMMENTS = `query FusionListCaseComments($arguments: CaseCommentsArguments!) {
  caseComments(arguments: $arguments) {
    totalCount
    totalUnreadCount
    comments {${CASE_COMMENT_FIELDS}
    }
  }
}`;

export const ADD_CASE_COMMENT = `mutation FusionAddCaseComment($input: AddCaseComment!) {
  addCaseComment(input: $input) {${CASE_COMMENT_FIELDS}
  }
}`;

export const UPDATE_CASE_COMMENT = `mutation FusionUpdateCaseComment($input: UpdateCaseCommentInput!) {
  updateCaseComment(input: $input) {${CASE_COMMENT_FIELDS}
  }
}`;

export const DELETE_CASE_COMMENT = `mutation FusionDeleteCaseComment($input: DeleteCaseCommentInput!) {
  deleteCaseComment(input: $input) {${CASE_COMMENT_FIELDS}
  }
}`;

export const CREATE_CASE = `mutation FusionCreateCase($input: CreateCaseInput!) {
  createCase(input: $input) {${CASE_DETAIL_FIELDS}
  }
}`;

export const UPDATE_CASE = `mutation FusionUpdateCase($input: UpdateCaseInput!) {
  updateCase(input: $input) {${CASE_DETAIL_FIELDS}
  }
}`;

export const ADD_EVIDENCE_TO_CASE = `mutation FusionAddEvidenceToCase($input: AddEvidenceToCaseInput!) {
  addEvidenceToCase(input: $input) {
    caseId
    detectionIds
    eventIds
    hostIds
    searchQueries
  }
}`;

export const REMOVE_EVIDENCE_FROM_CASE = `mutation FusionRemoveEvidenceFromCase($input: RemoveEvidenceFromCaseInput!) {
  removeEvidenceFromCase(input: $input) {
    caseId
    detectionIds
    eventIds
    assetIds
    searchQueries
  }
}`;

export const CREATE_CASE_LINK = `mutation FusionCreateCaseLink($input: CreateCaseLinkInput!) {
  createCaseLink(input: $input) {${CASE_LINK_FIELDS}
  }
}`;

export const UPDATE_CASE_LINK = `mutation FusionUpdateCaseLink($input: UpdateCaseLinkInput!) {
  updateCaseLink(input: $input) {${CASE_LINK_FIELDS}
  }
}`;

export const DELETE_CASE_LINK = `mutation FusionDeleteCaseLink($input: DeleteCaseLinkInput!) {
  deleteCaseLink(input: $input) {${CASE_LINK_FIELDS}
  }
}`;

// caseFiles has no case argument: it lists the tenant's files and each row
// carries caseId, so the tool filters client side. The `query` argument is
// omitted on purpose ("FROM case_file" is rejected as not valid for any known
// schema type; live tenant, 22/09/2026).
export const LIST_CASE_FILES = `query FusionListCaseFiles($arguments: CaseFilesArguments!) {
  caseFiles(arguments: $arguments) {
    totalCount
    files {${CASE_FILE_FIELDS}
    }
  }
}`;

export const LIST_CASE_FILES_WITH_URLS = `query FusionListCaseFilesWithUrls($arguments: CaseFilesArguments!) {
  caseFiles(arguments: $arguments) {
    totalCount
    files {${CASE_FILE_FIELDS}
      downloadURL
    }
  }
}`;

export const GET_CASE_FILE = `query FusionGetCaseFile($arguments: CaseFileArguments!) {
  caseFile(arguments: $arguments) {${CASE_FILE_FIELDS}
  }
}`;

export const START_CASE_FILE_UPLOAD = `mutation FusionStartCaseFileUpload($input: StartCaseFileUploadInput!) {
  startCaseFileUpload(input: $input) {
    file {${CASE_FILE_FIELDS}
    }
    presignedUrl
  }
}`;

export const DELETE_CASE_FILE = `mutation FusionDeleteCaseFile($input: DeleteCaseFileInput!) {
  deleteCaseFile(input: $input) {${CASE_FILE_FIELDS}
  }
}`;

/** Moves the named evidence to a case created by the same call. Irreversible. */
export const SPLIT_CASE = `mutation FusionSplitCase($input: SplitCaseInput!) {
  splitCase(input: $input) {
    caseId
    destinationCaseId
    detectionIds
    eventIds
    searchQueries
    fileIds
  }
}`;

/** Asynchronous: processingEventId is the job handle. Closes the sources. Irreversible. */
export const MERGE_CASES = `mutation FusionMergeCases($input: MergeCaseInput!) {
  mergeCase(input: $input) {
    targetCaseId
    sourceCaseIds
    processingEventId
  }
}`;

/**
 * Reference data the tenant's licensed services expose. One round trip for
 * all three lists; the cache in case-reference-data.ts owns the refresh.
 */
export const CASE_REFERENCE_DATA = `query FusionCaseReferenceData {
  caseTypes(arguments: {}) {
    types { id name title managedBy supportedPrimaryStatusIds supportedPrimaryVerdictIds }
  }
  casePrimaryStatuses(arguments: {}) {
    primaryStatuses { id name title isClosed isCaseVisibleToCustomers }
  }
  casePrimaryVerdicts(arguments: {}) {
    primaryVerdicts { id name title }
  }
}`;

/** Verdicts valid for closing a case of a given type into a given closed status. */
export const CASE_PRIMARY_VERDICTS_FOR = `query FusionCasePrimaryVerdictsFor($arguments: CasePrimaryVerdictsArguments!) {
  casePrimaryVerdicts(arguments: $arguments) {
    primaryVerdicts { id name title }
  }
}`;
