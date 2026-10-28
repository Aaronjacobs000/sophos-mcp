/**
 * Search GraphQL API v1 documents (released 12/10/2026): createSearch,
 * getOrCreateSearch, search and searchResults, the four operations the
 * reference supports. Schema: schemas/fusion/search-v1.graphql.
 *
 * A search is asynchronous: create it, poll search(urn) until status is
 * COMPLETE, check outcome.success, then page searchResults by cursor. values
 * is a JSON scalar, so rows cannot be narrowed in the selection set; QL
 * `| fields` projection narrows them. Field metadata for an unprojected
 * search runs to 861 entries (about 150,000 characters, live tenant
 * 29/10/2026), so the results document comes with and without it.
 */

const SEARCH_FIELDS = `
    urn
    status
    overThreshold
    errors
    outcome { success errors { urn errors } }
    queryText
    searchPartitions {
      urn
      searchURN
      schemaType
      status
      overThreshold
      errors
      createTime
      startTime
      endTime
      expireTime
    }
    createTime
    startTime
    endTime
    expireTime
    metadata
    hostnameMappings { hostname hostIds }`;

export const CREATE_SEARCH = `mutation FusionCreateSearch($input: CreateSearchInput) {
  createSearch(input: $input) {${SEARCH_FIELDS}
  }
}`;

export const GET_OR_CREATE_SEARCH = `mutation FusionGetOrCreateSearch($input: CreateSearchInput) {
  getOrCreateSearch(input: $input) {${SEARCH_FIELDS}
  }
}`;

export const GET_SEARCH = `query FusionSearch($urn: URN!) {
  search(urn: $urn) {${SEARCH_FIELDS}
  }
}`;

const RESULT_PAGE_FIELDS = `
    values
    totals { total { value } subtotals { schemaType value } }
    nextCursor
    previousCursor
    hostnameMappings { hostname hostIds }`;

export const SEARCH_RESULTS = `query FusionSearchResults($urn: URN!, $cursor: String, $limit: Int) {
  searchResults(urn: $urn, cursor: $cursor, limit: $limit) {${RESULT_PAGE_FIELDS}
  }
}`;

export const SEARCH_RESULTS_WITH_FIELDS = `query FusionSearchResultsWithFields($urn: URN!, $cursor: String, $limit: Int) {
  searchResults(urn: $urn, cursor: $cursor, limit: $limit) {${RESULT_PAGE_FIELDS}
    fields { name baseType logicalType enumValues originSchemaTypes }
  }
}`;
