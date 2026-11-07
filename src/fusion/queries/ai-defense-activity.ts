/**
 * AI Defense Activity GraphQL API v1 documents (released 15/10/2026): the
 * seven queries and one mutation the reference supports. Schema:
 * schemas/fusion/ai-defense-activity-v1.graphql.
 *
 * Measured on live tenants 07/11/2026:
 * - The activities list must not select additionalData. The reference says
 *   the list returns it as an empty object; live it is null on every row,
 *   which breaks the non-null rule and turns the whole response into errors
 *   with data null. Only activity(id) selects it.
 * - The live SecureAIAppInventoryEntry has none of the reference's
 *   trainingPolicy, trainsOnUserData, complianceCertificates, categories and
 *   trainingPolicies fields (selecting one is an HTTP 400 that fails the
 *   query), so the app inventory selects only the fields both carry.
 * - A year of activity or inventory took 13 to 22 s on a busy tenant, so
 *   these reads get a longer per-attempt timeout than the client's 30 s.
 */

export const AI_DEFENSE_ACTIVITY_TIMEOUT_MS = 90_000;

const ACTIVITY_LIST_FIELDS = `
      id
      timestamp { startTime endTime }
      actor { id name type }
      application { id name categories trainingPolicies compliance }
      applicationProvider { id name }
      modelProvider { name }
      model { id name version }
      sensors { id name type vendor }
      action
      policyId
      policy
      device { id name type platform }
      risk
      appRisk
      aggregationCount
      isUnsanctioned`;

export const AI_DEFENSE_ACTIVITIES = `query FusionAiDefenseActivities($filter: SecureAiActivityFilter, $sort: SortInput, $first: Int64, $after: String) {
  activities(filter: $filter, sort: $sort, first: $first, after: $after) {
    totalCount
    pageInfo { hasNextPage endCursor }
    activities {${ACTIVITY_LIST_FIELDS}
    }
  }
}`;

export const AI_DEFENSE_ACTIVITY = `query FusionAiDefenseActivity($id: ID!) {
  activity(id: $id) {${ACTIVITY_LIST_FIELDS}
      additionalData
  }
}`;

const OFFSET_PAGE_FIELDS = `
    totalCount
    offset
    limit
    hasNextPage`;

export const AI_DEFENSE_APP_INVENTORY = `query FusionAiDefenseAppInventory($filter: SecureAIAppInventoryFilter, $sort: SecureAIAppInventorySortInput, $limit: Int64, $offset: Int64) {
  appInventory(filter: $filter, sort: $sort, limit: $limit, offset: $offset) {${OFFSET_PAGE_FIELDS}
    entries { id name provider risk usage uniqueUsers lastSeen unsanctionedCount }
  }
}`;

export const AI_DEFENSE_USER_INVENTORY = `query FusionAiDefenseUserInventory($filter: SecureAIUserInventoryFilter, $sort: SecureAIUserInventorySortInput, $limit: Int64, $offset: Int64) {
  userInventory(filter: $filter, sort: $sort, limit: $limit, offset: $offset) {${OFFSET_PAGE_FIELDS}
    entries { id name risk appsUsed usage policyViolations topAppId topApp firstSeen lastSeen unsanctionedCount }
  }
}`;

export const AI_DEFENSE_USER_APPS = `query FusionAiDefenseUserApps($userId: ID!, $filter: SecureAIUserAppsFilter, $sort: SecureAIUserAppsSortInput, $limit: Int64, $offset: Int64) {
  userApps(userId: $userId, filter: $filter, sort: $sort, limit: $limit, offset: $offset) {${OFFSET_PAGE_FIELDS}
    entries { id name provider risk usage policyViolations notCoveredCount firstUsed lastUsed }
  }
}`;

export const AI_DEFENSE_INVENTORY_SUMMARY = `query FusionAiDefenseInventorySummary($filter: SecureAIInventorySummaryFilter) {
  inventorySummary(filter: $filter) {
    apps { totalApps criticalRisk highRisk mediumRisk lowRisk infoRisk unknownRisk errorRisk trainsOnData unsanctionedCount }
    users { totalUsers criticalRisk highRisk mediumRisk lowRisk infoRisk unknownRisk withViolations unsanctionedCount }
  }
}`;

const SETTINGS_FIELDS = `
    onboarding {
      status
      selections {
        organizationDetails { role numberOfUsers aiFamiliarity industry }
        productIntegration { acknowledgedCheckKeys selectedProductKeys }
        passedStepKeys
      }
    }
    licenseState
    gracePeriodEndsAt
    licenseExpiryDate
    licenseType
    licenseId
    refreshedAt
    renewalPending
    createdBy
    createdByType
    updatedBy
    updatedByType
    createdAt
    updatedAt`;

export const AI_DEFENSE_TENANT_SETTINGS = `query FusionAiDefenseTenantSettings {
  secureAITenantSettings {${SETTINGS_FIELDS}
  }
}`;

export const AI_DEFENSE_UPDATE_TENANT_SETTINGS = `mutation FusionAiDefenseUpdateTenantSettings($input: SecureAIUpdateTenantSettingsInput!) {
  updateSecureAITenantSettings(input: $input) {${SETTINGS_FIELDS}
  }
}`;
