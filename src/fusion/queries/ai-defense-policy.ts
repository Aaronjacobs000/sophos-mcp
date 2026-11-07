/**
 * AI Defense Policy GraphQL API v1 documents (released 15/10/2026): the ten
 * queries and eight mutations the reference supports. Schema:
 * schemas/fusion/ai-defense-policy-v1.graphql.
 *
 * Every policy document selects the same fields, so a mutation returns the
 * policy as a read would. createdBySubject and updatedBySubject are not
 * selected: the federated Subject carries only the id that createdBy and
 * updatedBy already hold. Rule previews (targetPreviewV2) resolve the matched
 * applications for every rule, so they are opt-in; the legacy targetPreview
 * is never selected.
 */

const RULE_FIELDS = `
      position
      target { conditions { dimension operator values } }
      action
      enforcementMechanismOverride
      note
      dataControls { clipboardCopy clipboardPaste upload download }`;

const RULE_PREVIEW_FIELDS = `
      targetPreviewV2 {
        matchedCount
        effectiveCount
        effectiveReachStatus
        topApps { id name riskLevel }
        riskCounts { level count }
        warnings
        enforcementImpact { webControlDomains appControlApplications { applicationId applicationName } }
      }`;

const SENSOR_FIELDS = `
    endpoint { enabled scope }
    firewall { enabled scope }
    dns { enabled scope }
    browser { enabled scope }`;

function policyFields(withPreviews: boolean): string {
  return `
    id
    tenantId
    name
    description
    priority
    rank
    state
    enforcementStatus
    origin
    kind
    partnerPolicyId
    builtInKey
    builtInVersion
    rules {${RULE_FIELDS}${withPreviews ? RULE_PREVIEW_FIELDS : ""}
    }
    baseRule { generativeAiCategoryAction appControlCategoryAction }
    sensors {${SENSOR_FIELDS}
    }
    tags
    createdAt
    updatedAt
    createdBy
    updatedBy
    version`;
}

const POLICY_FIELDS = policyFields(false);

export const AI_DEFENSE_POLICIES = `query FusionAiDefensePolicies($filter: PolicyFilterInput, $first: Int64, $after: String) {
  policies(filter: $filter, first: $first, after: $after) {
    totalCount
    enabledCount
    failedCount
    pageInfo { hasNextPage endCursor }
    policies {${POLICY_FIELDS}
    }
  }
}`;

export const AI_DEFENSE_POLICY = `query FusionAiDefensePolicy($id: ID!) {
  policy(id: $id) {${POLICY_FIELDS}
  }
}`;

export const AI_DEFENSE_POLICY_WITH_PREVIEWS = `query FusionAiDefensePolicyWithPreviews($id: ID!) {
  policy(id: $id) {${policyFields(true)}
  }
}`;

export const AI_DEFENSE_APP_SANCTIONING = `query FusionAiDefenseAppSanctioning($appIds: [String!]!) {
  appSanctioning(appIds: $appIds) {
    entries {
      appId
      status
      enforcementTargets {
        mechanism
        applicationId
        applicationName
        status
        matchedPolicy { id name rank state }
        matchedRulePosition
        computedAt
      }
    }
  }
}`;

const PREVIEW_FIELDS = `
    matchedCount
    effectiveCount
    topApps { id name riskLevel }
    riskCounts { level count }
    warnings
    enforcementImpact { webControlDomains appControlApplications { applicationId applicationName } }`;

export const AI_DEFENSE_PREVIEW_RULE_TARGET = `query FusionAiDefensePreviewRuleTarget($conditions: [TargetConditionInput!]!, $action: PolicyAction!) {
  previewRuleTarget(conditions: $conditions, action: $action) {${PREVIEW_FIELDS}
  }
}`;

export const AI_DEFENSE_PREVIEW_RULE_TARGETS = `query FusionAiDefensePreviewRuleTargets($rules: [RuleTargetInput!]!) {
  previewRuleTargets(rules: $rules) {${PREVIEW_FIELDS}
  }
}`;

export const AI_DEFENSE_PREVIEW_POLICY_IMPACT = `query FusionAiDefensePreviewPolicyImpact($rules: [PolicyRuleInput!]!) {
  previewPolicyImpact(rules: $rules) { totalApps blocked warned allowed }
}`;

function templateFields(withImpact: boolean): string {
  return `
    key
    name
    description
    recommended
    version
    rules {${RULE_FIELDS}
    }
    defaultSensors {${SENSOR_FIELDS}
    }
    baseRule { generativeAiCategoryAction appControlCategoryAction }${withImpact ? "\n    impact { totalApps blocked warned allowed }" : ""}`;
}

export const AI_DEFENSE_STARTER_TEMPLATES = `query FusionAiDefenseStarterTemplates {
  starterTemplates {${templateFields(false)}
  }
}`;

export const AI_DEFENSE_STARTER_TEMPLATES_WITH_IMPACT = `query FusionAiDefenseStarterTemplatesWithImpact {
  starterTemplates {${templateFields(true)}
  }
}`;

export const AI_DEFENSE_STARTER_TEMPLATE = `query FusionAiDefenseStarterTemplate($key: String!) {
  starterTemplate(key: $key) {${templateFields(false)}
  }
}`;

export const AI_DEFENSE_STARTER_TEMPLATE_WITH_IMPACT = `query FusionAiDefenseStarterTemplateWithImpact($key: String!) {
  starterTemplate(key: $key) {${templateFields(true)}
  }
}`;

export const AI_DEFENSE_ENFORCEMENT_MECHANISMS = `query FusionAiDefenseEnforcementMechanisms {
  supportedEnforcementMechanisms
}`;

export const AI_DEFENSE_POLICY_ACTIVITY_METRICS = `query FusionAiDefensePolicyActivityMetrics($timeFrame: SecureAITimeRange) {
  secureAIPolicyActivityMetrics(timeFrame: $timeFrame) {
    policiesWithActivityCount
    policiesWithoutActivityCount
    policiesWithoutActivityIds
    windowStart
    windowEnd
    mostBlockedPolicy { policyId blockedCount }
  }
}`;

export const AI_DEFENSE_CREATE_POLICY = `mutation FusionAiDefenseCreatePolicy($input: PolicyCreateInput!) {
  createPolicy(input: $input) {${POLICY_FIELDS}
  }
}`;

export const AI_DEFENSE_UPDATE_POLICY = `mutation FusionAiDefenseUpdatePolicy($id: ID!, $input: PolicyUpdateInput!) {
  updatePolicy(id: $id, input: $input) {${POLICY_FIELDS}
  }
}`;

export const AI_DEFENSE_DELETE_POLICY = `mutation FusionAiDefenseDeletePolicy($id: ID!) {
  deletePolicy(id: $id)
}`;

export const AI_DEFENSE_ENABLE_POLICY = `mutation FusionAiDefenseEnablePolicy($id: ID!) {
  enablePolicy(id: $id) {${POLICY_FIELDS}
  }
}`;

export const AI_DEFENSE_DISABLE_POLICY = `mutation FusionAiDefenseDisablePolicy($id: ID!) {
  disablePolicy(id: $id) {${POLICY_FIELDS}
  }
}`;

export const AI_DEFENSE_MOVE_POLICY = `mutation FusionAiDefenseMovePolicy($id: ID!, $afterId: ID) {
  movePolicy(id: $id, afterId: $afterId) {${POLICY_FIELDS}
  }
}`;

export const AI_DEFENSE_REORDER_POLICIES = `mutation FusionAiDefenseReorderPolicies($policyIds: [ID!]!) {
  reorderPolicies(policyIds: $policyIds)
}`;

export const AI_DEFENSE_CLONE_POLICY = `mutation FusionAiDefenseClonePolicy($id: ID!) {
  clonePolicy(id: $id) {${POLICY_FIELDS}
  }
}`;
