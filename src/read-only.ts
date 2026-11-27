/**
 * Read-only mode's tool filter (SOPHOS_READ_ONLY). With the mode on, a tool
 * is registered only when it is named in READ_ONLY_TOOLS and annotated
 * readOnlyHint true. Anything else, a tool added later included, is left out
 * until someone classifies it. The request guard in
 * src/client/read-only-guard.ts is the other half: each one stops a write on
 * its own.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/** Tools that only read. Each one sends GET requests, a REST search in READ_ONLY_POST_PATHS, or Fusion GraphQL queries. */
export const READ_ONLY_TOOLS: ReadonlySet<string> = new Set([
  // tenants.ts
  "sophos_list_tenants",
  // alerts.ts
  "sophos_list_alerts", "sophos_get_alert", "sophos_search_alerts",
  // endpoints.ts
  "sophos_list_endpoints", "sophos_get_endpoint", "sophos_get_tamper_protection",
  "sophos_get_adaptive_attack_protection", "sophos_get_forensic_log_status", "sophos_get_memory_dump_status",
  "sophos_get_endpoint_isolation_status",
  // health.ts
  "sophos_get_account_health", "sophos_list_account_health", "sophos_partner_gap_analysis",
  // directory.ts
  "sophos_list_users", "sophos_list_admins", "sophos_list_roles", "sophos_get_user",
  "sophos_list_user_groups", "sophos_get_user_group", "sophos_list_user_group_members",
  "sophos_list_user_group_policies",
  // policies.ts
  "sophos_list_policies", "sophos_get_policy",
  // groups.ts
  "sophos_list_endpoint_groups", "sophos_get_endpoint_group",
  // exclusions.ts
  "sophos_list_exclusions", "sophos_list_allowed_items", "sophos_list_blocked_items",
  // cases.ts
  "sophos_list_cases", "sophos_get_case", "sophos_list_case_detections", "sophos_get_case_mitre_summary",
  "sophos_list_case_impacted_entities", "sophos_get_case_detection",
  // detections.ts
  "sophos_get_detections_run", "sophos_get_detections_results", "sophos_get_detection_groups_run",
  "sophos_get_detection_groups_results",
  // siem.ts
  "sophos_list_siem_events", "sophos_list_siem_alerts",
  // xdr.ts
  "sophos_get_xdr_query_run", "sophos_get_xdr_query_results", "sophos_list_xdr_query_runs",
  "sophos_list_xdr_query_categories", "sophos_get_xdr_query_category", "sophos_list_xdr_queries",
  "sophos_get_xdr_query",
  // live-discover.ts
  "sophos_list_live_discover_queries", "sophos_get_live_discover_run", "sophos_get_live_discover_results",
  // admin-management.ts
  "sophos_get_admin", "sophos_list_admin_role_assignments", "sophos_get_admin_role_assignment",
  "sophos_get_role", "sophos_list_permission_sets",
  // endpoint-migrations.ts
  "sophos_list_migrations", "sophos_get_migration", "sophos_list_migration_endpoints",
  "sophos_list_recommended_packages", "sophos_list_static_packages",
  // endpoint-settings.ts
  "sophos_list_installer_downloads", "sophos_get_helm_values", "sophos_list_blocked_addresses",
  "sophos_list_local_sites", "sophos_list_web_control_categories", "sophos_get_tls_decryption_settings",
  "sophos_get_global_tamper_protection", "sophos_list_detected_exploits", "sophos_get_detected_exploit",
  "sophos_list_exploit_mitigation_categories", "sophos_get_exploit_mitigation_category",
  "sophos_list_exploit_mitigation_apps", "sophos_get_exploit_mitigation_app", "sophos_list_ips_exclusions",
  "sophos_list_isolation_exclusions",
  // firewall.ts
  "sophos_list_firewalls", "sophos_list_firewall_groups", "sophos_get_firewall_group",
  "sophos_get_firewall_sync_status", "sophos_get_threat_feed_settings",
  "sophos_search_threat_feed_indicators", "sophos_get_firewall_transaction",
  "sophos_get_firewall_import_export_transaction",
  // email.ts
  "sophos_search_quarantine", "sophos_preview_quarantine_message", "sophos_get_quarantine_urls",
  "sophos_get_quarantine_attachments", "sophos_search_post_delivery_quarantine",
  "sophos_preview_post_delivery_message", "sophos_get_post_delivery_attachments",
  "sophos_get_clawback_status", "sophos_list_mailboxes", "sophos_get_mailbox", "sophos_list_mailbox_aliases",
  "sophos_list_mailbox_delegates",
  // email-smime.ts
  "sophos_get_smime_config", "sophos_get_smime_internal_ca", "sophos_download_smime_internal_ca",
  "sophos_list_smime_internal_users", "sophos_download_smime_internal_user_cert",
  "sophos_list_smime_external_users", "sophos_download_smime_external_user_cert",
  "sophos_list_smime_external_cas", "sophos_download_smime_external_ca",
  // dns-protection.ts
  "sophos_list_dns_locations", "sophos_get_dns_location",
  // cloud-security.ts
  "sophos_list_cloud_security_profiles", "sophos_list_cloud_security_default_contents",
  "sophos_get_cloud_security_profile",
  // wifi.ts
  "sophos_list_wifi_mac_filters",
  // user-activity.ts
  "sophos_get_attestation",
  // partner.ts
  "sophos_get_managed_tenant", "sophos_list_partner_roles", "sophos_get_partner_role",
  "sophos_list_partner_permission_sets", "sophos_list_partner_admins", "sophos_get_partner_admin",
  "sophos_list_partner_admin_role_assignments", "sophos_get_billing_usage", "sophos_get_billing_summary",
  // mobile.ts
  "sophos_get_mobile_auto_enrollment", "sophos_list_mobile_os", "sophos_list_mobile_devices",
  "sophos_get_mobile_device", "sophos_list_mobile_device_properties", "sophos_get_mobile_device_compliance",
  "sophos_get_mobile_device_scans", "sophos_get_mobile_device_policies", "sophos_get_mobile_device_apps",
  "sophos_get_mobile_device_location", "sophos_list_mobile_device_groups", "sophos_get_mobile_device_group",
  "sophos_list_mobile_app_groups", "sophos_get_mobile_app_group",
  // audit-events.ts
  "sophos_list_audit_events",
  // licensing.ts
  "sophos_list_licenses", "sophos_list_firewall_licenses",
  // web-filtering.ts
  "sophos_list_web_filtering_profiles", "sophos_get_web_filtering_profile",
  "sophos_get_web_filtering_metadata", "sophos_list_site_lists", "sophos_get_site_list", "sophos_list_sites",
  // switch.ts
  "sophos_get_switch_mac_filtering", "sophos_list_switch_tasks",
  // accounts.ts
  "sophos_list_access_tokens",
  // business-automation.ts
  "sophos_list_ba_quotes", "sophos_get_ba_quote", "sophos_get_ba_partner_levels",
  // fusion-cases.ts
  "sophos_fusion_list_cases", "sophos_fusion_get_case", "sophos_fusion_get_case_evidence",
  "sophos_fusion_get_case_summary", "sophos_fusion_list_case_reference_data",
  "sophos_fusion_list_case_comments", "sophos_fusion_list_case_files",
  // fusion-detections.ts
  "sophos_fusion_search_detections",
  // fusion-search.ts
  "sophos_fusion_get_search", "sophos_fusion_get_search_results",
  // fusion-ai-defense-policies.ts
  "sophos_fusion_ai_defense_list_policies", "sophos_fusion_ai_defense_get_policy",
  "sophos_fusion_ai_defense_get_app_sanctioning", "sophos_fusion_ai_defense_preview_rule_target",
  "sophos_fusion_ai_defense_preview_rule_targets", "sophos_fusion_ai_defense_preview_impact",
  "sophos_fusion_ai_defense_list_templates", "sophos_fusion_ai_defense_get_template",
  "sophos_fusion_ai_defense_list_mechanisms", "sophos_fusion_ai_defense_get_policy_activity",
  // fusion-ai-defense-activity.ts
  "sophos_fusion_ai_defense_list_activities", "sophos_fusion_ai_defense_get_activity",
  "sophos_fusion_ai_defense_list_app_inventory", "sophos_fusion_ai_defense_list_user_inventory",
  "sophos_fusion_ai_defense_list_user_apps", "sophos_fusion_ai_defense_inventory_summary",
  "sophos_fusion_ai_defense_get_settings",
]);

/**
 * Annotated readOnlyHint true but left out of read-only mode: each one makes
 * something that stays in the tenant or runs on a device, or it is not clear
 * that it doesn't.
 */
export const READ_ONLY_EXCLUDED: Readonly<Record<string, string>> = {
  sophos_run_detections_query: "creates a detections query run in the tenant",
  sophos_run_detection_groups_query: "creates a detection groups query run in the tenant",
  sophos_run_xdr_query: "creates a Data Lake query run, which the tenant's run history keeps",
  sophos_run_live_discover_query: "runs a query on the tenant's devices and creates a run",
  sophos_export_firewall_config: "starts an export job on the firewall",
  sophos_download_quarantine_attachment: "creates an attachment download job",
  sophos_download_post_delivery_attachment: "creates an attachment download job",
  sophos_get_ba_pricing: "a POST; not clear that it stores nothing",
  sophos_fusion_create_search: "a mutation that creates a Data Lake search, kept for 30 days",
  sophos_fusion_get_or_create_search: "a mutation that can create a Data Lake search",
  sophos_fusion_endpoint_inventory: "creates Data Lake searches through the same mutations",
};

/** What read-only mode registered on one server. */
export interface ReadOnlyRegistration {
  registered: number;
  leftOut: number;
}

/**
 * Makes this server register only the tools in READ_ONLY_TOOLS that are
 * annotated readOnlyHint true. Call it before any register*Tools function.
 */
export function registerReadToolsOnly(server: McpServer): ReadOnlyRegistration {
  const counts: ReadOnlyRegistration = { registered: 0, leftOut: 0 };
  const register = server.registerTool.bind(server) as (...args: unknown[]) => unknown;
  const filtered = (name: string, config: { annotations?: { readOnlyHint?: boolean } }, ...rest: unknown[]) => {
    if (READ_ONLY_TOOLS.has(name) && config?.annotations?.readOnlyHint === true) {
      counts.registered++;
      return register(name, config, ...rest);
    }
    counts.leftOut++;
    return undefined;
  };
  server.registerTool = filtered as unknown as McpServer["registerTool"];
  // The older registration API carries no annotations to check, so read-only mode refuses it outright.
  server.tool = (() => {
    throw new Error("Read-only mode registers tools through registerTool only.");
  }) as unknown as McpServer["tool"];
  return counts;
}
