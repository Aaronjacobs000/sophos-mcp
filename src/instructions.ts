/**
 * The server instructions sent in the initialize result. Clients that support
 * them (Claude Code among them) read the text to decide when to reach for
 * these tools, which matters when the 362 tools load through tool search.
 * Keep it short and descriptive. test/server-instructions.test.mjs fails when
 * a tool or prefix named here is not registered for that caller and mode, or
 * when the text grows past its cap.
 */

import type { SophosIdType } from "./types/sophos.js";

export interface InstructionOptions {
  idType: SophosIdType;
  readOnly: boolean;
}

const SCOPE =
  "Tools for Sophos Fusion (formerly Sophos Central): endpoints, alerts, policies, " +
  "firewalls, email, mobile devices, directory users, admins, licensing, and audit events, plus investigation " +
  "with cases, detections, XDR and Data Lake queries, Live Discover, and AI Defense.";

const MULTI_TENANT =
  "Tenant tools need a tenant_id: sophos_list_tenants lists the tenants, and sophos_list_account_health compares their health.";

const CALLER: Record<SophosIdType, string> = {
  partner: `This connection uses a partner credential, so it reaches every tenant the partner manages. ${MULTI_TENANT}`,
  organization: `This connection uses an organization credential, so it reaches every tenant in the organization. ${MULTI_TENANT}`,
  tenant: "This connection uses a tenant credential, so every tool acts on that one tenant and tenant_id can be left out.",
};

const GROUPS =
  "sophos_fusion_ tools use the Sophos Fusion GraphQL APIs (cases, detections, Data Lake search, endpoint inventory), " +
  "sophos_fusion_ai_defense_ tools cover AI Defense, and the other sophos_ tools use the Sophos Central REST APIs. " +
  "On a tenant that has moved to Sophos Fusion, cases and detections come from the sophos_fusion_ tools; " +
  "sophos_fusion_list_case_reference_data reports the tenant type.";

const WRITES =
  "Read tools (list, get, search) come first. Write tools change the live tenant, so they suit a change the user has clearly asked for.";

const READ_ONLY =
  "Read-only mode is on. Write tools, and reads that start a query run, search, or job, are not registered, " +
  "and any request that could write is refused.";

export function serverInstructions({ idType, readOnly }: InstructionOptions): string {
  // idType comes from whoami; src/index.ts treats any caller but a tenant as multi-tenant
  const caller = CALLER[idType] ?? CALLER.organization;
  return [SCOPE, caller, GROUPS, readOnly ? READ_ONLY : WRITES].join("\n\n");
}
