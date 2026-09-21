/**
 * Per-tenant cache of the Cases reference data: case types, primary statuses
 * and primary verdicts. Fusion filters and sets these by UUID, and the set a
 * tenant gets depends on its licensed services, so names are resolved at
 * runtime and the cache is refreshed on a TTL rather than resolved once.
 */

import type { FusionClient } from "../client/fusion-client.js";
import { CASE_REFERENCE_DATA } from "./queries/cases.js";
import { isUuid } from "./format.js";
import type {
  FusionCasePrimaryStatus,
  FusionCaseReferenceDataResponse,
  FusionCaseType,
  FusionReferenceItem,
} from "./types.js";

export interface CaseReferenceData {
  types: FusionCaseType[];
  primaryStatuses: FusionCasePrimaryStatus[];
  primaryVerdicts: FusionReferenceItem[];
  fetchedAt: string;
}

const DEFAULT_TTL_MS = 15 * 60_000;

export class CaseReferenceDataCache {
  private cache = new Map<string, { data: CaseReferenceData; expiresAt: number }>();
  private inflight = new Map<string, Promise<CaseReferenceData>>();

  constructor(
    private client: FusionClient,
    private ttlMs: number = DEFAULT_TTL_MS
  ) {}

  async get(tenantId: string, options: { refresh?: boolean } = {}): Promise<CaseReferenceData> {
    const cached = this.cache.get(tenantId);
    if (cached && !options.refresh && Date.now() < cached.expiresAt) {
      return cached.data;
    }

    const pending = this.inflight.get(tenantId);
    if (pending) return pending;

    const promise = this.fetch(tenantId);
    this.inflight.set(tenantId, promise);
    try {
      const data = await promise;
      this.cache.set(tenantId, { data, expiresAt: Date.now() + this.ttlMs });
      return data;
    } finally {
      this.inflight.delete(tenantId);
    }
  }

  invalidate(tenantId: string): void {
    this.cache.delete(tenantId);
  }

  /** Accepts a UUID (passed through) or a type name or title (case-insensitive). */
  async resolveTypeId(tenantId: string, nameOrId: string): Promise<string> {
    if (isUuid(nameOrId)) return nameOrId;
    const { types } = await this.get(tenantId);
    return matchReference("case type", types, nameOrId).id;
  }

  async resolveStatusId(tenantId: string, nameOrId: string): Promise<string> {
    if (isUuid(nameOrId)) return nameOrId;
    const { primaryStatuses } = await this.get(tenantId);
    return matchReference("primary status", primaryStatuses, nameOrId).id;
  }

  async resolveStatus(tenantId: string, nameOrId: string): Promise<FusionCasePrimaryStatus> {
    const { primaryStatuses } = await this.get(tenantId);
    if (isUuid(nameOrId)) {
      const byId = primaryStatuses.find((s) => s.id === nameOrId);
      if (byId) return byId;
      // An ID the cache does not know may still be valid for the tenant (the
      // cache can be up to 15 minutes old). Let the API decide; assume open.
      return { id: nameOrId, name: nameOrId, title: null, isClosed: false };
    }
    return matchReference("primary status", primaryStatuses, nameOrId);
  }

  async resolveVerdictId(tenantId: string, nameOrId: string): Promise<string> {
    if (isUuid(nameOrId)) return nameOrId;
    const { primaryVerdicts } = await this.get(tenantId);
    return matchReference("primary verdict", primaryVerdicts, nameOrId).id;
  }

  private async fetch(tenantId: string): Promise<CaseReferenceData> {
    const { data, warnings } = await this.client.query<FusionCaseReferenceDataResponse>(
      tenantId,
      CASE_REFERENCE_DATA
    );
    const missing = (["caseTypes", "casePrimaryStatuses", "casePrimaryVerdicts"] as const).filter(
      (key) => data[key] === null || data[key] === undefined
    );
    if (missing.length > 0) {
      throw new Error(
        `Case reference data incomplete for tenant ${tenantId} (missing ${missing.join(", ")})${warnings.length ? `: ${warnings.join("; ")}` : ""}`
      );
    }
    return {
      types: data.caseTypes!.types,
      primaryStatuses: data.casePrimaryStatuses!.primaryStatuses,
      primaryVerdicts: data.casePrimaryVerdicts!.primaryVerdicts,
      fetchedAt: new Date().toISOString(),
    };
  }
}

/** Matches on `name` first, then `title`, both case-insensitive. */
export function matchReference<T extends FusionReferenceItem>(
  kind: string,
  items: T[],
  nameOrTitle: string
): T {
  const wanted = nameOrTitle.trim().toLowerCase();
  const found =
    items.find((item) => item.name.toLowerCase() === wanted) ??
    items.find((item) => (item.title ?? "").toLowerCase() === wanted);
  if (!found) {
    const available = items.map((item) => item.name).join(", ") || "none";
    throw new Error(
      `Unknown ${kind} "${nameOrTitle}" for this tenant. Available: ${available}. Use sophos_fusion_list_case_reference_data to see IDs and titles.`
    );
  }
  return found;
}
