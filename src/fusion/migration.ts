/**
 * Decides whether a tenant has moved to Sophos Fusion. For a migrated tenant
 * the Classic Cases and Detections REST tools are wrong, not merely
 * deprecated: those APIs answer from the pre-migration Sophos Central
 * objects, which are no longer the live ones (AJ, 22/09/2026; Sophos upgrade
 * centre, https://community.sophos.com/sophos-xdr/sophos-xdr-mdr-expansion/upgrade-center).
 * The Classic tools refuse such a tenant and name the Fusion tool to use.
 * For a tenant that has not moved they stay correct, so there is no blanket
 * deprecation label.
 *
 * The signal is the Fusion case reference data: a tenant that has not moved
 * gets HTTP 200 with an empty caseTypes list and no error (measured on 148
 * unmigrated tenants and one migrated one, 22/09/2026). The lookup shares the
 * 15 minute per-tenant cache, so a Classic call costs at most one extra
 * GraphQL round trip per tenant per cache window.
 *
 * A tenant Fusion does not hold gets HTTP 503 "tenant <id> not found or not
 * accessible" instead (FusionTenantNotOnFusionError, the same answer every
 * time, 29/10/2026). That is a definite "not migrated". The reference data
 * cache keeps only successes, so the guard holds this answer itself for the
 * same 15 minutes. Any other failure is not held and yields a warning.
 */

import { CLASSIC_MIGRATION_CHECK } from "../config/config.js";
import { FusionTenantNotOnFusionError } from "../client/fusion-client.js";
import { CASE_REFERENCE_DATA_TTL_MS, type CaseReferenceDataCache } from "./case-reference-data.js";

export const UPGRADE_CENTRE_URL =
  "https://community.sophos.com/sophos-xdr/sophos-xdr-mdr-expansion/upgrade-center";

export interface MigrationStatus {
  tenantId: string;
  /** true migrated, false not migrated (including a tenant Fusion does not hold), null when the check was skipped or Fusion could not be reached. */
  migrated: boolean | null;
  /** Fusion case type names the tenant exposes (empty when not migrated). */
  caseTypes: string[];
  detail: string;
}

export class FusionMigrationGuard {
  /** Tenants Fusion answered "not found or not accessible" for, and until when that answer holds. */
  private notOnFusion = new Map<string, number>();

  constructor(
    private referenceData: Pick<CaseReferenceDataCache, "get">,
    private enabled: boolean = CLASSIC_MIGRATION_CHECK,
    private notOnFusionTtlMs: number = CASE_REFERENCE_DATA_TTL_MS
  ) {}

  async status(tenantId: string): Promise<MigrationStatus> {
    if (!this.enabled) {
      return {
        tenantId,
        migrated: null,
        caseTypes: [],
        detail: "migration check disabled (SOPHOS_CLASSIC_MIGRATION_CHECK=off)",
      };
    }
    const heldUntil = this.notOnFusion.get(tenantId);
    if (heldUntil !== undefined && Date.now() < heldUntil) {
      return notOnFusionStatus(tenantId);
    }
    try {
      const { types } = await this.referenceData.get(tenantId);
      const caseTypes = types.map((t) => t.name);
      return {
        tenantId,
        migrated: caseTypes.length > 0,
        caseTypes,
        detail:
          caseTypes.length > 0
            ? `Fusion exposes case types ${caseTypes.join(", ")} for this tenant`
            : "Fusion exposes no case types for this tenant",
      };
    } catch (error) {
      if (error instanceof FusionTenantNotOnFusionError) {
        this.notOnFusion.set(tenantId, Date.now() + this.notOnFusionTtlMs);
        return notOnFusionStatus(tenantId);
      }
      const message = error instanceof Error ? error.message : String(error);
      return {
        tenantId,
        migrated: null,
        caseTypes: [],
        detail: `Fusion reference data unavailable: ${message}`,
      };
    }
  }

  /**
   * Gate for a Classic tool. Throws with a pointer to the Fusion replacement
   * when the tenant has migrated. Returns warnings to attach to the Classic
   * result otherwise: one when the check could not run, none when the tenant
   * is known not to have migrated or the check is disabled.
   */
  async assertClassic(tenantId: string, classicTool: string, useInstead: string): Promise<string[]> {
    const status = await this.status(tenantId);
    if (status.migrated === true) {
      throw new Error(
        `Tenant ${tenantId} has migrated to Sophos Fusion (${status.detail}). ${classicTool} calls the Classic Sophos Central API, which for a migrated tenant references the pre-migration objects rather than the live ones, so its answer would be wrong. Use ${useInstead}. Upgrade centre: ${UPGRADE_CENTRE_URL}`
      );
    }
    if (status.migrated === null && this.enabled) {
      return [
        `Could not confirm whether tenant ${tenantId} has migrated to Sophos Fusion (${status.detail}). If it has, this Classic result references pre-migration data; use ${useInstead}.`,
      ];
    }
    return [];
  }
}

function notOnFusionStatus(tenantId: string): MigrationStatus {
  return {
    tenantId,
    migrated: false,
    caseTypes: [],
    detail: "Fusion does not hold this tenant (HTTP 503 tenant not found or not accessible), so it is not on Sophos Fusion",
  };
}
