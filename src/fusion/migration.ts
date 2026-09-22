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
 */

import { CLASSIC_MIGRATION_CHECK } from "../config/config.js";
import type { CaseReferenceDataCache } from "./case-reference-data.js";

export const UPGRADE_CENTRE_URL =
  "https://community.sophos.com/sophos-xdr/sophos-xdr-mdr-expansion/upgrade-center";

export interface MigrationStatus {
  tenantId: string;
  /** true migrated, false not migrated, null when the check was skipped or Fusion could not be reached. */
  migrated: boolean | null;
  /** Fusion case type names the tenant exposes (empty when not migrated). */
  caseTypes: string[];
  detail: string;
}

export class FusionMigrationGuard {
  constructor(
    private referenceData: Pick<CaseReferenceDataCache, "get">,
    private enabled: boolean = CLASSIC_MIGRATION_CHECK
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
