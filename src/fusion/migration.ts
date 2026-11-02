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
 * The signal is the tenant record's xdrOwnership, read on the Fusion GraphQL
 * endpoint: "sophos" means the tenant is not yet upgraded and its cases are
 * still in the Classic Threat Analysis Center; any other value
 * ("securityOperations" where measured) means it is upgraded (live,
 * 27/09/2026 and 02/11/2026). Case types do not tell the two apart: a tenant
 * not yet upgraded can list Fusion case types too (a partner's test tenant
 * lists five and holds five live Classic cases, 02/11/2026).
 * So case types are only a fallback for when xdrOwnership can't be read, and
 * then only an empty list settles it: no case types means not upgraded (148
 * such tenants, 22/09/2026). A list with types leaves the answer unknown.
 *
 * A tenant Fusion does not hold gets HTTP 503 "tenant <id> not found or not
 * accessible" instead (FusionTenantNotOnFusionError, the same answer every
 * time, 29/10/2026). That is a definite "not migrated". The guard holds each
 * definite answer (an xdrOwnership value or that 503) per tenant for the
 * reference data TTL, 15 minutes, so a Classic call costs at most one extra
 * GraphQL round trip per tenant per window. Any other failure is not held
 * and yields a warning.
 */

import { CLASSIC_MIGRATION_CHECK } from "../config/config.js";
import { FusionTenantNotOnFusionError } from "../client/fusion-client.js";
import { CASE_REFERENCE_DATA_TTL_MS, type CaseReferenceDataCache } from "./case-reference-data.js";

export const UPGRADE_CENTRE_URL =
  "https://community.sophos.com/sophos-xdr/sophos-xdr-mdr-expansion/upgrade-center";

export interface MigrationStatus {
  tenantId: string;
  /** true migrated, false not migrated (including a tenant Fusion does not hold), null when the check was skipped or could not decide. */
  migrated: boolean | null;
  /** The tenant record's xdrOwnership, or null when it was not read or had no value. */
  xdrOwnership: string | null;
  /** Fusion case type names, read only by the fallback when xdrOwnership is unavailable (empty otherwise). */
  caseTypes: string[];
  detail: string;
}

/** upgraded: Sophos Fusion XDR, Security Operations. not_upgraded: still on the Classic Threat Analysis Center. */
export type TenantType = "upgraded" | "not_upgraded" | "unknown";

export function tenantTypeOf(status: Pick<MigrationStatus, "migrated">): TenantType {
  if (status.migrated === true) return "upgraded";
  if (status.migrated === false) return "not_upgraded";
  return "unknown";
}

export class FusionMigrationGuard {
  /** Definite answers (an xdrOwnership value, or Fusion's "not found or not accessible") and until when each holds. */
  private held = new Map<string, { status: MigrationStatus; until: number }>();

  constructor(
    private referenceData: Pick<CaseReferenceDataCache, "get" | "xdrOwnership">,
    private enabled: boolean = CLASSIC_MIGRATION_CHECK,
    private heldTtlMs: number = CASE_REFERENCE_DATA_TTL_MS
  ) {}

  /** The answer the Classic tools act on. Never calls Fusion when the check is disabled. */
  async status(tenantId: string): Promise<MigrationStatus> {
    if (!this.enabled) {
      return {
        tenantId,
        migrated: null,
        xdrOwnership: null,
        caseTypes: [],
        detail: "migration check disabled (SOPHOS_CLASSIC_MIGRATION_CHECK=off)",
      };
    }
    return this.detect(tenantId);
  }

  /**
   * Decides the tenant type whether or not the Classic check is enabled.
   * Never throws. refresh ignores a held answer.
   */
  async detect(tenantId: string, options: { refresh?: boolean } = {}): Promise<MigrationStatus> {
    const held = this.held.get(tenantId);
    if (held && !options.refresh && Date.now() < held.until) return held.status;

    let unread: string;
    try {
      const owner = await this.referenceData.xdrOwnership(tenantId);
      if (owner !== null) return this.hold(ownershipStatus(tenantId, owner));
      unread = "the tenant record has no xdrOwnership value";
    } catch (error) {
      if (error instanceof FusionTenantNotOnFusionError) return this.hold(notOnFusionStatus(tenantId));
      unread = `xdrOwnership unavailable: ${messageOf(error)}`;
    }

    try {
      const { types } = await this.referenceData.get(tenantId);
      const caseTypes = types.map((t) => t.name);
      if (caseTypes.length === 0) {
        return {
          tenantId,
          migrated: false,
          xdrOwnership: null,
          caseTypes,
          detail: `${unread}; Fusion exposes no case types for this tenant, so it is not upgraded`,
        };
      }
      return {
        tenantId,
        migrated: null,
        xdrOwnership: null,
        caseTypes,
        detail: `${unread}; Fusion exposes case types ${caseTypes.join(", ")}, which a tenant not yet upgraded can list too`,
      };
    } catch (error) {
      if (error instanceof FusionTenantNotOnFusionError) return this.hold(notOnFusionStatus(tenantId));
      return {
        tenantId,
        migrated: null,
        xdrOwnership: null,
        caseTypes: [],
        detail: `${unread}; Fusion reference data unavailable: ${messageOf(error)}`,
      };
    }
  }

  /**
   * Gate for a Classic tool. Throws with a pointer to the Fusion replacement
   * when the tenant has migrated. Returns warnings to attach to the Classic
   * result otherwise: one when the check could not decide, none when the
   * tenant is known not to have migrated or the check is disabled.
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

  private hold(status: MigrationStatus): MigrationStatus {
    this.held.set(status.tenantId, { status, until: Date.now() + this.heldTtlMs });
    return status;
  }
}

function ownershipStatus(tenantId: string, owner: string): MigrationStatus {
  const notUpgraded = owner.toLowerCase() === "sophos";
  return {
    tenantId,
    migrated: !notUpgraded,
    xdrOwnership: owner,
    caseTypes: [],
    detail: notUpgraded
      ? `xdrOwnership is "${owner}": not yet upgraded, its cases and detections are still in the Classic Threat Analysis Center`
      : `xdrOwnership is "${owner}": upgraded to Sophos Fusion XDR Security Operations`,
  };
}

function notOnFusionStatus(tenantId: string): MigrationStatus {
  return {
    tenantId,
    migrated: false,
    xdrOwnership: null,
    caseTypes: [],
    detail: "Fusion does not hold this tenant (HTTP 503 tenant not found or not accessible), so it is not on Sophos Fusion",
  };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
