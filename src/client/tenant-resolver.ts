/**
 * Discovers the caller's identity type via /whoami/v1 and resolves
 * tenant IDs to their regional API hosts. Caches the mapping.
 */

import { SOPHOS_GLOBAL_API } from "../config/config.js";
import { refuseRedirect } from "./redirect.js";
import type { TokenManager } from "../auth/token-manager.js";
import type {
  SophosIdType,
  SophosWhoamiResponse,
  SophosTenant,
  SophosTenantPage,
} from "../types/sophos.js";

export interface TenantInfo {
  id: string;
  name: string;
  apiHost: string;
  dataRegion: string;
  dataGeography: string;
}

export interface CallerIdentity {
  id: string;
  idType: SophosIdType;
  apiHosts: {
    global: string;
    dataRegion?: string;
  };
}

export class TenantResolver {
  private identity: CallerIdentity | null = null;
  private tenantCache = new Map<string, TenantInfo>();
  private tenantsLoaded = false;

  constructor(private tokenManager: TokenManager) {}

  /**
   * Initialise: calls /whoami/v1 and discovers the caller identity.
   */
  async init(): Promise<CallerIdentity> {
    const token = await this.tokenManager.getToken();
    const whoamiUrl = `${SOPHOS_GLOBAL_API}/whoami/v1`;
    const response = await fetch(whoamiUrl, {
      headers: { Authorization: `Bearer ${token}` },
      redirect: "manual",
    });
    refuseRedirect(response, whoamiUrl);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Whoami failed (${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as SophosWhoamiResponse;
    this.identity = {
      id: data.id,
      idType: data.idType,
      apiHosts: data.apiHosts,
    };

    console.error(
      `[sophos-tenant] Identity: ${data.idType} (${data.id})`
    );

    // For tenant-level callers, the data region host is returned directly
    if (data.idType === "tenant" && data.apiHosts.dataRegion) {
      this.tenantCache.set(data.id, {
        id: data.id,
        name: "self",
        apiHost: data.apiHosts.dataRegion,
        dataRegion: "self",
        dataGeography: "unknown",
      });
      this.tenantsLoaded = true;
    }

    return this.identity;
  }

  getIdentity(): CallerIdentity {
    if (!this.identity) {
      throw new Error("TenantResolver not initialised. Call init() first.");
    }
    return this.identity;
  }

  /**
   * Returns the ID type header name needed for partner/org API calls.
   */
  getIdHeader(): { name: string; value: string } {
    const identity = this.getIdentity();
    switch (identity.idType) {
      case "partner":
        return { name: "X-Partner-ID", value: identity.id };
      case "organization":
        return { name: "X-Organization-ID", value: identity.id };
      case "tenant":
        return { name: "X-Tenant-ID", value: identity.id };
    }
  }

  /**
   * Loads all tenants for partner/org callers. Paginates through all pages.
   */
  async loadTenants(): Promise<TenantInfo[]> {
    const identity = this.getIdentity();

    if (identity.idType === "tenant") {
      return Array.from(this.tenantCache.values());
    }

    if (this.tenantsLoaded) {
      return Array.from(this.tenantCache.values());
    }

    const apiPath =
      identity.idType === "partner"
        ? "/partner/v1/tenants"
        : "/organization/v1/tenants";

    const idHeader = this.getIdHeader();
    let page = 1;
    let totalPages = 1;

    while (page <= totalPages) {
      const token = await this.tokenManager.getToken();
      const url = new URL(`${SOPHOS_GLOBAL_API}${apiPath}`);
      url.searchParams.set("page", String(page));
      if (page === 1) {
        url.searchParams.set("pageTotal", "true");
      }

      const response = await fetch(url.toString(), {
        headers: {
          Authorization: `Bearer ${token}`,
          [idHeader.name]: idHeader.value,
        },
        redirect: "manual",
      });
      refuseRedirect(response, url.toString());

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `List tenants failed (${response.status}): ${errorText}`
        );
      }

      const data = (await response.json()) as SophosTenantPage;

      if (page === 1 && data.pages.total) {
        totalPages = data.pages.total;
      }

      for (const tenant of data.items) {
        this.tenantCache.set(tenant.id, {
          id: tenant.id,
          name: tenant.name,
          apiHost: tenant.apiHost,
          dataRegion: tenant.dataRegion,
          dataGeography: tenant.dataGeography,
        });
      }

      page++;
    }

    this.tenantsLoaded = true;
    console.error(
      `[sophos-tenant] Loaded ${this.tenantCache.size} tenants`
    );
    return Array.from(this.tenantCache.values());
  }

  /**
   * Resolves a tenant ID to its API host. Loads tenants if not cached.
   */
  async resolveApiHost(tenantId: string): Promise<string> {
    if (this.tenantCache.has(tenantId)) {
      return this.tenantCache.get(tenantId)!.apiHost;
    }

    // Try loading tenants if we haven't yet
    if (!this.tenantsLoaded) {
      await this.loadTenants();
    }

    const info = this.tenantCache.get(tenantId);
    if (!info) {
      throw new Error(
        `Tenant ${tenantId} not found. Use sophos_list_tenants to see available tenants.`
      );
    }
    return info.apiHost;
  }

  /**
   * Returns the tenant ID to use. For single-tenant callers, returns the
   * identity ID. For partner/org callers, requires an explicit tenant ID.
   */
  resolveTenantId(providedTenantId?: string): string {
    const identity = this.getIdentity();

    if (identity.idType === "tenant") {
      return providedTenantId || identity.id;
    }

    if (!providedTenantId) {
      throw new Error(
        "tenant_id is required for partner/organization callers. " +
          "Use sophos_list_tenants to find available tenant IDs."
      );
    }

    return providedTenantId;
  }

  /**
   * Returns all cached tenants.
   */
  getCachedTenants(): TenantInfo[] {
    return Array.from(this.tenantCache.values());
  }
}
