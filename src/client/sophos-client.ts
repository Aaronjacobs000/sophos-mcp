/**
 * HTTP client for Sophos Central APIs.
 * Handles region-aware routing, auth headers, retries, and error mapping.
 */

import type { TokenManager } from "../auth/token-manager.js";
import type { TenantResolver } from "./tenant-resolver.js";
import type { SophosApiError } from "../types/sophos.js";

export interface RequestOptions {
  /** HTTP method */
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Query parameters */
  params?: Record<string, string>;
  /** JSON request body */
  body?: unknown;
  /** Additional headers */
  headers?: Record<string, string>;
}

/**
 * Tools build REST paths by interpolating ID arguments, and those arguments
 * come from the model, so a prompt-injected ID such as "../../common/v1/admins/x"
 * would turn an approved call into the same method on a different resource.
 * URL parsing resolves "." and ".." segments (percent-encoded too), treats a
 * backslash as a slash and drops tabs and newlines, and "?" or "#" would cut
 * the path short. No API path or ID needs any of these, and query strings go
 * through `params`, never the path, so a path carrying one is refused before
 * any token is fetched or request sent.
 */
export function assertSafeApiPath(path: string): void {
  const refuse = (): never => {
    throw new Error(
      `Refused request path "${path}": an ID argument contains a "." or ".." segment, "?", "#", a backslash, an encoded "/" or a control character, which would send the request to a different API path. Check the ID.`
    );
  };
  if (!path.startsWith("/") || /[?#\\\u0000-\u001f\u007f]/.test(path)) refuse();
  for (const segment of path.slice(1).split("/")) {
    // Decode until stable so double encoding cannot hide a dot segment
    let decoded = segment;
    for (let rounds = 0; ; rounds++) {
      if (rounds === 5) refuse();
      let next: string;
      try {
        next = decodeURIComponent(decoded);
      } catch {
        return refuse();
      }
      if (next === decoded) break;
      decoded = next;
    }
      if (decoded === "." || decoded === ".." || /[/\\\u0000-\u001f\u007f]/.test(decoded)) refuse();
  }
}

export class SophosClient {
  constructor(
    private tokenManager: TokenManager,
    private tenantResolver: TenantResolver
  ) {}

  /**
   * Make a request to a tenant-scoped API endpoint.
   * Automatically resolves the regional API host for the tenant.
   */
  async tenantRequest<T>(
    tenantId: string,
    path: string,
    options: RequestOptions = {}
  ): Promise<T> {
    assertSafeApiPath(path);
    const apiHost = await this.tenantResolver.resolveApiHost(tenantId);
    const token = await this.tokenManager.getToken();

    const url = new URL(`${apiHost}${path}`);
    if (options.params) {
      for (const [key, value] of Object.entries(options.params)) {
        if (value !== undefined && value !== "") {
          url.searchParams.set(key, value);
        }
      }
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      "X-Tenant-ID": tenantId,
      ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    };

    const fetchOptions: globalThis.RequestInit = {
      method: options.method || "GET",
      headers,
    };

    if (options.body) {
      fetchOptions.body = JSON.stringify(options.body);
    }

    return this.executeWithRetry<T>(url.toString(), fetchOptions);
  }

  /**
   * Make a request to a global API endpoint (partner/org level).
   */
  async globalRequest<T>(
    path: string,
    options: RequestOptions = {}
  ): Promise<T> {
    assertSafeApiPath(path);
    const identity = this.tenantResolver.getIdentity();
    const token = await this.tokenManager.getToken();
    const idHeader = this.tenantResolver.getIdHeader();

    const url = new URL(`${identity.apiHosts.global}${path}`);
    if (options.params) {
      for (const [key, value] of Object.entries(options.params)) {
        if (value !== undefined && value !== "") {
          url.searchParams.set(key, value);
        }
      }
    }

    // Some global-host APIs (licensing, accounts, audit, business automation) are
    // scoped by an explicit X-Tenant-ID / X-Distributor-ID header. Sending the
    // caller's identity header alongside those can be rejected, so skip it when
    // the caller provides its own scope header.
    const hasOwnScopeHeader =
      options.headers &&
      Object.keys(options.headers).some((h) =>
        ["x-tenant-id", "x-distributor-id"].includes(h.toLowerCase())
      );

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      ...(hasOwnScopeHeader ? {} : { [idHeader.name]: idHeader.value }),
      ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    };

    const fetchOptions: globalThis.RequestInit = {
      method: options.method || "GET",
      headers,
    };

    if (options.body) {
      fetchOptions.body = JSON.stringify(options.body);
    }

    return this.executeWithRetry<T>(url.toString(), fetchOptions);
  }

  private async executeWithRetry<T>(
    url: string,
    options: globalThis.RequestInit,
    retries = 2
  ): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30_000);
        let response: globalThis.Response;
        try {
          response = await fetch(url, { ...options, signal: controller.signal });
        } finally {
          clearTimeout(timeout);
        }

        if (response.status === 429) {
          // Rate limited: wait and retry
          const retryAfter = response.headers.get("Retry-After");
          const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000;
          console.error(
            `[sophos-client] Rate limited, waiting ${waitMs}ms (attempt ${attempt + 1})`
          );
          await this.sleep(waitMs);
          continue;
        }

        if (!response.ok) {
          const errorBody = await response.text();
          let parsed: SophosApiError | null = null;
          try {
            parsed = JSON.parse(errorBody) as SophosApiError;
          } catch {
            // Not JSON
          }

          const msg = parsed
            ? `Sophos API error ${response.status}: ${parsed.error ?? "UnknownError"}${parsed.message ? ` - ${parsed.message}` : ""}${parsed.correlationId ? ` (correlationId: ${parsed.correlationId})` : ""}`
            : `Sophos API error (${response.status}): ${errorBody.slice(0, 500)}`;

          throw new Error(msg);
        }

        // Some endpoints return 204 No Content
        if (response.status === 204) {
          return {} as T;
        }

        return (await response.json()) as T;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Don't retry on 4xx client errors (message contains "error NNN:" where NNN is 4xx)
        if (/Sophos API error 4\d\d:/.test(lastError.message)) {
          throw lastError;
        }

        if (attempt < retries) {
          const backoff = Math.pow(2, attempt) * 1000;
          console.error(
            `[sophos-client] Request failed, retrying in ${backoff}ms: ${lastError.message}`
          );
          await this.sleep(backoff);
        }
      }
    }

    throw lastError || new Error("Request failed after retries");
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
