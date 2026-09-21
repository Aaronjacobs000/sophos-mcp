/**
 * GraphQL client for the Sophos Fusion APIs (Cases v2, Detections v2, Threat
 * Timeline v2, Events v1, Live Endpoint Search v1). Sits beside SophosClient,
 * which keeps serving the Sophos Central REST APIs.
 *
 * One endpoint for every tenant, no regional host lookup. Auth is unchanged:
 * the same bearer token from TokenManager and the same X-Tenant-ID header the
 * REST client sends.
 *
 * The rule that shapes this file: a GraphQL-layer failure comes back as HTTP
 * 200 with an `errors` array beside `data`. A 200 is not success until the
 * body has been read. Transport failures (expired token, 429, 5xx) use the
 * usual non-2xx status and the standard Sophos error object, and those are
 * retried the same way SophosClient retries them. GraphQL-layer errors are
 * never retried: a query the schema rejects will be rejected again.
 */

import { SOPHOS_FUSION_GRAPHQL_URL } from "../config/config.js";
import type { TokenManager } from "../auth/token-manager.js";
import type { SophosApiError } from "../types/sophos.js";

/** One entry of a GraphQL response `errors` array. */
export interface GraphQLErrorEntry {
  message: string;
  path?: Array<string | number>;
  locations?: Array<{ line: number; column: number }>;
  extensions?: Record<string, unknown>;
}

interface GraphQLResponseBody<T> {
  data?: T | null;
  errors?: GraphQLErrorEntry[];
}

export interface FusionQueryResult<T> {
  /** The response `data` object. Never null: a response with no usable data throws. */
  data: T;
  /**
   * GraphQL errors that arrived beside usable data (a partial response, for
   * example a federated field that could not be resolved). Empty on a clean
   * response. Tools must surface these; they are not silently dropped.
   */
  warnings: string[];
}

export interface FusionClientOptions {
  /** GraphQL endpoint. Defaults to SOPHOS_FUSION_GRAPHQL_URL. */
  url?: string;
  /** Per-attempt timeout. Default 30 s, matching SophosClient. */
  timeoutMs?: number;
  /** Retries after the first attempt for 429, 5xx and network errors. Default 2. */
  retries?: number;
  /** Base for the full-jitter exponential backoff. Default 1000 ms. */
  backoffBaseMs?: number;
}

/** Thrown when the GraphQL layer returns errors and no usable data. */
export class FusionGraphQLError extends Error {
  constructor(
    message: string,
    readonly errors: GraphQLErrorEntry[]
  ) {
    super(message);
    this.name = "FusionGraphQLError";
  }
}

export class FusionClient {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly backoffBaseMs: number;

  constructor(
    private tokenManager: TokenManager,
    options: FusionClientOptions = {}
  ) {
    this.url = options.url ?? SOPHOS_FUSION_GRAPHQL_URL;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.retries = options.retries ?? 2;
    this.backoffBaseMs = options.backoffBaseMs ?? 1000;
  }

  /** The endpoint this client posts to. */
  get endpoint(): string {
    return this.url;
  }

  /**
   * Run a GraphQL query or mutation for a tenant.
   *
   * Returns the `data` object plus any partial-response warnings. Throws
   * FusionGraphQLError when the response carries errors and no usable data,
   * and a plain Error for transport failures.
   */
  async query<T extends object>(
    tenantId: string,
    document: string,
    variables: Record<string, unknown> = {}
  ): Promise<FusionQueryResult<T>> {
    const token = await this.tokenManager.getToken();

    const fetchOptions: globalThis.RequestInit = {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Tenant-ID": tenantId,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ query: document, variables }),
    };

    const body = await this.executeWithRetry<GraphQLResponseBody<T>>(fetchOptions);
    return interpretGraphQLBody<T>(body);
  }

  private async executeWithRetry<T>(options: globalThis.RequestInit): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
        let response: globalThis.Response;
        try {
          response = await fetch(this.url, { ...options, signal: controller.signal });
        } finally {
          clearTimeout(timeout);
        }

        if (response.status === 429) {
          const retryAfter = response.headers.get("Retry-After");
          const waitMs = retryAfter
            ? parseInt(retryAfter, 10) * 1000
            : this.backoffBaseMs * 5;
          console.error(
            `[fusion-client] Rate limited, waiting ${waitMs}ms (attempt ${attempt + 1})`
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
            ? `Sophos Fusion API error ${response.status}: ${parsed.error ?? "UnknownError"}${parsed.message ? ` - ${parsed.message}` : ""}${parsed.correlationId ? ` (correlationId: ${parsed.correlationId})` : ""}`
            : `Sophos Fusion API error ${response.status}: ${errorBody.slice(0, 500)}`;

          throw new Error(msg);
        }

        const text = await response.text();
        try {
          return JSON.parse(text) as T;
        } catch {
          throw new Error(
            `Sophos Fusion API returned a non-JSON body with status ${response.status}: ${text.slice(0, 200)}`
          );
        }
      } catch (error) {
        lastError =
          error instanceof Error && error.name === "AbortError"
            ? new Error(`Sophos Fusion API request timed out after ${this.timeoutMs}ms`)
            : error instanceof Error
              ? error
              : new Error(String(error));

        // Don't retry on 4xx client errors
        if (/Sophos Fusion API error 4\d\d:/.test(lastError.message)) {
          throw lastError;
        }

        if (attempt < this.retries) {
          // Full-jitter exponential backoff, as the Sophos rate-limit guidance recommends
          const cap = this.backoffBaseMs * Math.pow(2, attempt);
          const backoff = Math.round(Math.random() * cap);
          console.error(
            `[fusion-client] Request failed, retrying in ${backoff}ms: ${lastError.message}`
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

/**
 * Decide what a 200 response actually means.
 *
 * - errors present, no usable data: throw with every message joined.
 * - errors present beside usable data: return the data with the errors as warnings.
 * - no errors, data present: clean result. A root field that is null with no
 *   error (for example `case` for an unknown ID) is legitimate and passes
 *   through for the tool to report.
 * - no errors, no data: malformed, throw.
 */
export function interpretGraphQLBody<T extends object>(
  body: GraphQLResponseBody<T> | null | undefined
): FusionQueryResult<T> {
  const errors = Array.isArray(body?.errors) ? body.errors : [];
  const data = body?.data;
  const hasUsableData =
    data !== null &&
    data !== undefined &&
    typeof data === "object" &&
    Object.values(data).some((value) => value !== null && value !== undefined);

  if (errors.length > 0 && !hasUsableData) {
    throw new FusionGraphQLError(
      `Sophos Fusion GraphQL error: ${errors.map(formatGraphQLError).join("; ")}`,
      errors
    );
  }

  if (data === null || data === undefined || typeof data !== "object") {
    throw new Error("Sophos Fusion API returned neither data nor errors");
  }

  return { data, warnings: errors.map(formatGraphQLError) };
}

export function formatGraphQLError(error: GraphQLErrorEntry): string {
  const parts = [error.message || "Unknown GraphQL error"];
  if (error.path && error.path.length > 0) {
    parts.push(`(path: ${error.path.join(".")})`);
  }
  const code = error.extensions?.code;
  if (typeof code === "string" && code) {
    parts.push(`[${code}]`);
  }
  return parts.join(" ");
}
