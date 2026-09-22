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
 * not retried, with one measured exception: the intermittent
 * partnerPreferences fault on the case write path, which is keyed on the
 * error path and bounded (see FusionGraphQLError.isTransientPartnerPreferences).
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
  /**
   * Total attempts for a call that hits the transient partnerPreferences
   * fault, which affects createCase and addEvidenceToCase. Measured on a live
   * tenant 22/09/2026: 111 faults in 150 calls, so 74%, and it drifts, with
   * four samples over six minutes running 60%, 85%, 72.5% and 80%. Default 20:
   * about 1 call in 410 fails at the measured 74%, and about 1 in 26 at the
   * worst rate observed. updateCase does not carry the fault at all, 0 in 30
   * in the same minute addEvidenceToCase was 24 in 30, so the defect is in the
   * two resolvers that read partner preferences.
   */
  transientAttempts?: number;
  /** Base for the short full-jitter backoff between those attempts. Default 300 ms, capped at 2 s. */
  transientBackoffMs?: number;
}

const TRANSIENT_BACKOFF_CAP_MS = 2000;

/** Thrown when the GraphQL layer returns errors and no usable data. */
export class FusionGraphQLError extends Error {
  constructor(
    message: string,
    readonly errors: GraphQLErrorEntry[]
  ) {
    super(message);
    this.name = "FusionGraphQLError";
  }

  /**
   * True when every error says the record does not exist. Fusion reports an
   * unknown case ID this way, as HTTP 200 with "record not found" beside a
   * null root field, rather than as a bare null (live tenant, 21/09/2026).
   */
  get notFound(): boolean {
    return (
      this.errors.length > 0 &&
      this.errors.every((error) => /record not found/i.test(error.message ?? ""))
    );
  }

  /**
   * True for the intermittent investigations-v2 fault on the case write
   * path: `errors[0].path[0]` is "partnerPreferences" ("not allowed",
   * DOWNSTREAM_SERVICE_ERROR). It is not an authorisation failure: the
   * identical call with identical input succeeds on retry. Keyed on the path
   * and nothing else, because `extensions.code` is DOWNSTREAM_SERVICE_ERROR
   * for transient faults, not found and malformed queries alike, while a
   * genuine input or permission error carries the operation name in the path
   * (createCase, addEvidenceToCase, tdrusers) with a specific message.
   */
  get isTransientPartnerPreferences(): boolean {
    return this.errors[0]?.path?.[0] === "partnerPreferences";
  }
}

export class FusionClient {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly backoffBaseMs: number;
  private readonly transientAttempts: number;
  private readonly transientBackoffMs: number;

  constructor(
    private tokenManager: TokenManager,
    options: FusionClientOptions = {}
  ) {
    this.url = options.url ?? SOPHOS_FUSION_GRAPHQL_URL;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.retries = options.retries ?? 2;
    this.backoffBaseMs = options.backoffBaseMs ?? 1000;
    this.transientAttempts = Math.max(1, options.transientAttempts ?? 20);
    this.transientBackoffMs = options.transientBackoffMs ?? 300;
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
   * and a plain Error for transport failures. The transient partnerPreferences
   * fault is retried up to transientAttempts times; every other GraphQL-layer
   * error surfaces at once.
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

    for (let attempt = 1; ; attempt++) {
      const body = await this.executeWithRetry<GraphQLResponseBody<T>>(fetchOptions);
      try {
        return interpretGraphQLBody<T>(body);
      } catch (error) {
        if (!(error instanceof FusionGraphQLError) || !error.isTransientPartnerPreferences) {
          throw error;
        }
        if (attempt >= this.transientAttempts) {
          throw new FusionGraphQLError(
            `${error.message} (transient investigations-v2 fault persisted across ${attempt} attempts; the same call normally succeeds on retry, so try again)`,
            error.errors
          );
        }
        const cap = Math.min(this.transientBackoffMs * Math.pow(2, attempt - 1), TRANSIENT_BACKOFF_CAP_MS);
        const backoff = Math.round(Math.random() * cap);
        console.error(
          `[fusion-client] Transient partnerPreferences fault, retrying in ${backoff}ms (attempt ${attempt} of ${this.transientAttempts})`
        );
        await this.sleep(backoff);
      }
    }
  }

  /**
   * PUT raw bytes to a presigned upload URL (case files). The signature lives
   * in the URL, so no bearer token is sent, and the Content-Type must match
   * what startCaseFileUpload was told. One attempt, no retry.
   */
  async putPresigned(url: string, body: Uint8Array, contentType: string): Promise<void> {
    const controller = new AbortController();
    const timeoutMs = Math.max(this.timeoutMs, 120_000);
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    let response: globalThis.Response;
    try {
      response = await fetch(url, {
        method: "PUT",
        headers: { "Content-Type": contentType },
        // A fresh copy sits on a plain ArrayBuffer, which is what fetch's body type accepts.
        body: new Uint8Array(body),
        signal: controller.signal,
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`Case file upload timed out after ${timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Case file upload failed with HTTP ${response.status}: ${text.slice(0, 300)}`);
    }
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
          let parsed: (SophosApiError & { errors?: GraphQLErrorEntry[] }) | null = null;
          try {
            parsed = JSON.parse(errorBody) as SophosApiError & { errors?: GraphQLErrorEntry[] };
          } catch {
            // Not JSON
          }

          // A query the schema rejects comes back as HTTP 400 with a GraphQL
          // errors array and no data (live tenant, 21/09/2026); keep its message.
          const graphqlErrors = Array.isArray(parsed?.errors) ? parsed.errors : [];
          const detail =
            graphqlErrors.length > 0
              ? graphqlErrors.map(formatGraphQLError).join("; ")
              : parsed
                ? [parsed.error, parsed.message].filter(Boolean).join(" - ") || errorBody.slice(0, 500)
                : errorBody.slice(0, 500);
          const correlation = parsed?.correlationId ? ` (correlationId: ${parsed.correlationId})` : "";

          throw new Error(`Sophos Fusion API error ${response.status}: ${detail}${correlation}`);
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
