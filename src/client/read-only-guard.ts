/**
 * Read-only mode's request guard (SOPHOS_READ_ONLY). Every request this
 * process sends goes through guardedFetch. With the mode on, it refuses
 * anything that could change a tenant before it leaves the process: every
 * method but GET and HEAD, except the OAuth token request, a Fusion GraphQL
 * request whose document holds no mutation or subscription, and the REST
 * searches in READ_ONLY_POST_PATHS. The tool filter in src/read-only.ts is
 * the other guard. Each one stops a write on its own.
 *
 * The clients also check before they fetch a token, so a refused call sends
 * nothing at all. guardedFetch is the backstop for every other path,
 * including the presigned transfers and anything added later.
 */

import { SOPHOS_AUTH_URL, SOPHOS_FUSION_GRAPHQL_URL } from "../config/config.js";
import { isSophosApiBase } from "./hosts.js";

let readOnly = false;

/** Turns the guard on for the life of the process. There is no way to turn it off again. */
export function enableReadOnlyMode(): void {
  readOnly = true;
}

export function isReadOnlyMode(): boolean {
  return readOnly;
}

export class ReadOnlyModeError extends Error {
  constructor(what: string) {
    super(`Read-only mode (SOPHOS_READ_ONLY) refused ${what}. Nothing was sent.`);
    this.name = "ReadOnlyModeError";
  }
}

/**
 * The REST POSTs read-only mode lets through. Each one searches and returns
 * matches; none stores anything in the tenant. Matched against the path only,
 * on a sophos.com API host.
 */
export const READ_ONLY_POST_PATHS: readonly RegExp[] = [
  /^\/common\/v1\/alerts\/search$/,
  /^\/email\/v1\/quarantine\/messages\/search$/,
  /^\/email\/v1\/post-delivery-quarantine\/messages\/search$/,
  /^\/firewall\/v1\/firewall-config\/firewalls\/[^/]+\/mdr-threat-feed\/indicators\/search$/,
];

/**
 * True when a GraphQL document can only read. A mutation or subscription
 * operation has to spell its keyword as a bare name, so a document without
 * either word anywhere cannot hold one. Case is ignored and comments and
 * strings are not skipped, so the check can refuse a read, never pass a write.
 */
export function isGraphQLReadOnly(document: unknown): boolean {
  return typeof document === "string" && document.trim() !== "" && !/\b(?:mutation|subscription)\b/i.test(document);
}

/** Why read-only mode refuses this REST call, or null when it may go. */
export function restRefusal(method: string, path: string): string | null {
  const verb = method.toUpperCase();
  if (verb === "GET" || verb === "HEAD") return null;
  if (verb === "POST" && READ_ONLY_POST_PATHS.some((pattern) => pattern.test(path))) return null;
  return `${verb} ${path}`;
}

/** Throws ReadOnlyModeError when read-only mode is on and this REST call could write. */
export function assertReadOnlyRest(method: string, path: string): void {
  if (!readOnly) return;
  const refusal = restRefusal(method, path);
  if (refusal) throw new ReadOnlyModeError(refusal);
}

/** Throws ReadOnlyModeError when read-only mode is on and the document could write. */
export function assertReadOnlyGraphQL(document: string): void {
  if (readOnly && !isGraphQLReadOnly(document)) throw new ReadOnlyModeError("a Fusion GraphQL mutation");
}

function graphQLDocument(body: unknown): unknown {
  if (typeof body !== "string") return undefined;
  try {
    const parsed = JSON.parse(body) as unknown;
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as { query?: unknown }).query
      : undefined;
  } catch {
    return undefined;
  }
}

/** Why read-only mode refuses this request, or null when it may go. */
export function requestRefusal(url: string, init: RequestInit = {}): string | null {
  const method = (init.method ?? "GET").toUpperCase();
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `${method} to an address that does not parse`;
  }
  const where = `${parsed.host}${parsed.pathname}`;

  const graphql = new URL(SOPHOS_FUSION_GRAPHQL_URL);
  if (parsed.origin === graphql.origin && parsed.pathname === graphql.pathname) {
    if (method !== "POST") return `${method} ${where}`;
    return isGraphQLReadOnly(graphQLDocument(init.body)) ? null : "a Fusion GraphQL mutation";
  }
  if (method === "GET" || method === "HEAD") return null;
  if (method === "POST" && url === SOPHOS_AUTH_URL) return null;
  if (isSophosApiBase(parsed.origin) && restRefusal(method, parsed.pathname) === null) return null;
  return `${method} ${where}`;
}

/** fetch, behind the read-only guard. Every outbound request in src/ goes through this. */
export function guardedFetch(url: string, init?: RequestInit): Promise<Response> {
  if (readOnly) {
    const refusal = requestRefusal(url, init);
    if (refusal) return Promise.reject(new ReadOnlyModeError(refusal));
  }
  return globalThis.fetch(url, init);
}
