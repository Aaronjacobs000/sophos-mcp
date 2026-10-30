/**
 * Where a bearer token may go, ported from NotFusion (sophos-core hosts.ts,
 * 3a952a1). Sophos's answers name the API hosts the server calls later:
 * whoami's global and dataRegion hosts, and each tenant's apiHost in a
 * partner or organization tenant list. Before a token goes on a request, its
 * host must be an https address on sophos.com: no other scheme, no port, no
 * user name or password, no path, query or fragment. A host from an
 * unexpected answer then fails here, and nothing is sent.
 */

const SOPHOS_API_BASE = /^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+sophos\.com$/;

export class UntrustedHostError extends Error {
  constructor() {
    super("Sophos named an API address outside sophos.com, so the MCP server sent nothing to it.");
    this.name = "UntrustedHostError";
  }
}

/** True for an https host on sophos.com, as Sophos writes them: "https://api-eu01.central.sophos.com". */
export function isSophosApiBase(host: unknown): host is string {
  return typeof host === "string" && SOPHOS_API_BASE.test(host.endsWith("/") ? host.slice(0, -1) : host);
}

/** The host as a base to build request URLs on, without a trailing slash. Throws UntrustedHostError for anything else. */
export function sophosApiBase(host: unknown): string {
  if (!isSophosApiBase(host)) throw new UntrustedHostError();
  return host.endsWith("/") ? host.slice(0, -1) : host;
}
