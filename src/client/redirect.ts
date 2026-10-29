/**
 * Every request to Sophos goes out with redirect: "manual", and an answer in
 * the 3xx range is refused here instead of followed. Following it would send
 * the request again to whatever address the Location header names: on a 307
 * or 308 with the same body, which on the token request is the client secret,
 * and on an API call with the tenant or partner ID header.
 */

export class SophosRedirectError extends Error {
  constructor(
    readonly status: number,
    url: string,
    location: string | null
  ) {
    const target = redirectHost(url, location);
    super(
      `Sophos answered ${describe(url)} with a ${status} redirect${target ? ` to ${target}` : ""}. ` +
        "Redirects are never followed, so nothing was sent there."
    );
    this.name = "SophosRedirectError";
  }
}

/** Throws SophosRedirectError when the answer is a redirect. */
export function refuseRedirect(response: globalThis.Response, url: string): void {
  if (response.status < 300 || response.status > 399) return;
  response.body?.cancel().catch(() => {});
  throw new SophosRedirectError(response.status, url, response.headers.get("Location"));
}

/** Host and path, without the query string. */
function describe(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.host}${parsed.pathname}`;
  } catch {
    return "the request";
  }
}

function redirectHost(url: string, location: string | null): string | null {
  if (!location) return null;
  try {
    return new URL(location, url).host;
  } catch {
    return null;
  }
}
