/**
 * Retry-After on a 429: seconds or an HTTP date (RFC 9110 section 10.2.3),
 * capped. parseInt on a date gave NaN and an instant retry. Checked on the
 * parser and on the REST and Fusion clients' waits, with fetch stubbed and
 * sleep recorded. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { retryAfterMs, MAX_RETRY_AFTER_MS } from "../dist/client/retry-after.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { FusionClient } from "../dist/client/fusion-client.js";

const NOW = Date.parse("2026-10-29T00:00:00Z");
const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";

test("seconds are honoured up to the cap", () => {
  assert.equal(retryAfterMs("0", 5000, NOW), 0);
  assert.equal(retryAfterMs("1", 5000, NOW), 1000);
  assert.equal(retryAfterMs(" 30 ", 5000, NOW), 30_000);
  assert.equal(retryAfterMs("60", 5000, NOW), MAX_RETRY_AFTER_MS);
  assert.equal(retryAfterMs("3600", 5000, NOW), MAX_RETRY_AFTER_MS);
  assert.equal(retryAfterMs("99999999999999999999", 5000, NOW), MAX_RETRY_AFTER_MS);
  assert.equal(MAX_RETRY_AFTER_MS, 60_000);
});

test("an HTTP date in any of its three forms waits until then, capped, and a past date means now", () => {
  assert.equal(retryAfterMs("Thu, 29 Oct 2026 00:00:10 GMT", 5000, NOW), 10_000, "IMF-fixdate");
  assert.equal(retryAfterMs("Thursday, 29-Oct-26 00:00:20 GMT", 5000, NOW), 20_000, "RFC 850");
  assert.equal(retryAfterMs("Thu Oct 29 00:00:30 2026", 5000, NOW), 30_000, "asctime is UTC, not local time");
  assert.equal(retryAfterMs("Thu, 29 Oct 2026 01:00:00 GMT", 5000, NOW), MAX_RETRY_AFTER_MS, "an hour away is capped");
  assert.equal(retryAfterMs("Wed, 28 Oct 2026 23:59:00 GMT", 5000, NOW), 0, "already passed");
});

test("a missing or unreadable Retry-After gives the fallback, never NaN", () => {
  for (const value of [null, undefined, "", "  ", "soon", "1.5", "-5", "60s", "Thu, 99 Oct 2026 00:00:10 GMT"]) {
    const ms = retryAfterMs(value, 5000, NOW);
    assert.equal(ms, 5000, JSON.stringify(value));
  }
});

/** fetch answers 429 with `retryAfter` on the first call and 200 after it. */
function stubOne429(retryAfter, okBody) {
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    if (calls === 1) {
      return new Response(JSON.stringify({ error: "TooManyRequests" }), {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": retryAfter },
      });
    }
    return new Response(JSON.stringify(okBody), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  return { calls: () => calls, restore: () => (globalThis.fetch = realFetch) };
}

/** An HTTP date `seconds` from now, as a server would send it. */
const httpDateIn = (seconds) => new Date(Date.now() + seconds * 1000).toUTCString();

test("the REST client waits for an HTTP date Retry-After instead of retrying at once", async () => {
  for (const [header, low, high] of [
    [httpDateIn(10), 8_000, 10_000],
    [httpDateIn(3600), MAX_RETRY_AFTER_MS, MAX_RETRY_AFTER_MS],
    ["2", 2_000, 2_000],
    ["garbage", 5_000, 5_000],
  ]) {
    const stub = stubOne429(header, { ok: true });
    try {
      const client = new SophosClient({ getToken: async () => "t" }, { resolveApiHost: async () => HOST, resolveTenantId: (id) => id });
      const waits = [];
      client.sleep = async (ms) => void waits.push(ms);
      assert.deepEqual(await client.tenantRequest(TENANT, "/endpoint/v1/endpoints"), { ok: true });
      assert.equal(stub.calls(), 2, header);
      assert.equal(waits.length, 1, header);
      assert.ok(Number.isFinite(waits[0]) && waits[0] >= low && waits[0] <= high, `${header}: waited ${waits[0]}ms`);
    } finally {
      stub.restore();
    }
  }
});

test("the Fusion client waits for an HTTP date Retry-After instead of retrying at once", async () => {
  for (const [header, low, high] of [
    [httpDateIn(10), 8_000, 10_000],
    [httpDateIn(3600), MAX_RETRY_AFTER_MS, MAX_RETRY_AFTER_MS],
    ["2", 2_000, 2_000],
    ["garbage", 5, 5],
  ]) {
    const stub = stubOne429(header, { data: { ok: true } });
    try {
      const client = new FusionClient({ getToken: async () => "t" }, { url: "https://fusion.test/graphql", backoffBaseMs: 1, retries: 2 });
      const waits = [];
      client.sleep = async (ms) => void waits.push(ms);
      assert.deepEqual((await client.query(TENANT, "query { ok }")).data, { ok: true });
      assert.equal(stub.calls(), 2, header);
      assert.equal(waits.length, 1, header);
      assert.ok(Number.isFinite(waits[0]) && waits[0] >= low && waits[0] <= high, `${header}: waited ${waits[0]}ms`);
    } finally {
      stub.restore();
    }
  }
});
