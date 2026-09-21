/**
 * FusionClient transport tests. fetch is stubbed; nothing here reaches the
 * network. The important cases are the GraphQL-layer ones: a 200 is not
 * success until the body has been read.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  FusionClient,
  FusionGraphQLError,
  formatGraphQLError,
  interpretGraphQLBody,
} from "../dist/client/fusion-client.js";

const tokenManager = { getToken: async () => "test-token" };
const url = "https://fusion.test/graphql";
const originalFetch = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

function json(body, init = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

/** Installs a fetch stub. handler(attemptNumber, init) returns a Response. */
function stubFetch(handler) {
  const calls = [];
  globalThis.fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return handler(calls.length, init);
  };
  return calls;
}

function makeClient(options = {}) {
  return new FusionClient(tokenManager, { url, backoffBaseMs: 1, retries: 2, ...options });
}

test("clean 200 returns data and no warnings", async () => {
  stubFetch(() => json({ data: { cases: { totalCount: 1, cases: [{ id: "a" }] } } }));
  const result = await makeClient().query("tenant-1", "query { cases }");
  assert.deepEqual(result.data, { cases: { totalCount: 1, cases: [{ id: "a" }] } });
  assert.deepEqual(result.warnings, []);
});

test("posts JSON with the bearer token, X-Tenant-ID and the document plus variables", async () => {
  const calls = stubFetch(() => json({ data: { ok: true } }));
  await makeClient().query("tenant-1", "query Q($a: Int) { ok }", { a: 1 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, url);
  const { init } = calls[0];
  assert.equal(init.method, "POST");
  assert.equal(init.headers.Authorization, "Bearer test-token");
  assert.equal(init.headers["X-Tenant-ID"], "tenant-1");
  assert.equal(init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(init.body), { query: "query Q($a: Int) { ok }", variables: { a: 1 } });
});

test("200 with errors and null data throws with every message joined", async () => {
  stubFetch(() =>
    json({
      data: null,
      errors: [
        { message: "Cannot query field x", path: ["cases"], extensions: { code: "GRAPHQL_VALIDATION_FAILED" } },
        { message: "second problem" },
      ],
    })
  );
  await assert.rejects(
    () => makeClient().query("tenant-1", "query { cases }"),
    (error) => {
      assert.ok(error instanceof FusionGraphQLError);
      assert.match(error.message, /Cannot query field x \(path: cases\) \[GRAPHQL_VALIDATION_FAILED\]/);
      assert.match(error.message, /second problem/);
      assert.equal(error.errors.length, 2);
      return true;
    }
  );
});

test("200 with errors and every root field null throws", async () => {
  stubFetch(() => json({ data: { case: null }, errors: [{ message: "not found" }] }));
  await assert.rejects(() => makeClient().query("tenant-1", "query { case }"), FusionGraphQLError);
});

test("200 with data beside errors returns the data and non-empty warnings", async () => {
  stubFetch(() =>
    json({
      data: { case: { id: "c1", assigneeSubject: null } },
      errors: [{ message: "subject unavailable", path: ["case", "assigneeSubject"] }],
    })
  );
  const result = await makeClient().query("tenant-1", "query { case }");
  assert.equal(result.data.case.id, "c1");
  assert.deepEqual(result.warnings, ["subject unavailable (path: case.assigneeSubject)"]);
});

test("200 with a null root field and no errors passes through for the tool to report", async () => {
  stubFetch(() => json({ data: { case: null } }));
  const result = await makeClient().query("tenant-1", "query { case }");
  assert.deepEqual(result.data, { case: null });
  assert.deepEqual(result.warnings, []);
});

test("GraphQL-layer errors are never retried", async () => {
  const calls = stubFetch(() => json({ data: null, errors: [{ message: "bad query" }] }));
  await assert.rejects(() => makeClient().query("tenant-1", "query { x }"), FusionGraphQLError);
  assert.equal(calls.length, 1);
});

test("200 with a non-JSON body throws a clear error", async () => {
  stubFetch(() => json("<html>proxy page</html>", { headers: { "content-type": "text/html" } }));
  await assert.rejects(
    () => makeClient({ retries: 0 }).query("tenant-1", "query { x }"),
    /non-JSON body with status 200/
  );
});

test("4xx throws with the Sophos error object and is not retried", async () => {
  const calls = stubFetch(() =>
    json(
      { error: "Unauthorized", message: "token expired", correlationId: "abc-123" },
      { status: 401 }
    )
  );
  await assert.rejects(
    () => makeClient().query("tenant-1", "query { x }"),
    /Sophos Fusion API error 401: Unauthorized - token expired \(correlationId: abc-123\)/
  );
  assert.equal(calls.length, 1);
});

test("400 with a GraphQL errors array keeps the validation message", async () => {
  // Live shape (21/09/2026): a query the schema rejects is HTTP 400 with
  // errors and no data, not a 200.
  const calls = stubFetch(() =>
    json(
      {
        errors: [
          {
            message: 'Cannot query field "nonexistentField" on type "Case".',
            locations: [{ line: 1, column: 72 }],
            extensions: { code: "GRAPHQL_VALIDATION_FAILED" },
          },
        ],
      },
      { status: 400 }
    )
  );
  await assert.rejects(
    () => makeClient().query("tenant-1", "query { case { nonexistentField } }"),
    /Sophos Fusion API error 400: Cannot query field "nonexistentField" on type "Case"\. \[GRAPHQL_VALIDATION_FAILED\]/
  );
  assert.equal(calls.length, 1);
});

test("401 with only a message field reports the message without UnknownError", async () => {
  // Live shape (21/09/2026): {"message":"unauthorized token"}
  stubFetch(() => json({ message: "unauthorized token" }, { status: 401 }));
  await assert.rejects(
    () => makeClient().query("tenant-1", "query { x }"),
    (error) => {
      assert.equal(error.message, "Sophos Fusion API error 401: unauthorized token");
      return true;
    }
  );
});

test("notFound is true only when every error says record not found", async () => {
  // Live shape (21/09/2026): an unknown case ID is HTTP 200 with
  // errors: [record not found] beside data: { case: null }.
  stubFetch(() =>
    json({
      errors: [
        { message: "record not found", path: ["case"], extensions: { code: "DOWNSTREAM_SERVICE_ERROR" } },
      ],
      data: { case: null },
    })
  );
  await assert.rejects(
    () => makeClient().query("tenant-1", "query { case }"),
    (error) => {
      assert.ok(error instanceof FusionGraphQLError);
      assert.equal(error.notFound, true);
      return true;
    }
  );
  const mixed = new FusionGraphQLError("m", [{ message: "record not found" }, { message: "conn busy" }]);
  assert.equal(mixed.notFound, false);
  assert.equal(new FusionGraphQLError("m", []).notFound, false);
});

test("429 waits for Retry-After and then succeeds", async () => {
  const calls = stubFetch((attempt) =>
    attempt === 1
      ? json({ error: "TooManyRequests" }, { status: 429, headers: { "Retry-After": "0" } })
      : json({ data: { ok: true } })
  );
  const result = await makeClient().query("tenant-1", "query { ok }");
  assert.deepEqual(result.data, { ok: true });
  assert.equal(calls.length, 2);
});

test("5xx is retried and a later success is returned", async () => {
  const calls = stubFetch((attempt) =>
    attempt < 3 ? json("upstream down", { status: 503 }) : json({ data: { ok: true } })
  );
  const result = await makeClient().query("tenant-1", "query { ok }");
  assert.deepEqual(result.data, { ok: true });
  assert.equal(calls.length, 3);
});

test("5xx exhausts the retries and throws the last error", async () => {
  const calls = stubFetch(() => json("upstream down", { status: 502 }));
  await assert.rejects(
    () => makeClient().query("tenant-1", "query { ok }"),
    /Sophos Fusion API error 502: upstream down/
  );
  assert.equal(calls.length, 3);
});

test("a hung request is aborted at the timeout and reported as such", async () => {
  stubFetch(
    (_attempt, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () =>
          reject(new DOMException("The operation was aborted", "AbortError"))
        );
      })
  );
  await assert.rejects(
    () => makeClient({ timeoutMs: 5, retries: 0 }).query("tenant-1", "query { ok }"),
    /timed out after 5ms/
  );
});

test("interpretGraphQLBody rejects a body with neither data nor errors", () => {
  assert.throws(() => interpretGraphQLBody({}), /neither data nor errors/);
  assert.throws(() => interpretGraphQLBody(null), /neither data nor errors/);
});

test("formatGraphQLError includes path and extension code when present", () => {
  assert.equal(formatGraphQLError({ message: "m" }), "m");
  assert.equal(
    formatGraphQLError({ message: "m", path: ["a", 0, "b"], extensions: { code: "X" } }),
    "m (path: a.0.b) [X]"
  );
});

test("the endpoint defaults to the Sophos Fusion URL and honours the option", () => {
  assert.equal(new FusionClient(tokenManager).endpoint, "https://api.taegis.sophos.com/graphql");
  assert.equal(makeClient().endpoint, url);
});
