/**
 * A redirect from Sophos is refused, never followed: a followed 307 or 308 on
 * the token request sends the client secret to the new host, and on an API
 * call the body and the tenant ID go with it. These tests run Node's real
 * fetch against two local servers, a stand-in Sophos that answers with a
 * redirect and the host it points at, which must never see a request.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { TokenManager } from "../dist/auth/token-manager.js";
import { TenantResolver } from "../dist/client/tenant-resolver.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { FusionClient } from "../dist/client/fusion-client.js";
import { SophosRedirectError } from "../dist/client/redirect.js";

const SECRET = "secret-must-stay-home";
const TENANT = "11111111-1111-4111-8111-111111111111";

/** Requests the redirect target received. Must stay empty. */
const stolen = [];
/** Requests the stand-in Sophos received, as "host/path". */
const seen = [];
/** "host/path" to the status the stand-in Sophos answers it with; anything else answers normally. */
let redirects = new Map();

function listen(handler) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => handler(req, res, body));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

let sink;
let sophos;
const realFetch = globalThis.fetch;
const realError = console.error;

/** Sends https://<host>/<path> to the stand-in Sophos as /<host>/<path>, with the caller's options untouched. */
const toStandIn = (input, init) => {
  const url = new URL(String(input));
  return realFetch(`http://127.0.0.1:${sophos.address().port}/${url.host}${url.pathname}${url.search}`, init);
};

before(async () => {
  sink = await listen((req, res, body) => {
    stolen.push({ method: req.method, url: req.url, body, headers: req.headers });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ access_token: "stolen", expires_in: 3600, id: "x", idType: "tenant", apiHosts: {}, data: {} }));
  });
  sophos = await listen((req, res) => {
    const key = req.url.split("?")[0].slice(1);
    seen.push(key);
    const status = redirects.get(key);
    if (status) {
      res.writeHead(status, { Location: `http://127.0.0.1:${sink.address().port}/collect` });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    if (key === "id.sophos.com/api/v2/oauth2/token") {
      res.end(JSON.stringify({ access_token: "tok-1", token_type: "bearer", expires_in: 3600 }));
    } else if (key === "api.central.sophos.com/whoami/v1") {
      res.end(JSON.stringify({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com", dataRegion: "https://api-au01.central.sophos.com" } }));
    } else {
      res.end(JSON.stringify({ items: [] }));
    }
  });
  globalThis.fetch = toStandIn;
  console.error = () => {};
});

after(() => {
  globalThis.fetch = realFetch;
  console.error = realError;
  sink.close();
  sophos.close();
});

function reset(map) {
  redirects = new Map(map);
  seen.length = 0;
  stolen.length = 0;
}

for (const status of [307, 308]) {
  test(`a ${status} on the token request is refused and the client secret goes nowhere else`, async () => {
    reset([["id.sophos.com/api/v2/oauth2/token", status]]);
    await assert.rejects(
      () => new TokenManager("client-1", SECRET).getToken(),
      (error) =>
        error instanceof SophosRedirectError &&
        error.status === status &&
        error.message.includes(`with a ${status} redirect to 127.0.0.1:${sink.address().port}`) &&
        !error.message.includes(SECRET)
    );
    assert.deepEqual(seen, ["id.sophos.com/api/v2/oauth2/token"], "the token request was sent once, to Sophos");
    assert.deepEqual(stolen, [], "the redirect target got nothing");
  });
}

test("whoami and the tenant list refuse a redirect", async () => {
  reset([["api.central.sophos.com/whoami/v1", 307]]);
  await assert.rejects(() => new TenantResolver(new TokenManager("client-1", SECRET)).init(), SophosRedirectError);
  assert.deepEqual(stolen, []);

  reset([["api.central.sophos.com/partner/v1/tenants", 308]]);
  const partner = new TenantResolver(new TokenManager("client-1", SECRET));
  // A partner credential: whoami answers normally, then the tenant list redirects.
  globalThis.fetch = (input, init) =>
    String(input).endsWith("/whoami/v1")
      ? Promise.resolve(Response.json({ id: "p-1", idType: "partner", apiHosts: { global: "https://api.central.sophos.com" } }))
      : toStandIn(input, init);
  try {
    await partner.init();
    await assert.rejects(() => partner.loadTenants(), SophosRedirectError);
  } finally {
    globalThis.fetch = toStandIn;
  }
  assert.deepEqual(seen.filter((key) => key.endsWith("/tenants")), ["api.central.sophos.com/partner/v1/tenants"]);
  assert.deepEqual(stolen, []);
});

test("a REST read or write Sophos redirects is refused at once and not retried", async () => {
  const tokens = new TokenManager("client-1", SECRET);
  reset([]);
  const resolver = new TenantResolver(tokens);
  await resolver.init();
  const client = new SophosClient(tokens, resolver);
  client.sleep = async () => {};

  reset([["api-au01.central.sophos.com/endpoint/v1/endpoints", 307]]);
  await assert.rejects(() => client.tenantRequest(TENANT, "/endpoint/v1/endpoints"), SophosRedirectError);
  assert.deepEqual(seen, ["api-au01.central.sophos.com/endpoint/v1/endpoints"], "one try, no retry");

  reset([["api-au01.central.sophos.com/endpoint/v1/endpoint-groups", 308]]);
  await assert.rejects(
    () => client.tenantRequest(TENANT, "/endpoint/v1/endpoint-groups", { method: "POST", body: { name: "g" } }),
    (error) => error instanceof SophosRedirectError && !/may already have taken effect/.test(error.message)
  );
  assert.deepEqual(seen, ["api-au01.central.sophos.com/endpoint/v1/endpoint-groups"]);
  assert.deepEqual(stolen, [], "neither the body nor the tenant ID went to the redirect target");
});

test("a Fusion GraphQL call Sophos redirects is refused at once and not retried", async () => {
  const fusion = new FusionClient(new TokenManager("client-1", SECRET), { backoffBaseMs: 1 });
  reset([["api.taegis.sophos.com/graphql", 307]]);
  await assert.rejects(() => fusion.query(TENANT, "query Cases { cases { totalCount } }"), SophosRedirectError);
  assert.deepEqual(seen, ["id.sophos.com/api/v2/oauth2/token", "api.taegis.sophos.com/graphql"], "one try, no retry");

  reset([["api.taegis.sophos.com/graphql", 308]]);
  await assert.rejects(
    () => fusion.query(TENANT, "mutation AddCaseComment($input: AddCaseCommentInput!) { addCaseComment(input: $input) { id } }", { input: {} }),
    (error) => error instanceof SophosRedirectError && !/may already have taken effect/.test(error.message)
  );
  assert.deepEqual(seen, ["api.taegis.sophos.com/graphql"]);
  assert.deepEqual(stolen, []);
});
