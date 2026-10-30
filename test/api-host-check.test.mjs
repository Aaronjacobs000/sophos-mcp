/**
 * The tenant's API host comes from Sophos's answers (whoami's global and
 * dataRegion hosts, each tenant's apiHost in a partner tenant list), so a
 * host that isn't an https address on sophos.com is refused before the
 * bearer token goes on a request. These tests run Node's real fetch: an
 * https request to a sophos.com host goes to a stand-in Sophos, and anything
 * else goes, over plain http, to the host it names, where a local collector
 * records what it receives and must stay empty.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { TokenManager } from "../dist/auth/token-manager.js";
import { TenantResolver } from "../dist/client/tenant-resolver.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { UntrustedHostError, isSophosApiBase, sophosApiBase } from "../dist/client/hosts.js";

const TENANT = "11111111-1111-4111-8111-111111111111";
const PARTNER = "p-1";

/** Requests the collector received. Must stay empty. */
const stolen = [];
/** Requests the stand-in Sophos received, as "host/path". */
const seen = [];
/** What whoami and the tenant list answer; set per test. */
let answers = {};

function listen(handler) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => handler(req, res, body));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

let collector;
let sophos;
let sink;
const realFetch = globalThis.fetch;
const realError = console.error;

before(async () => {
  collector = await listen((req, res, body) => {
    stolen.push({ method: req.method, url: req.url, body, authorization: req.headers.authorization });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ items: [] }));
  });
  sink = `127.0.0.1:${collector.address().port}`;
  sophos = await listen((req, res) => {
    const key = req.url.split("?")[0].slice(1);
    seen.push(key);
    res.writeHead(200, { "Content-Type": "application/json" });
    if (key === "id.sophos.com/api/v2/oauth2/token") {
      res.end(JSON.stringify({ access_token: "tok-1", token_type: "bearer", expires_in: 3600 }));
    } else if (key === "api.central.sophos.com/whoami/v1") {
      res.end(JSON.stringify(answers.whoami));
    } else if (key === "api.central.sophos.com/partner/v1/tenants") {
      res.end(JSON.stringify({ pages: { current: 1, size: 100, total: 1, maxSize: 100 }, items: answers.tenants ?? [] }));
    } else {
      res.end(JSON.stringify({ items: [] }));
    }
  });
  globalThis.fetch = (input, init) => {
    const url = new URL(String(input));
    if (url.protocol === "https:" && url.hostname.endsWith(".sophos.com")) {
      return realFetch(`http://127.0.0.1:${sophos.address().port}/${url.host}${url.pathname}${url.search}`, init);
    }
    // Any other host gets the request as sent, so without the check the collector would see the token.
    return realFetch(`http://${url.host}${url.pathname}${url.search}`, init);
  };
  console.error = () => {};
});

after(() => {
  globalThis.fetch = realFetch;
  console.error = realError;
  collector.close();
  sophos.close();
});

function reset(next) {
  answers = next;
  seen.length = 0;
  stolen.length = 0;
}

async function tenantClient(dataRegion, global = "https://api.central.sophos.com") {
  reset({ whoami: { id: TENANT, idType: "tenant", apiHosts: { global, dataRegion } } });
  const tokens = new TokenManager("client-1", "secret-1");
  const resolver = new TenantResolver(tokens);
  await resolver.init();
  const client = new SophosClient(tokens, resolver);
  client.sleep = async () => {};
  return client;
}

test("only an https host on sophos.com passes, as NotFusion checks it", () => {
  for (const good of [
    "https://api-eu01.central.sophos.com",
    "https://api-au01.central.sophos.com/",
    "https://api.central.sophos.com",
  ]) {
    assert.equal(isSophosApiBase(good), true, good);
  }
  assert.equal(sophosApiBase("https://api-au01.central.sophos.com/"), "https://api-au01.central.sophos.com");
  for (const bad of [
    "http://api-au01.central.sophos.com",
    "https://api-au01.central.sophos.com:8443",
    "https://api-au01.central.sophos.com@collector.example",
    "https://user:pw@api-au01.central.sophos.com",
    "https://api-au01.central.sophos.com.collector.example",
    "https://notsophos.com",
    "https://sophos.com.collector.example",
    "https://api-au01.central.sophos.com/path",
    "https://api-au01.central.sophos.com?x=1",
    "https://api-au01.central.sophos.com#x",
    "https://api-au01.central.sophos.com//",
    "https://-bad.sophos.com",
    "",
    null,
    undefined,
    42,
  ]) {
    assert.equal(isSophosApiBase(bad), false, String(bad));
    assert.throws(() => sophosApiBase(bad), UntrustedHostError, String(bad));
  }
});

test("a tenant's data region host outside sophos.com is refused and the token goes nowhere", async () => {
  for (const dataRegion of [`https://api-au01.central.sophos.com@${sink}`, `http://${sink}`, `https://${sink}`]) {
    const client = await tenantClient(dataRegion);
    await assert.rejects(
      () => client.tenantRequest(TENANT, "/endpoint/v1/endpoints"),
      (error) => error instanceof UntrustedHostError && /outside sophos\.com/.test(error.message),
      dataRegion,
    );
    await assert.rejects(
      () => client.tenantRequest(TENANT, "/endpoint/v1/endpoint-groups", { method: "POST", body: { name: "g" } }),
      UntrustedHostError,
    );
    assert.deepEqual(stolen, [], `nothing reached ${dataRegion}`);
  }
});

test("a partner tenant list naming a host outside sophos.com is refused for that tenant only", async () => {
  reset({
    whoami: { id: PARTNER, idType: "partner", apiHosts: { global: "https://api.central.sophos.com" } },
    tenants: [
      { id: TENANT, name: "Bad", apiHost: `https://${sink}`, dataRegion: "au01", dataGeography: "AU" },
      { id: "t-good", name: "Good", apiHost: "https://api-au01.central.sophos.com", dataRegion: "au01", dataGeography: "AU" },
    ],
  });
  const tokens = new TokenManager("client-1", "secret-1");
  const resolver = new TenantResolver(tokens);
  await resolver.init();
  const client = new SophosClient(tokens, resolver);
  await assert.rejects(() => client.tenantRequest(TENANT, "/endpoint/v1/endpoints"), UntrustedHostError);
  assert.deepEqual(stolen, []);

  seen.length = 0;
  await client.tenantRequest("t-good", "/endpoint/v1/endpoints");
  assert.deepEqual(seen, ["api-au01.central.sophos.com/endpoint/v1/endpoints"], "a Sophos host still works");
});

test("a global host outside sophos.com is refused before the partner ID or token goes to it", async () => {
  const client = await tenantClient("https://api-au01.central.sophos.com", `https://api.central.sophos.com@${sink}`);
  await assert.rejects(() => client.globalRequest("/licenses/v1/licenses"), UntrustedHostError);
  assert.deepEqual(stolen, []);
});

test("a Sophos host with a trailing slash still builds the right address", async () => {
  const client = await tenantClient("https://api-au01.central.sophos.com/");
  seen.length = 0;
  await client.tenantRequest(TENANT, "/endpoint/v1/endpoints");
  assert.deepEqual(seen, ["api-au01.central.sophos.com/endpoint/v1/endpoints"]);
});
