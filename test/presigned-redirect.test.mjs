/**
 * The presigned transfers carry no token, but they carry file contents: the
 * case file upload and the firewall import PUT a file, and the firewall
 * backup download saves whatever answers, which may later be imported into
 * firewalls. A redirect on any of them is refused, never followed. These
 * tests run Node's real fetch against local servers: a stand-in storage host
 * that answers with a redirect, and the host it points at, which must never
 * see a request. The Sophos REST answers are in memory.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { FusionClient } from "../dist/client/fusion-client.js";
import { SophosRedirectError } from "../dist/client/redirect.js";
import { registerFirewallTools } from "../dist/tools/firewall.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const FW1 = "659240aa-797e-42cf-bb82-cca43c4e80d8";
const TXN = "a1b2c3d4-0000-4000-8000-000000000042";
const ARCHIVE = "archive-contents-must-stay-home";

/** Requests the redirect target received. Must stay empty. */
const stolen = [];
/** Requests the storage host received, as "METHOD /path". */
const stored = [];
/** Sophos REST calls, as "METHOD /path". */
const rest = [];
/** What the storage host answers: a 3xx redirects to the collector, anything else is a plain answer. */
let storageStatus = 200;

function listen(handler) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => handler(req, res, Buffer.concat(chunks).toString()));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

let collector;
let storage;
let dir;
const realFetch = globalThis.fetch;
const realError = console.error;
const storageUrl = (path) => `http://127.0.0.1:${storage.address().port}${path}?X-Amz-Signature=sig-must-not-show`;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "sophos-mcp-presigned-"));
  collector = await listen((req, res, body) => {
    stolen.push({ method: req.method, url: req.url, body });
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end("archive-from-somewhere-else");
  });
  storage = await listen((req, res) => {
    stored.push(`${req.method} ${req.url.split("?")[0]}`);
    if (storageStatus >= 300 && storageStatus < 400) {
      res.writeHead(storageStatus, { Location: `http://127.0.0.1:${collector.address().port}/collect` });
      res.end();
      return;
    }
    res.writeHead(storageStatus, { "Content-Type": "application/octet-stream" });
    res.end(req.method === "GET" ? "archive-from-sophos" : "");
  });
  // Sophos REST answers in memory; every other address (the storage host) goes through Node's real fetch untouched.
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    if (url.origin !== HOST) return realFetch(input, init);
    const method = init?.method ?? "GET";
    rest.push(`${method} ${url.pathname}`);
    const json = (body) => Response.json(body);
    if (method === "GET" && url.pathname === `/firewall/v1/firewall-config/firewalls/transactions/${TXN}`) {
      return json({ status: "finished", result: "success", response: { url: storageUrl("/backup"), method: "GET", expiresAt: "2099-01-01T00:00:00Z", firewallId: FW1 } });
    }
    if (method === "POST" && url.pathname === "/firewall/v1/firewall-config/firewalls/import") {
      return json({ transactionId: TXN, url: storageUrl("/import"), method: "PUT", expiresAt: "2099-01-01T00:00:00Z" });
    }
    if (method === "POST" && url.pathname === `/firewall/v1/firewall-config/firewalls/import/${TXN}/upload-complete`) {
      return json({ id: TXN, status: "inProgress" });
    }
    return json({ error: "unexpected" });
  };
  console.error = () => {};
});

after(() => {
  globalThis.fetch = realFetch;
  console.error = realError;
  collector.close();
  storage.close();
  rmSync(dir, { recursive: true, force: true });
});

function reset(status) {
  storageStatus = status;
  stolen.length = 0;
  stored.length = 0;
  rest.length = 0;
}

async function firewallTools() {
  const tokenManager = { getToken: async () => "fake-token" };
  const tenantResolver = { resolveApiHost: async () => HOST, resolveTenantId: (id) => id ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFirewallTools(server, new SophosClient(tokenManager, tenantResolver), tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      return { isError: Boolean(result.isError), text: result.content.map((c) => c.text ?? "").join("\n") };
    },
    async close() {
      await mcp.close();
      await server.close();
    },
  };
}

test("each transfer works when storage answers plainly (control)", async () => {
  reset(200);
  const fusion = new FusionClient({ getToken: async () => "fake-token" });
  await fusion.putPresigned(storageUrl("/case-file"), new TextEncoder().encode(ARCHIVE), "text/plain");

  const tools = await firewallTools();
  try {
    const out = join(dir, "control.bak");
    const dl = await tools.call("sophos_download_firewall_backup", { transaction_id: TXN, output_path: out });
    assert.equal(dl.isError, false, dl.text);
    assert.equal(readFileSync(out, "utf8"), "archive-from-sophos");

    const archive = join(dir, "control-import.bak");
    writeFileSync(archive, ARCHIVE);
    const imp = await tools.call("sophos_import_firewall_config", { firewall_ids: [FW1], file_path: archive });
    assert.equal(imp.isError, false, imp.text);
  } finally {
    await tools.close();
  }
  assert.deepEqual(stored, ["PUT /case-file", "GET /backup", "PUT /import"]);
  assert.ok(rest.includes(`POST /firewall/v1/firewall-config/firewalls/import/${TXN}/upload-complete`));
  assert.deepEqual(stolen, []);
});

for (const status of [307, 308]) {
  test(`a ${status} on a case file upload is refused and the file goes nowhere else`, async () => {
    reset(status);
    const fusion = new FusionClient({ getToken: async () => "fake-token" });
    await assert.rejects(
      () => fusion.putPresigned(storageUrl("/case-file"), new TextEncoder().encode(ARCHIVE), "text/plain"),
      (error) =>
        error instanceof SophosRedirectError &&
        error.status === status &&
        error.message.includes(`with a ${status} redirect to 127.0.0.1:${collector.address().port}`) &&
        !error.message.includes("sig-must-not-show")
    );
    assert.deepEqual(stored, ["PUT /case-file"], "one try");
    assert.deepEqual(stolen, [], "the redirect target got nothing");
  });
}

for (const status of [302, 307]) {
  test(`a ${status} on a firewall backup download is refused, not retried, and nothing is saved`, async () => {
    reset(status);
    const out = join(dir, `backup-${status}.bak`);
    const tools = await firewallTools();
    try {
      const result = await tools.call("sophos_download_firewall_backup", { transaction_id: TXN, output_path: out });
      assert.equal(result.isError, true);
      assert.match(result.text, new RegExp(`${status} redirect`));
      assert.doesNotMatch(result.text, /sig-must-not-show/);
    } finally {
      await tools.close();
    }
    assert.equal(existsSync(out), false, "no archive saved");
    assert.deepEqual(stored, ["GET /backup"], "one try");
    assert.deepEqual(stolen, [], "nothing fetched from the redirect target");
  });
}

for (const status of [307, 308]) {
  test(`a ${status} on a firewall import upload is refused and Sophos is not told the upload finished`, async () => {
    reset(status);
    const archive = join(dir, `import-${status}.bak`);
    writeFileSync(archive, ARCHIVE);
    const tools = await firewallTools();
    try {
      const result = await tools.call("sophos_import_firewall_config", { firewall_ids: [FW1], file_path: archive });
      assert.equal(result.isError, true);
      assert.match(result.text, new RegExp(`${status} redirect`));
    } finally {
      await tools.close();
    }
    assert.deepEqual(stored, ["PUT /import"], "one try");
    assert.deepEqual(rest, ["POST /firewall/v1/firewall-config/firewalls/import"], "no upload-complete");
    assert.deepEqual(stolen, [], "the archive went nowhere else");
  });
}
