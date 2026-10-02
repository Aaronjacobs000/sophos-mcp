// The Sophos bearer token goes to SOPHOS_FUSION_GRAPHQL_URL. dotenv fills that
// from a .env in the working directory, which for a stdio server is the
// directory the client was started in, so the override must stay on Sophos.
// The HTTP transport settings (bind host, token, allowed origins) are read here too.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkFusionGraphQLUrl, loadConfig } from "../dist/config/config.js";

test("the Fusion URL override is accepted only as https on a sophos.com host", () => {
  for (const ok of [
    "https://api.taegis.sophos.com/graphql",
    "https://api.fusion.sophos.com/graphql",
    "https://sophos.com/graphql",
  ]) {
    assert.equal(checkFusionGraphQLUrl(ok), ok);
  }
  for (const bad of [
    "https://attacker.example/graphql",
    "http://api.taegis.sophos.com/graphql",
    "https://api.taegis.sophos.com.attacker.example/graphql",
    "https://evilsophos.com/graphql",
    "https://api.sophos.com@attacker.example/graphql",
    "not a url",
  ]) {
    assert.throws(() => checkFusionGraphQLUrl(bad), /SOPHOS_FUSION_GRAPHQL_URL/, bad);
  }
});

test("a .env in the working directory cannot point the token at another host", () => {
  const dir = mkdtempSync(join(tmpdir(), "sophos-mcp-env-"));
  try {
    writeFileSync(join(dir, ".env"), "SOPHOS_FUSION_GRAPHQL_URL=https://attacker.example/graphql\n");
    const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
    // fetch is stubbed so nothing leaves the machine even if the check regresses
    const noNetwork =
      "data:text/javascript,globalThis.fetch=async(u)=>{process.stderr.write('FETCH '+u+'\\n');throw new Error('network disabled in test')}";
    const env = { ...process.env, SOPHOS_CLIENT_ID: "test-id", SOPHOS_CLIENT_SECRET: "test-secret", TRANSPORT: "stdio" };
    delete env.SOPHOS_FUSION_GRAPHQL_URL;
    const run = spawnSync(process.execPath, ["--import", noNetwork, entry], { cwd: dir, env, encoding: "utf8", timeout: 20_000 });

    assert.equal(run.status, 1);
    assert.match(run.stderr, /Invalid SOPHOS_FUSION_GRAPHQL_URL "https:\/\/attacker\.example\/graphql"/);
    assert.doesNotMatch(run.stderr, /FETCH /, "no request is made before the check");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the HTTP bind host, token and allowed origins come from the environment", () => {
  const names = ["SOPHOS_CLIENT_ID", "SOPHOS_CLIENT_SECRET", "MCP_HTTP_HOST", "MCP_HTTP_TOKEN", "MCP_ALLOWED_ORIGINS"];
  const saved = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  try {
    process.env.SOPHOS_CLIENT_ID = "test-id";
    process.env.SOPHOS_CLIENT_SECRET = "test-secret";
    for (const name of names.slice(2)) delete process.env[name];

    const defaults = loadConfig();
    assert.equal(defaults.httpHost, "127.0.0.1");
    assert.equal(defaults.httpToken, undefined);
    assert.deepEqual(defaults.allowedOrigins, []);

    process.env.MCP_HTTP_HOST = "0.0.0.0";
    process.env.MCP_HTTP_TOKEN = "s3cret";
    process.env.MCP_ALLOWED_ORIGINS = "https://inspector.example.com";
    const set = loadConfig();
    assert.equal(set.httpHost, "0.0.0.0");
    assert.equal(set.httpToken, "s3cret");
    assert.deepEqual(set.allowedOrigins, ["https://inspector.example.com"]);

    process.env.MCP_HTTP_HOST = "100.105.82.70";
    process.env.MCP_HTTP_TOKEN = "";
    assert.equal(loadConfig().httpHost, "100.105.82.70");
    assert.equal(loadConfig().httpToken, undefined, "an empty token means no token");

    process.env.MCP_ALLOWED_ORIGINS = "not a url";
    assert.throws(() => loadConfig(), /MCP_ALLOWED_ORIGINS/);
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});
