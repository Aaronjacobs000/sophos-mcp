// The Sophos bearer token goes to SOPHOS_FUSION_GRAPHQL_URL. dotenv fills that
// from a .env in the working directory, which for a stdio server is the
// directory the client was started in, so the override must stay on Sophos.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkFusionGraphQLUrl } from "../dist/config/config.js";

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
