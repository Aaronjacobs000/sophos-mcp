#!/usr/bin/env node
/**
 * Live smoke test for the Sophos Fusion GraphQL tools. Read-only.
 *
 * Spawns the built server over stdio with the credentials from the
 * environment (or .env), then calls:
 *   1. sophos_fusion_list_case_reference_data
 *   2. sophos_fusion_list_cases (newest 5)
 *   3. sophos_fusion_get_case on the newest case, by short ID
 *   4. sophos_fusion_get_case_summary on the same case
 *
 * Usage:
 *   node scripts/fusion-smoke.mjs              # tenant credential
 *   node scripts/fusion-smoke.mjs <tenant-id>  # partner or organisation credential
 *
 * Exits non-zero if any call returns an error. Run `npm run build` first.
 */

import "dotenv/config";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const serverPath = fileURLToPath(new URL("../dist/index.js", import.meta.url));
if (!existsSync(serverPath)) {
  console.error("dist/index.js is missing; run npm run build first");
  process.exit(1);
}
if (!process.env.SOPHOS_CLIENT_ID || !process.env.SOPHOS_CLIENT_SECRET) {
  console.error("SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET must be set (or in .env)");
  process.exit(1);
}

const tenantId = process.argv[2];
const scope = tenantId ? { tenant_id: tenantId } : {};

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  env: { ...process.env, TRANSPORT: "stdio" },
  stderr: "inherit",
});
const client = new Client({ name: "fusion-smoke", version: "0.0.0" });
await client.connect(transport);

let failures = 0;

async function call(name, args) {
  console.log(`\n== ${name} ${JSON.stringify(args)} ==`);
  const result = await client.callTool({ name, arguments: args });
  const text = result.content.map((c) => c.text ?? "").join("\n");
  console.log(text);
  if (result.isError) {
    failures += 1;
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

try {
  await call("sophos_fusion_list_case_reference_data", scope);
  const list = await call("sophos_fusion_list_cases", { ...scope, per_page: 5 });
  const newest = list?.cases?.[0];
  if (newest) {
    await call("sophos_fusion_get_case", { ...scope, case_id: newest.short_id });
    await call("sophos_fusion_get_case_summary", { ...scope, case_id: newest.id, max_detections: 10 });
  } else {
    console.log("\nNo Fusion cases in this tenant; get_case and get_case_summary skipped.");
  }
} finally {
  await client.close();
}

console.log(failures === 0 ? "\nSmoke test passed." : `\nSmoke test failed: ${failures} call(s) returned an error.`);
process.exit(failures === 0 ? 0 : 1);
