/**
 * Handler-level tests for the firewall firmware tools through the real
 * SophosClient and the registered schemas, with fetch stubbed: upgrade_at is
 * sent as UTC, a time with no offset is refused before anything is sent,
 * omitted fields are not sent, cancel reports cancelled only when Sophos
 * answers {deleted: true}, and the check body is unchanged. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerFirewallTools } from "../dist/tools/firewall.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const FW1 = "659240aa-797e-42cf-bb82-cca43c4e80d8";
const FW2 = "28a4f2df-dd5f-44b5-8316-da1f6cfbd254";
const UPGRADE_PATH = "/firewall/v1/firewalls/actions/firmware-upgrade";

/**
 * Registers the firewall tools on a real SophosClient. fetch records every
 * request and answers `reply`: a JSON body, or a function returning a Response.
 */
async function harness(reply = {}) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({
      url: new URL(String(url)),
      method: init?.method,
      body: init?.body === undefined ? undefined : JSON.parse(init.body),
    });
    if (typeof reply === "function") return reply();
    return new Response(JSON.stringify(reply), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const tokenManager = { getToken: async () => "fake-token" };
  const tenantResolver = { resolveApiHost: async () => HOST, resolveTenantId: (id) => id ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFirewallTools(server, new SophosClient(tokenManager, tenantResolver), tenantResolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    mcp,
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = result.content.map((c) => c.text ?? "").join("\n");
      return { isError: Boolean(result.isError), text, json: result.isError ? null : JSON.parse(text) };
    },
    async close() {
      await mcp.close();
      await server.close();
      globalThis.fetch = realFetch;
    },
  };
}

test("an upgrade_at with an offset is sent as UTC and the result shows what was sent", async () => {
  const reply = { passedThrough: true };
  const h = await harness(reply);
  try {
    const { isError, json } = await h.call("sophos_start_firmware_upgrade", {
      firewalls: [{ id: FW1, upgrade_to_version: "22.0.1", upgrade_at: "2026-10-08T02:00:00+10:00" }],
    });
    assert.equal(isError, false);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].method, "POST");
    assert.equal(h.calls[0].url.href, `${HOST}${UPGRADE_PATH}`);
    const sent = [{ id: FW1, upgradeToVersion: "22.0.1", upgradeAt: "2026-10-07T16:00:00.000Z" }];
    assert.deepEqual(h.calls[0].body, { firewalls: sent });
    assert.equal(json.status, "firmware_upgrade_initiated");
    assert.deepEqual(json.firewalls, [FW1]);
    assert.deepEqual(json.sent, sent);
    assert.deepEqual(json.result, reply);
  } finally {
    await h.close();
  }
});

test("a Z time is normalised to the documented format, and each firewall keeps its own time", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_start_firmware_upgrade", {
      firewalls: [
        { id: FW1, upgrade_at: "2026-10-07T16:00:00Z" },
        { id: FW2, upgrade_at: "2026-10-07T20:30:00-05:30" },
      ],
    });
    assert.equal(isError, false);
    const sent = [
      { id: FW1, upgradeAt: "2026-10-07T16:00:00.000Z" },
      { id: FW2, upgradeAt: "2026-10-08T02:00:00.000Z" },
    ];
    assert.deepEqual(h.calls[0].body, { firewalls: sent });
    assert.deepEqual(json.sent, sent);
  } finally {
    await h.close();
  }
});

test("a time with no offset is refused by the registered schema and nothing is sent", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_start_firmware_upgrade", {
      firewalls: [{ id: FW1, upgrade_at: "2026-10-08T02:00:00" }],
    });
    assert.equal(isError, true);
    // The SDK's input validation answers, not the handler ("Error: ...")
    assert.match(text, /^MCP error -32602: Input validation error/);
    assert.match(text, /"upgrade_at"/);
    assert.match(text, /A time with no offset is ambiguous/);
    assert.equal(h.calls.length, 0, "no request was sent");
  } finally {
    await h.close();
  }
});

test("an impossible offset that passes the schema is refused before anything is sent", async () => {
  const h = await harness();
  try {
    const { isError, text } = await h.call("sophos_start_firmware_upgrade", {
      firewalls: [{ id: FW1, upgrade_at: "2026-10-08T02:00:00+99:99" }],
    });
    assert.equal(isError, true);
    assert.match(text, /is not a valid date and time\. Nothing was sent\./);
    assert.equal(h.calls.length, 0, "no request was sent");
  } finally {
    await h.close();
  }
});

test("omitting upgrade_at and upgrade_to_version sends neither key", async () => {
  const h = await harness();
  try {
    const { isError, json } = await h.call("sophos_start_firmware_upgrade", { firewalls: [{ id: FW1 }] });
    assert.equal(isError, false);
    assert.deepEqual(h.calls[0].body, { firewalls: [{ id: FW1 }] });
    assert.deepEqual(json.sent, [{ id: FW1 }]);
  } finally {
    await h.close();
  }
});

test("cancel reports cancelled when Sophos answers deleted: true", async () => {
  const h = await harness({ deleted: true });
  try {
    const { isError, json } = await h.call("sophos_cancel_firmware_upgrade", { firewall_ids: [FW1, FW2] });
    assert.equal(isError, false);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].method, "DELETE");
    assert.equal(h.calls[0].url.pathname, UPGRADE_PATH);
    assert.equal(h.calls[0].url.searchParams.get("ids"), `${FW1},${FW2}`);
    assert.equal(json.status, "firmware_upgrade_cancelled");
    assert.deepEqual(json.firewall_ids, [FW1, FW2]);
  } finally {
    await h.close();
  }
});

test("cancel does not claim success on deleted: false or an empty 204", async () => {
  const replies = [
    ["deleted: false", { deleted: false }, { deleted: false }],
    ["empty 204", () => new Response(null, { status: 204 }), {}],
  ];
  for (const [label, reply, raw] of replies) {
    const h = await harness(reply);
    try {
      const { isError, text, json } = await h.call("sophos_cancel_firmware_upgrade", { firewall_ids: [FW1] });
      assert.equal(isError, false, label);
      assert.equal(json.status, "firmware_upgrade_not_cancelled", label);
      assert.match(json.message, /did not confirm the cancellation/, label);
      assert.deepEqual(json.result, raw, label);
      assert.doesNotMatch(text, /"firmware_upgrade_cancelled"|Scheduled firmware upgrades cancelled/, label);
    } finally {
      await h.close();
    }
  }
});

test("cancel still needs at least one firewall ID", async () => {
  const h = await harness({ deleted: true });
  try {
    const { isError, text } = await h.call("sophos_cancel_firmware_upgrade", { firewall_ids: [] });
    assert.equal(isError, true);
    assert.match(text, /^MCP error -32602: Input validation error/);
    assert.equal(h.calls.length, 0, "no request was sent");
  } finally {
    await h.close();
  }
});

test("the check body is unchanged and the response passes through", async () => {
  const reply = {
    firewalls: [{ id: FW1, serialNumber: "X1", firmwareVersion: "21.5.0", upgradeToVersion: ["22.0.1"] }],
    firmwareVersions: [{ version: "22.0.1", size: "1", bugs: [], news: [] }],
  };
  const h = await harness(reply);
  try {
    const { isError, json } = await h.call("sophos_check_firmware_upgrade", { firewall_ids: [FW1, FW2] });
    assert.equal(isError, false);
    assert.equal(h.calls[0].method, "POST");
    assert.equal(h.calls[0].url.href, `${HOST}${UPGRADE_PATH}-check`);
    assert.deepEqual(h.calls[0].body, { firewalls: [FW1, FW2] });
    assert.deepEqual(json, reply);
  } finally {
    await h.close();
  }
});

test("the firmware descriptions explain UTC and the version list, with no dashes", async () => {
  const h = await harness();
  try {
    const { tools } = await h.mcp.listTools();
    const byName = new Map(tools.map((t) => [t.name, t]));
    const start = byName.get("sophos_start_firmware_upgrade");
    const item = start.inputSchema.properties.firewalls.items.properties;
    assert.equal(item.upgrade_at.type, "string");
    assert.equal(item.upgrade_at.format, "date-time");
    assert.match(item.upgrade_at.description, /converted to UTC/);
    assert.match(item.upgrade_at.description, /Omit to upgrade now/);
    assert.match(item.upgrade_to_version.description, /sophos_check_firmware_upgrade's upgradeToVersion list/);
    assert.match(start.description, /A time with no offset is refused/);
    assert.doesNotMatch(JSON.stringify(start), /omit for latest/i);
    assert.match(byName.get("sophos_check_firmware_upgrade").description, /sophos_start_firmware_upgrade/);
    for (const name of ["sophos_check_firmware_upgrade", "sophos_start_firmware_upgrade", "sophos_cancel_firmware_upgrade"]) {
      assert.doesNotMatch(JSON.stringify(byName.get(name)), /[–—]/, `${name} has no en or em dash`);
    }
  } finally {
    await h.close();
  }
});
