/**
 * Request shapes for the tools built on the October 2026 Sophos API releases:
 * the bulk endpoint scan, reset health and tamper protection operations
 * (Endpoint API v1), the S/MIME operations of the Email API, and the Search
 * GraphQL API v1. Each case calls a tool through its real handler with fetch
 * (or the Fusion client) stubbed and checks the exact request sent. Also the
 * REST client's text downloads and its errorDetails messages. No network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { SophosClient } from "../dist/client/sophos-client.js";
import { registerEndpointTools } from "../dist/tools/endpoints.js";
import { registerEmailSmimeTools } from "../dist/tools/email-smime.js";
import { registerFusionSearchTools } from "../dist/tools/fusion-search.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const HOST = "https://api-au01.central.sophos.com";
const A = "00000000-0000-4000-8000-0000000000a1";
const B = "00000000-0000-4000-8000-0000000000b1";
const FP = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
const PEM = `-----BEGIN CERTIFICATE-----\n${"A".repeat(400)}\n-----END CERTIFICATE-----\n`;
const P12 = "B".repeat(1500);
const URN = "urn:sophos:search:123456:dbh72v4h76bs73av7av0";

/**
 * Connects an MCP client to one registrar. `answer(method, path, query, body)`
 * returns { status, body, contentType } or a plain JSON body (status 200).
 */
async function restHarness(registrar, answer = () => ({})) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body === undefined ? undefined : JSON.parse(init.body);
    const query = Object.fromEntries(u.searchParams);
    calls.push({ method, path: u.pathname, query, body });
    const reply = answer(method, u.pathname, query, body) ?? {};
    const shaped = reply && typeof reply === "object" && "status" in reply && "body" in reply;
    const status = shaped ? reply.status : 200;
    const payload = shaped ? reply.body : reply;
    const contentType = shaped && reply.contentType ? reply.contentType : "application/json";
    return new Response(typeof payload === "string" ? payload : JSON.stringify(payload), {
      status,
      headers: { "Content-Type": contentType },
    });
  };
  const tenantResolver = {
    resolveApiHost: async () => HOST,
    resolveTenantId: (id) => id ?? TENANT,
    getIdentity: () => ({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com" } }),
    getIdHeader: () => ({ name: "X-Tenant-ID", value: TENANT }),
  };
  const client = new SophosClient({ getToken: async () => "fake-token" }, tenantResolver);
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registrar(server, client, tenantResolver);
  return connect(server, calls, () => (globalThis.fetch = realFetch));
}

async function connect(server, calls, restore = () => {}) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const mcp = new Client({ name: "test-client", version: "0.0.0" });
  await mcp.connect(clientTransport);
  return {
    calls,
    async call(name, args) {
      const result = await mcp.callTool({ name, arguments: args });
      const text = result.content.map((c) => c.text ?? "").join("\n");
      return { isError: Boolean(result.isError), text, json: result.isError ? null : JSON.parse(text) };
    },
    async close() {
      await mcp.close();
      await server.close();
      restore();
    },
  };
}

const sent = (h) => h.calls.map(({ method, path, query, body }) => ({ method, path, query, body }));
const req = (method, path, body, query = {}) => ({ method, path, query, body });

// ---------------------------------------------------------------------------
// Endpoint API v1: bulk scan, reset health, tamper protection
// ---------------------------------------------------------------------------

test("bulk scan, reset health and tamper protection POST the spec bodies and count the outcome", async () => {
  const h = await restHarness(registerEndpointTools, (m, p) =>
    p.endsWith("/scans")
      ? {
          status: 202,
          body: {
            items: [{ id: A, status: "requested", requestedAt: "2026-10-29T00:00:00Z" }],
            errors: [{ id: B, errorCode: "notFound", errorMessage: "Endpoint not found" }],
          },
        }
      : { status: 202, body: { items: [{ id: A, status: "requested", requestedAt: "2026-10-29T00:00:00Z" }] } }
  );
  try {
    const scan = await h.call("sophos_bulk_scan_endpoints", { ids: [A, B, A] });
    await h.call("sophos_bulk_reset_endpoint_health", { ids: [A] });
    const off = await h.call("sophos_bulk_update_tamper_protection", { ids: [A, A], enabled: false });
    await h.call("sophos_bulk_update_tamper_protection", { ids: [A], regenerate_password: true });
    await h.call("sophos_bulk_update_tamper_protection", { ids: [A], enabled: true, regenerate_password: true });
    assert.deepEqual(sent(h), [
      req("POST", "/endpoint/v1/endpoints/scans", { ids: [A, B] }),
      req("POST", "/endpoint/v1/endpoints/reset-health", { ids: [A] }),
      req("POST", "/endpoint/v1/endpoints/tamper-protection", { ids: [A], enabled: false }),
      req("POST", "/endpoint/v1/endpoints/tamper-protection", { ids: [A], regeneratePassword: true }),
      req("POST", "/endpoint/v1/endpoints/tamper-protection", { ids: [A], enabled: true, regeneratePassword: true }),
    ]);
    assert.equal(scan.json.requested, 2, "duplicates dropped");
    assert.equal(scan.json.accepted, 1);
    assert.equal(scan.json.rejected, 1);
    assert.equal(scan.json.errors[0].errorCode, "notFound");
    assert.match(off.json.note, /sophos_get_tamper_protection/);
  } finally {
    await h.close();
  }
});

test("bulk tamper protection needs enabled or regenerate_password, and the bulk tools keep the spec limits", async () => {
  const h = await restHarness(registerEndpointTools);
  try {
    const neither = await h.call("sophos_bulk_update_tamper_protection", { ids: [A] });
    assert.equal(neither.isError, true);
    assert.match(neither.text, /Pass enabled, regenerate_password, or both/);
    const tooManyTp = await h.call("sophos_bulk_update_tamper_protection", {
      ids: Array.from({ length: 201 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`),
      enabled: true,
    });
    assert.match(tooManyTp.text, /Input validation error/);
    const tooManyScans = await h.call("sophos_bulk_scan_endpoints", {
      ids: Array.from({ length: 501 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`),
    });
    assert.match(tooManyScans.text, /Input validation error/);
    const empty = await h.call("sophos_bulk_reset_endpoint_health", { ids: [] });
    assert.match(empty.text, /Input validation error/);
    assert.equal(h.calls.length, 0, "nothing was sent");
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Email API S/MIME
// ---------------------------------------------------------------------------

test("S/MIME configuration tools: get, create, update, reset", async () => {
  const config = { smimeEnabled: false, extractCertificate: true, certExpiryNotificationEmailAddresses: [], deleteToken: "a1b2c3d4" };
  const h = await restHarness(registerEmailSmimeTools, (m) => (m === "DELETE" ? { deleted: true } : config));
  try {
    const got = await h.call("sophos_get_smime_config", {});
    await h.call("sophos_create_smime_config", {
      smime_enabled: false,
      extract_certificate: true,
      cert_expiry_notification_emails: ["admin@example.com"],
    });
    await h.call("sophos_create_smime_config", { smime_enabled: false });
    await h.call("sophos_update_smime_config", { smime_enabled: true });
    await h.call("sophos_update_smime_config", { cert_expiry_notification_emails: [] });
    const nothing = await h.call("sophos_update_smime_config", {});
    const reset = await h.call("sophos_reset_smime_config", { delete_token: "a1b2c3d4" });
    const shortToken = await h.call("sophos_reset_smime_config", { delete_token: "a1b2" });
    assert.deepEqual(sent(h), [
      req("GET", "/email/v1/smime/config"),
      req("POST", "/email/v1/smime/config", {
        smimeEnabled: false,
        extractCertificate: true,
        certExpiryNotificationEmailAddresses: ["admin@example.com"],
      }),
      req("POST", "/email/v1/smime/config", { smimeEnabled: false }),
      req("PATCH", "/email/v1/smime/config", { smimeEnabled: true }),
      req("PATCH", "/email/v1/smime/config", { certExpiryNotificationEmailAddresses: [] }),
      req("DELETE", "/email/v1/smime/config/a1b2c3d4"),
    ]);
    assert.equal(got.json.configured, true);
    assert.equal(got.json.deleteToken, "a1b2c3d4");
    assert.match(nothing.text, /Nothing to update/);
    assert.equal(reset.json.status, "reset");
    assert.match(shortToken.text, /Input validation error/);
  } finally {
    await h.close();
  }
});

test("S/MIME get config and get internal CA report a missing resource rather than failing; other errors carry errorDetails", async () => {
  const notFound = (code, text) => ({
    status: 404,
    body: { error: "ResourceNotFound", correlationId: "c1", errorDetails: [{ error: text, code }] },
  });
  const h = await restHarness(registerEmailSmimeTools, (m, p) => {
    if (p.endsWith("/config")) return notFound("SMIME_CONFIG_NOT_FOUND", "S/MIME configuration does not exist.");
    if (p.endsWith("/ca/internal")) return notFound("SMIME_INTERNAL_CA_NOT_FOUND", "Internal CA certificate does not exist.");
    return {
      status: 400,
      body: {
        error: "ValidationErrors",
        correlationId: "c2",
        errorDetails: [{ error: "Internal CA certificate does not exist", code: "SMIME_CUSTOMER_CA_NOT_PRESENT" }],
      },
    };
  });
  try {
    const config = await h.call("sophos_get_smime_config", {});
    assert.equal(config.json.configured, false);
    assert.match(config.json.message, /sophos_create_smime_internal_ca/);
    const ca = await h.call("sophos_get_smime_internal_ca", {});
    assert.equal(ca.json.exists, false);
    const create = await h.call("sophos_create_smime_internal_user_cert", { email: "user@example.com" });
    assert.equal(create.isError, true);
    assert.match(
      create.text,
      /Sophos API error 400: ValidationErrors - Internal CA certificate does not exist \[SMIME_CUSTOMER_CA_NOT_PRESENT\] \(correlationId: c2\)/
    );
    assert.equal(h.calls.filter((c) => c.method === "POST").length, 1, "a 400 POST is sent once");
  } finally {
    await h.close();
  }
});

test("S/MIME internal CA tools send the spec bodies and download PEM text", async () => {
  const h = await restHarness(registerEmailSmimeTools, (m, p) =>
    p.endsWith("/ca/internal/certificate") && m === "GET"
      ? { status: 200, body: PEM, contentType: "application/octet-stream" }
      : { fingerprint: FP, certificateDetails: { origin: "created" } }
  );
  try {
    await h.call("sophos_create_smime_internal_ca", {
      organization_name: "Example Pty Ltd",
      organization_unit: "Security",
      locality: "Wollongong",
      country: "AU",
      email: "admin@example.com",
      cert_expiry_date: "2030-12-31",
      cert_validity_period: 3,
    });
    await h.call("sophos_create_smime_internal_ca", {
      organization_name: "Example Pty Ltd",
      locality: "Wollongong",
      country: "AU",
      email: "admin@example.com",
    });
    await h.call("sophos_upload_smime_internal_ca", { pkcs12: P12, password: "secret" });
    const download = await h.call("sophos_download_smime_internal_ca", {});
    const got = await h.call("sophos_get_smime_internal_ca", {});
    const lowerCountry = await h.call("sophos_create_smime_internal_ca", {
      organization_name: "Example Pty Ltd",
      locality: "Wollongong",
      country: "au",
      email: "admin@example.com",
    });
    assert.deepEqual(sent(h), [
      req("POST", "/email/v1/smime/ca/internal", {
        organizationName: "Example Pty Ltd",
        locality: "Wollongong",
        country: "AU",
        email: "admin@example.com",
        organizationUnit: "Security",
        certExpiryDate: "2030-12-31",
        certValidityPeriod: 3,
      }),
      req("POST", "/email/v1/smime/ca/internal", {
        organizationName: "Example Pty Ltd",
        locality: "Wollongong",
        country: "AU",
        email: "admin@example.com",
      }),
      req("POST", "/email/v1/smime/ca/internal/certificate", { password: "secret", pkcs12: P12 }),
      req("GET", "/email/v1/smime/ca/internal/certificate"),
      req("GET", "/email/v1/smime/ca/internal"),
    ]);
    assert.equal(download.json.pem, PEM);
    assert.equal(got.json.exists, true);
    assert.equal(got.json.fingerprint, FP);
    assert.match(lowerCountry.text, /Input validation error/);
  } finally {
    await h.close();
  }
});

test("S/MIME internal user tools: list filters, create, upload, download, delete", async () => {
  const h = await restHarness(registerEmailSmimeTools, (m, p) =>
    m === "GET" && p.includes("/certificate/")
      ? { status: 200, body: PEM, contentType: "application/octet-stream" }
      : m === "DELETE"
        ? { deleted: true }
        : { items: [], pages: { size: 0, maxSize: 50 } }
  );
  try {
    await h.call("sophos_list_smime_internal_users", {
      user_name: "john",
      email_starts_with: "joh",
      cert_valid_after: "2026-01-01",
      cert_expiry_before: "2027-01-01",
      cert_fingerprint: FP,
      issuer_cn: "Sophos",
      page_size: 200,
      page_from_key: "k1",
    });
    await h.call("sophos_list_smime_internal_users", {});
    await h.call("sophos_create_smime_internal_user_cert", { email: "john@example.com", cert_validity_period: 2 });
    await h.call("sophos_upload_smime_internal_user_cert", {
      email: "john@example.com",
      pkcs12: P12,
      password: "secret",
      confirm_signing_only_cert: true,
    });
    const download = await h.call("sophos_download_smime_internal_user_cert", { fingerprint: FP });
    const del = await h.call("sophos_delete_smime_internal_user_cert", { email: "john@example.com", cert_fingerprint: FP });
    const badFp = await h.call("sophos_download_smime_internal_user_cert", { fingerprint: "../../x" });
    const bigPage = await h.call("sophos_list_smime_internal_users", { page_size: 201 });
    assert.deepEqual(sent(h), [
      req("GET", "/email/v1/smime/users/internal", undefined, {
        pageSize: "200",
        userName: "john",
        emailStartsWith: "joh",
        certValidAfter: "2026-01-01",
        certExpiryBefore: "2027-01-01",
        certFingerprint: FP,
        issuerCN: "Sophos",
        pageFromKey: "k1",
      }),
      req("GET", "/email/v1/smime/users/internal", undefined, { pageSize: "50" }),
      req("POST", "/email/v1/smime/users/internal", { email: "john@example.com", certValidityPeriod: 2 }),
      req("POST", "/email/v1/smime/users/internal/certificate", {
        email: "john@example.com",
        password: "secret",
        pkcs12: P12,
        confirmSigningOnlyCert: true,
      }),
      req("GET", `/email/v1/smime/users/internal/certificate/${FP}`),
      req("DELETE", "/email/v1/smime/users/internal", undefined, { email: "john@example.com", certFingerprint: FP }),
    ]);
    assert.deepEqual(download.json, { fingerprint: FP, pem: PEM });
    assert.equal(del.json.status, "deleted");
    assert.match(badFp.text, /Input validation error/);
    assert.match(bigPage.text, /Input validation error/);
  } finally {
    await h.close();
  }
});

test("S/MIME external user and trusted CA tools send the spec routes", async () => {
  const h = await restHarness(registerEmailSmimeTools, (m, p) =>
    m === "GET" && p.includes("/certificate/")
      ? { status: 200, body: PEM, contentType: "application/octet-stream" }
      : m === "DELETE"
        ? { deleted: true }
        : { items: [], pages: { size: 0, maxSize: 50 } }
  );
  try {
    await h.call("sophos_list_smime_external_users", { email: "ext@example.org", cert_expiry_after: "2026-11-01" });
    await h.call("sophos_upload_smime_external_user_cert", { certificate: PEM, confirm_verification_only_cert: false });
    await h.call("sophos_download_smime_external_user_cert", { fingerprint: FP });
    await h.call("sophos_delete_smime_external_user_cert", { email: "ext@example.org", cert_fingerprint: FP });
    await h.call("sophos_list_smime_external_cas", { common_name: "Example Root", cert_valid_before: "2026-10-01" });
    await h.call("sophos_upload_smime_external_ca", { certificate: PEM });
    const ca = await h.call("sophos_download_smime_external_ca", { fingerprint: FP });
    const del = await h.call("sophos_delete_smime_external_ca", { cert_fingerprint: FP });
    const shortPem = await h.call("sophos_upload_smime_external_ca", { certificate: "-----BEGIN CERTIFICATE-----" });
    assert.deepEqual(sent(h), [
      req("GET", "/email/v1/smime/users/external", undefined, {
        pageSize: "50",
        email: "ext@example.org",
        certExpiryAfter: "2026-11-01",
      }),
      req("POST", "/email/v1/smime/users/external/certificate", { certificate: PEM, confirmVerificationOnlyCert: false }),
      req("GET", `/email/v1/smime/users/external/certificate/${FP}`),
      req("DELETE", "/email/v1/smime/users/external", undefined, { email: "ext@example.org", certFingerprint: FP }),
      req("GET", "/email/v1/smime/cas/external", undefined, {
        pageSize: "50",
        commonName: "Example Root",
        certValidBefore: "2026-10-01",
      }),
      req("POST", "/email/v1/smime/cas/external/certificate", { certificate: PEM }),
      req("GET", `/email/v1/smime/cas/external/certificate/${FP}`),
      req("DELETE", "/email/v1/smime/cas/external", undefined, { certFingerprint: FP }),
    ]);
    assert.equal(ca.json.pem, PEM);
    assert.equal(del.json.status, "deleted");
    assert.match(shortPem.text, /Input validation error/);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Search GraphQL API v1
// ---------------------------------------------------------------------------

function searchRecord(overrides = {}) {
  return {
    urn: URN,
    status: "QUEUED",
    overThreshold: false,
    errors: [],
    outcome: { success: "UNKNOWN", errors: [] },
    queryText: "from process earliest=-1h | fields host_id, image_path",
    searchPartitions: [],
    createTime: "2026-10-29T00:00:00Z",
    startTime: null,
    endTime: null,
    expireTime: "2026-11-28T00:00:00Z",
    metadata: null,
    hostnameMappings: [],
    ...overrides,
  };
}

async function searchHarness(answer) {
  const calls = [];
  const fusion = {
    query: async (tenantId, document, variables) => {
      calls.push({ tenantId, operation: document.match(/^(query|mutation) (\w+)/)[2], document, variables });
      return { data: answer(document, variables), warnings: [] };
    },
  };
  const tenantResolver = { resolveTenantId: (id) => id ?? TENANT };
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerFusionSearchTools(server, fusion, tenantResolver);
  return connect(server, calls);
}

test("Search: create and get-or-create send the QL text and metadata; get polls by URN", async () => {
  const h = await searchHarness((document) =>
    document.includes("createSearch(")
      ? { createSearch: searchRecord() }
      : document.includes("getOrCreateSearch(")
        ? { getOrCreateSearch: searchRecord() }
        : { search: searchRecord({ status: "COMPLETE", outcome: { success: "PARTIAL", errors: [{ urn: "p", errors: ["x"] }] } }) }
  );
  try {
    const created = await h.call("sophos_fusion_create_search", {
      query: "from process earliest=-1h | fields host_id, image_path",
      metadata: { source: "mcp" },
    });
    await h.call("sophos_fusion_get_or_create_search", { query: "from dnsquery earliest=-1d | aggregate count by 1h" });
    const polled = await h.call("sophos_fusion_get_search", { urn: URN });
    const badUrn = await h.call("sophos_fusion_get_search", { urn: "not-a-urn" });
    const noQuery = await h.call("sophos_fusion_create_search", {});
    assert.deepEqual(
      h.calls.map(({ operation, variables }) => ({ operation, variables })),
      [
        {
          operation: "FusionCreateSearch",
          variables: { input: { text: "from process earliest=-1h | fields host_id, image_path", metadata: { source: "mcp" } } },
        },
        { operation: "FusionGetOrCreateSearch", variables: { input: { text: "from dnsquery earliest=-1d | aggregate count by 1h" } } },
        { operation: "FusionSearch", variables: { urn: URN } },
      ]
    );
    assert.ok(h.calls[0].document.startsWith("mutation FusionCreateSearch($input: CreateSearchInput)"));
    assert.ok(h.calls[2].document.startsWith("query FusionSearch($urn: URN!)"));
    assert.equal(created.json.search.urn, URN);
    assert.match(created.json.next_step, /Poll sophos_fusion_get_search/);
    assert.match(polled.json.next_step, /outcome PARTIAL/);
    assert.match(badUrn.text, /Input validation error/);
    assert.match(noQuery.text, /Input validation error/);
  } finally {
    await h.close();
  }
});

test("Search results page by cursor, cap the limit at 1000, and add field metadata only when asked", async () => {
  const page = {
    values: [{ host_id: "h1", image_path: "C:\\x.exe", schema_type: "process" }],
    totals: { total: { value: 178 }, subtotals: [{ schemaType: "process", value: 178 }] },
    nextCursor: "2",
    previousCursor: null,
    hostnameMappings: [],
  };
  const h = await searchHarness((document) => ({
    searchResults: document.includes("fields {")
      ? { ...page, fields: [{ name: "host_id", baseType: "STRING", logicalType: null, enumValues: null, originSchemaTypes: ["process"] }] }
      : page,
  }));
  try {
    const first = await h.call("sophos_fusion_get_search_results", { urn: URN });
    const next = await h.call("sophos_fusion_get_search_results", { urn: URN, cursor: "2", limit: 1000, include_fields: true });
    const tooMany = await h.call("sophos_fusion_get_search_results", { urn: URN, limit: 1001 });
    assert.deepEqual(
      h.calls.map(({ operation, variables }) => ({ operation, variables })),
      [
        { operation: "FusionSearchResults", variables: { urn: URN, limit: 50 } },
        { operation: "FusionSearchResultsWithFields", variables: { urn: URN, limit: 1000, cursor: "2" } },
      ]
    );
    assert.equal(first.json.returned, 1);
    assert.equal(first.json.total, 178);
    assert.equal(first.json.next_cursor, "2");
    assert.equal(first.json.fields, undefined, "no field metadata unless asked");
    assert.equal(next.json.fields[0].name, "host_id");
    assert.match(tooMany.text, /Input validation error/);
  } finally {
    await h.close();
  }
});
