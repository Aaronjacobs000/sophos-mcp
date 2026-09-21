#!/usr/bin/env node
/**
 * Sophos Central MCP Server
 *
 * Entry point. Bootstraps auth, discovers caller identity, registers
 * tools based on identity type, and starts the MCP transport.
 */

import "dotenv/config";
import { createRequire } from "node:module";

const nodeRequire = createRequire(import.meta.url);
const pkgVersion: string = nodeRequire("../package.json").version;
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import express from "express";

import { loadConfig } from "./config/config.js";
import { TokenManager } from "./auth/token-manager.js";
import { TenantResolver } from "./client/tenant-resolver.js";
import { SophosClient } from "./client/sophos-client.js";
import { FusionClient } from "./client/fusion-client.js";
import { CaseReferenceDataCache } from "./fusion/case-reference-data.js";

// Tool registration modules
import { registerTenantTools } from "./tools/tenants.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerEndpointTools } from "./tools/endpoints.js";
import { registerHealthTools } from "./tools/health.js";
import { registerDirectoryTools } from "./tools/directory.js";
import { registerPolicyTools } from "./tools/policies.js";
import { registerGroupTools } from "./tools/groups.js";
import { registerExclusionTools } from "./tools/exclusions.js";
import { registerCaseTools } from "./tools/cases.js";
import { registerDetectionTools } from "./tools/detections.js";
import { registerSiemTools } from "./tools/siem.js";
import { registerXdrTools } from "./tools/xdr.js";
import { registerLiveDiscoverTools } from "./tools/live-discover.js";
import { registerAdminManagementTools } from "./tools/admin-management.js";
import { registerEndpointMigrationTools } from "./tools/endpoint-migrations.js";
import { registerEndpointSettingsTools } from "./tools/endpoint-settings.js";
import { registerFirewallTools } from "./tools/firewall.js";
import { registerEmailTools } from "./tools/email.js";
import { registerDnsProtectionTools } from "./tools/dns-protection.js";
import { registerCloudSecurityTools } from "./tools/cloud-security.js";
import { registerWifiTools } from "./tools/wifi.js";
import { registerUserActivityTools } from "./tools/user-activity.js";
import { registerPartnerTools } from "./tools/partner.js";
import { registerMobileTools } from "./tools/mobile.js";
import { registerAuditEventTools } from "./tools/audit-events.js";
import { registerLicensingTools } from "./tools/licensing.js";
import { registerWebFilteringTools } from "./tools/web-filtering.js";
import { registerSwitchTools } from "./tools/switch.js";
import { registerAccountsTools } from "./tools/accounts.js";
import { registerBusinessAutomationTools } from "./tools/business-automation.js";
import { registerFusionCaseTools } from "./tools/fusion-cases.js";

async function main(): Promise<void> {
  // Load and validate config
  const config = loadConfig();
  console.error("[sophos-mcp] Starting Sophos Fusion MCP server (formerly Sophos Central)...");

  // Initialise auth
  const tokenManager = new TokenManager(config.clientId, config.clientSecret);
  const tenantResolver = new TenantResolver(tokenManager);

  // Discover caller identity
  const identity = await tenantResolver.init();

  // Pre-load tenants for partner/org callers
  if (identity.idType !== "tenant") {
    await tenantResolver.loadTenants();
  }

  // Create the HTTP clients: REST for Sophos Central, GraphQL for Sophos Fusion
  const sophosClient = new SophosClient(tokenManager, tenantResolver);
  const fusionClient = new FusionClient(tokenManager);
  const caseReferenceData = new CaseReferenceDataCache(fusionClient);

  // Create the MCP server
  const server = new McpServer({
    name: "sophos-central-mcp-server",
    version: pkgVersion,
  });

  // Register tools based on identity type
  console.error(`[sophos-mcp] Registering tools for ${identity.idType} caller...`);

  // Partner/org-only tools
  if (identity.idType !== "tenant") {
    registerTenantTools(server, tenantResolver);
    registerPartnerTools(server, sophosClient, tenantResolver);
  }

  // Phase 1: Tenant-scoped SOC monitoring tools
  registerAlertTools(server, sophosClient, tenantResolver);
  registerEndpointTools(server, sophosClient, tenantResolver);
  registerHealthTools(server, sophosClient, tenantResolver);
  registerDirectoryTools(server, sophosClient, tenantResolver);

  // Phase 2: Admin automation tools
  registerPolicyTools(server, sophosClient, tenantResolver);
  registerGroupTools(server, sophosClient, tenantResolver);
  registerExclusionTools(server, sophosClient, tenantResolver);

  // Phase 3: Investigation tools
  registerCaseTools(server, sophosClient, tenantResolver);
  registerDetectionTools(server, sophosClient, tenantResolver);
  registerSiemTools(server, sophosClient, tenantResolver);
  registerXdrTools(server, sophosClient, tenantResolver);
  registerLiveDiscoverTools(server, sophosClient, tenantResolver);

  // Phase 4: Endpoint migration and software package tools
  registerEndpointMigrationTools(server, sophosClient, tenantResolver);

  // Phase 5: Endpoint settings tools
  registerEndpointSettingsTools(server, sophosClient, tenantResolver);

  // Phase 6: Firewall management tools
  registerFirewallTools(server, sophosClient, tenantResolver);

  // Phase 7: Admin management and directory user/group tools
  registerAdminManagementTools(server, sophosClient, tenantResolver);

  // Phase 8: Email protection tools
  registerEmailTools(server, sophosClient, tenantResolver);

  // Phase 9: DNS, cloud security, Wi-Fi, licensing, accounts, user activity
  registerDnsProtectionTools(server, sophosClient, tenantResolver);
  registerCloudSecurityTools(server, sophosClient, tenantResolver);
  registerWifiTools(server, sophosClient, tenantResolver);
  registerUserActivityTools(server, sophosClient, tenantResolver);

  // Phase 10: Mobile device management tools
  registerMobileTools(server, sophosClient, tenantResolver);

  // Phase 11: Audit events, licensing, web filtering, switch, accounts,
  // business automation
  registerAuditEventTools(server, sophosClient, tenantResolver);
  registerLicensingTools(server, sophosClient, tenantResolver);
  registerWebFilteringTools(server, sophosClient, tenantResolver);
  registerSwitchTools(server, sophosClient, tenantResolver);
  registerAccountsTools(server, sophosClient, tenantResolver);
  registerBusinessAutomationTools(server, sophosClient, tenantResolver);

  // Fusion: GraphQL APIs on api.taegis.sophos.com, beside the Classic REST tools
  registerFusionCaseTools(server, fusionClient, tenantResolver, caseReferenceData);

  console.error("[sophos-mcp] All tools registered.");

  // Start transport
  if (config.transport === "http") {
    await runHTTP(server, config.port);
  } else {
    await runStdio(server);
  }
}

async function runHTTP(server: McpServer, port: number): Promise<void> {
  const app = express();
  app.use(express.json());

  // MCP endpoint: stateless streamable HTTP
  app.post("/mcp", async (req, res) => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
      enableJsonResponse: true,
    });

    res.on("close", () => transport.close());

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // Health check endpoint
  app.get("/health", (_req, res) => {
    res.json({ status: "ok", server: "sophos-central-mcp-server" });
  });

  app.listen(port, "127.0.0.1", () => {
    console.error(`[sophos-mcp] HTTP server listening on http://127.0.0.1:${port}/mcp`);
  });
}

async function runStdio(server: McpServer): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[sophos-mcp] Running on stdio transport");
}

main().catch((error) => {
  console.error("[sophos-mcp] Fatal error:", error);
  process.exit(1);
});
