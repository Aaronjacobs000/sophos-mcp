# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run build       # Compile TypeScript to dist/
npm start           # Run the compiled server
npm run dev         # Watch mode (tsc --watch)
npm test            # Build, then run the node:test suites in test/ (no network)
npm run build:mcpb  # Build the Claude Desktop extension bundle into release/
node scripts/fusion-smoke.mjs [tenant-id]   # Live check of the Fusion tools and the Classic gate (needs credentials); read-only unless --write, --write-classic or --all
```

`npm test` and TypeScript compilation (`npm run build`) are the verification steps. Fix all type errors and keep the tests green before considering a change complete. The tests stub `fetch`; nothing in them reaches Sophos.

Run the server locally:
```bash
cp .env.example .env   # Then fill in credentials
npm run build && npm start
```

## MCPB packaging

`manifest.json` at the repo root is the [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) manifest. `scripts/build-mcpb.mjs` (run via `npm run build:mcpb`) rewrites its `version` from `package.json` and its `tools` array from every `registerTool` call in `src/tools/`, validates it, stages `dist/` plus production dependencies in `build/mcpb/`, and packs `release/sophos-central-mcp-server-<version>.mcpb`. Do not hand-edit `version` or `tools` in the manifest; edit the other fields (description, `user_config`, compatibility) directly and re-run the build. New tools must follow the `registerTool("name", { title: "...", description: `...` ...` shape or the build fails on purpose.

Credentials come from `user_config` (`sophos_client_id`, `sophos_client_secret`, both `sensitive`) mapped to `SOPHOS_CLIENT_ID` / `SOPHOS_CLIENT_SECRET` in `server.mcp_config.env`, with `TRANSPORT=stdio` fixed.

## Naming

The product is Sophos Fusion (formerly Sophos Central). Human-facing titles and descriptions say "Sophos Fusion (formerly Sophos Central)". The npm package, the `.mcpb` manifest `name`, the `bin` entries and the `McpServer` name string stay `sophos-central-mcp-server` so existing installs update in place. Never write "Sophos Taegis": `api.taegis.sophos.com` is a hostname, and the product it came from is Secureworks Taegis. Use the developer portal's wording for the query language: "Fusion Query Language (QL)".

## Architecture

This is a **Model Context Protocol (MCP) server** that wraps the Sophos Central REST APIs and the Sophos Fusion GraphQL APIs, built with `@modelcontextprotocol/sdk`, Express (HTTP transport), and Zod (schema validation). TypeScript ESM (`"type": "module"`, `Node16` module resolution): all imports must use `.js` extensions.

### Startup flow (`src/index.ts`)

1. Load config from env vars (`src/config/config.ts`)
2. `TokenManager` fetches an OAuth2 token from `https://id.sophos.com/api/v2/oauth2/token`
3. `TenantResolver.init()` calls `/whoami/v1` to discover caller identity type: `partner | organization | tenant`
4. For partner/org callers, `loadTenants()` paginates through all managed tenants and caches `tenantId → apiHost`
5. `SophosClient` (REST) and `FusionClient` (GraphQL) are created on the same `TokenManager`
6. Tools are registered conditionally: `sophos_list_tenants` only for partner/org; all others always. The Classic case and detection tools take a `FusionMigrationGuard` built on the case reference cache. The Fusion block (cases, then detections) is registered last
7. Transport starts: streamable HTTP on `127.0.0.1:PORT/mcp` (stateless, new transport per request) or stdio

### Core classes

- **`TokenManager`** (`src/auth/token-manager.ts`): OAuth2 client credentials flow with in-memory token caching (60s early refresh, deduplicates concurrent refresh calls). Shared by both clients.
- **`TenantResolver`** (`src/client/tenant-resolver.ts`): Holds caller identity and `tenantId → TenantInfo` map. Key methods: `resolveTenantId(providedId?)`, which enforces that partner/org callers must supply a tenant ID; `resolveApiHost(tenantId)`, which returns the per-tenant regional REST host. Fusion calls use `resolveTenantId` only; there is no regional host.
- **`SophosClient`** (`src/client/sophos-client.ts`): Two methods, `tenantRequest<T>(tenantId, path, opts)` and `globalRequest<T>(path, opts)`. Both inject auth headers and run `executeWithRetry` (2 retries, exponential backoff, respects `Retry-After` on 429, no retry on 401/403/404).
- **`FusionClient`** (`src/client/fusion-client.ts`): `query<T>(tenantId, document, variables)` POSTs to `SOPHOS_FUSION_GRAPHQL_URL` with the bearer token and `X-Tenant-ID`. Same transport retry shape as the REST client (30 s timeout, 2 retries, `Retry-After` on 429, no retry on 4xx) with full-jitter backoff, plus the one GraphQL-layer retry described below. Returns `{ data, warnings }`. `putPresigned(url, bytes, contentType)` is the plain PUT behind case file uploads.
- **`FusionMigrationGuard`** (`src/fusion/migration.ts`): `assertClassic(tenantId, classicTool, useInstead)` throws when the tenant has moved to Fusion (the case reference cache returns at least one case type; an unmigrated tenant gets an empty list with no error) and returns warnings otherwise. Every Classic case and detection handler calls it first. `SOPHOS_CLASSIC_MIGRATION_CHECK=off` disables it.

### The GraphQL 200 rule

A GraphQL-layer failure comes back as **HTTP 200 with an `errors` array** beside `data`. `FusionClient` never treats a 200 as success until the body has been read:

- `errors` present and no usable data (data null, or every root field null): throws `FusionGraphQLError` with every message joined. Never retried.
- `errors` present beside usable data (a partial response, typically a federated field): returns the data with the messages in `warnings`. Tools attach `warnings` to their result; they are never dropped.
- A null root field with no errors passes through for the tool to report as not found. In practice an unknown case ID arrives as errors (`record not found`) beside `data: { case: null }`, which the first rule throws; `FusionGraphQLError.notFound` recognises it and the case tools translate it into their not-found message.
- The `extensions.code` cannot tell a transient failure from a rejected query: `conn busy`, `record not found` and `query not valid for any known schema type(s)` all carry `DOWNSTREAM_SERVICE_ERROR`. So the code is never used to decide a retry.
- The one GraphQL-layer retry is keyed on the error path. `createCase` and `addEvidenceToCase` fail roughly one call in two with `not allowed`, `path: ["partnerPreferences"]`, from `investigations-v2`; the identical call succeeds on retry (measured 22/09/2026). `FusionGraphQLError.isTransientPartnerPreferences` is `errors[0].path[0] === "partnerPreferences"` and nothing else; `query()` retries only that, up to 8 attempts with a short capped backoff. An error carrying the operation name in its path (`createCase`, `addEvidenceToCase`, `tdrusers`) is a real input or permission error and surfaces at once.

Transport failures (expired token, 429, 5xx) use the usual non-2xx status and the standard Sophos error object. A query the schema rejects is HTTP 400 with a GraphQL `errors` array and no data; the client keeps that message. A missing required variable is HTTP 200 with `errors` (`BAD_USER_INPUT`) and no `data` key at all.

### Fusion layout (`src/fusion/`)

- `queries/<api>.ts`: hand-written GraphQL documents as string constants, one file per API, minimal selection sets, no codegen. Operation names use the `detection*` form, never the `alertsService*` aliases. Federated `*Subject` fields are not selected. Never put two case-scoped root fields in one document (`case` plus `caseEvidence`, or two aliased `case` fields): investigations-v2 answers `conn busy` every time. The three reference-data root fields are fine together.
- `case-reference-data.ts`: `CaseReferenceDataCache`, per tenant, 15 minute TTL, one round trip for case types, primary statuses and primary verdicts. Fusion filters and writes these by UUID and the set depends on the tenant's licensed services, so names resolve at runtime and are never hard-coded.
- `cases-ql.ts`: builds the QL string for `cases(arguments: { query })` from the list tool's filters. Names never reach QL; only `*Id` columns are searchable.
- `format.ts`: severity scales (case 2 to 10 integer; detection 0 to 1 float; Classic REST detection 0 to 10; never converted), `{ seconds, nanos }` to ISO 8601, ID shape checks (UUID, `CSE#####` short ID, legacy `1-598868`, six section resource names for detection and event IDs), QL quoting, comment mention parsing, tag merging, the detection row formatter.
- `migration.ts`: the migration guard (above).
- `types.ts`: response types for the selected fields.
- `schemas/fusion/*.graphql` (repo root): the five schemas exactly as downloaded from the developer portal on 21/09/2026, for reference and diffing. Do not edit them; re-download to update.

Fusion and Classic cases are separate sets. A legacy ID never resolves in Fusion and a Fusion ID never resolves in REST; the tools refuse the wrong shape with a pointer to the other family. There is no delete in Fusion: close (with a verdict when the type supports one), then archive.

Measured case rules the tools enforce or explain (live tenant, 22/09/2026): `managedBy` is required on create, never defaulted (omitting it makes an unclaimed case) and immutable, and `health_check` and `threat_hunt` pin it to `PROVIDER`; `keyFindings.documentVersion` is exactly `"1.0"`; tags on update replace, so the tool merges unless told to replace; a closed case is frozen apart from status, verdicts, secondary status, archive and reasons; an archived case refuses every update; a closed case with a verdict reopens only with `primaryVerdictId: null` in the same update; `new` is a one way door; retitle before archive. Evidence: detection and event IDs are six section RNs; adding a detection also attaches its asset and events and removing it does not retract them; `removeEvidenceFromCase` takes source IDs (an entry `id` is a silent no-op); reads lag writes by a few seconds. Comments: `AddCaseComment` has no `Input` suffix; `@authorized_contacts`, `@customer` and `@sophos` fire wherever they appear and unknown tokens are dropped silently, so the tools read `mentionsIds` back; never select `authorSubject` or `mentionsSubjects` (they turn the response into an error). Files: `caseFiles` is tenant wide with no `query` (client-side filter by `caseId`), `deleteCaseFile` is soft. `casePrimaryStatuses` returns six statuses while case types list eight, so status IDs degrade to the raw ID rather than throwing.

### Tool registration pattern

Each file in `src/tools/` exports a `register*Tools(server, client, tenantResolver)` function (`cases.ts` and `detections.ts` take the migration guard as a fourth parameter; `fusion-cases.ts` takes `(server, fusionClient, tenantResolver, caseReferenceData)`; `fusion-detections.ts` takes `(server, fusionClient, tenantResolver)`). Tools follow this pattern:

```typescript
server.registerTool(
  "sophos_tool_name",
  { title, description, inputSchema: { /* Zod fields */ }, annotations: { readOnlyHint, destructiveHint, ... } },
  withErrorHandling(async (args) => {
    const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
    const data = await client.tenantRequest<ResponseType>(tenantId, "/api/path", { params, method, body });
    return jsonResult(formatData(data));
  })
);
```

Helper functions in `src/tools/helpers.ts`:
- `jsonResult(data)`: JSON-serialises and truncates at `CHARACTER_LIMIT` with a truncation notice
- `errorResult(error)`: formats errors as MCP error responses
- `withErrorHandling(handler)`: wraps handlers to catch and return errors cleanly

### Adding a new tool

1. Create (or add to) a file in `src/tools/`
2. Add Sophos API response types to `src/types/sophos.ts` (REST) or `src/fusion/types.ts` (GraphQL) if needed
3. Export a `register*Tools(...)` function
4. Import and call it in `src/index.ts`
5. All tenant-scoped tools must call `tenantResolver.resolveTenantId(args.tenant_id)` first; this throws with a useful message for partner/org callers who omit `tenant_id`
6. Fusion tools take the `sophos_fusion_` prefix, name the severity scale a field uses, give one working QL example where a query is accepted, and batch ID lookups (the rate limit is per credential and shared with the Central tools)
7. Update the count in `test/tool-registration.test.mjs` and run `npm test`

### Pagination

- Endpoint APIs use cursor-based pagination (`pageFromKey` / `nextKey`)
- Most other REST APIs use offset-based pagination (`page` / `pageSize`)
- Fusion cases accept offset (`page` / `perPage`, max 100) or cursor (`first` / `after`) pagination; cursors are opaque and replayed verbatim
- `DEFAULT_PAGE_SIZE = 50`, `MAX_PAGE_SIZE = 100` from `src/config/config.ts`

### Constants (`src/config/config.ts`)

| Constant | Value |
|---|---|
| `SOPHOS_AUTH_URL` | `https://id.sophos.com/api/v2/oauth2/token` |
| `SOPHOS_GLOBAL_API` | `https://api.central.sophos.com` |
| `SOPHOS_FUSION_GRAPHQL_URL` | `https://api.taegis.sophos.com/graphql`, env override of the same name |
| `CHARACTER_LIMIT` | `50000` (env override, minimum 10000) |
| `DEFAULT_PAGE_SIZE` | `50` |

## Prose

README, CLAUDE.md and tool descriptions carry no em dashes and no en dashes. Keep them short.
