# Changelog

Notes for 0.13.1 and earlier are on the [GitHub releases page](https://github.com/Aaronjacobs000/sophos-mcp/releases).

## Unreleased

- `sophos_add_endpoints_to_group` reports what Sophos did. Before, it ignored the response and said every requested endpoint was added. It now returns `added` (id and hostname) from `addedEndpoints`, and `not_added` with a reason for each ID: `not_found` and `wrong_type` from `errors.endpointsNotFound` and `errors.endpointsOfWrongType`, or `not_in_response` for an ID in neither list (Sophos leaves out endpoints already in the group). `status` is `added`, `partially_added` or `none_added`, and `endpoints_added` is the real count.

## 0.13.7 (26/11/2026)

- `F-#####` case short IDs (for example `F-08717`, first seen 26/11/2026) count as Fusion short IDs, like `CSE#####` and `E-#####`. They already resolved by short ID, but one that matched nothing came back with the Classic case ID hint; now it is a plain not-found.
- Fusion short IDs are matched by their real format: the region's first letter, a dash and five or more digits (`P-12345`, in any case), beside the older `CSE#####`. Sophos changed case IDs to this format in mid November 2026, and `E-#####` and `F-#####` were the first two letters seen. A one letter ID with fewer digits (`X-1234`) or a two letter one (`AP-23456789`) is still looked up first and gets the Classic hint when nothing matches. Tool descriptions and errors name `P-12345` as the example.
- The lockfile moves hono, `@hono/node-server` and node-forge past open advisories, so the `.mcpb` bundle ships the patched versions. `npm audit` on runtime dependencies is clean.

## 0.13.6 (22/11/2026)

- Read-only mode. `SOPHOS_READ_ONLY=true` registers only the 176 tools classified as reads and refuses any request that could write before it leaves the process: any method but GET and HEAD, except the token request, Fusion GraphQL queries, and four REST searches. Eleven tools annotated read-only are left out: ten create query runs, searches, or jobs, or run on devices, and one is a POST that might store something. `src/read-only.ts` lists both sets. Off by default, and with it off every request goes out as before.

## 0.13.5 (21/11/2026)

- The Fusion case tools accept the new `E-#####` short IDs (for example `E-01167`, first seen 18/11/2026) as well as `CSE#####`, in any case. Before, they were refused as Classic case IDs. Only digits, a dash and digits (`1-598868`) now count as a Classic ID; any other two part ID is looked up as a short ID first and gets the Classic hint only when nothing matches.

## 0.13.4 (21/11/2026)

- LICENSE names the copyright holder: `Copyright (c) 2026 Aaron Jacobs`.
- Listed in the official MCP Registry as `io.github.Aaronjacobs000/sophos-mcp`. `package.json` carries the matching `mcpName`, and `server.json` describes the npm package. No code changes.

## 0.13.3 (10/11/2026)

- `sophos_fusion_list_cases` with `open_only` no longer lists closed cases whose `closedAt` is null. Cases closed in early 2026 never got a `closedAt`, so they came back as open (13 on one tenant). `open_only` now also leaves out the Closed status of both status sets Fusion has used, plus any closed status in the tenant's cached reference data. No extra call is made.
- `scripts/fusion-smoke.mjs` expects the new `open_only` predicate.

## 0.13.2 (09/11/2026)

- AI Defense policy writes (create, update, delete, enable, disable, move, reorder, clone) that get a 5xx, time out or lose their connection are now read back, the same way as a write Sophos answers with no result. The result says `status: "unclear"` with `took_effect`. Before, they returned "may already have taken effect" with no read-back.
- `sophos_fusion_ai_defense_update_settings` reads the settings back when Sophos gives no result or the call fails that way. Before, an empty result was an error with no read-back. The settings must show the status and selections sent, and a base policy must exist when one was sent.
- The Fusion client throws `FusionMutationUnconfirmedError` for a mutation that gets a 5xx, a timeout or a dropped connection. The message is unchanged, so other tools report the same text.
- `scripts/fusion-smoke.mjs --write-ai-defense` updates the tags with a different key from the one the policy was created with, so the check can tell a replace from a merge.
