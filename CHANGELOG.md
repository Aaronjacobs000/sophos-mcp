# Changelog

Notes for 0.13.1 and earlier are on the [GitHub releases page](https://github.com/Aaronjacobs000/sophos-mcp/releases).

## 0.13.3 (10/11/2026)

- `sophos_fusion_list_cases` with `open_only` no longer lists closed cases whose `closedAt` is null. Cases closed in early 2026 never got a `closedAt`, so they came back as open (13 on one tenant). `open_only` now also leaves out the Closed status of both status sets Fusion has used, plus any closed status in the tenant's cached reference data. No extra call is made.
- `scripts/fusion-smoke.mjs` expects the new `open_only` predicate.

## 0.13.2 (09/11/2026)

- AI Defense policy writes (create, update, delete, enable, disable, move, reorder, clone) that get a 5xx, time out or lose their connection are now read back, the same way as a write Sophos answers with no result. The result says `status: "unclear"` with `took_effect`. Before, they returned "may already have taken effect" with no read-back.
- `sophos_fusion_ai_defense_update_settings` reads the settings back when Sophos gives no result or the call fails that way. Before, an empty result was an error with no read-back. The settings must show the status and selections sent, and a base policy must exist when one was sent.
- The Fusion client throws `FusionMutationUnconfirmedError` for a mutation that gets a 5xx, a timeout or a dropped connection. The message is unchanged, so other tools report the same text.
- `scripts/fusion-smoke.mjs --write-ai-defense` updates the tags with a different key from the one the policy was created with, so the check can tell a replace from a merge.
