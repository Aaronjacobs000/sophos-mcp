/**
 * Tool: sophos_fusion_endpoint_inventory
 * Endpoint inventory (softwareinfo, patchstate, inventoryinfo) from the Sophos
 * Fusion Data Lake through the Search GraphQL API v1, reduced to the latest
 * snapshot per device and flagged stale by the Endpoint API's lastSeenAt.
 *
 * Two searches over the same where clause: an aggregate (one row per device:
 * newest row time and row count), so the device list and the counts are whole
 * even when the rows are capped, and the rows themselves, read newest first
 * until every device's latest snapshot is in or max_rows is reached. Absolute
 * hour-aligned bounds let getOrCreateSearch hand the same searches back for
 * the rest of the hour. Measured rules are in src/fusion/inventory.ts.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { FusionClient } from "../client/fusion-client.js";
import type { SophosClient } from "../client/sophos-client.js";
import type { TenantResolver } from "../client/tenant-resolver.js";
import { CREATE_SEARCH, GET_OR_CREATE_SEARCH, GET_SEARCH, SEARCH_RESULTS } from "../fusion/queries/search.js";
import type { FusionSearch, FusionSearchResultPage } from "../fusion/types.js";
import type { SophosEndpointPage } from "../types/sophos.js";
import {
  INVENTORY_SCHEMAS,
  MAX_SEARCH_ROWS,
  buildDevicesQl,
  buildRowsQl,
  classifyLastSeen,
  compactRow,
  compareDevices,
  inventoryWindow,
  latestSnapshots,
  lookupIds,
  mergeDeviceAggregates,
  msToIso,
  pick,
  readFloor,
  sortRows,
  type DeviceStatus,
  type InventoryFilters,
  type InventorySchema,
  type LatestSnapshot,
} from "../fusion/inventory.js";
import { isUuid } from "../fusion/format.js";
import { jsonResult, withErrorHandling, withWarnings } from "./helpers.js";

/** Rows per searchResults page, the most it accepts. */
const PAGE_ROWS = 1000;
/** IDs per Endpoint API lookup: 501 IDs overflow the URL, 151 pass. */
const ID_BATCH = 100;
/** Above this many devices, one listing of every endpoint takes fewer calls. */
const LOOKUP_BY_ID_MAX = 500;
const ENDPOINT_FIELDS = "id,hostname,lastSeenAt";

export interface InventoryToolOptions {
  now?: () => number;
  pollIntervalMs?: number;
  waitMs?: number;
}

type Row = Record<string, unknown>;

interface EndpointSeen {
  hostname?: string;
  lastSeenAt?: string;
}

async function startSearch(
  client: FusionClient,
  tenantId: string,
  text: string,
  refresh: boolean
): Promise<{ search: FusionSearch; warnings: string[] }> {
  const { data, warnings } = await client.query<{
    createSearch?: FusionSearch | null;
    getOrCreateSearch?: FusionSearch | null;
  }>(tenantId, refresh ? CREATE_SEARCH : GET_OR_CREATE_SEARCH, { input: { text } });
  const search = refresh ? data.createSearch : data.getOrCreateSearch;
  if (!search) throw new Error("The Data Lake search returned no search.");
  return { search, warnings };
}

/** Reads every page, or up to maxRows, stopping early once a row older than stopBelow arrives. */
async function readResults(
  client: FusionClient,
  tenantId: string,
  urn: string,
  maxRows: number,
  stopBelow: number | null
): Promise<{ rows: Row[]; readAll: boolean; warnings: string[] }> {
  const rows: Row[] = [];
  const warnings: string[] = [];
  let cursor: string | null = null;
  do {
    const variables: Record<string, unknown> = { urn, limit: Math.min(PAGE_ROWS, maxRows - rows.length) };
    if (cursor) variables.cursor = cursor;
    const result = await client.query<{ searchResults: FusionSearchResultPage | null }>(tenantId, SEARCH_RESULTS, variables);
    warnings.push(...result.warnings);
    const page = result.data.searchResults;
    if (!page) throw new Error(`searchResults returned nothing for ${urn}.`);
    const values = page.values ?? [];
    rows.push(...values);
    cursor = values.length > 0 ? page.nextCursor ?? null : null;
    const last = Number(values[values.length - 1]?.time);
    if (stopBelow !== null && Number.isFinite(last) && last < stopBelow) break;
  } while (cursor && rows.length < maxRows);
  return { rows, readAll: !cursor, warnings };
}

/** lastSeenAt by endpoint ID: by ID in batches, or the whole list when that is fewer calls. */
async function endpointLastSeen(client: SophosClient, tenantId: string, ids: string[]): Promise<Map<string, EndpointSeen>> {
  const seen = new Map<string, EndpointSeen>();
  const keep = (page: SophosEndpointPage) => {
    for (const item of page.items ?? []) seen.set(item.id, { hostname: item.hostname, lastSeenAt: item.lastSeenAt });
  };
  if (ids.length === 0) return seen;
  if (ids.length <= LOOKUP_BY_ID_MAX) {
    for (let i = 0; i < ids.length; i += ID_BATCH) {
      const batch = ids.slice(i, i + ID_BATCH);
      keep(
        await client.tenantRequest<SophosEndpointPage>(tenantId, "/endpoint/v1/endpoints", {
          params: { ids: batch.join(","), fields: ENDPOINT_FIELDS, pageSize: String(ID_BATCH) },
        })
      );
    }
    return seen;
  }
  let key: string | undefined;
  do {
    const params: Record<string, string> = { pageSize: "500", fields: ENDPOINT_FIELDS };
    if (key) params.pageFromKey = key;
    const page = await client.tenantRequest<SophosEndpointPage>(tenantId, "/endpoint/v1/endpoints", { params });
    keep(page);
    key = page.pages?.nextKey;
  } while (key);
  return seen;
}

function unmatchedReason(hostId: string, lookedUp: boolean, record: EndpointSeen | undefined): string {
  if (!lookedUp) return "The last seen lookup failed (see warnings).";
  if (!isUuid(hostId)) return "Not a Sophos endpoint ID (a third-party sensor): no last seen to check.";
  if (!record) return "No Sophos endpoint has this ID: deleted, or re-registered under a new ID.";
  return "The endpoint record has no lastSeenAt.";
}

export function registerFusionInventoryTools(
  server: McpServer,
  fusionClient: FusionClient,
  sophosClient: SophosClient,
  tenantResolver: TenantResolver,
  options: InventoryToolOptions = {}
): void {
  const now = options.now ?? Date.now;
  const pollIntervalMs = options.pollIntervalMs ?? 2000;
  const waitMs = options.waitMs ?? 45_000;

  server.registerTool(
    "sophos_fusion_endpoint_inventory",
    {
      title: "Get Fusion Endpoint Inventory with Last Seen",
      description: `Endpoint inventory from the Sophos Fusion Data Lake: each device's latest snapshot, flagged stale, fresh or unmatched by when its endpoint was last seen.

schema: softwareinfo (installed applications), patchstate (installed OS patches, one row per KB) or inventoryinfo (device record: OS, OS last update, boot time, domain, disk encryption).

Why the flag: the Data Lake writes one snapshot per device per day and keeps writing them for about 30 days after a device goes offline, rebuilt from its last report (measured 03/11/2026). A snapshot dated today can describe a device last online weeks ago. The snapshot has no last seen of its own, so each device is matched on host_id, which is its endpoint ID, to lastSeenAt from the Endpoint API (as sophos_list_endpoints shows it). stale: last seen more than stale_after_days ago. fresh: within it. unmatched: no endpoint with that ID (deleted, re-registered under a new ID, or a third-party sensor) or no lastSeenAt, so its rows can't be dated.

Not a vulnerability scan: there is no CVE or missing patch field. patchstate shows what is installed, never what is missing.

Coverage: Sophos agents on Windows feed all three schemas, on Linux softwareinfo and inventoryinfo (a Linux device had no patchstate rows, 03/11/2026), on macOS patchstate and inventoryinfo; CrowdStrike only softwareinfo; Microsoft Defender and SentinelOne none.

Runs two Data Lake searches (devices, rows) with absolute bounds ending at the next whole UTC hour, so the same arguments in the same hour reuse them: paging with offset costs nothing, and if a search is still running, call again. refresh starts new ones. Devices sort stale, unmatched, fresh, then by hostname; rows follow their device's order, and each carries its device's status.

Args:
  - schema (string): softwareinfo, patchstate or inventoryinfo.
  - endpoint_id (string, optional): One device by endpoint ID.
  - hostname (string, optional): Hostname contains this, case-insensitive.
  - software_name (string, optional): softwareinfo only. Application name contains this, for example "Chrome".
  - kb (string, optional): patchstate only. Patch title contains this, for example "KB5007651".
  - days (number, optional): Snapshot window, 1 to 30 days back from the next whole hour. Default 2, which holds the latest daily snapshot.
  - stale_after_days (number, optional): Last seen more than this many days ago is stale. Default 3.
  - status (string, optional): Return only stale, unmatched or fresh devices. Default all. The summary counts every device.
  - include_rows (boolean, optional): Return the rows of each device's latest snapshot. Default true; false returns devices only and runs only the device search.
  - max_rows (number, optional): Most rows read, 1 to 10000 (a search returns at most 10,000). Default 5000. A device whose snapshot was cut off has snapshot_complete false.
  - offset (number, optional): Rows to skip (devices when include_rows is false). Default 0.
  - limit (number, optional): Rows per response (devices when include_rows is false), 1 to 1000. Default 100.
  - refresh (boolean, optional): Start new searches instead of reusing this hour's. Default false.
  - tenant_id (string, optional): Tenant ID. Required for partner/org callers.

Returns:
  summary (devices, fresh, stale, unmatched, rows_in_window, rows_read, latest_snapshot_rows, incomplete_devices), the window, the search URNs, total, next_offset, then:
  - devices (those on this page of rows, or the page of devices): endpoint_id, hostname, status (with a reason when unmatched), last_seen_at, days_since_seen, snapshot_time, sensor_type, os, snapshot_rows, snapshot_complete.
  - rows: endpoint_id, hostname, status, plus for softwareinfo name, version, vendor, installed_at; patchstate kb, title, installed_at, installed_by; inventoryinfo os, os_version, os_last_update_at, boot_time, domain, device_type, is_domain_controller, mac, ip, storage_volumes.`,
      inputSchema: {
        schema: z.enum(INVENTORY_SCHEMAS).describe("softwareinfo, patchstate or inventoryinfo"),
        endpoint_id: z.string().guid().optional().describe("One device by endpoint ID"),
        hostname: z.string().min(1).optional().describe("Hostname contains this (case-insensitive)"),
        software_name: z.string().min(1).optional().describe("softwareinfo only: application name contains this"),
        kb: z.string().min(1).optional().describe('patchstate only: patch title contains this, for example "KB5007651"'),
        days: z.number().int().min(1).max(30).optional().default(2).describe("Snapshot window in days (1-30, default 2)"),
        stale_after_days: z
          .number()
          .int()
          .min(1)
          .max(365)
          .optional()
          .default(3)
          .describe("Last seen more than this many days ago is stale (default 3)"),
        status: z
          .enum(["all", "stale", "unmatched", "fresh"])
          .optional()
          .default("all")
          .describe("Return only devices with this status (default all)"),
        include_rows: z.boolean().optional().default(true).describe("Include each device's latest snapshot rows"),
        max_rows: z
          .number()
          .int()
          .min(1)
          .max(MAX_SEARCH_ROWS)
          .optional()
          .default(5000)
          .describe("Most rows read (1-10000, default 5000)"),
        offset: z.number().int().min(0).optional().default(0).describe("Rows to skip (devices when include_rows is false)"),
        limit: z
          .number()
          .int()
          .min(1)
          .max(1000)
          .optional()
          .default(100)
          .describe("Rows per response, or devices when include_rows is false (1-1000, default 100)"),
        refresh: z.boolean().optional().default(false).describe("Start new searches instead of reusing this hour's"),
        tenant_id: z.string().guid().optional().describe("Tenant ID. Required for partner/org callers."),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    withErrorHandling(async (args) => {
      const tenantId = tenantResolver.resolveTenantId(args.tenant_id);
      const schema: InventorySchema = args.schema;
      const filters: InventoryFilters = {
        endpointId: args.endpoint_id,
        hostname: args.hostname,
        softwareName: args.software_name,
        kb: args.kb,
      };
      const window = inventoryWindow(now(), args.days);
      const devicesQl = buildDevicesQl(schema, filters, window);
      const rowsQl = args.include_rows ? buildRowsQl(schema, filters, window) : null;
      const warnings: string[] = [];

      // Start both searches, then poll the ones still running.
      const started = await Promise.all(
        [devicesQl, rowsQl].map((text) => (text ? startSearch(fusionClient, tenantId, text, args.refresh) : null))
      );
      const searches = started.map((s) => s?.search ?? null);
      for (const s of started) if (s) warnings.push(...s.warnings);
      const deadline = Date.now() + waitMs;
      while (searches.some((s) => s && s.status !== "COMPLETE") && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
        for (const [i, s] of searches.entries()) {
          if (!s || s.status === "COMPLETE") continue;
          const polled = await fusionClient.query<{ search: FusionSearch | null }>(tenantId, GET_SEARCH, { urn: s.urn });
          warnings.push(...polled.warnings);
          if (polled.data.search) searches[i] = polled.data.search;
        }
      }
      const [devicesSearch, rowsSearch] = searches as [FusionSearch, FusionSearch | null];
      const urns = { devices: devicesSearch.urn, rows: rowsSearch?.urn ?? null };
      if (searches.some((s) => s && s.status !== "COMPLETE")) {
        return jsonResult(
          withWarnings(
            {
              tenant_id: tenantId,
              schema,
              status: "running",
              next_step:
                "The Data Lake searches are still running. Call again with the same arguments (refresh false) within this UTC hour: it picks up these searches instead of starting new ones.",
              window,
              searches: urns,
            },
            warnings
          )
        );
      }
      for (const [label, s] of [["device", devicesSearch], ["rows", rowsSearch]] as const) {
        if (!s) continue;
        const errors = [...s.outcome.errors.flatMap((e) => e.errors), ...s.errors];
        if (s.outcome.success === "NONE") {
          throw new Error(`The ${label} search failed${errors.length ? `: ${errors.join("; ")}` : ""}. Retry with refresh true.`);
        }
        if (s.outcome.success !== "ALL") {
          warnings.push(`The ${label} search completed with outcome ${s.outcome.success}${errors.length ? `: ${errors.join("; ")}` : ""}.`);
        }
      }

      const aggregate = await readResults(fusionClient, tenantId, devicesSearch.urn, MAX_SEARCH_ROWS, null);
      warnings.push(...aggregate.warnings);
      const devices = mergeDeviceAggregates(aggregate.rows);

      let rowsRead = 0;
      let snapshots = new Map<string, LatestSnapshot>();
      if (rowsSearch) {
        const read = await readResults(fusionClient, tenantId, rowsSearch.urn, args.max_rows, readFloor(devices.values()));
        warnings.push(...read.warnings);
        rowsRead = read.rows.length;
        snapshots = latestSnapshots(read.rows, read.readAll);
        // A device can appear in the rows and not the aggregate if a batch landed between the two searches.
        for (const [hostId, snapshot] of snapshots) {
          if (devices.has(hostId)) continue;
          const row = snapshot.rows[0];
          devices.set(hostId, {
            hostId,
            hostname: (pick(row, "device.hostname") as string | null) ?? null,
            sensorType: (row.sensor_type as string | null) ?? null,
            maxTime: snapshot.time,
            rowCount: snapshot.rows.length,
          });
        }
      }

      let lookedUp = true;
      let lastSeen = new Map<string, EndpointSeen>();
      try {
        lastSeen = await endpointLastSeen(sophosClient, tenantId, lookupIds(devices.keys()));
      } catch (error) {
        lookedUp = false;
        warnings.push(`Last seen lookup in the Endpoint API failed, so every device is unmatched: ${error instanceof Error ? error.message : String(error)}`);
      }

      const nowMs = now();
      const all = [...devices.values()].map((device) => {
        const record = lastSeen.get(device.hostId);
        const { status, daysSinceSeen } = classifyLastSeen(record?.lastSeenAt, nowMs, args.stale_after_days);
        const snapshot = snapshots.get(device.hostId);
        const os = snapshot ? pick(snapshot.rows[0], "device.os.name") : undefined;
        return {
          endpoint_id: device.hostId,
          hostname: device.hostname ?? record?.hostname ?? null,
          status,
          ...(status === "unmatched" ? { reason: unmatchedReason(device.hostId, lookedUp, record) } : {}),
          last_seen_at: record?.lastSeenAt ?? null,
          days_since_seen: daysSinceSeen,
          snapshot_time: msToIso(snapshot?.time ?? device.maxTime),
          sensor_type: device.sensorType,
          ...(rowsSearch
            ? {
                os: typeof os === "string" && os.trim() !== "" ? os.trim() : null,
                snapshot_rows: snapshot?.rows.length ?? 0,
                snapshot_complete: snapshot?.complete ?? false,
              }
            : {}),
        };
      });
      all.sort(compareDevices);

      const count = (status: DeviceStatus) => all.filter((d) => d.status === status).length;
      const incomplete = rowsSearch ? all.filter((d) => !d.snapshot_complete).length : 0;
      const notes: string[] = [];
      if (incomplete > 0) {
        notes.push(
          `${incomplete} device(s) have snapshot_complete false: their latest snapshot was not fully read within max_rows ${args.max_rows}. Raise max_rows (up to 10000) or narrow with endpoint_id, hostname, software_name or kb.`
        );
      }
      if (aggregate.rows.length >= MAX_SEARCH_ROWS) {
        notes.push("The device search stopped at its 10,000 row limit, so devices may be missing. Narrow the search.");
      }

      const selected = args.status === "all" ? all : all.filter((d) => d.status === args.status);
      const head = {
        tenant_id: tenantId,
        schema,
        window,
        stale_after_days: args.stale_after_days,
        last_seen_source: "Endpoint API lastSeenAt, matched on host_id = endpoint ID",
        summary: {
          devices: all.length,
          fresh: count("fresh"),
          stale: count("stale"),
          unmatched: count("unmatched"),
          rows_in_window: [...devices.values()].reduce((sum, d) => sum + d.rowCount, 0),
          ...(rowsSearch
            ? {
                rows_read: rowsRead,
                latest_snapshot_rows: [...snapshots.values()].reduce((sum, s) => sum + s.rows.length, 0),
                incomplete_devices: incomplete,
              }
            : {}),
        },
        ...(notes.length ? { notes } : {}),
        searches: urns,
        status_filter: args.status,
      };
      const paging = { offset: args.offset, limit: args.limit };

      if (!rowsSearch) {
        const page = selected.slice(args.offset, args.offset + args.limit);
        const next = args.offset + page.length < selected.length ? args.offset + page.length : null;
        return jsonResult(
          withWarnings({ ...head, total: selected.length, offset: args.offset, returned: page.length, next_offset: next, devices: page }, warnings),
          paging,
          "devices"
        );
      }

      // One flat list of rows, device by device in device order, each tagged with its device's status.
      const rows = selected.flatMap((device) =>
        sortRows(schema, (snapshots.get(device.endpoint_id)?.rows ?? []).map((row) => compactRow(schema, row))).map((row) => ({
          endpoint_id: device.endpoint_id,
          hostname: device.hostname,
          status: device.status,
          ...row,
        }))
      );
      const page = rows.slice(args.offset, args.offset + args.limit);
      const next = args.offset + page.length < rows.length ? args.offset + page.length : null;
      const onPage = new Set(page.map((row) => row.endpoint_id));
      return jsonResult(
        withWarnings(
          {
            ...head,
            total: rows.length,
            offset: args.offset,
            returned: page.length,
            next_offset: next,
            devices: selected.filter((device) => onPage.has(device.endpoint_id)),
            rows: page,
          },
          warnings
        ),
        paging,
        "rows"
      );
    })
  );
}
