/**
 * Endpoint inventory from the Fusion Data Lake: the QL for the softwareinfo,
 * patchstate and inventoryinfo schemas, the reduction to each device's latest
 * snapshot, and the stale flag from the Endpoint API's lastSeenAt.
 *
 * Measured on two tenants, 03/11/2026:
 * - host_id is the Endpoint API endpoint ID (sensor_id carries the same value),
 *   so it joins to lastSeenAt exactly. Hostnames do not: one tenant had five
 *   endpoint records named DC01, and a re-registered device keeps its old
 *   host_id rows under the same hostname as the new record.
 * - The snapshot rows have no last seen of their own: device.last_seen_time is
 *   null, and the Endpoint API record embedded in inventoryinfo's
 *   original_data has no lastSeenAt.
 * - A tenant writes one snapshot batch a day. Rows of one device's snapshot
 *   sit within a few milliseconds of each other; snapshots are a day apart.
 * - Snapshots keep coming for 30 days after a device was last seen (three
 *   devices on two tenants), rebuilt from its last report.
 * - Results come back newest first, and a search returns at most 10,000 rows
 *   (an aggregate counted 16,098 where the rows search stopped at 10,000).
 * - inventoryinfo also holds device_discovery events from the telemetry
 *   normalizer: another device the endpoint saw on its network, filed under
 *   the reporting endpoint's host_id. They are not snapshots, so the QL drops
 *   them.
 */

import { isUuid, qlString } from "./format.js";

export const INVENTORY_SCHEMAS = ["softwareinfo", "patchstate", "inventoryinfo"] as const;
export type InventorySchema = (typeof INVENTORY_SCHEMAS)[number];

/** The normalizer that files device_discovery events into inventoryinfo. */
export const DISCOVERY_NORMALIZER = "sophos-xdr-telemetry-normalizer";

/** Rows of one snapshot are milliseconds apart and snapshots a day apart. */
export const SNAPSHOT_SPREAD_MS = 10 * 60 * 1000;

/** A search returns at most this many rows. */
export const MAX_SEARCH_ROWS = 10_000;

export const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

/**
 * Leaf fields each schema's rows search projects. QL returns the whole parent
 * object of a nested leaf (all of device for device.hostname), and refuses
 * device.storage_volumes, so the volumes are read from the device object.
 */
const COMMON_FIELDS = ["host_id", "time", "sensor_type", "device.hostname", "device.os.name"];
const SCHEMA_FIELDS: Record<InventorySchema, string[]> = {
  softwareinfo: ["product.name", "product.version", "product.vendor_name", "install_time"],
  patchstate: ["kb_article.title", "kb_article.install_time", "actor.user.name"],
  inventoryinfo: [
    "device.os.version",
    "device.os.last_update_time",
    "device.boot_time",
    "device.domain",
    "device.type_id",
    "device.is_domain_controller",
    "device.mac",
    "device.ip",
  ],
};

export interface InventoryFilters {
  endpointId?: string;
  hostname?: string;
  softwareName?: string;
  kb?: string;
}

export interface InventoryWindow {
  earliest: string;
  latest: string;
}

/** Whole-second UTC ISO 8601, the absolute bound form QL takes. */
function isoSeconds(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Absolute bounds ending at the next whole UTC hour. getOrCreateSearch reuses
 * a search only for absolute bounds, so every call in the same hour gets the
 * same search: paging and a retry after a timeout cost nothing.
 */
export function inventoryWindow(now: number, days: number): InventoryWindow {
  const latest = Math.ceil(now / HOUR_MS) * HOUR_MS;
  return { earliest: isoSeconds(latest - days * DAY_MS), latest: isoSeconds(latest) };
}

/** The where clause and time bounds both searches share. */
function baseQl(schema: InventorySchema, filters: InventoryFilters, window: InventoryWindow): string {
  if (filters.softwareName !== undefined && schema !== "softwareinfo") {
    throw new Error("software_name filters softwareinfo only.");
  }
  if (filters.kb !== undefined && schema !== "patchstate") {
    throw new Error("kb filters patchstate only.");
  }
  const where = [`normalizer != ${qlString(DISCOVERY_NORMALIZER)}`];
  if (filters.endpointId !== undefined) where.push(`host_id = ${qlString(filters.endpointId)}`);
  if (filters.hostname !== undefined) where.push(`device.hostname contains ${qlString(filters.hostname)}`);
  if (filters.softwareName !== undefined) where.push(`product.name contains ${qlString(filters.softwareName)}`);
  if (filters.kb !== undefined) where.push(`kb_article.title contains ${qlString(filters.kb)}`);
  return `from ${schema} where ${where.join(" and ")} earliest='${window.earliest}' latest='${window.latest}'`;
}

/** One row per device and hostname: its newest row time and its row count. */
export function buildDevicesQl(schema: InventorySchema, filters: InventoryFilters, window: InventoryWindow): string {
  return `${baseQl(schema, filters, window)} | aggregate max(time), count by host_id, device.hostname, sensor_type`;
}

/** The rows, projected to the fields the tool returns. */
export function buildRowsQl(schema: InventorySchema, filters: InventoryFilters, window: InventoryWindow): string {
  return `${baseQl(schema, filters, window)} | fields ${[...COMMON_FIELDS, ...SCHEMA_FIELDS[schema]].join(", ")}`;
}

/** A field by its dotted name, from a flat key or the nested objects. */
export function pick(row: Record<string, unknown>, path: string): unknown {
  if (path in row) return row[path];
  let value: unknown = row;
  for (const part of path.split(".")) {
    if (value === null || typeof value !== "object") return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

function toNumber(value: unknown): number | null {
  const n = typeof value === "number" ? value : typeof value === "string" && value.trim() !== "" ? Number(value) : NaN;
  return Number.isFinite(n) ? n : null;
}

function str(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/** Epoch milliseconds to ISO 8601, or null. */
export function msToIso(value: unknown): string | null {
  const n = toNumber(value);
  return n === null || n <= 0 ? null : new Date(n).toISOString();
}

export interface InventoryDevice {
  hostId: string;
  hostname: string | null;
  sensorType: string | null;
  maxTime: number;
  rowCount: number;
}

/**
 * Merges the aggregate rows into one entry per host_id. A renamed device has
 * a row per hostname; the newest row names it.
 */
export function mergeDeviceAggregates(rows: Array<Record<string, unknown>>): Map<string, InventoryDevice> {
  const devices = new Map<string, InventoryDevice>();
  for (const row of rows) {
    const hostId = str(row.host_id);
    const maxTime = toNumber(row.max_time);
    if (!hostId || maxTime === null) continue;
    const count = toNumber(row.row_count) ?? 0;
    const hostname = str(row.device_hostname ?? pick(row, "device.hostname"));
    const sensorType = str(row.sensor_type);
    const known = devices.get(hostId);
    if (!known) {
      devices.set(hostId, { hostId, hostname, sensorType, maxTime, rowCount: count });
      continue;
    }
    known.rowCount += count;
    if (maxTime > known.maxTime || (maxTime === known.maxTime && !known.hostname)) {
      known.maxTime = maxTime;
      known.hostname = hostname ?? known.hostname;
      known.sensorType = sensorType ?? known.sensorType;
    }
  }
  return devices;
}

/**
 * The time below which every device's latest snapshot has been read: rows
 * come newest first, so once a row older than this arrives, reading can stop.
 */
export function readFloor(devices: Iterable<InventoryDevice>): number | null {
  let floor: number | null = null;
  for (const device of devices) {
    const start = device.maxTime - SNAPSHOT_SPREAD_MS;
    floor = floor === null ? start : Math.min(floor, start);
  }
  return floor;
}

export interface LatestSnapshot {
  /** The snapshot's newest row time, epoch milliseconds. */
  time: number;
  rows: Array<Record<string, unknown>>;
  /** Every row of the snapshot was read, so rows is the whole snapshot. */
  complete: boolean;
}

/**
 * Keeps each device's latest snapshot: its rows within SNAPSHOT_SPREAD_MS of
 * the device's newest row read. readAll says the search had no more rows. Rows
 * come newest first, so a device's snapshot is complete once a row older than
 * the snapshot was read; a device whose rows were not reached has no entry,
 * and one cut off part way has complete false.
 */
export function latestSnapshots(rows: Array<Record<string, unknown>>, readAll: boolean): Map<string, LatestSnapshot> {
  const newest = new Map<string, number>();
  let oldestRead = Infinity;
  for (const row of rows) {
    const hostId = str(row.host_id);
    const time = toNumber(row.time);
    if (!hostId || time === null) continue;
    oldestRead = Math.min(oldestRead, time);
    newest.set(hostId, Math.max(newest.get(hostId) ?? time, time));
  }
  const out = new Map<string, LatestSnapshot>();
  for (const row of rows) {
    const hostId = str(row.host_id);
    const time = toNumber(row.time);
    if (!hostId || time === null) continue;
    const newestTime = newest.get(hostId) as number;
    const start = newestTime - SNAPSHOT_SPREAD_MS;
    if (time < start) continue;
    let snapshot = out.get(hostId);
    if (!snapshot) {
      snapshot = { time: newestTime, rows: [], complete: readAll || oldestRead < start };
      out.set(hostId, snapshot);
    }
    snapshot.rows.push(row);
  }
  return out;
}

export type DeviceStatus = "fresh" | "stale" | "unmatched";

export interface LastSeen {
  status: DeviceStatus;
  daysSinceSeen: number | null;
}

/**
 * Stale when the endpoint was last seen more than staleAfterDays ago, fresh
 * otherwise, unmatched when there is no lastSeenAt to judge by.
 */
export function classifyLastSeen(lastSeenAt: string | null | undefined, now: number, staleAfterDays: number): LastSeen {
  const seen = lastSeenAt ? Date.parse(lastSeenAt) : NaN;
  if (!Number.isFinite(seen)) return { status: "unmatched", daysSinceSeen: null };
  const age = now - seen;
  return {
    status: age > staleAfterDays * DAY_MS ? "stale" : "fresh",
    daysSinceSeen: Math.round((age / DAY_MS) * 10) / 10,
  };
}

/** Endpoint API lookups take UUIDs only; anything else is a third-party ID. */
export function lookupIds(hostIds: Iterable<string>): string[] {
  return [...new Set([...hostIds].filter(isUuid))];
}

/** "KB5007651" from a patch title, or null. */
export function kbFromTitle(title: string | null): string | null {
  const match = title?.match(/\bKB\d{6,8}\b/i);
  return match ? match[0].toUpperCase() : null;
}

/** The fields the tool returns for one row of each schema. */
export function compactRow(schema: InventorySchema, row: Record<string, unknown>): Record<string, unknown> {
  if (schema === "softwareinfo") {
    return {
      name: str(pick(row, "product.name")),
      version: str(pick(row, "product.version")),
      vendor: str(pick(row, "product.vendor_name")),
      installed_at: msToIso(pick(row, "install_time")),
    };
  }
  if (schema === "patchstate") {
    const title = str(pick(row, "kb_article.title"));
    return {
      kb: kbFromTitle(title),
      title,
      installed_at: msToIso(pick(row, "kb_article.install_time")),
      installed_by: str(pick(row, "actor.user.name")),
    };
  }
  const volumes = pick(row, "device.storage_volumes");
  return {
    os: str(pick(row, "device.os.name")),
    os_version: str(pick(row, "device.os.version")),
    os_last_update_at: msToIso(pick(row, "device.os.last_update_time")),
    boot_time: msToIso(pick(row, "device.boot_time")),
    domain: str(pick(row, "device.domain")),
    device_type: str(pick(row, "device.type_id")),
    is_domain_controller: pick(row, "device.is_domain_controller") ?? null,
    mac: str(pick(row, "device.mac")),
    ip: str(pick(row, "device.ip")),
    storage_volumes: Array.isArray(volumes)
      ? volumes.map((v) => ({
          uid: str((v as Record<string, unknown>)?.uid),
          encryption_status: str((v as Record<string, unknown>)?.encryption_status_id),
        }))
      : null,
  };
}

const ROW_ORDER: Record<InventorySchema, string[]> = {
  softwareinfo: ["name", "version"],
  patchstate: ["kb", "title", "installed_at"],
  inventoryinfo: [],
};

/** A device's compact rows by name and version, or KB, title and install time; nulls last. */
export function sortRows<T extends Record<string, unknown>>(schema: InventorySchema, rows: T[]): T[] {
  const keys = ROW_ORDER[schema];
  return [...rows].sort((a, b) => {
    for (const key of keys) {
      const x = a[key];
      const y = b[key];
      if (x === y) continue;
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      const order = String(x).localeCompare(String(y), "en", { sensitivity: "base", numeric: true });
      if (order !== 0) return order;
    }
    return 0;
  });
}

const STATUS_ORDER: Record<DeviceStatus, number> = { stale: 0, unmatched: 1, fresh: 2 };

/** Stale first, then unmatched, then fresh; by hostname, then endpoint ID, within each. */
export function compareDevices(
  a: { status: DeviceStatus; hostname: string | null; endpoint_id: string },
  b: { status: DeviceStatus; hostname: string | null; endpoint_id: string }
): number {
  return (
    STATUS_ORDER[a.status] - STATUS_ORDER[b.status] ||
    (a.hostname ?? "").localeCompare(b.hostname ?? "", "en", { sensitivity: "base" }) ||
    a.endpoint_id.localeCompare(b.endpoint_id)
  );
}
