/**
 * TypeScript type definitions for Sophos Central API responses.
 */

// --- Auth ---

export interface SophosTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  errorCode?: string;
  message?: string;
}

// --- Whoami ---

export type SophosIdType = "partner" | "organization" | "tenant";

export interface SophosWhoamiResponse {
  id: string;
  idType: SophosIdType;
  apiHosts: {
    global: string;
    dataRegion?: string;
  };
}

// --- Tenants ---

export interface SophosTenant {
  id: string;
  name: string;
  dataGeography: string;
  dataRegion: string;
  billingType: string;
  apiHost: string;
  status?: string;
  partner?: { id: string };
  organization?: { id: string };
}

export interface SophosTenantPage {
  pages: {
    current: number;
    size: number;
    total: number;
    maxSize: number;
  };
  items: SophosTenant[];
}

// --- Alerts ---

export interface SophosAlert {
  id: string;
  allowedActions: string[];
  category: string;
  description: string;
  groupKey: string;
  managedAgent?: {
    id: string;
    type: string;
  };
  person?: {
    id: string;
  };
  product: string;
  raisedAt: string;
  severity: string;
  tenant: {
    id: string;
    name?: string;
  };
  type: string;
}

export interface SophosAlertPage {
  pages: {
    current?: number;
    size: number;
    total?: number;
    maxSize: number;
    items?: number;
    fromKey?: string;
    nextKey?: string;
  };
  items: SophosAlert[];
}

// --- Endpoints ---

export interface SophosEndpoint {
  id: string;
  type: string;
  tenant: { id: string };
  hostname: string;
  health: {
    overall: string;
    threats: { status: string };
    services: {
      status: string;
      serviceDetails?: Array<{
        name: string;
        status: string;
      }>;
    };
  };
  os: {
    isServer: boolean;
    platform: string;
    name: string;
    majorVersion: number;
    minorVersion: number;
    build?: number;
  };
  ipv4Addresses?: string[];
  ipv6Addresses?: string[];
  macAddresses?: string[];
  associatedPerson?: {
    name?: string;
    viaLogin?: string;
    id?: string;
  };
  tamperProtectionEnabled: boolean;
  assignedProducts?: Array<{
    code: string;
    version: string;
    status: string;
  }>;
  lastSeenAt?: string;
  groupId?: string;
  groupName?: string;
  lockdown?: {
    status: string;
  };
  isolation?: {
    status: string;
  };
}

export interface SophosEndpointPage {
  pages: {
    fromKey?: string;
    nextKey?: string;
    size: number;
    maxSize: number;
    total?: number;
    current?: number;
    items?: number;
  };
  items: SophosEndpoint[];
}

// --- Account Health Check ---

export interface SophosHealthCheck {
  endpoint: {
    protection: {
      computer: { percentage: number; status: string };
      server?: { percentage: number; status: string };
    };
    policy?: Record<string, unknown>;
    exclusions?: Record<string, unknown>;
    tamperProtection?: Record<string, unknown>;
  };
}

// --- Cases ---

export interface SophosCase {
  id: string;
  type: string;
  name: string;
  severity: string;
  status: string;
  assignee?: string;
  overview?: string;
  tenant: { id: string };
  managedBy?: string;
  createdAt: string;
  createdBy?: { id?: string; name?: string; email?: string };
  updatedAt?: string;
  detectionCount?: number;
  initialDetection?: { id: string };
}

export interface SophosCasePage {
  pages: {
    current: number;
    size: number;
    total: number;
    maxSize: number;
  };
  items: SophosCase[];
}

export interface SophosCaseDetection {
  id: string;
  attackType?: string;
  detectionDescription?: string;
  detectionRule?: string;
  sensorGeneratedAt?: string;
  severity?: number;
  device?: { id: string; type: string; entity?: string };
  sensor?: { id: string; type: string; source?: string };
}

export interface SophosCaseDetectionPage {
  pages: {
    current?: number;
    size: number;
    total?: number;
    maxSize: number;
    items?: number;
  };
  items: SophosCaseDetection[];
}

export interface SophosCaseMitreSummary {
  tactics: Array<{
    id: string;
    name: string;
    techniques: Array<{ id: string; name: string; count: number }>;
  }>;
}

// --- Detections ---

export interface SophosQueryRun {
  id: string;
  createdAt: string;
  result: "notAvailable" | "succeeded" | "failed";
  status: "pending" | "finished";
  finishedAt?: string;
  expiresAt?: string;
}

export interface SophosDetection {
  id: string;
  attackType?: string;
  caseDescription?: string;
  detectionDescription?: string;
  detectionRule?: string;
  sensorGeneratedAt?: string;
  severity?: number;
  sensor?: { id: string; type: string; source?: string; version?: string };
  device?: { id: string; type: string; entity?: string };
  detectionAttack?: Record<string, unknown>;
}

export interface SophosDetectionsResultPage {
  pages: {
    current?: number;
    size: number;
    total?: number;
    maxSize: number;
    items?: number;
  };
  items: SophosDetection[];
}

// --- SIEM ---

export interface SophosSiemEvent {
  id: string;
  type: string;
  name: string;
  severity?: string;
  when: string;
  created_at?: string;
  source?: string;
  user_id?: string;
  location?: string;
  data?: Record<string, unknown>;
}

export interface SophosSiemResponse {
  items: SophosSiemEvent[];
  next_cursor: string;
  has_more: boolean;
}

// --- XDR Query ---

export interface SophosXdrQueryResultsPage {
  items: Record<string, unknown>[];
  metadata?: {
    columns: Array<{ name: string; type: string }>;
  };
  pages: {
    fromKey?: string;
    nextKey?: string;
    size: number;
    maxSize: number;
    total?: number | null;
  };
}

// --- Live Discover ---

export interface SophosLiveDiscoverQuery {
  id: string;
  name: string;
  code?: string;
  description?: string;
  template?: string;
}

export interface SophosLiveDiscoverQueryPage {
  pages: {
    current?: number;
    size: number;
    total?: number;
    maxSize: number;
  };
  items: SophosLiveDiscoverQuery[];
}

export interface SophosLiveDiscoverRun {
  id: string;
  status: string;
  template?: string;
  performance?: Record<string, unknown>;
  endpointCounts?: Record<string, number>;
  createdAt?: string;
  finishedAt?: string;
}

export interface SophosLiveDiscoverResultsPage {
  items: Record<string, unknown>[];
  pages: {
    fromKey?: string;
    nextKey?: string;
    size: number;
    maxSize: number;
    total?: number | null;
  };
}

// --- Generic Error ---

export interface SophosApiError {
  error: string;
  message: string;
  correlationId?: string;
  code?: string;
  createdAt?: string;
  requestId?: string;
  docUrl?: string;
}

// --- Generic paginated response wrapper ---

export interface SophosPagedResponse<T> {
  pages: {
    current?: number;
    size: number;
    total?: number;
    maxSize: number;
    items?: number;
    fromKey?: string;
    nextKey?: string;
  };
  items: T[];
}
