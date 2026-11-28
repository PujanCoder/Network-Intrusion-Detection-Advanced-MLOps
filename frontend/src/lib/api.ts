/**
 * Client for the unified NDR API served by `src.serving`.
 *
 * Authentication is a same-origin HttpOnly session cookie: the browser posts the
 * platform key once to /api/v1/session and never stores it. `credentials:
 * "same-origin"` is what carries the cookie on every read, including the
 * WebSocket upgrade.
 */

export class ApiError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export const UNAUTHORIZED_EVENT = "ndr:unauthorized";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
export type Source = "zeek" | "cicids";

export interface SeverityBand {
  severity: Severity;
  attack: boolean | null;
  min_confidence: number;
}

export interface SeverityPolicy {
  source: string;
  description: string;
  bands: SeverityBand[];
}

export interface DetectionModel {
  source: Source;
  name: string;
  schema: string | null;
  experimental: boolean;
}

export interface Detection {
  id: string;
  source: Source;
  ts: string | null;
  sensor_id: string | null;
  log_type: string | null;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  proto: string | null;
  service: string | null;
  conn_state: string | null;
  duration: number | null;
  orig_bytes: number | null;
  resp_bytes: number | null;
  orig_pkts: number | null;
  resp_pkts: number | null;
  label: string;
  is_attack: boolean;
  confidence: number | null;
  status: string;
  severity: Severity;
  severity_source: string;
  model: DetectionModel;
  explanation: string;
  probabilities?: Record<string, number> | null;
  raw?: Record<string, unknown>;
  reason?: string | null;
  event_severity?: string | null;
}

export interface DetectionPage {
  items: Detection[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
  sort: string;
  severity_policy: SeverityPolicy;
}

export interface ModelRuntime {
  predictions: number;
  scored: number;
  unclassified: number;
  last_inference_ts: string | null;
  label_counts: Record<string, number>;
}

export interface ModelInfo {
  key: Source;
  name: string;
  task: string;
  loaded: boolean;
  error: string | null;
  error_kind: string | null;
  estimator: string | null;
  version: string | null;
  trained_at: string | null;
  loaded_at: string | null;
  artifact: { path?: string; exists?: boolean; bytes?: number | null; sha256?: string } | null;
  schema: {
    schema_version: string | null;
    features: number | null;
    model_features: number | null;
    feature_names: string[] | null;
    threshold?: number | null;
  };
  classes: string[] | null;
  experimental: boolean;
  notes: string[];
  runtime: ModelRuntime;
  latency: { available: boolean; reason: string };
}

export interface SeriesPoint {
  t: number;
  events: number;
  predictions: number;
  attacks: number;
  bytes: number;
}

export interface DistributionItem {
  label: string;
  count: number;
}

export interface IpCount {
  ip: string;
  count: number;
}

export interface BucketCount {
  bucket: string;
  count: number;
}

export interface SensorRow {
  sensor_id: string;
  status: "online" | "offline" | "unknown";
  status_reason: string;
  seconds_since_ingest: number | null;
  last_seen_ts: string | null;
  last_ingested_at: string | null;
  last_error: string | null;
  events: number;
  detections: number;
  scored: number;
  unclassified: number;
  attacks: number;
  duplicates: number;
  dead_letters: number;
  is_local_ingestion?: boolean;
}

export interface Overview {
  generated_at: string;
  server_time: number;
  window_s: number;
  bucket_s: number;
  app: { name: string; version: string; build: { commit: string | null; branch: string | null; service: string | null } };
  totals: {
    events: number;
    detections: number;
    attacks: number;
    benign: number;
    scored: number;
    unclassified: number;
    detection_rate: number | null;
    dead_letters: number;
    by_source: Record<string, number>;
    by_log_type: Record<string, number>;
    last_detection_ts: string | null;
  };
  rates: { window_s: number; events_per_second: number; attacks_per_second: number };
  activity: {
    last_event_ts: string | null;
    seconds_since_event: number | null;
    last_detection_ts: string | null;
    no_new_events: boolean;
    message: string;
  };
  sensors: {
    total: number;
    online: number;
    offline: number;
    unknown: number;
    stale_after_s: number;
    items: SensorRow[];
  };
  models: Record<Source, ModelInfo>;
  severity_policy: SeverityPolicy;
  series: SeriesPoint[];
  distributions: {
    labels: DistributionItem[];
    protocols: DistributionItem[];
    severities: DistributionItem[];
    log_types: DistributionItem[];
    sources: DistributionItem[];
    confidence: BucketCount[];
    top_src_ips: IpCount[];
    top_dst_ips: IpCount[];
  };
  recent: Detection[];
}

export interface LiveFeed {
  generated_at: string;
  server_time: number;
  records: Detection[];
  total: number;
  last_event_ts: string | null;
  seconds_since_event: number | null;
  no_new_events: boolean;
  activity_message: string | null;
  websocket: { clients: number; max_clients: number; broadcasts: number; rejected_clients: number; available: boolean };
}

export interface SensorPayload {
  generated_at: string;
  stale_after_s: number;
  summary: { total: number; online: number; offline: number; unknown: number; events: number; dead_letters: number };
  sensors: SensorRow[];
  ingestion: Record<string, unknown>;
  expected: {
    sensor_id: string;
    mode: string;
    local_ingestion_enabled: boolean;
    log_dir: string;
    log_types: string[];
  };
  counters: { events: number; by_log_type: Record<string, number>; dead_letters: number; last_event_ts: string | null };
}

export interface SystemStatus {
  generated_at: string;
  server_time: number;
  status: string;
  degraded_components: string[];
  app: { name: string; version: string };
  build: { commit: string | null; branch: string | null; service: string | null };
  uptime_s: number;
  components: Record<string, Record<string, any>>;
  database: { path: string; exists: boolean; integrity: string; events?: number; detections?: number };
  websocket: { clients: number; max_clients: number; broadcasts: number; rejected_clients: number; available: boolean };
  auth: Record<string, any>;
  endpoints: Record<string, string>;
}

export interface SessionState {
  configured: boolean;
  authenticated: boolean;
  method: "session" | "api_key" | null;
  expires_at: number | null;
  session_ttl_s?: number;
  source?: string | null;
}

export type QueryValue = string | number | boolean | null | undefined;

export function buildQuery(params: Record<string, QueryValue>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers },
  });

  if (!response.ok) {
    let code: string | undefined;
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      const detail = body?.detail;
      if (typeof detail === "string") message = detail;
      else if (detail && typeof detail === "object") {
        message = detail.message ?? message;
        code = detail.code;
      }
    } catch {
      /* non-JSON error body (proxy page) */
    }
    if (response.status === 401) window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    throw new ApiError(message, response.status, code);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export interface DetectionQuery {
  limit?: number;
  offset?: number;
  source?: Source | null;
  label?: string | null;
  severity?: Severity | null;
  status?: "scored" | "unclassified" | null;
  sensor_id?: string | null;
  model?: Source | null;
  q?: string | null;
  start?: string | null;
  end?: string | null;
  only_attacks?: boolean;
  sort?: "ts_desc" | "ts_asc";
}

export const api = {
  session: () => request<SessionState>("/api/v1/session"),
  login: (apiKey: string) =>
    request<{ authenticated: boolean; method: string; expires_at: number }>("/api/v1/session", {
      method: "POST",
      body: JSON.stringify({ api_key: apiKey }),
    }),
  logout: () => request<{ authenticated: boolean }>("/api/v1/session", { method: "DELETE" }),
  overview: (windowS = 3600) => request<Overview>(`/api/v1/metrics/overview${buildQuery({ window: windowS })}`),
  live: (limit = 100) => request<LiveFeed>(`/api/v1/metrics/live${buildQuery({ limit })}`),
  detections: (query: DetectionQuery) => request<DetectionPage>(`/api/v1/detections${buildQuery({ ...query })}`),
  detection: (id: string) => request<Detection>(`/api/v1/detections/${encodeURIComponent(id)}`),
  exportUrl: (query: DetectionQuery) => `/api/v1/detections/export${buildQuery({ ...query })}`,
  sensors: () => request<SensorPayload>("/api/v1/sensors"),
  models: () => request<{ generated_at: string; models: Record<Source, ModelInfo>; severity_policy: SeverityPolicy; counts: Record<string, unknown> }>("/api/v1/models/status"),
  system: () => request<SystemStatus>("/api/v1/system/status"),
  health: () => request<Record<string, any>>("/api/v1/health"),
};

export function wsUrl(): string {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${window.location.host}/ws/alerts`;
}
