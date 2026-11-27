/**
 * Typed client for the NDR REST/WebSocket API.
 *
 * The shapes mirror the payloads produced by `src/api/routes.py` and
 * `src/realtime/store.py`; keep them in sync when the backend changes.
 */

export interface Alert {
  rule: string;
  category: string;
  severity: string;
  confidence: number | null;
  explanation: string;
  evidence: Record<string, unknown>;
  created_at: number;
}

export interface NetworkEvent {
  id: number;
  event_uid: string;
  ts: number;
  iso_time?: string;
  ingested_at: number;
  log_type: string;
  sensor: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  proto: string | null;
  service: string | null;
  conn_state: string | null;
  duration: number | null;
  orig_bytes: number | null;
  resp_bytes: number | null;
  orig_pkts: number | null;
  resp_pkts: number | null;
  orig_ip_bytes: number | null;
  resp_ip_bytes: number | null;
  prediction: string | null;
  confidence: number | null;
  severity: string | null;
  is_malicious: boolean | null;
  explanation: string | null;
  latency_ms: number | null;
  model_name: string | null;
  model_version: string | null;
  prediction_error?: string | null;
  threshold: number | null;
  raw: Record<string, unknown>;
  alerts?: Alert[];
}

export interface EventPage {
  items: NetworkEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface WebsocketStatus {
  clients: number;
  max_clients: number;
  dropped_messages: number;
  rejected_clients: number;
}

export interface OverviewModel {
  name: string;
  version: string;
  loaded: boolean;
  load_error: string | null;
  threshold: number | null;
  trained_at: string | null;
  training_datasets: Record<string, number> | null;
}

export interface OverviewSensor {
  sensor_id: string;
  mode: string;
  replay_records: number;
  ingestion_running: boolean;
  log_dir_exists: boolean;
  log_file_count: number;
  seconds_since_event: number | null;
  last_error: string | null;
}

export interface Overview {
  total_events: number;
  total_predictions: number;
  attacks: number;
  benign: number;
  suspicious: number;
  unclassified: number;
  critical_alerts: number;
  critical_detections: number;
  total_alerts: number;
  dead_letters: number;
  model_errors: number;
  events_per_second: number;
  predictions_per_second: number;
  events_per_second_live?: number;
  predictions_per_second_live?: number;
  burst_window_s?: number;
  avg_prediction_latency_ms: number | null;
  last_event_ts: number | null;
  last_ingest_ts: number | null;
  seconds_since_last_event: number | null;
  window_s: number;
  generated_at: number;
  no_new_events?: boolean;
  model?: OverviewModel;
  sensor?: OverviewSensor;
  websocket?: WebsocketStatus;
}

export interface SeriesPoint {
  t: number;
  events: number;
  predictions: number;
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

export interface Analytics {
  window_s: number;
  generated_at: number;
  series: SeriesPoint[];
  attack_distribution: DistributionItem[];
  protocol_distribution: DistributionItem[];
  severity_distribution: DistributionItem[];
  top_src_ips: IpCount[];
  top_dst_ips: IpCount[];
  confidence_histogram: BucketCount[];
  prediction_counts: Record<string, number>;
}

export interface ModelMetrics {
  support: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  false_positive_rate: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  confusion_matrix?: number[][] | null;
}

export interface MetricsBundle {
  binary?: ModelMetrics | null;
  multiclass?: { macro_f1?: number | null } | null;
}

export interface LiveMetrics {
  validation?: MetricsBundle | null;
  test?: MetricsBundle | null;
  official_test_partitions?: Record<string, MetricsBundle>;
  cross_dataset?: {
    unseen_dataset: string;
    trained_on: string[];
    metrics: {
      binary: ModelMetrics;
      multiclass?: { macro_f1?: number | null } | null;
    };
  } | null;
}

export interface FeatureImportance {
  feature: string;
  importance: number;
}

export interface LiveModel {
  kind: string;
  name: string;
  version: string;
  algorithm?: string | null;
  trained_at?: string | null;
  loaded: boolean;
  load_error: string | null;
  artifact_path?: string;
  threshold: number | null;
  target_false_positive_rate?: number | null;
  training_datasets?: Record<string, number> | null;
  dataset_distribution?: Record<string, unknown> | null;
  row_counts?: { train: number; validation: number; test: number } | null;
  label_distribution?: Record<string, number> | null;
  classes?: string[] | null;
  feature_schema?: string[] | null;
  top_features?: FeatureImportance[] | null;
  metrics: LiveMetrics;
  latency?: Record<string, unknown> | null;
  candidates?: Record<string, { validation_macro_f1: number }> | null;
  environment?: { python?: string; numpy?: string; pandas?: string } | null;
  notes: string[];
}

export interface LatencyPercentiles {
  count: number;
  avg_ms: number | null;
  p50_ms: number | null;
  p95_ms: number | null;
  max_ms: number | null;
}

export interface RuntimeInfo {
  predictions: number;
  prediction_count_by_label: Record<string, number>;
  unclassified_events: number;
  total_events: number;
  model_errors: number;
  dead_letters: number;
  avg_prediction_latency_ms: number | null;
  latency_percentiles: LatencyPercentiles;
  confidence_histogram: BucketCount[];
  predictions_per_second: number;
}

export interface BatchModel {
  kind: string;
  name: string;
  task: string;
  best_model: string | null;
  training_results_available: boolean;
  evaluation_results_available: boolean;
  validation_metrics: Record<string, { f1_score?: number; f1?: number; accuracy?: number }>;
  test_metrics: Record<string, number | string>;
  confusion_matrix?: number[][] | null;
  notes: string[];
}

export interface ModelInfo {
  live_model: LiveModel;
  runtime: RuntimeInfo;
  batch_model: BatchModel;
}

export interface ReaderInfo {
  log_dir: string;
  log_dir_exists: boolean;
  log_file_count: number;
  files_tracked: number;
  rotations: number;
  truncations: number;
  unparsed_lines: number;
}

export interface SensorStatus {
  sensor_id: string;
  sensor_mode: string;
  replay_records: number;
  ingestion_running: boolean;
  ingest_enabled: boolean;
  poll_interval_s: number;
  counters: Record<string, number>;
  last_poll_at: number | null;
  last_event_at: number | null;
  seconds_since_event: number | null;
  last_error: string | null;
  reader: ReaderInfo;
  detectors: { rules: string[] };
}

export interface IngestionStateRow {
  source_file: string;
  offset: number | null;
  size: number | null;
  updated_at: number | null;
  seconds_since_update: number | null;
}

export interface DatabaseStatus {
  path: string;
  size_bytes: number;
  integrity: string;
  events: number;
  journal_mode: string;
}

export interface ProcessingDelay {
  avg_delay_s: number | null;
  max_delay_s: number | null;
  samples: number;
}

export interface SensorsInfo {
  sensor: SensorStatus;
  ingestion_state: IngestionStateRow[];
  database: DatabaseStatus;
  api: { status: string; uptime_s: number; version: string };
  websocket: WebsocketStatus;
  model: { loaded: boolean; name: string; version: string; load_error: string | null };
  processing_delay: ProcessingDelay;
  dead_letters: number;
  server_time: number;
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

function apiKey(): string {
  return import.meta.env.VITE_API_KEY ?? "";
}

export async function getJson<T = unknown>(path: string): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const key = apiKey();
  if (key) headers["X-API-Key"] = key;

  const response = await fetch(path, { headers });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} (${path})`);
  }
  return (await response.json()) as T;
}

export function wsUrl(): string {
  const base =
    import.meta.env.VITE_WS_URL ??
    `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/api/ws`;
  const key = apiKey();
  if (!key) return base;
  return `${base}${base.includes("?") ? "&" : "?"}api_key=${encodeURIComponent(key)}`;
}
