import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { DonutChart, RateChart } from "../components/Charts";
import { EventTable, useMergedEvents } from "../components/EventTable";
import { EventDrawer } from "../components/EventDrawer";
import { EmptyState, Panel, Pill, StatCard } from "../components/ui";
import type { Analytics, NetworkEvent } from "../lib/api";
import { getJson } from "../lib/api";
import { useLive } from "../lib/LiveContext";
import { formatDateTime, formatNumber, relativeSeconds } from "../lib/format";
import { usePolled } from "../lib/usePolled";

export function OverviewPage() {
  const live = useLive();
  const [selected, setSelected] = useState<NetworkEvent | null>(null);
  const analytics = usePolled<Analytics>(() => getJson<Analytics>("/api/analytics?window=900"), 5000);
  const recent = usePolled<{ items: NetworkEvent[] }>(() => getJson<{ items: NetworkEvent[] }>("/api/events?limit=12"), 8000);

  const overview = live.overview;
  const merged = useMergedEvents(live.events, recent.data?.items ?? [], 12);

  const trafficMix = useMemo(() => {
    if (!overview) return [];
    return [
      { label: "Benign", count: overview.benign },
      { label: "Attacks", count: overview.attacks },
      { label: "Suspicious", count: overview.suspicious },
      { label: "Unclassified", count: overview.unclassified },
    ];
  }, [overview]);

  const idle = overview?.no_new_events ?? true;
  const zeekCapturing =
    (live.overview?.sensor?.log_dir_exists ?? false) && (live.overview?.sensor?.log_file_count ?? 0) > 0;
  const remoteIngest = overview?.sensor?.remote_ingest_enabled ?? false;
  const ingestionLabel = overview?.sensor?.ingestion_running
    ? "ingestion running"
    : remoteIngest
      ? "remote ingestion ready"
      : "ingestion stopped";
  const ingestionOk = (overview?.sensor?.ingestion_running ?? false) || remoteIngest;
  const captureLabel = zeekCapturing ? "capture active" : remoteIngest ? "remote sensor" : "no log files";

  return (
    <>
      {(overview?.sensor?.replay_records ?? 0) > 0 && (
        <div className="banner">
          <strong>Replay data detected.</strong>
          <span>
            {formatNumber(overview?.sensor?.replay_records)} events came from the held-out replay harness,
            not a live capture interface. Start Zeek with scripts/zeek_live.sh for live traffic.
          </span>
        </div>
      )}

      {idle && (
        <div className="banner">
          <strong>No new network events received.</strong>
          <span>
            The sensor is {live.connected ? "connected" : "reconnecting"} and ingestion is
            {" "}
            {overview?.sensor?.ingestion_running ? "running" : remoteIngest ? "waiting for sensor pushes" : "stopped"}. Last event{" "}
            {relativeSeconds(overview?.seconds_since_last_event)}. Nothing is fabricated while the
            network is quiet.
          </span>
        </div>
      )}

      <div className="grid cols-4">
        <StatCard
          label="Total network events"
          value={formatNumber(overview?.total_events)}
          foot={`${formatNumber(overview?.total_predictions)} predictions · ${formatNumber(overview?.unclassified)} unclassified`}
          accent="cyan"
        />
        <StatCard
          label="Events / second"
          value={overview ? (overview.events_per_second_live ?? overview.events_per_second).toFixed(2) : "—"}
          foot={`${overview?.burst_window_s ?? 10}s window · ${overview?.events_per_second.toFixed(2) ?? "—"}/s over ${overview?.window_s ?? 300}s`}
          accent="violet"
        />
        <StatCard
          label="Predictions / second"
          value={overview ? (overview.predictions_per_second_live ?? overview.predictions_per_second).toFixed(2) : "—"}
          foot={`avg inference ${overview?.avg_prediction_latency_ms?.toFixed(2) ?? "—"} ms`}
          accent="violet"
        />
        <StatCard
          label="Detected attacks"
          value={formatNumber(overview?.attacks)}
          foot={`${formatNumber(overview?.suspicious)} suspicious · ${formatNumber(overview?.critical_alerts)} critical alerts`}
          accent="red"
        />
      </div>

      <div className="grid cols-4">
        <StatCard label="Benign events" value={formatNumber(overview?.benign)} accent="green" />
        <StatCard label="Suspicious events" value={formatNumber(overview?.suspicious)} accent="amber" />
        <StatCard label="Unclassified" value={formatNumber(overview?.unclassified)} accent="orange" />
        <StatCard
          label="Critical detections"
          value={formatNumber(overview?.critical_detections ?? overview?.critical_alerts)}
          foot={`${formatNumber(overview?.critical_alerts)} critical rule alerts · ${formatNumber(overview?.total_alerts)} alerts total`}
          accent="red"
        />
      </div>

      <div className="grid cols-3">
        <Panel title="Sensor" hint="Zeek capture">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
            <Pill text={captureLabel} tone={zeekCapturing || remoteIngest ? "ok" : "warn"} />
            <Pill text={overview?.sensor?.mode ?? "unknown"} tone="info" />
            <Pill text={ingestionLabel} tone={ingestionOk ? "ok" : "bad"} />
          </div>
          <dl className="kv">
            <dt>Sensor ID</dt>
            <dd className="mono">{overview?.sensor?.sensor_id ?? "—"}</dd>
            <dt>Log directory</dt>
            <dd className="mono">
              {live.overview?.sensor?.log_dir_exists ? "present" : remoteIngest ? "remote push" : "missing"}
            </dd>
            <dt>Log files</dt>
            <dd className="mono">{formatNumber(overview?.sensor?.log_file_count ?? 0)}</dd>
            <dt>Last event</dt>
            <dd className="mono">{formatDateTime(overview?.last_event_ts)}</dd>
            <dt>Seconds since</dt>
            <dd className="mono">{overview?.seconds_since_last_event ?? "—"}</dd>
            <dt>Sensor error</dt>
            <dd className="mono">{overview?.sensor?.last_error ?? "none"}</dd>
          </dl>
        </Panel>

        <Panel title="Current model" hint="Live classifier">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
            <Pill
              text={overview?.model?.loaded ? "model loaded" : "model unavailable"}
              tone={overview?.model?.loaded ? "ok" : "bad"}
            />
            <Pill text={`threshold ${overview?.model?.threshold ?? "—"}`} tone="info" />
          </div>
          <dl className="kv">
            <dt>Name</dt>
            <dd className="mono">{overview?.model?.name ?? "—"}</dd>
            <dt>Version</dt>
            <dd className="mono">{overview?.model?.version ?? "—"}</dd>
            <dt>Trained</dt>
            <dd className="mono">{overview?.model?.trained_at ?? "—"}</dd>
            <dt>Datasets</dt>
            <dd className="mono">
              {overview?.model?.training_datasets
                ? Object.entries(overview.model.training_datasets).map(([name, rows]) => `${name} (${formatNumber(rows)})`).join(", ")
                : "—"}
            </dd>
            <dt>Model errors</dt>
            <dd className="mono">{formatNumber(overview?.model_errors)}</dd>
            <dt>Dead letters</dt>
            <dd className="mono">{formatNumber(overview?.dead_letters)}</dd>
          </dl>
        </Panel>

        <Panel title="Traffic mix" hint="All processed events">
          <DonutChart
            data={trafficMix}
            colors={["#31d39b", "#ff5b6e", "#f3b23f", "#7c90aa"]}
            height={220}
            emptyLabel="No events yet"
          />
        </Panel>
      </div>

      <Panel
        title="Network events per second"
        hint={
          <>
            last 15 minutes ·{" "}
            <Link to="/analytics" style={{ color: "var(--cyan)" }}>
              full analytics →
            </Link>
          </>
        }
      >
        {analytics.error && <div className="error-box">{analytics.error}</div>}
        <RateChart series={analytics.data?.series ?? []} />
      </Panel>

      <Panel
        title="Latest predictions"
        hint={
          <>
            live WebSocket stream ·{" "}
            <Link to="/stream" style={{ color: "var(--cyan)" }}>
              open stream →
            </Link>
          </>
        }
      >
        {merged.length ? (
          <EventTable events={merged} onSelect={setSelected} flashNew={false} />
        ) : (
          <EmptyState
            title="No new network events received."
            detail="Rows appear automatically when Zeek appends a record to its JSON logs."
          />
        )}
      </Panel>

      <EventDrawer event={selected} onClose={() => setSelected(null)} />
    </>
  );
}
