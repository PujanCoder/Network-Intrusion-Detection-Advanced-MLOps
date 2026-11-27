import { EmptyState, KeyValue, Panel, Pill, StatCard } from "../components/ui";
import type { SensorsInfo } from "../lib/api";
import { getJson } from "../lib/api";
import { useLive } from "../lib/LiveContext";
import { formatBytes, formatDateTime, formatNumber, relativeSeconds } from "../lib/format";
import { usePolled } from "../lib/usePolled";

export function SensorsPage() {
  const live = useLive();
  const sensors = usePolled<SensorsInfo>(() => getJson<SensorsInfo>("/api/sensors"), 3000);
  const data = sensors.data;

  if (sensors.loading && !data) return <div className="loading">Reading sensor state…</div>;
  if (sensors.error && !data) return <div className="error-box">{sensors.error}</div>;
  if (!data) return <EmptyState title="Sensor state unavailable" />;

  const sensor = data.sensor;
  const reader = sensor?.reader;
  const capturing = (reader?.log_file_count ?? 0) > 0 && (reader?.log_dir_exists ?? false);
  const replayRecords = Number(sensor?.counters?.replay_records ?? 0);
  const replayMode = sensor?.sensor_mode === "replay" || replayRecords > 0;

  return (
    <>
      <div className="grid cols-4">
        <StatCard
          label="Zeek capture"
          value={capturing ? "receiving" : "idle"}
          foot={`${reader?.log_file_count ?? 0} log files · ${reader?.rotations ?? 0} rotations`}
          accent={capturing ? "green" : "amber"}
          small
        />
        <StatCard
          label="Ingestion"
          value={sensor?.ingestion_running ? "running" : "stopped"}
          foot={`poll ${sensor?.poll_interval_s ?? "—"}s · mode ${sensor?.sensor_mode ?? "—"}`}
          accent={sensor?.ingestion_running ? "green" : "red"}
          small
        />
        <StatCard
          label="Database"
          value={data.database.integrity === "ok" ? "healthy" : "check"}
          foot={`${formatBytes(data.database.size_bytes)} · ${formatNumber(data.database.events)} events`}
          accent={data.database.integrity === "ok" ? "green" : "red"}
          small
        />
        <StatCard
          label="WebSocket clients"
          value={formatNumber(data.websocket.clients)}
          foot={`${formatNumber(data.websocket.dropped_messages)} dropped · ${formatNumber(data.websocket.rejected_clients)} rejected`}
          accent="violet"
          small
        />
      </div>

      {replayMode && (
        <div className="banner">
          <strong>Replay data detected.</strong>
          <span>
            {formatNumber(replayRecords)} records carry the replay marker, so this traffic comes from the
            held-out replay harness, not from a live capture interface.
          </span>
        </div>
      )}

      <div className="grid cols-3">
        <Panel title="Zeek sensor" hint="log reader">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
            <Pill text={capturing ? "logs present" : "no logs"} tone={capturing ? "ok" : "warn"} />
            <Pill text={sensor?.sensor_mode ?? "unknown"} tone={sensor?.sensor_mode === "live" && !replayRecords ? "ok" : "warn"} />
            {replayRecords > 0 && <Pill text={`${formatNumber(replayRecords)} replay records`} tone="warn" />}
            <Pill text={sensor?.ingest_enabled ? "ingest enabled" : "ingest disabled"} tone={sensor?.ingest_enabled ? "info" : "bad"} />
          </div>
          <KeyValue
            rows={[
              ["Sensor ID", <span className="mono">{sensor?.sensor_id ?? "—"}</span>],
              ["Log directory", <span className="mono">{reader?.log_dir ?? "—"}</span>],
              ["Directory exists", <span className="mono">{String(reader?.log_dir_exists ?? false)}</span>],
              ["Tracked files", <span className="mono">{formatNumber(reader?.files_tracked ?? 0)}</span>],
              ["Rotations handled", <span className="mono">{formatNumber(reader?.rotations ?? 0)}</span>],
              ["Truncations handled", <span className="mono">{formatNumber(reader?.truncations ?? 0)}</span>],
              ["Unparsed lines", <span className="mono">{formatNumber(reader?.unparsed_lines ?? 0)}</span>],
              ["Last event", <span className="mono">{formatDateTime(sensor?.last_event_at)}</span>],
              ["Since last event", <span className="mono">{relativeSeconds(sensor?.seconds_since_event)}</span>],
              ["Last error", <span className="mono">{sensor?.last_error ?? "none"}</span>],
            ]}
          />
        </Panel>

        <Panel title="Processing pipeline" hint="counters since start">
          <KeyBar counters={sensor?.counters ?? {}} />
          <div style={{ marginTop: 14 }}>
            <KeyValue
              rows={[
                [
                  "Event → DB delay",
                  <span className="mono">
                    {data.processing_delay.avg_delay_s !== null ? `${(data.processing_delay.avg_delay_s * 1000).toFixed(1)} ms avg` : "—"}{" "}
                    {data.processing_delay.max_delay_s !== null ? `· ${(data.processing_delay.max_delay_s * 1000).toFixed(0)} ms max` : ""}
                  </span>,
                ],
                ["Delay samples", <span className="mono">{formatNumber(data.processing_delay.samples)}</span>],
                ["Dead letters", <span className="mono">{formatNumber(data.dead_letters)}</span>],
                ["Last poll", <span className="mono">{formatDateTime(sensor?.last_poll_at)}</span>],
              ]}
            />
          </div>
        </Panel>

        <Panel title="Platform services" hint="API · database · model">
          <KeyValue
            rows={[
              ["API status", <span className="mono" style={{ color: "var(--green)" }}>{data.api.status}</span>],
              ["API version", <span className="mono">{data.api.version}</span>],
              ["API uptime", <span className="mono">{relativeSeconds(data.api.uptime_s)}</span>],
              ["Database path", <span className="mono">{data.database.path}</span>],
              ["Journal mode", <span className="mono">{data.database.journal_mode}</span>],
              ["Integrity check", <span className="mono">{data.database.integrity}</span>],
              ["Events stored", <span className="mono">{formatNumber(data.database.events)}</span>],
              [
                "Model",
                <span className="mono" style={{ color: data.model.loaded ? "var(--green)" : "var(--red)" }}>
                  {data.model.loaded ? `${data.model.name} ${data.model.version}` : data.model.load_error ?? "not loaded"}
                </span>,
              ],
              ["WS connected", <span className="mono">{String(live.connected)}</span>],
              ["Server time", <span className="mono">{formatDateTime(data.server_time)}</span>],
            ]}
          />
        </Panel>
      </div>

      <Panel title="Incremental log ingestion" hint="byte offsets persisted in SQLite">
        {data.ingestion_state.length ? (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Log file</th>
                  <th>Offset</th>
                  <th>Size</th>
                  <th>Updated</th>
                  <th>Idle</th>
                </tr>
              </thead>
              <tbody>
                {data.ingestion_state.map((row) => (
                  <tr key={row.source_file}>
                    <td className="mono">{row.source_file}</td>
                    <td className="mono">{formatNumber(row.offset)}</td>
                    <td className="mono">{formatNumber(row.size)}</td>
                    <td className="mono">{formatDateTime(row.updated_at)}</td>
                    <td className="mono muted">{relativeSeconds(row.seconds_since_update)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No log offsets recorded yet."
            detail="Offsets appear after the reader processes its first Zeek record."
          />
        )}
      </Panel>

      <Panel title="Behavioural detectors" hint="rules evaluated on every flow">
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {(sensor?.detectors.rules ?? []).map((rule) => (
            <span key={rule} className="tag">{rule}</span>
          ))}
        </div>
      </Panel>
    </>
  );
}

function KeyBar({ counters }: { counters: Record<string, number> }) {
  const entries = Object.entries(counters).filter(([, value]) => typeof value === "number");
  if (!entries.length) return <EmptyState title="No counters yet" />;
  return (
    <div className="grid cols-2" style={{ gap: 8 }}>
      {entries.map(([key, value]) => (
        <div
          key={key}
          style={{
            border: "1px solid var(--line)",
            borderRadius: 8,
            padding: "9px 11px",
            background: "rgba(8,14,26,0.6)",
          }}
        >
          <div className="dim" style={{ fontFamily: "var(--mono)", fontSize: 9, letterSpacing: "0.1em", textTransform: "uppercase" }}>
            {key.replaceAll("_", " ")}
          </div>
          <div className="mono" style={{ fontSize: 16, marginTop: 3 }}>{formatNumber(value)}</div>
        </div>
      ))}
    </div>
  );
}
