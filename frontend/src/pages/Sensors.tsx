import { ErrorBox, KeyValue, Loading, Panel, Pill, StatCard } from "../components/ui";
import { api } from "../lib/api";
import { formatDateTime, formatNumber, relativeFrom } from "../lib/format";
import { usePolled } from "../lib/usePolled";

const tone = (status: string) => (status === "online" ? "ok" : status === "offline" ? "bad" : "warn") as "ok" | "bad" | "warn";

export function SensorsPage() {
  const { data, error, loading } = usePolled(() => api.sensors(), 5000, []);

  if (loading && !data) return <Loading label="Loading sensors" />;

  return (
    <>
      <ErrorBox error={error} />
      {data && (
        <>
          <div className="stat-grid">
            <StatCard label="Sensors seen" value={formatNumber(data.summary.total)} foot="rows in ingestion status" />
            <StatCard label="Online" value={formatNumber(data.summary.online)} accent="green" foot={`event within ${data.stale_after_s}s`} />
            <StatCard label="Offline" value={formatNumber(data.summary.offline)} accent="red" foot="silent beyond threshold" />
            <StatCard label="Events stored" value={formatNumber(data.summary.events)} accent="violet" foot="zeek_events rows" />
            <StatCard label="Dead letters" value={formatNumber(data.summary.dead_letters)} accent="amber" foot="records that failed to parse" />
            <StatCard label="Sensor mode" value={data.expected.mode} accent="cyan" foot={`expected id ${data.expected.sensor_id}`} />
          </div>

          <Panel title="Registered sensors" hint="online means an event arrived recently — not that a row exists">
            {data.sensors.length === 0 ? (
              <div className="empty">
                <strong>No sensor has ever pushed an event</strong>
                <div>
                  Point a Zeek sensor at <span className="mono">POST /api/v1/zeek/ingest/records</span> with the API key, or
                  enable local ingestion with <span className="mono">IDS_ZEEK_ENABLED=true</span>.
                </div>
              </div>
            ) : (
              <div className="card-grid">
                {data.sensors.map((sensor) => (
                  <article key={sensor.sensor_id} className="sensor-card">
                    <header>
                      <div>
                        <div className="mono sensor-name">{sensor.sensor_id}</div>
                        <div className="muted tiny">{sensor.status_reason}</div>
                      </div>
                      <Pill text={sensor.status} tone={tone(sensor.status)} pulse={sensor.status === "online"} />
                    </header>
                    <dl className="sensor-metrics">
                      <div>
                        <dt>Events</dt>
                        <dd>{formatNumber(sensor.events)}</dd>
                      </div>
                      <div>
                        <dt>Scored</dt>
                        <dd>{formatNumber(sensor.scored)}</dd>
                      </div>
                      <div>
                        <dt>Unclassified</dt>
                        <dd>{formatNumber(sensor.unclassified)}</dd>
                      </div>
                      <div>
                        <dt>Attacks</dt>
                        <dd className={sensor.attacks > 0 ? "pred-attack" : ""}>{formatNumber(sensor.attacks)}</dd>
                      </div>
                      <div>
                        <dt>Duplicates</dt>
                        <dd>{formatNumber(sensor.duplicates)}</dd>
                      </div>
                      <div>
                        <dt>Dead letters</dt>
                        <dd>{formatNumber(sensor.dead_letters)}</dd>
                      </div>
                    </dl>
                    <KeyValue
                      rows={[
                        ["Last event received", formatDateTime(sensor.last_ingested_at)],
                        ["Since last event", relativeFrom(sensor.last_ingested_at)],
                        ["Last Zeek ts", formatDateTime(sensor.last_seen_ts)],
                        ["Last error", sensor.last_error ?? "none"],
                      ]}
                    />
                  </article>
                ))}
              </div>
            )}
          </Panel>

          <div className="grid-2">
            <Panel title="Expected configuration" hint="from this deployment's environment">
              <KeyValue
                rows={[
                  ["Sensor id", <span className="mono">{data.expected.sensor_id}</span>],
                  ["Mode", data.expected.mode],
                  ["Local ingestion", data.expected.local_ingestion_enabled ? "enabled" : "disabled (remote sensors push)"],
                  ["Zeek log dir", <span className="mono">{data.expected.log_dir}</span>],
                  ["Log types", <span className="mono">{data.expected.log_types.join(", ")}</span>],
                  ["Stale threshold", `${data.stale_after_s} s`],
                ]}
              />
            </Panel>
            <Panel title="Ingestion service" hint="tailer and reader state reported by the app">
              <pre className="json">{JSON.stringify(data.ingestion, null, 2)}</pre>
            </Panel>
          </div>

          <Panel title="Log types ingested" hint="zeek_events grouped by log type">
            <KeyValue
              rows={
                Object.keys(data.counters.by_log_type).length
                  ? Object.entries(data.counters.by_log_type).map(([type, count]) => [type, formatNumber(count)] as [string, string])
                  : [["—", "no events stored"]]
              }
            />
          </Panel>
        </>
      )}
    </>
  );
}
