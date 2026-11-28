import type { ReactNode } from "react";

import { ErrorBox, KeyValue, Loading, Panel, Pill, StatCard } from "../components/ui";
import { api } from "../lib/api";
import { formatDateTime, formatNumber } from "../lib/format";
import { useLive } from "../lib/LiveContext";
import { usePolled } from "../lib/usePolled";

export function HealthPage() {
  const live = useLive();
  const { data, error, loading } = usePolled(() => api.system(), 5000, []);

  if (loading && !data) return <Loading label="Loading system status" />;

  return (
    <>
      <ErrorBox error={error} />
      {data && (
        <>
          <div className="stat-grid">
            <StatCard
              label="Application"
              value={data.status}
              accent={data.status === "ok" ? "green" : "red"}
              foot={`${data.app.name} v${data.app.version}`}
            />
            <StatCard label="Uptime" value={`${Math.round(data.uptime_s / 60)} min`} accent="violet" foot="since process start" />
            <StatCard
              label="Database"
              value={data.database.integrity}
              accent={data.database.integrity === "ok" ? "green" : "red"}
              foot={`${formatNumber(data.database.events ?? 0)} events · ${formatNumber(data.database.detections ?? 0)} detections`}
            />
            <StatCard
              label="WebSocket"
              value={live.connected ? "connected" : "offline"}
              accent={live.connected ? "green" : "amber"}
              foot={`server saw ${data.websocket.clients} client(s) at last poll · ${data.websocket.broadcasts} broadcast(s)`}
            />
            <StatCard
              label="Deployed commit"
              value={<span className="mono">{data.build.commit?.slice(0, 7) ?? "unknown"}</span>}
              accent="cyan"
              foot={data.build.branch ?? "branch unknown"}
              small
            />
            <StatCard
              label="Server time"
              value={formatDateTime(new Date(data.server_time * 1000).toISOString())}
              foot="local rendering of server clock"
              small
            />
          </div>

          {data.degraded_components.length > 0 && (
            <div className="banner bad">Degraded components: {data.degraded_components.join(", ")}</div>
          )}

          <div className="grid-2">
            <Panel title="Components" hint="live state read from each subsystem">
              <div className="component-list">
                {Object.entries(data.components).map(([name, component]) => {
                  const loaded = "loaded" in component ? Boolean(component.loaded) : undefined;
                  const ok = "integrity" in component ? component.integrity === "ok" : loaded;
                  return (
                    <div key={name} className="component-row">
                      <span className="mono">{name}</span>
                      <Pill
                        text={ok === undefined ? "reported" : ok ? "ok" : "problem"}
                        tone={ok === undefined ? "neutral" : ok ? "ok" : "bad"}
                      />
                    </div>
                  );
                })}
              </div>
            </Panel>

            <Panel title="Deployment" hint="what is actually running">
              <KeyValue
                rows={[
                  ["Service", data.build.service ?? "—"],
                  ["Branch", data.build.branch ?? "—"],
                  ["Commit", <span className="mono">{data.build.commit ?? "unknown"}</span>],
                  ["Database path", <span className="mono tiny">{data.database.path}</span>],
                  ["Database exists", String(data.database.exists)],
                  ["Auth configured", String(data.auth.configured)],
                  ["Auth source", String(data.auth.source ?? "—")],
                  ["Authenticated by", String(data.auth.request_authenticated_by ?? "—")],
                ]}
              />
            </Panel>
          </div>

          <div className="grid-2">
            <Panel title="Model availability" hint="from the loader, not a config flag">
              <KeyValue
                rows={[
                  ["CICIDS loaded", String(Boolean(data.components.cicids_model?.loaded))],
                  ["CICIDS error", String(data.components.cicids_model?.error ?? "none")],
                  ["Zeek loaded", String(Boolean(data.components.zeek_model?.loaded))],
                  ["Zeek schema", String(data.components.zeek_model?.schema_version ?? "—")],
                  ["Zeek classes", (data.components.zeek_model?.classes ?? []).join(", ") || "—"],
                ]}
              />
            </Panel>

            <Panel title="API surface" hint="authenticated endpoints used by this dashboard">
              <KeyValue
                rows={Object.entries(data.endpoints).map(
                  ([name, path]) => [name, <span className="mono">{path}</span>] as [string, ReactNode],
                )}
              />
            </Panel>
          </div>

          <Panel title="Raw component payload" hint="exactly what /api/v1/system/status returns">
            <pre className="json">{JSON.stringify(data.components, null, 2)}</pre>
          </Panel>
        </>
      )}
    </>
  );
}
