import { useEffect, useRef } from "react";
import type { NetworkEvent } from "../lib/api";
import { formatBytes, formatDateTime, formatTime, severityClass } from "../lib/format";
import { Chip, KeyValue } from "./ui";

export function EventDrawer({
  event,
  onClose,
}: {
  event: NetworkEvent | null;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!event) return;
    closeRef.current?.focus();
    const handler = (key: KeyboardEvent) => {
      if (key.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [event, onClose]);

  if (!event) return null;

  const raw = event.raw && Object.keys(event.raw).length ? JSON.stringify(event.raw, null, 2) : "{}";

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" onClick={(stop) => stop.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <div className="drawer-title">
              Event #{event.id} · {event.prediction ?? "Unclassified"}
            </div>
            <div className="drawer-sub">
              {formatDateTime(event.ts)} · {event.sensor} · {event.log_type}.log
            </div>
          </div>
          <button ref={closeRef} className="btn ghost" onClick={onClose}>
            Close
          </button>
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 18 }}>
          <Chip text={event.prediction ?? "unclassified"} className={event.is_malicious ? "pred-attack" : event.prediction ? "pred-benign" : "pred-unclassified"} />
          <Chip text={event.severity ?? "info"} className={severityClass(event.severity)} />
          {event.confidence !== null && (
            <Chip text={`confidence ${(event.confidence * 100).toFixed(1)}%`} className="sev-info" />
          )}
          {event.latency_ms !== null && <Chip text={`${event.latency_ms.toFixed(2)} ms inference`} className="sev-info" />}
        </div>

        <KeyValue
          rows={[
            ["Event UID", <span className="mono">{event.event_uid}</span>],
            ["Timestamp", <span className="mono">{formatDateTime(event.ts)}</span>],
            ["Ingested", <span className="mono">{formatDateTime(event.ingested_at)}</span>],
            ["Source", <span className="mono">{event.src_ip ?? "—"}:{event.src_port ?? "—"}</span>],
            ["Destination", <span className="mono">{event.dst_ip ?? "—"}:{event.dst_port ?? "—"}</span>],
            ["Protocol / service", <span className="mono">{event.proto ?? "—"} / {event.service ?? "—"}</span>],
            ["Connection state", <span className="mono">{event.conn_state ?? "—"}</span>],
            ["Duration", <span className="mono">{event.duration !== null ? `${event.duration.toFixed(4)} s` : "—"}</span>],
            [
              "Volume",
              <span className="mono">
                {formatBytes(event.orig_bytes)} out / {formatBytes(event.resp_bytes)} in ·{" "}
                {event.orig_pkts ?? 0}/{event.resp_pkts ?? 0} pkts
              </span>,
            ],
            ["Model", <span className="mono">{event.model_name ?? "—"} {event.model_version ? `· ${event.model_version}` : ""}</span>],
            ["Threshold", <span className="mono">{event.threshold ?? "—"}</span>],
            ["Explanation", <span>{event.explanation ?? "—"}</span>],
          ]}
        />

        {event.alerts && event.alerts.length > 0 && (
          <div style={{ marginTop: 22 }}>
            <div className="panel-title" style={{ marginBottom: 10 }}>
              Detection evidence ({event.alerts.length})
            </div>
            {event.alerts.map((alert, index) => (
              <div key={`${alert.rule}-${index}`} className={`alert-card ${(alert.severity || "").toLowerCase()}`}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <span className="alert-rule">{alert.rule}</span>
                  <Chip text={alert.severity} className={severityClass(alert.severity)} />
                </div>
                <div className="alert-desc">{alert.explanation}</div>
                <div className="mono dim" style={{ marginTop: 6, fontSize: 10.5 }}>
                  category {alert.category} · confidence{" "}
                  {alert.confidence !== null ? `${(alert.confidence * 100).toFixed(0)}%` : "—"}
                </div>
                <pre className="json" style={{ marginTop: 8, maxHeight: 180 }}>
                  {JSON.stringify(alert.evidence, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        )}

        <div style={{ marginTop: 22 }}>
          <div className="panel-title" style={{ marginBottom: 8 }}>
            Original Zeek record
          </div>
          <pre className="json">{raw}</pre>
        </div>

        <div className="mono dim" style={{ marginTop: 12, fontSize: 10.5 }}>
          Event time {formatTime(event.ts)} · stored in SQLite · served from /api/events/{event.id}
        </div>
      </aside>
    </div>
  );
}
