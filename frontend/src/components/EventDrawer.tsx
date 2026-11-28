import { useEffect, useState } from "react";

import { api, type Detection } from "../lib/api";
import { confidence, duration, formatBytes, formatDateTime, severityTone } from "../lib/format";
import { ErrorBox, KeyValue, Loading, SeverityBadge, SourceBadge } from "./ui";

export function DetectionDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const [record, setRecord] = useState<Detection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!id) {
      setRecord(null);
      return;
    }
    let active = true;
    setLoading(true);
    setError(null);
    api
      .detection(id)
      .then((data) => active && setRecord(data))
      .catch((caught) => active && setError(caught instanceof Error ? caught.message : String(caught)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [id]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!id) return null;

  const probabilities = record?.probabilities ? Object.entries(record.probabilities) : [];
  const topProbability = Math.max(...probabilities.map(([, value]) => value), 0.0001);

  return (
    <div className="drawer-backdrop" onClick={onClose} role="presentation">
      <aside className="drawer" onClick={(event) => event.stopPropagation()} aria-label="Detection detail">
        <header className="drawer-head">
          <div>
            <div className="drawer-title mono">{id}</div>
            <div className="muted small">complete stored record</div>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        <ErrorBox error={error} />
        {loading && !record && <Loading label="Loading record" />}

        {record && (
          <div className="drawer-body">
            <div className="drawer-badges">
              <SeverityBadge severity={record.severity} />
              <SourceBadge source={record.source} experimental={record.model.experimental} />
              <span className={`badge ${record.is_attack ? "sev-critical" : "sev-info"}`}>
                {record.is_attack ? "attack" : "benign"}
              </span>
              <span className="badge">{record.status}</span>
            </div>

            <h3>Prediction</h3>
            <KeyValue
              rows={[
                ["Label", <span className="mono">{record.label}</span>],
                ["Confidence", <span className="mono">{confidence(record.confidence)}</span>],
                ["Severity", <span className={severityTone(record.severity)}>{record.severity}</span>],
                ["Severity source", <span className="mono tiny">{record.severity_source}</span>],
                ["Model", `${record.model.name} (${record.model.schema ?? "schema unknown"})`],
                ["Explanation", <span className="small">{record.explanation}</span>],
              ]}
            />

            {probabilities.length > 0 && (
              <>
                <h3>Class probabilities</h3>
                <div className="proba-list">
                  {probabilities
                    .sort((a, b) => b[1] - a[1])
                    .map(([label, value]) => (
                      <div key={label} className="proba-row">
                        <span className="mono">{label}</span>
                        <span className="proba-track">
                          <span style={{ width: `${Math.max(2, (value / topProbability) * 100)}%` }} />
                        </span>
                        <span className="mono muted">{(value * 100).toFixed(2)}%</span>
                      </div>
                    ))}
                </div>
              </>
            )}

            <h3>Network flow</h3>
            <KeyValue
              rows={[
                ["Timestamp", <span className="mono">{formatDateTime(record.ts)}</span>],
                ["Sensor", <span className="mono">{record.sensor_id ?? "—"}</span>],
                ["Log type", <span className="mono">{record.log_type ?? "—"}</span>],
                [
                  "Source",
                  <span className="mono">
                    {record.src_ip ?? "—"}
                    {record.src_port !== null ? `:${record.src_port}` : ""}
                  </span>,
                ],
                [
                  "Destination",
                  <span className="mono">
                    {record.dst_ip ?? "—"}
                    {record.dst_port !== null ? `:${record.dst_port}` : ""}
                  </span>,
                ],
                ["Protocol / service", `${(record.proto ?? "—").toUpperCase()} / ${record.service ?? "—"}`],
                ["Connection state", <span className="mono">{record.conn_state ?? "—"}</span>],
                ["Duration", duration(record.duration)],
                [
                  "Bytes (orig / resp)",
                  `${formatBytes(record.orig_bytes)} / ${formatBytes(record.resp_bytes)}`,
                ],
                [
                  "Packets (orig / resp)",
                  `${record.orig_pkts ?? "—"} / ${record.resp_pkts ?? "—"}`,
                ],
              ]}
            />

            <h3>Original event</h3>
            <pre className="json">{JSON.stringify(record.raw ?? {}, null, 2)}</pre>
          </div>
        )}
      </aside>
    </div>
  );
}
