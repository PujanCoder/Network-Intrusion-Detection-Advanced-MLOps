import type { Detection } from "../lib/api";
import { confidence, formatTime, relativeFrom } from "../lib/format";
import { EmptyState, SeverityBadge, SourceBadge } from "./ui";

export function DetectionTable({
  rows,
  onOpen,
  emptyTitle = "No detections yet",
  emptyDetail,
  dense = false,
}: {
  rows: Detection[];
  onOpen?: (id: string) => void;
  emptyTitle?: string;
  emptyDetail?: string;
  dense?: boolean;
}) {
  if (!rows.length) return <EmptyState title={emptyTitle} detail={emptyDetail} />;

  return (
    <div className="table-wrap">
      <table className={`data-table ${dense ? "dense" : ""}`}>
        <thead>
          <tr>
            <th>Time</th>
            <th>Sensor</th>
            <th>Source → destination</th>
            <th>Proto / service</th>
            <th>Label</th>
            <th className="num">Confidence</th>
            <th>Severity</th>
            <th>Model</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.id}
              className={`row-${row.severity.toLowerCase()} ${row.is_attack ? "is-attack" : ""} ${
                onOpen ? "clickable" : ""
              }`}
              onClick={onOpen ? () => onOpen(row.id) : undefined}
              title={row.explanation}
            >
              <td className="mono nowrap">
                <div>{formatTime(row.ts)}</div>
                <div className="muted tiny">{relativeFrom(row.ts)}</div>
              </td>
              <td className="mono">{row.sensor_id ?? "—"}</td>
              <td className="mono nowrap">
                <div>
                  {row.src_ip ?? "—"}
                  {row.src_port !== null && <span className="muted">:{row.src_port}</span>}
                </div>
                <div className="muted tiny">
                  → {row.dst_ip ?? "—"}
                  {row.dst_port !== null && `:${row.dst_port}`}
                </div>
              </td>
              <td className="mono">
                <div>{(row.proto ?? "—").toUpperCase()}</div>
                <div className="muted tiny">
                  {row.service ?? "—"}
                  {row.conn_state ? ` · ${row.conn_state}` : ""}
                </div>
              </td>
              <td>
                <div className={row.is_attack ? "pred-attack mono" : "pred-benign mono"}>{row.label}</div>
                <div className="muted tiny">{row.status}</div>
              </td>
              <td className="num mono">{confidence(row.confidence)}</td>
              <td>
                <SeverityBadge severity={row.severity} />
              </td>
              <td>
                <SourceBadge source={row.source} experimental={row.model.experimental} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
