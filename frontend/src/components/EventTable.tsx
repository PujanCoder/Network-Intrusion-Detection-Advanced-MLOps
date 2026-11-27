import { useEffect, useMemo, useRef, useState } from "react";

import type { NetworkEvent } from "../lib/api";
import { formatBytes, formatNumber, formatTime, predictionClass, severityClass } from "../lib/format";
import { Chip, EmptyState } from "./ui";

function rowClass(event: NetworkEvent): string {
  if (event.is_malicious) return "row-attack";
  if (event.severity === "HIGH" || event.severity === "CRITICAL") return "row-attack";
  if (event.severity === "MEDIUM" || event.severity === "LOW") return "row-suspicious";
  return "";
}

export function EventTable({
  events,
  onSelect,
  emptyTitle = "No new network events received.",
  emptyDetail = "The stream is live. Rows appear the moment Zeek writes a new log record.",
  flashNew = true,
}: {
  events: NetworkEvent[];
  onSelect: (event: NetworkEvent) => void;
  emptyTitle?: string;
  emptyDetail?: string;
  flashNew?: boolean;
}) {
  const [highlightId, setHighlightId] = useState<number | null>(null);
  const lastTopId = useRef<number | null>(null);

  useEffect(() => {
    if (!flashNew || !events.length) return;
    const top = events[0].id;
    if (lastTopId.current !== null && top !== lastTopId.current) {
      setHighlightId(top);
      const timer = window.setTimeout(() => setHighlightId(null), 1200);
      lastTopId.current = top;
      return () => window.clearTimeout(timer);
    }
    lastTopId.current = top;
  }, [events, flashNew]);

  if (!events.length) {
    return <EmptyState title={emptyTitle} detail={emptyDetail} />;
  }

  return (
    <div className="table-wrap" style={{ maxHeight: 560 }}>
      <table className="data">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Ports</th>
            <th>Proto</th>
            <th>State</th>
            <th>Volume</th>
            <th>Prediction</th>
            <th>Conf.</th>
            <th>Severity</th>
            <th>Latency</th>
            <th>Detection explanation</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.id}
              className={rowClass(event)}
              onClick={() => onSelect(event)}
              style={highlightId === event.id ? { boxShadow: "inset 0 0 0 1px rgba(36,212,226,0.45)" } : undefined}
            >
              <td className="mono">{formatTime(event.ts)}</td>
              <td className="mono">{event.src_ip ?? "—"}</td>
              <td className="mono">{event.dst_ip ?? "—"}</td>
              <td className="mono">
                {event.src_port ?? "—"} → {event.dst_port ?? "—"}
              </td>
              <td className="mono muted">{event.proto ?? "—"}</td>
              <td className="mono muted">{event.conn_state ?? "—"}</td>
              <td className="mono muted">
                {formatBytes((event.orig_bytes ?? 0) + (event.resp_bytes ?? 0))}
                <span className="dim"> · {formatNumber(event.orig_pkts ?? 0)}/{formatNumber(event.resp_pkts ?? 0)}p</span>
              </td>
              <td>
                <Chip
                  text={event.prediction ?? "unclassified"}
                  className={predictionClass(event)}
                />
              </td>
              <td className="mono">{event.confidence !== null ? `${(event.confidence * 100).toFixed(1)}%` : "—"}</td>
              <td>
                <Chip text={event.severity ?? "info"} className={severityClass(event.severity)} />
              </td>
              <td className="mono muted">{event.latency_ms !== null ? `${event.latency_ms.toFixed(2)}ms` : "—"}</td>
              <td className="truncate muted" title={event.explanation ?? ""}>
                {event.explanation ?? (event.log_type !== "conn" ? `${event.log_type} log event (no flow features)` : "—")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function mergeEvents(primary: NetworkEvent[], secondary: NetworkEvent[], limit: number): NetworkEvent[] {
  const seen = new Set<number>();
  const merged: NetworkEvent[] = [];
  for (const event of [...primary, ...secondary]) {
    if (seen.has(event.id)) continue;
    seen.add(event.id);
    merged.push(event);
  }
  merged.sort((a, b) => b.ts - a.ts || b.id - a.id);
  return merged.slice(0, limit);
}

export function useMergedEvents(live: NetworkEvent[], fetched: NetworkEvent[], limit = 400): NetworkEvent[] {
  return useMemo(() => mergeEvents(live, fetched, limit), [live, fetched, limit]);
}
