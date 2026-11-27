import { useState } from "react";

import { EventDrawer } from "../components/EventDrawer";
import { Chip, EmptyState, Panel } from "../components/ui";
import type { EventPage, NetworkEvent } from "../lib/api";
import { buildQuery, getJson } from "../lib/api";
import { formatBytes, formatDateTime, formatNumber, severityClass, toIsoLocal } from "../lib/format";
import { usePolled } from "../lib/usePolled";

const PAGE_SIZE = 50;

interface Filters {
  search: string;
  proto: string;
  prediction: string;
  severity: string;
  start: string;
  end: string;
  maliciousOnly: boolean;
}

const EMPTY: Filters = {
  search: "",
  proto: "",
  prediction: "",
  severity: "",
  start: "",
  end: "",
  maliciousOnly: false,
};

function toEpoch(local: string): number | null {
  if (!local) return null;
  const parsed = new Date(local).getTime();
  return Number.isNaN(parsed) ? null : Math.floor(parsed / 1000);
}

export function ExplorerPage() {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<NetworkEvent | null>(null);

  const query = buildQuery({
    search: applied.search || undefined,
    proto: applied.proto || undefined,
    prediction: applied.prediction || undefined,
    severity: applied.severity || undefined,
    start: toEpoch(applied.start) ?? undefined,
    end: toEpoch(applied.end) ?? undefined,
    malicious_only: applied.maliciousOnly || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const events = usePolled<EventPage>(() => getJson<EventPage>(`/api/events${query}`), 15000, [query]);

  const apply = () => {
    setPage(0);
    setApplied(filters);
  };

  const reset = () => {
    setFilters(EMPTY);
    setApplied(EMPTY);
    setPage(0);
  };

  const open = async (event: NetworkEvent) => {
    setSelected(event);
    try {
      const full = await getJson<NetworkEvent>(`/api/events/${event.id}`);
      setSelected(full);
    } catch {
      /* keep list row */
    }
  };

  const items = events.data?.items ?? [];
  const total = events.data?.total ?? 0;
  const exportQuery = buildQuery({
    search: applied.search || undefined,
    proto: applied.proto || undefined,
    prediction: applied.prediction || undefined,
    severity: applied.severity || undefined,
    start: toEpoch(applied.start) ?? undefined,
    end: toEpoch(applied.end) ?? undefined,
    malicious_only: applied.maliciousOnly || undefined,
  });

  return (
    <>
      <Panel title="Query builder" hint={`${formatNumber(total)} matching events`}>
        <div className="controls">
          <div className="field">
            <label>IP address or text</label>
            <input
              className="input"
              placeholder="10.0.0.5, DDoS, tcp…"
              value={filters.search}
              onChange={(event) => setFilters({ ...filters, search: event.target.value })}
              onKeyDown={(event) => event.key === "Enter" && apply()}
            />
          </div>
          <div className="field">
            <label>Protocol</label>
            <select className="select" value={filters.proto} onChange={(event) => setFilters({ ...filters, proto: event.target.value })}>
              <option value="">Any</option>
              {["tcp", "udp", "icmp", "unknown"].map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>Prediction</label>
            <select className="select" value={filters.prediction} onChange={(event) => setFilters({ ...filters, prediction: event.target.value })}>
              <option value="">Any</option>
              {["BENIGN", "DDoS", "DoS", "PortScan", "BruteForce", "Recon", "WebAttack", "Exploit", "Backdoor", "Worm", "Exfiltration", "DnsTunneling", "Other", "UNCLASSIFIED"].map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>Severity</label>
            <select className="select" value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}>
              <option value="">Any</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>From</label>
            <input
              className="input"
              type="datetime-local"
              value={filters.start}
              max={toIsoLocal(new Date())}
              onChange={(event) => setFilters({ ...filters, start: event.target.value })}
            />
          </div>
          <div className="field">
            <label>To</label>
            <input
              className="input"
              type="datetime-local"
              value={filters.end}
              onChange={(event) => setFilters({ ...filters, end: event.target.value })}
            />
          </div>
          <label style={{ display: "inline-flex", gap: 7, alignItems: "center", fontSize: 12.5, marginTop: 14 }}>
            <input
              type="checkbox"
              checked={filters.maliciousOnly}
              onChange={(event) => setFilters({ ...filters, maliciousOnly: event.target.checked })}
            />
            Attacks only
          </label>
          <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
            <button className="btn primary" onClick={apply}>Search</button>
            <button className="btn ghost" onClick={reset}>Reset</button>
            <a className="btn" href={`/api/events/export.csv${exportQuery}`} download>
              Export CSV
            </a>
          </div>
        </div>
      </Panel>

      <Panel title="Results" hint={events.loading ? "refreshing…" : "click a row for the full record"}>
        {events.error && <div className="error-box">{events.error}</div>}
        {items.length ? (
          <>
            <div className="table-wrap" style={{ maxHeight: 560 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Proto</th>
                    <th>State</th>
                    <th>Bytes</th>
                    <th>Prediction</th>
                    <th>Confidence</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((event) => (
                    <tr
                      key={event.id}
                      className={event.is_malicious ? "row-attack" : ""}
                      onClick={() => open(event)}
                    >
                      <td className="mono dim">{event.id}</td>
                      <td className="mono">{formatDateTime(event.ts)}</td>
                      <td className="mono">{event.src_ip ?? "—"}:{event.src_port ?? "—"}</td>
                      <td className="mono">{event.dst_ip ?? "—"}:{event.dst_port ?? "—"}</td>
                      <td className="mono muted">{event.proto ?? "—"}</td>
                      <td className="mono muted">{event.conn_state ?? "—"}</td>
                      <td className="mono muted">{formatBytes((event.orig_bytes ?? 0) + (event.resp_bytes ?? 0))}</td>
                      <td>
                        <Chip
                          text={event.prediction ?? "unclassified"}
                          className={event.is_malicious ? "pred-attack" : event.prediction ? "pred-benign" : "pred-unclassified"}
                        />
                      </td>
                      <td className="mono">{event.confidence !== null ? `${(event.confidence * 100).toFixed(1)}%` : "—"}</td>
                      <td>
                        <Chip text={event.severity ?? "info"} className={severityClass(event.severity)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pager">
              <span>
                {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {formatNumber(total)}
              </span>
              <button className="btn ghost" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>
                Previous
              </button>
              <button
                className="btn ghost"
                disabled={(page + 1) * PAGE_SIZE >= total}
                onClick={() => setPage((value) => value + 1)}
              >
                Next
              </button>
            </div>
          </>
        ) : (
          <EmptyState title="No events match the query." detail="Adjust the filters or wait for new traffic." />
        )}
      </Panel>

      <EventDrawer event={selected} onClose={() => setSelected(null)} />
    </>
  );
}
