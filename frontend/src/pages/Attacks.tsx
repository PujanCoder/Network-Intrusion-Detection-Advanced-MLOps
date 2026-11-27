import { useState } from "react";

import { EventDrawer } from "../components/EventDrawer";
import { Chip, EmptyState, Panel, StatCard } from "../components/ui";
import type { NetworkEvent } from "../lib/api";
import { getJson } from "../lib/api";
import { useLive } from "../lib/LiveContext";
import { formatDateTime, formatNumber, severityClass } from "../lib/format";
import { usePolled } from "../lib/usePolled";

interface AttackResponse {
  items: NetworkEvent[];
  total: number;
}

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function AttacksPage() {
  const live = useLive();
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<NetworkEvent | null>(null);

  const attacks = usePolled<AttackResponse>(
    () => getJson<AttackResponse>(`/api/attacks?limit=100${severity ? `&severity=${severity}` : ""}`),
    5000,
    [severity],
  );

  const items = attacks.data?.items ?? [];
  const overview = live.overview;
  const critical = items.filter((item) => (item.severity || "").toUpperCase() === "CRITICAL").length;
  const high = items.filter((item) => (item.severity || "").toUpperCase() === "HIGH").length;

  const open = async (event: NetworkEvent) => {
    setSelected(event);
    try {
      const full = await getJson<NetworkEvent>(`/api/events/${event.id}`);
      setSelected(full);
    } catch {
      /* keep the list row if the detail call fails */
    }
  };

  return (
    <>
      <div className="grid cols-4">
        <StatCard label="Detected attacks" value={formatNumber(overview?.attacks)} accent="red" />
        <StatCard label="Critical in view" value={formatNumber(critical)} accent="red" />
        <StatCard label="High in view" value={formatNumber(high)} accent="orange" />
        <StatCard label="Suspicious events" value={formatNumber(overview?.suspicious)} accent="amber" />
      </div>

      <Panel
        title="Attack timeline"
        hint={`${attacks.data?.total ?? 0} attacks persisted · newest first`}
      >
        <div className="controls" style={{ marginBottom: 12 }}>
          <div className="field">
            <label>Severity</label>
            <select className="select" value={severity} onChange={(event) => setSeverity(event.target.value)}>
              {SEVERITIES.map((value) => (
                <option key={value || "all"} value={value}>
                  {value || "All severities"}
                </option>
              ))}
            </select>
          </div>
          <span className="mono dim" style={{ marginLeft: "auto" }}>
            Click a row for evidence and the original Zeek record.
          </span>
        </div>

        {attacks.error && <div className="error-box">{attacks.error}</div>}

        {items.length ? (
          <div className="table-wrap" style={{ maxHeight: 620 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Detected</th>
                  <th>Category</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Proto</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                  <th>Severity</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => (
                  <tr key={event.id} className="row-attack" onClick={() => open(event)}>
                    <td className="mono">{formatDateTime(event.ts)}</td>
                    <td>
                      <span className="tag">{event.prediction ?? "rule"}</span>
                    </td>
                    <td className="mono">
                      {event.src_ip ?? "—"}:{event.src_port ?? "—"}
                    </td>
                    <td className="mono">
                      {event.dst_ip ?? "—"}:{event.dst_port ?? "—"}
                    </td>
                    <td className="mono muted">{event.proto ?? "—"}</td>
                    <td>
                      <Chip text={event.prediction ?? "unclassified"} className={event.is_malicious ? "pred-attack" : "pred-unclassified"} />
                    </td>
                    <td className="mono">{event.confidence !== null ? `${(event.confidence * 100).toFixed(1)}%` : "—"}</td>
                    <td>
                      <Chip text={event.severity ?? "info"} className={severityClass(event.severity)} />
                    </td>
                    <td className="truncate muted" title={event.explanation ?? ""}>
                      {event.alerts && event.alerts.length
                        ? event.alerts.map((alert) => alert.rule).join(", ")
                        : event.explanation ?? "model decision"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No attacks detected yet."
            detail="The attack view fills only from real detections. Nothing is simulated."
          />
        )}
      </Panel>

      <Panel title="Detection categories" hint="rule engine + model classes">
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {["PortScan", "BruteForce", "DoS", "DDoS", "Exfiltration", "DnsTunneling", "Recon", "WebAttack", "Backdoor", "Exploit", "Worm", "Other"].map(
            (category) => (
              <span key={category} className="tag">
                {category}
              </span>
            ),
          )}
        </div>
      </Panel>

      <EventDrawer event={selected} onClose={() => setSelected(null)} />
    </>
  );
}
