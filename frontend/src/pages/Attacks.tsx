import { useMemo, useState } from "react";

import { DistributionBarChart } from "../components/Charts";
import { DetectionDrawer } from "../components/EventDrawer";
import { DetectionTable } from "../components/EventTable";
import { ErrorBox, Loading, Panel, SeverityBadge, StatCard } from "../components/ui";
import { api, type Severity } from "../lib/api";
import { formatNumber } from "../lib/format";
import { usePolled } from "../lib/usePolled";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function AttacksPage() {
  const [severity, setSeverity] = useState<Severity | "">("");
  const [source, setSource] = useState<"zeek" | "cicids" | "">("");
  const [label, setLabel] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);

  const overview = usePolled(() => api.overview(86400), 5000, []);
  const page = usePolled(
    () =>
      api.detections({
        only_attacks: true,
        limit: 100,
        severity: severity || null,
        source: source || null,
        label: label || null,
      }),
    5000,
    [severity, source, label],
  );

  const labels = useMemo(
    () => (overview.data?.distributions.labels ?? []).filter((item) => item.label !== "BENIGN"),
    [overview.data],
  );
  const severityCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const item of overview.data?.distributions.severities ?? []) map.set(item.label, item.count);
    return map;
  }, [overview.data]);

  return (
    <>
      <ErrorBox error={page.error ?? overview.error} />

      <div className="stat-grid">
        <StatCard label="Attacks (24h)" value={formatNumber(page.data?.total ?? 0)} accent="red" foot="is_attack = true, all pages" />
        <StatCard label="Critical" value={formatNumber(severityCounts.get("CRITICAL") ?? 0)} accent="red" foot="confidence ≥ 0.90" />
        <StatCard label="High" value={formatNumber(severityCounts.get("HIGH") ?? 0)} accent="orange" foot="confidence ≥ 0.75" />
        <StatCard label="Medium" value={formatNumber(severityCounts.get("MEDIUM") ?? 0)} accent="amber" foot="confidence ≥ 0.50" />
        <StatCard label="Low" value={formatNumber(severityCounts.get("LOW") ?? 0)} accent="violet" foot="confidence < 0.50" />
        <StatCard
          label="Rows shown"
          value={formatNumber(page.data?.items.length ?? 0)}
          accent="cyan"
          foot="filtered page"
        />
      </div>

      <Panel title="Severity bands" hint="rule applied to model confidence, not model output">
        <div className="severity-strip">
          {SEVERITIES.map((band) => (
            <button
              key={band}
              type="button"
              className={`severity-cell ${severity === band ? "active" : ""}`}
              onClick={() => setSeverity(severity === band ? "" : band)}
            >
              <SeverityBadge severity={band} />
              <span className="mono">{formatNumber(severityCounts.get(band) ?? 0)}</span>
            </button>
          ))}
        </div>
        <p className="small muted">{overview.data?.severity_policy.description}</p>
      </Panel>

      <div className="toolbar">
        <div className="toolbar-group">
          <span className="toolbar-label">model</span>
          {[
            { label: "all", value: "" },
            { label: "zeek", value: "zeek" },
            { label: "cicids", value: "cicids" },
          ].map((option) => (
            <button
              key={option.value || "all"}
              type="button"
              className={`chip-button ${source === option.value ? "active" : ""}`}
              onClick={() => setSource(option.value as "zeek" | "cicids" | "")}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="toolbar-group">
          <span className="toolbar-label">label</span>
          <select value={label} onChange={(event) => setLabel(event.target.value)} className="control">
            <option value="">all attack labels</option>
            {labels.map((item) => (
              <option key={item.label} value={item.label}>
                {item.label} ({item.count})
              </option>
            ))}
          </select>
          {(severity || source || label) && (
            <button
              type="button"
              className="chip-button"
              onClick={() => {
                setSeverity("");
                setSource("");
                setLabel("");
              }}
            >
              reset
            </button>
          )}
        </div>
      </div>

      <Panel
        title="Detected attacks"
        hint="click a row for the full record, evidence and class probabilities"
        className="flush"
      >
        {page.loading && !page.data ? (
          <Loading label="Loading attacks" />
        ) : (
          <DetectionTable
            rows={page.data?.items ?? []}
            onOpen={setOpenId}
            emptyTitle="No attacks match these filters"
            emptyDetail="Attacks appear when a model labels a record as malicious."
          />
        )}
      </Panel>

      <Panel title="Attack distribution" hint="labels across stored detections (24h)">
        <DistributionBarChart
          data={(overview.data?.distributions.labels ?? []).filter((item) => item.label !== "BENIGN")}
          color="#ff5b6e"
          emptyLabel="No attack labels yet"
        />
      </Panel>

      <DetectionDrawer id={openId} onClose={() => setOpenId(null)} />
    </>
  );
}
