import { HistogramChart } from "../components/Charts";
import { BarList, EmptyState, KeyValue, Panel, Pill, StatCard } from "../components/ui";
import type { ModelInfo, ModelMetrics } from "../lib/api";
import { getJson } from "../lib/api";
import { formatNumber } from "../lib/format";
import { usePolled } from "../lib/usePolled";

function pct(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${(value * 100).toFixed(2)}%`;
}

function MetricRow({ label, metrics }: { label: string; metrics?: ModelMetrics | null }) {
  if (!metrics) return null;
  return (
    <tr>
      <td className="mono">{label}</td>
      <td className="mono">{formatNumber(metrics.support)}</td>
      <td className="mono">{pct(metrics.precision)}</td>
      <td className="mono">{pct(metrics.recall)}</td>
      <td className="mono">{pct(metrics.f1)}</td>
      <td className="mono" style={{ color: metrics.false_positive_rate > 0.1 ? "var(--red)" : "var(--green)" }}>
        {pct(metrics.false_positive_rate)}
      </td>
      <td className="mono muted">
        {metrics.tp} / {metrics.fp} / {metrics.tn} / {metrics.fn}
      </td>
    </tr>
  );
}

function Confusion({ matrix }: { matrix?: number[][] | null }) {
  if (!matrix || matrix.length < 2) return null;
  return (
    <div className="grid cols-2" style={{ gap: 6, maxWidth: 320, fontFamily: "var(--mono)", fontSize: 11.5 }}>
      {matrix.map((row, rowIndex) =>
        row.map((value, colIndex) => (
          <div
            key={`${rowIndex}-${colIndex}`}
            style={{
              padding: "10px 12px",
              borderRadius: 8,
              border: "1px solid var(--line-bright)",
              background: rowIndex === colIndex ? "rgba(49,211,155,0.1)" : "rgba(255,91,110,0.08)",
            }}
          >
            <div className="dim" style={{ fontSize: 9, letterSpacing: "0.1em", textTransform: "uppercase" }}>
              true {rowIndex === 0 ? "benign" : "attack"} → pred {colIndex === 0 ? "benign" : "attack"}
            </div>
            <div style={{ fontSize: 17, marginTop: 3 }}>{value.toLocaleString()}</div>
          </div>
        )),
      )}
    </div>
  );
}

export function ModelPage() {
  const model = usePolled<ModelInfo>(() => getJson<ModelInfo>("/api/model"), 10000);
  const data = model.data;
  const live = data?.live_model;
  const runtime = data?.runtime;
  const batch = data?.batch_model;

  if (model.loading && !data) return <Panel title="Model monitoring">{<div className="loading">Loading model card…</div>}</Panel>;
  if (model.error && !data) return <div className="error-box">{model.error}</div>;
  if (!data || !live) return <EmptyState title="Model metadata unavailable" />;

  return (
    <>
      <div className="grid cols-4">
        <StatCard
          label="Live model"
          value={live.loaded ? "loaded" : "offline"}
          foot={`${live.name} · ${live.version}`}
          accent={live.loaded ? "green" : "red"}
          small
        />
        <StatCard label="Operating threshold" value={live.threshold ?? "—"} foot={`FPR budget ${pct(live.target_false_positive_rate)}`} accent="violet" small />
        <StatCard label="Predictions served" value={formatNumber(runtime?.predictions)} foot={`${formatNumber(runtime?.unclassified_events)} unclassified events`} accent="cyan" />
        <StatCard
          label="Inference latency"
          value={`${runtime?.latency_percentiles.avg_ms ?? runtime?.avg_prediction_latency_ms ?? "—"} ms`}
          foot={`p95 ${runtime?.latency_percentiles.p95_ms ?? "—"} ms · ${runtime?.predictions_per_second.toFixed(2) ?? "0"} pred/s`}
          accent="amber"
          small
        />
      </div>

      {!live.loaded && (
        <div className="banner">
          <strong>Live model unavailable.</strong>
          <span>{live.load_error ?? "Train it with: python -m src.realtime.training"}</span>
        </div>
      )}

      <div className="grid cols-3">
        <Panel title="Live Zeek flow classifier" hint="real-time">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
            <Pill text={live.algorithm ?? "—"} tone="info" />
            <Pill text={`${live.classes?.length ?? 0} classes`} tone="neutral" />
            <Pill text={`${live.feature_schema?.length ?? 0} features`} tone="neutral" />
          </div>
          <KeyValue
            rows={[
              ["Model name", <span className="mono">{live.name}</span>],
              ["Version", <span className="mono">{live.version}</span>],
              ["Trained at", <span className="mono">{live.trained_at ?? "—"}</span>],
              ["Artifact", <span className="mono">{live.artifact_path}</span>],
              [
                "Training datasets",
                <span className="mono">
                  {live.training_datasets
                    ? Object.entries(live.training_datasets).map(([name, rows]) => `${name}: ${formatNumber(rows)}`).join(" · ")
                    : "—"}
                </span>,
              ],
              [
                "Rows",
                <span className="mono">
                  {live.row_counts
                    ? `train ${formatNumber(live.row_counts.train)} · val ${formatNumber(live.row_counts.validation)} · test ${formatNumber(live.row_counts.test)}`
                    : "—"}
                </span>,
              ],
              [
                "Classes",
                <span className="mono">{live.classes?.join(", ") ?? "—"}</span>,
              ],
              ["Model errors", <span className="mono">{formatNumber(runtime?.model_errors)}</span>],
              ["Dead letters", <span className="mono">{formatNumber(runtime?.dead_letters)}</span>],
            ]}
          />
        </Panel>

        <Panel title="Offline evaluation" hint="held-out test split">
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Partition</th>
                  <th>Rows</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1</th>
                  <th>FPR</th>
                  <th>TP/FP/TN/FN</th>
                </tr>
              </thead>
              <tbody>
                <MetricRow label="validation (all)" metrics={live.metrics.validation?.binary} />
                <MetricRow label="test (all)" metrics={live.metrics.test?.binary} />
                {Object.entries(live.metrics.official_test_partitions ?? {}).map(([name, value]) => (
                  <MetricRow key={name} label={name} metrics={value.binary} />
                ))}
              </tbody>
            </table>
          </div>
          {live.metrics.cross_dataset && (
            <div className="banner cyber" style={{ marginTop: 12 }}>
              <strong>Zero-day transfer probe.</strong>{" "}
              <span>
                A second model was retrained without {live.metrics.cross_dataset.unseen_dataset} and scored
                on its official test partition: recall{" "}
                {pct(live.metrics.cross_dataset.metrics.binary.recall)} at FPR{" "}
                {pct(live.metrics.cross_dataset.metrics.binary.false_positive_rate)} (trained on{" "}
                {live.metrics.cross_dataset.trained_on.join(", ")}). This measures cross-dataset
                generalisation only — the live classifier above is trained on all three datasets.
              </span>
            </div>
          )}
        </Panel>

        <Panel title="Confusion matrix" hint="test split (binary)">
          <Confusion matrix={live.metrics.test?.binary?.confusion_matrix} />
          <div className="mono dim" style={{ marginTop: 12, fontSize: 10.5 }}>
            Multiclass macro F1: {live.metrics.test?.multiclass?.macro_f1?.toFixed(3) ?? "—"}
          </div>
          <div className="mono dim" style={{ fontSize: 10.5 }}>
            Candidate selection:{" "}
            {live.candidates
              ? Object.entries(live.candidates)
                  .map(([name, value]) => `${name} ${value.validation_macro_f1.toFixed(3)}`)
                  .join(" · ")
              : "—"}
          </div>
        </Panel>
      </div>

      <div className="grid cols-3">
        <Panel title="Runtime behaviour" hint="since first event">
          <KeyValue
            rows={[
              ["Predictions", <span className="mono">{formatNumber(runtime?.predictions)}</span>],
              ["Unclassified events", <span className="mono">{formatNumber(runtime?.unclassified_events)}</span>],
              ["Avg latency", <span className="mono">{runtime?.latency_percentiles.avg_ms ?? "—"} ms</span>],
              ["p50 / p95 latency", <span className="mono">{runtime?.latency_percentiles.p50_ms ?? "—"} / {runtime?.latency_percentiles.p95_ms ?? "—"} ms</span>],
              ["Max latency", <span className="mono">{runtime?.latency_percentiles.max_ms ?? "—"} ms</span>],
              ["Predictions / second", <span className="mono">{runtime?.predictions_per_second.toFixed(2)}</span>],
            ]}
          />
          <div style={{ marginTop: 14 }}>
            <div className="panel-hint" style={{ marginBottom: 6 }}>Predicted label counts</div>
            <BarList
              items={Object.entries(runtime?.prediction_count_by_label ?? {}).map(([label, value]) => ({ label, value }))}
              emptyLabel="No predictions yet"
            />
          </div>
        </Panel>

        <Panel title="Confidence distribution" hint="live predictions">
          <HistogramChart data={runtime?.confidence_histogram ?? []} />
        </Panel>

        <Panel title="Feature schema" hint="shared by training and inference">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {(live.feature_schema ?? []).map((feature) => (
              <span key={feature} className="tag">
                {feature}
              </span>
            ))}
          </div>
          <div style={{ marginTop: 14 }}>
            <div className="panel-hint" style={{ marginBottom: 6 }}>Top permutation importance</div>
            <BarList
              items={(live.top_features ?? []).map((item) => ({ label: item.feature, value: Number(item.importance.toFixed(4)) }))}
              emptyLabel="Importance not available"
            />
          </div>
        </Panel>
      </div>

      <div className="grid cols-2">
        <Panel title="CICIDS2017 batch model (separate)" hint="offline DVC / MLflow pipeline">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
            <Pill text="batch model" tone="neutral" />
            <Pill text={batch?.best_model ?? "not trained"} tone="info" />
            <Pill text={batch?.training_results_available ? "reports present" : "reports missing"} tone={batch?.training_results_available ? "ok" : "warn"} />
          </div>
          <div className="mono dim" style={{ fontSize: 11, marginBottom: 10 }}>{batch?.task}</div>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Val F1</th>
                  <th>Val accuracy</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(batch?.validation_metrics ?? {}).map(([name, metrics]) => (
                  <tr key={name}>
                    <td className="mono">{name}</td>
                    <td className="mono">{metrics.f1_score?.toFixed(4) ?? metrics.f1?.toFixed(4) ?? "—"}</td>
                    <td className="mono">{metrics.accuracy?.toFixed(4) ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: 12 }}>
            <KeyValue
              rows={[
                ["Test metrics", <span className="mono">{batch?.test_metrics ? Object.entries(batch.test_metrics).map(([k, v]) => `${k} ${typeof v === "number" ? v.toFixed(4) : v}`).join(" · ") : "—"}</span>],
              ]}
            />
          </div>
          <ul className="mono dim" style={{ fontSize: 11, paddingLeft: 16, marginTop: 10 }}>
            {batch?.notes.map((note) => (
              <li key={note} style={{ marginBottom: 4 }}>{note}</li>
            ))}
          </ul>
        </Panel>

        <Panel title="Known limitations" hint="read before trusting a prediction">
          <ul className="mono" style={{ fontSize: 11.5, lineHeight: 1.7, paddingLeft: 16, color: "var(--muted)" }}>
            {live.notes.map((note) => (
              <li key={note} style={{ marginBottom: 6 }}>{note}</li>
            ))}
          </ul>
          <div className="mono dim" style={{ fontSize: 10.5, marginTop: 10 }}>
            Environment: Python {live.environment?.python} · numpy {live.environment?.numpy} · pandas {live.environment?.pandas}
          </div>
        </Panel>
      </div>
    </>
  );
}
