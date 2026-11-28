import { useState } from "react";

import { ErrorBox, KeyValue, Loading, Panel, Pill, StatCard } from "../components/ui";
import { api, type ModelInfo } from "../lib/api";
import { formatDateTime, formatNumber, relativeFrom } from "../lib/format";
import { usePolled } from "../lib/usePolled";

function ModelCard({ model }: { model: ModelInfo }) {
  const [showFeatures, setShowFeatures] = useState(false);
  const runtime = model.runtime;

  return (
    <Panel
      title={model.name}
      hint={model.task}
      actions={
        <div className="row-gap">
          <Pill text={model.loaded ? "loaded" : "unavailable"} tone={model.loaded ? "ok" : "bad"} pulse={model.loaded} />
          <Pill
            text={model.experimental ? "experimental" : "validated"}
            tone={model.experimental ? "warn" : "info"}
            title={model.experimental ? "trained on synthetic records" : "trained on CICIDS2017"}
          />
        </div>
      }
    >
      {model.experimental && (
        <div className="banner warn">
          This model was trained on 300 synthetic connection records. Its labels are a pipeline
          wiring test, not threat intelligence — do not treat them as production-grade detections.
        </div>
      )}
      {!model.loaded && <ErrorBox error={model.error ?? "artefact not loaded"} />}

      <div className="model-stats">
        <StatCard label="Predictions" value={formatNumber(runtime.predictions)} small />
        <StatCard label="Scored" value={formatNumber(runtime.scored)} accent="green" small />
        <StatCard label="Unclassified" value={formatNumber(runtime.unclassified)} accent="amber" small />
        <StatCard label="Last inference" value={relativeFrom(runtime.last_inference_ts)} accent="violet" small />
      </div>

      <KeyValue
        rows={[
          ["Estimator", <span className="mono">{model.estimator ?? "—"}</span>],
          ["Version", <span className="mono">{model.version ?? "—"}</span>],
          ["Schema", <span className="mono">{model.schema.schema_version ?? "—"}</span>],
          ["Input features", String(model.schema.features ?? "—")],
          ["Features to estimator", String(model.schema.model_features ?? "—")],
          ["Classes", <span className="mono">{(model.classes ?? []).join(", ") || "—"}</span>],
          [
            "Threshold",
            model.schema.threshold === null || model.schema.threshold === undefined ? "—" : String(model.schema.threshold),
          ],
          ["Loaded at", formatDateTime(model.loaded_at)],
          ["Last inference", formatDateTime(runtime.last_inference_ts)],
          ["Artefact", <span className="mono tiny">{model.artifact?.path ?? "—"}</span>],
          [
            "Prediction latency",
            <span>
              not recorded — <span className="muted tiny">{model.latency.reason}</span>
            </span>,
          ],
        ]}
      />

      <h3>Labels seen</h3>
      {Object.keys(runtime.label_counts).length ? (
        <div className="label-chips">
          {Object.entries(runtime.label_counts).map(([label, count]) => (
            <span key={label} className="badge">
              {label} · {formatNumber(count)}
            </span>
          ))}
        </div>
      ) : (
        <p className="muted small">No inference recorded yet for this model.</p>
      )}

      {model.schema.feature_names && model.schema.feature_names.length > 0 && (
        <>
          <button type="button" className="chip-button" onClick={() => setShowFeatures((open) => !open)}>
            {showFeatures ? "hide" : "show"} feature schema ({model.schema.feature_names.length})
          </button>
          {showFeatures && <pre className="json">{model.schema.feature_names.join("\n")}</pre>}
        </>
      )}

      <h3>Notes</h3>
      <ul className="notes">
        {model.notes.map((note) => (
          <li key={note}>{note}</li>
        ))}
      </ul>
    </Panel>
  );
}

export function ModelPage() {
  const { data, error, loading } = usePolled(() => api.models(), 10000, []);

  if (loading && !data) return <Loading label="Loading model status" />;

  return (
    <>
      <ErrorBox error={error} />
      {data && (
        <>
          <div className="stat-grid">
            <StatCard
              label="CICIDS model"
              value={data.models.cicids.loaded ? "loaded" : "down"}
              accent={data.models.cicids.loaded ? "green" : "red"}
              foot="CICIDS2017 flow classifier"
            />
            <StatCard
              label="Zeek model"
              value={data.models.zeek.loaded ? "loaded" : "down"}
              accent="amber"
              foot="experimental · synthetic training set"
            />
            <StatCard label="Detections stored" value={formatNumber(Number(data.counts.detections ?? 0))} accent="violet" />
            <StatCard label="Unclassified records" value={formatNumber(Number(data.counts.unclassified ?? 0))} accent="amber" />
          </div>

          <div className="grid-2">
            <ModelCard model={data.models.cicids} />
            <ModelCard model={data.models.zeek} />
          </div>

          <Panel title="Severity policy" hint="the only derived value the dashboard applies">
            <p className="small">{data.severity_policy.description}</p>
            <table className="data-table dense">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Applies to</th>
                  <th className="num">Minimum confidence</th>
                </tr>
              </thead>
              <tbody>
                {data.severity_policy.bands.map((band) => (
                  <tr key={band.severity}>
                    <td>{band.severity}</td>
                    <td>{band.attack === null ? "unscored records" : band.attack ? "attacks" : "non-attacks"}</td>
                    <td className="num mono">{band.min_confidence.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        </>
      )}
    </>
  );
}
