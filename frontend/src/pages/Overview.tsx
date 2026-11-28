import { useState } from "react";

import {
  DonutChart,
  EventsOverTimeChart,
  HistogramChart,
  TopIpsChart,
  TrafficVolumeChart,
} from "../components/Charts";
import { DetectionDrawer } from "../components/EventDrawer";
import { DetectionTable } from "../components/EventTable";
import { ErrorBox, Loading, NoEventsNotice, Panel, Pill, StatCard } from "../components/ui";
import { api } from "../lib/api";
import { confidence, formatNumber, relativeSeconds } from "../lib/format";
import { usePolled } from "../lib/usePolled";

const WINDOWS = [
  { label: "15 min", value: 900 },
  { label: "1 hour", value: 3600 },
  { label: "6 hours", value: 21600 },
  { label: "24 hours", value: 86400 },
];

export function OverviewPage() {
  const [windowS, setWindowS] = useState(3600);
  const [openId, setOpenId] = useState<string | null>(null);
  const { data, error, loading } = usePolled(() => api.overview(windowS), 3000, [windowS]);

  if (loading && !data) return <Loading label="Loading overview" />;

  return (
    <>
      <ErrorBox error={error} />
      {data && (
        <>
          {data.activity.no_new_events && <NoEventsNotice message="No new network events received." />}

          <div className="toolbar">
            <div className="toolbar-group">
              <span className="toolbar-label">window</span>
              {WINDOWS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  className={`chip-button ${windowS === option.value ? "active" : ""}`}
                  onClick={() => setWindowS(option.value)}
                >
                  {option.label}
                </button>
              ))}
            </div>
            <div className="toolbar-group">
              <span className="muted tiny">
                updated {relativeSeconds((Date.now() - data.server_time * 1000) / 1000)} · bucket {data.bucket_s}s
              </span>
            </div>
          </div>

          <div className="stat-grid">
            <StatCard
              label="Network events"
              value={formatNumber(data.totals.events)}
              foot={`${data.rates.events_per_second.toFixed(3)}/s over last ${data.rates.window_s / 60} min`}
            />
            <StatCard label="Scored records" value={formatNumber(data.totals.scored)} accent="violet" foot="model produced a label" />
            <StatCard
              label="Detected attacks"
              value={formatNumber(data.totals.attacks)}
              accent="red"
              foot={`${data.rates.attacks_per_second.toFixed(3)} attacks/s`}
            />
            <StatCard label="Benign" value={formatNumber(data.totals.benign)} accent="green" foot="classified as BENIGN" />
            <StatCard
              label="Unclassified"
              value={formatNumber(data.totals.unclassified)}
              accent="amber"
              foot="model could not score the record"
            />
            <StatCard
              label="Detection rate"
              value={data.totals.detection_rate === null ? "—" : `${(data.totals.detection_rate * 100).toFixed(1)}%`}
              accent="orange"
              foot="attacks / scored records"
            />
            <StatCard
              label="Sensors online"
              value={`${data.sensors.online}/${data.sensors.total}`}
              accent={data.sensors.online > 0 ? "green" : "amber"}
              foot={`silent threshold ${data.sensors.stale_after_s}s`}
            />
            <StatCard label="Dead letters" value={formatNumber(data.totals.dead_letters)} accent="amber" foot="unparsable records" />
          </div>

          <div className="grid-2">
            <Panel
              title="Events over time"
              hint={`predictions and attacks per ${data.bucket_s}s bucket`}
              actions={<Pill text={`${data.window_s / 60} min window`} tone="neutral" />}
            >
              <EventsOverTimeChart series={data.series} />
            </Panel>
            <Panel title="Benign vs malicious" hint="scored records only; unclassified stay unknown">
              <DonutChart
                data={[
                  { label: "benign", count: data.totals.benign },
                  { label: "attacks", count: data.totals.attacks },
                ]}
                emptyLabel="No scored records yet"
              />
            </Panel>
          </div>

          <div className="grid-3">
            <Panel title="Severity distribution" hint="rule bands over model confidence" className="span-1">
              <DonutChart data={data.distributions.severities} height={150} emptyLabel="No detections yet" />
            </Panel>
            <Panel title="Confidence distribution" hint="every scored record, 0.0 – 1.0">
              <HistogramChart data={data.distributions.confidence} />
            </Panel>
            <Panel title="Protocols" hint="from Zeek conn records">
              <DonutChart data={data.distributions.protocols} height={150} emptyLabel="No protocols yet" />
            </Panel>
          </div>

          <div className="grid-2">
            <Panel title="Top source addresses" hint="most frequent client IPs">
              <TopIpsChart data={data.distributions.top_src_ips} />
            </Panel>
            <Panel title="Top destination addresses" hint="most frequent server IPs">
              <TopIpsChart data={data.distributions.top_dst_ips} color="#8d6bff" />
            </Panel>
          </div>

          <Panel title="Traffic volume" hint="bytes derived from Zeek conn records">
            <TrafficVolumeChart series={data.series} />
          </Panel>

          <Panel
            title="Recent security events"
            hint="latest stored detections; click a row for the full record"
            actions={
              <span className="muted tiny">
                CICIDS loaded: {String(data.models.cicids.loaded)} · highest confidence{" "}
                {confidence(data.recent[0]?.confidence ?? null)}
              </span>
            }
          >
            <DetectionTable rows={data.recent} onOpen={setOpenId} dense />
          </Panel>
        </>
      )}
      <DetectionDrawer id={openId} onClose={() => setOpenId(null)} />
    </>
  );
}
