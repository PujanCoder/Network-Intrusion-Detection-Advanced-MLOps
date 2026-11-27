import {
  CHART_COLORS,
  DistributionBarChart,
  DonutChart,
  RateChart,
  TopIpsChart,
  TrafficVolumeChart,
} from "../components/Charts";
import { BarList, EmptyState, Panel, StatCard } from "../components/ui";
import type { Analytics } from "../lib/api";
import { getJson } from "../lib/api";
import { useLive } from "../lib/LiveContext";
import { formatBytes, formatNumber } from "../lib/format";
import { usePolled } from "../lib/usePolled";

export function AnalyticsPage() {
  const live = useLive();
  const overview = live.overview;
  const analytics = usePolled<Analytics>(() => getJson<Analytics>("/api/analytics?window=3600"), 5000);

  const data = analytics.data;
  const mix = overview
    ? [
        { label: "Benign", count: overview.benign },
        { label: "Attacks", count: overview.attacks },
        { label: "Suspicious", count: overview.suspicious },
        { label: "Unclassified", count: overview.unclassified },
      ]
    : [];

  const totalBytes = (data?.series ?? []).reduce((sum, point) => sum + (point.bytes || 0), 0);

  return (
    <>
      <div className="grid cols-4">
        <StatCard label="Events (1h)" value={formatNumber(overview?.total_events)} accent="cyan" />
        <StatCard
          label="Events / second"
          value={overview ? (overview.events_per_second_live ?? overview.events_per_second).toFixed(2) : "—"}
          foot={`${overview?.burst_window_s ?? 10}s window`}
          accent="violet"
        />
        <StatCard label="Volume (1h)" value={formatBytes(totalBytes)} accent="green" />
        <StatCard label="Attack share" value={overview && overview.total_events ? `${((overview.attacks / overview.total_events) * 100).toFixed(1)}%` : "—"} accent="red" />
      </div>

      {analytics.error && <div className="error-box">{analytics.error}</div>}

      <div className="grid cols-2">
        <Panel title="Events and predictions per second" hint="15 minute window">
          <RateChart series={data?.series ?? []} />
        </Panel>
        <Panel title="Traffic volume over time" hint="bytes per bucket">
          <TrafficVolumeChart series={data?.series ?? []} />
        </Panel>
      </div>

      <div className="grid cols-3">
        <Panel title="Benign vs suspicious" hint="all events">
          <DonutChart data={mix} colors={["#31d39b", "#ff5b6e", "#f3b23f", "#7c90aa"]} emptyLabel="No events yet" />
        </Panel>
        <Panel title="Attack distribution" hint="by predicted class">
          <DonutChart
            data={data?.attack_distribution ?? []}
            colors={CHART_COLORS.slice(2)}
            emptyLabel="No attacks detected yet"
          />
        </Panel>
        <Panel title="Protocol distribution" hint="transport protocol">
          <DonutChart
            data={data?.protocol_distribution ?? []}
            colors={["#24d4e2", "#8d6bff", "#f3b23f", "#31d39b"]}
            emptyLabel="No protocol data yet"
          />
        </Panel>
      </div>

      <div className="grid cols-2">
        <Panel title="Top source addresses" hint="last hour">
          <TopIpsChart data={data?.top_src_ips ?? []} color="#24d4e2" />
        </Panel>
        <Panel title="Top destination addresses" hint="last hour">
          <TopIpsChart data={data?.top_dst_ips ?? []} color="#8d6bff" />
        </Panel>
      </div>

      <div className="grid cols-3">
        <Panel title="Severity distribution" hint="ML severity + rule alerts">
          <DistributionBarChart data={data?.severity_distribution ?? []} color="#f3b23f" emptyLabel="No severities yet" />
        </Panel>
        <Panel title="Predicted classes" hint="live model output">
          {data && Object.keys(data.prediction_counts).length ? (
            <BarList
              items={Object.entries(data.prediction_counts)
                .map(([label, value]) => ({ label, value }))
                .sort((a, b) => b.value - a.value)}
              emptyLabel="No predictions yet"
            />
          ) : (
            <EmptyState title="No predictions yet" />
          )}
        </Panel>
        <Panel title="Confidence distribution" hint="all predictions">
          <BarList
            items={(data?.confidence_histogram ?? []).map((item) => ({ label: item.bucket, value: item.count }))}
            color="linear-gradient(90deg,#8d6bff,#24d4e2)"
            emptyLabel="No predictions yet"
          />
        </Panel>
      </div>
    </>
  );
}
