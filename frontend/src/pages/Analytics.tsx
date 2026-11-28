import {
  DistributionBarChart,
  DonutChart,
  EventsOverTimeChart,
  HistogramChart,
  TopIpsChart,
  TrafficVolumeChart,
} from "../components/Charts";
import { ErrorBox, Loading, Panel, StatCard } from "../components/ui";
import { api } from "../lib/api";
import { formatNumber } from "../lib/format";
import { usePolled } from "../lib/usePolled";

export function AnalyticsPage() {
  const { data, error, loading } = usePolled(() => api.overview(86400), 5000, []);

  if (loading && !data) return <Loading label="Loading analytics" />;

  return (
    <>
      <ErrorBox error={error} />
      {data && (
        <>
          <div className="stat-grid">
            <StatCard label="Records (24h)" value={formatNumber(data.totals.detections)} foot="detections in window" />
            <StatCard label="Events stored" value={formatNumber(data.totals.events)} accent="violet" foot="Zeek records" />
            <StatCard label="Attacks" value={formatNumber(data.totals.attacks)} accent="red" />
            <StatCard label="Benign" value={formatNumber(data.totals.benign)} accent="green" />
          </div>

          <Panel title="Volume over time" hint={`per ${data.bucket_s}s bucket, last 24h`}>
            <EventsOverTimeChart series={data.series} height={260} />
          </Panel>

          <div className="grid-2">
            <Panel title="Traffic volume" hint="bytes from Zeek conn records">
              <TrafficVolumeChart series={data.series} />
            </Panel>
            <Panel title="Protocol distribution">
              <DonutChart data={data.distributions.protocols} emptyLabel="No protocols yet" />
            </Panel>
          </div>

          <div className="grid-2">
            <Panel title="Top sources">
              <TopIpsChart data={data.distributions.top_src_ips} />
            </Panel>
            <Panel title="Top destinations">
              <TopIpsChart data={data.distributions.top_dst_ips} color="#8d6bff" />
            </Panel>
          </div>

          <div className="grid-2">
            <Panel title="Log types" hint="Zeek log families ingested">
              <DistributionBarChart data={data.distributions.log_types} color="#24d4e2" />
            </Panel>
            <Panel title="Confidence distribution">
              <HistogramChart data={data.distributions.confidence} height={210} />
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
