import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { BucketCount, DistributionItem, IpCount, SeriesPoint } from "../lib/api";
import { formatBytes, formatTime } from "../lib/format";
import { EmptyState } from "./ui";

export const CHART_COLORS = [
  "#24d4e2",
  "#8d6bff",
  "#ff5b6e",
  "#f3b23f",
  "#31d39b",
  "#ff8a4c",
  "#59a8ff",
  "#ff7ad4",
  "#a3b1c6",
  "#5ee6c0",
  "#c9b8ff",
  "#ffd166",
];

const axisStyle = { stroke: "#22344f", tick: { fill: "#55677f", fontSize: 9.5 } };

// Semantic colours: a slice keeps its meaning whatever order the API returns.
const LABEL_COLOURS: Record<string, string> = {
  BENIGN: "#31d39b",
  benign: "#31d39b",
  attacks: "#ff5b6e",
  CRITICAL: "#ff5b6e",
  HIGH: "#ff8a4c",
  MEDIUM: "#f3b23f",
  LOW: "#59a8ff",
  INFO: "#7c90aa",
  UNKNOWN: "#55677f",
  UNCLASSIFIED: "#55677f",
};

function colourFor(label: string, index: number): string {
  return LABEL_COLOURS[label] ?? CHART_COLORS[index % CHART_COLORS.length];
}

function tooltipTime(label: unknown): string {
  if (typeof label === "number") return formatTime(label);
  return String(label);
}

export function EventsOverTimeChart({ series, height = 236 }: { series: SeriesPoint[]; height?: number }) {
  const hasData = series.some((point) => point.predictions > 0);
  if (!hasData) return <EmptyState title="No events in this window" detail="Charts fill as traffic is ingested." />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={series} margin={{ top: 8, right: 10, bottom: 0, left: -16 }}>
        <defs>
          <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#24d4e2" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#24d4e2" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="attackFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ff5b6e" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#ff5b6e" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="t" tickFormatter={(value) => formatTime(value)} {...axisStyle} minTickGap={28} />
        <YAxis allowDecimals={false} {...axisStyle} />
        <Tooltip labelFormatter={tooltipTime} />
        <Area type="monotone" dataKey="predictions" name="predictions" stroke="#24d4e2" strokeWidth={1.7} fill="url(#eventsFill)" />
        <Area type="monotone" dataKey="attacks" name="attacks" stroke="#ff5b6e" strokeWidth={1.5} fill="url(#attackFill)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function TrafficVolumeChart({ series, height = 190 }: { series: SeriesPoint[]; height?: number }) {
  const hasData = series.some((point) => point.bytes > 0);
  if (!hasData) return <EmptyState title="No byte counters in this window" detail="Zeek conn records carry byte totals." />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={series} margin={{ top: 6, right: 8, bottom: 0, left: -4 }}>
        <defs>
          <linearGradient id="bytesFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#8d6bff" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#8d6bff" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="t" tickFormatter={(value) => formatTime(value)} {...axisStyle} minTickGap={30} />
        <YAxis tickFormatter={(value) => formatBytes(value)} {...axisStyle} width={56} />
        <Tooltip labelFormatter={tooltipTime} formatter={(value) => [formatBytes(Number(value)), "bytes"]} />
        <Area type="monotone" dataKey="bytes" stroke="#8d6bff" strokeWidth={1.5} fill="url(#bytesFill)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function DonutChart({
  data,
  colors,
  semantic = true,
  height = 180,
  emptyLabel = "No data",
}: {
  data: DistributionItem[];
  colors?: string[];
  semantic?: boolean;
  height?: number;
  emptyLabel?: string;
}) {
  const palette = (label: string, index: number) =>
    semantic ? colourFor(label, index) : (colors ?? CHART_COLORS)[index % (colors ?? CHART_COLORS).length];
  const filtered = data.filter((item) => item.count > 0);
  if (!filtered.length) return <EmptyState title={emptyLabel} />;
  const total = filtered.reduce((sum, item) => sum + item.count, 0);

  let cursor = 0;
  const stops = filtered.map((entry, index) => {
    const from = (cursor / total) * 100;
    cursor += entry.count;
    const to = (cursor / total) * 100;
    return `${palette(entry.label, index)} ${from.toFixed(2)}% ${to.toFixed(2)}%`;
  });

  return (
    <div className="donut">
      <div
        role="img"
        aria-label={filtered.map((entry) => `${entry.label}: ${entry.count}`).join(", ")}
        className="donut-ring"
        style={{ width: height, height, background: `conic-gradient(${stops.join(", ")})` }}
      />
      <div className="donut-legend">
        {filtered.slice(0, 8).map((entry, index) => (
          <div key={entry.label} className="legend-row">
            <span className="legend-label">
              <span className="swatch" style={{ background: palette(entry.label, index) }} />
              <span className="mono">{entry.label}</span>
            </span>
            <span className="mono muted">
              {entry.count.toLocaleString()} · {((entry.count / total) * 100).toFixed(1)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function DistributionBarChart({
  data,
  height = 210,
  color = "#8d6bff",
  emptyLabel = "No data",
}: {
  data: DistributionItem[];
  height?: number;
  color?: string;
  emptyLabel?: string;
}) {
  const filtered = data.filter((item) => item.count > 0);
  if (!filtered.length) return <EmptyState title={emptyLabel} />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={filtered} margin={{ top: 6, right: 8, bottom: 0, left: -18 }}>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" vertical={false} />
        <XAxis
          dataKey="label"
          {...axisStyle}
          interval={0}
          angle={filtered.length > 5 ? -18 : 0}
          textAnchor={filtered.length > 5 ? "end" : "middle"}
          height={filtered.length > 5 ? 48 : 26}
        />
        <YAxis allowDecimals={false} {...axisStyle} />
        <Tooltip />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {filtered.map((entry, index) => (
            <Cell key={entry.label} fill={index === 0 ? color : `${color}b0`} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function HistogramChart({
  data,
  height = 180,
  color = "#24d4e2",
}: {
  data: BucketCount[];
  height?: number;
  color?: string;
}) {
  const hasData = data.some((item) => item.count > 0);
  if (!hasData) return <EmptyState title="No scored records yet" />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: -20 }}>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="bucket" {...axisStyle} interval={1} />
        <YAxis allowDecimals={false} {...axisStyle} />
        <Tooltip />
        <Bar dataKey="count" fill={color} radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TopIpsChart({
  data,
  height = 226,
  color = "#24d4e2",
  emptyLabel = "No addresses recorded yet",
}: {
  data: IpCount[];
  height?: number;
  color?: string;
  emptyLabel?: string;
}) {
  if (!data.length) return <EmptyState title={emptyLabel} />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 18, bottom: 0, left: 8 }}>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" horizontal={false} />
        <XAxis type="number" allowDecimals={false} {...axisStyle} />
        <YAxis type="category" dataKey="ip" width={122} {...axisStyle} />
        <Tooltip />
        <Bar dataKey="count" fill={color} radius={[0, 4, 4, 0]} barSize={12} />
      </BarChart>
    </ResponsiveContainer>
  );
}
