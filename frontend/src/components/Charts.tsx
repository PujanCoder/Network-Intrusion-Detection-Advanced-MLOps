import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { DistributionItem, SeriesPoint } from "../lib/api";
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

function tooltipTime(label: unknown): string {
  if (typeof label === "number") return formatTime(label);
  return String(label);
}

export function RateChart({ series }: { series: SeriesPoint[] }) {
  if (!series.length) return <EmptyState title="No traffic yet" detail="Charts populate as events arrive." />;
  return (
    <ResponsiveContainer width="100%" height={230}>
      <LineChart data={series} margin={{ top: 6, right: 8, bottom: 0, left: -14 }}>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="t" tickFormatter={(value) => formatTime(value)} {...axisStyle} minTickGap={28} />
        <YAxis allowDecimals={false} {...axisStyle} />
        <Tooltip
          labelFormatter={tooltipTime}
          formatter={(value: any, name: any) => [value, name === "events" ? "events/s" : "predictions/s"]}
        />
        <Line type="monotone" dataKey="events" stroke="#24d4e2" strokeWidth={1.8} dot={false} name="events" />
        <Line type="monotone" dataKey="predictions" stroke="#8d6bff" strokeWidth={1.6} dot={false} name="predictions" />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function TrafficVolumeChart({ series }: { series: SeriesPoint[] }) {
  if (!series.length) return <EmptyState title="No volume recorded yet" />;
  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={series} margin={{ top: 6, right: 8, bottom: 0, left: -6 }}>
        <defs>
          <linearGradient id="bytesFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#24d4e2" stopOpacity={0.45} />
            <stop offset="100%" stopColor="#24d4e2" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="t" tickFormatter={(value) => formatTime(value)} {...axisStyle} minTickGap={30} />
        <YAxis tickFormatter={(value) => formatBytes(value)} {...axisStyle} width={54} />
        <Tooltip labelFormatter={tooltipTime} formatter={(value: any) => [formatBytes(Number(value)), "bytes"]} />
        <Area type="monotone" dataKey="bytes" stroke="#24d4e2" strokeWidth={1.6} fill="url(#bytesFill)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function DonutChart({
  data,
  colors = CHART_COLORS,
  height = 190,
  emptyLabel = "No data",
}: {
  data: DistributionItem[];
  colors?: string[];
  height?: number;
  emptyLabel?: string;
}) {
  const filtered = data.filter((item) => item.count > 0);
  if (!filtered.length) return <EmptyState title={emptyLabel} />;
  const total = filtered.reduce((sum, item) => sum + item.count, 0);

  let cursor = 0;
  const stops = filtered.map((entry, index) => {
    const from = (cursor / total) * 100;
    cursor += entry.count;
    const to = (cursor / total) * 100;
    return `${colors[index % colors.length]} ${from.toFixed(2)}% ${to.toFixed(2)}%`;
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <div
        role="img"
        aria-label={filtered.map((entry) => `${entry.label}: ${entry.count}`).join(", ")}
        style={{
          width: height,
          height: height,
          flex: "0 0 auto",
          borderRadius: "50%",
          background: `conic-gradient(${stops.join(", ")})`,
          WebkitMask: "radial-gradient(circle, transparent 57%, #000 58%)",
          mask: "radial-gradient(circle, transparent 57%, #000 58%)",
        }}
      />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 7, minWidth: 0 }}>
        {filtered.slice(0, 8).map((entry, index) => (
          <div key={entry.label} style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 12 }}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
              <span className="swatch" style={{ background: colors[index % colors.length] }} />
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
  height = 220,
  color = "#8d6bff",
  emptyLabel = "No data",
}: {
  data: DistributionItem[];
  height?: number;
  color?: string;
  emptyLabel?: string;
}) {
  if (!data.length) return <EmptyState title={emptyLabel} />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: -18 }}>
        <CartesianGrid stroke="#122034" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="label" {...axisStyle} interval={0} angle={data.length > 5 ? -18 : 0} textAnchor={data.length > 5 ? "end" : "middle"} height={data.length > 5 ? 46 : 26} />
        <YAxis allowDecimals={false} {...axisStyle} />
        <Tooltip />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((entry, index) => (
            <Cell key={entry.label} fill={index === 0 ? color : `${color}b0`} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function HistogramChart({
  data,
  height = 190,
  color = "#24d4e2",
}: {
  data: { bucket: string; count: number }[];
  height?: number;
  color?: string;
}) {
  const hasData = data.some((item) => item.count > 0);
  if (!hasData) return <EmptyState title="No predictions yet" />;
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
  height = 240,
  color = "#24d4e2",
  emptyLabel = "No IPs recorded yet",
}: {
  data: { ip: string; count: number }[];
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
        <YAxis type="category" dataKey="ip" width={118} {...axisStyle} />
        <Tooltip />
        <Bar dataKey="count" fill={color} radius={[0, 4, 4, 0]} barSize={13} />
      </BarChart>
    </ResponsiveContainer>
  );
}
