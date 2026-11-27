import type { ReactNode } from "react";

export function Panel({
  title,
  hint,
  children,
  className = "",
}: {
  title?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || hint) && (
        <div className="panel-head">
          {title && <div className="panel-title">{title}</div>}
          {hint && <div className="panel-hint">{hint}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatCard({
  label,
  value,
  foot,
  accent = "cyan",
  small = false,
}: {
  label: string;
  value: ReactNode;
  foot?: ReactNode;
  accent?: "cyan" | "green" | "red" | "amber" | "violet" | "orange";
  small?: boolean;
}) {
  return (
    <div className={`stat accent-${accent}`}>
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${small ? "small" : ""}`}>{value}</div>
      {foot !== undefined && <div className="stat-foot">{foot}</div>}
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {detail && <div>{detail}</div>}
    </div>
  );
}

export function Chip({ text, className }: { text: string; className: string }) {
  return <span className={`chip ${className}`}>{text}</span>;
}

export function Pill({
  text,
  tone = "info",
  pulse = false,
}: {
  text: string;
  tone?: "ok" | "warn" | "bad" | "info" | "neutral";
  pulse?: boolean;
}) {
  const cls = tone === "neutral" ? "pill" : `pill ${tone}`;
  return (
    <span className={cls}>
      <span className={`dot ${pulse ? "pulse" : ""}`} />
      {text}
    </span>
  );
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="error-box">{error}</div>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return <div className="loading">{label}…</div>;
}

export function BarList({
  items,
  color,
  emptyLabel,
}: {
  items: { label: string; value: number }[];
  color?: string;
  emptyLabel: string;
}) {
  if (!items.length) return <EmptyState title={emptyLabel} />;
  const max = Math.max(...items.map((item) => item.value), 1);
  return (
    <div>
      {items.map((item) => (
        <div key={item.label} className="bar-row">
          <div>
            <div className="mono">{item.label}</div>
            <div className="bar-track">
              <div
                className="bar-fill"
                style={{ width: `${Math.max(3, (item.value / max) * 100)}%`, background: color }}
              />
            </div>
          </div>
          <div className="mono muted">{item.value.toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}

export function KeyValue({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([key, value]) => (
        <div key={key} style={{ display: "contents" }}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
