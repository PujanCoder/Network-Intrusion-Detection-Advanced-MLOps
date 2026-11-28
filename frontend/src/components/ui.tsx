import type { ReactNode } from "react";

import type { Severity, Source } from "../lib/api";
import { severityTone } from "../lib/format";

export function Panel({
  title,
  hint,
  children,
  className = "",
  actions,
}: {
  title?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || hint || actions) && (
        <div className="panel-head">
          <div>
            {title && <div className="panel-title">{title}</div>}
            {hint && <div className="panel-hint">{hint}</div>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
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

export function Pill({
  text,
  tone = "info",
  pulse = false,
  title,
}: {
  text: string;
  tone?: "ok" | "warn" | "bad" | "info" | "neutral";
  pulse?: boolean;
  title?: string;
}) {
  const cls = tone === "neutral" ? "pill" : `pill ${tone}`;
  return (
    <span className={cls} title={title}>
      <span className={`dot ${pulse ? "pulse" : ""}`} />
      {text}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`badge ${severityTone(severity)}`}>{severity}</span>;
}

export function SourceBadge({ source, experimental }: { source: Source; experimental?: boolean }) {
  return (
    <span className={`badge src-${source}`} title={experimental ? "experimental model" : "validated model"}>
      {source}
      {experimental ? " · exp" : ""}
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
              <div className="bar-fill" style={{ width: `${Math.max(3, (item.value / max) * 100)}%`, background: color }} />
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

export function NoEventsNotice({ message = "No new network events received." }: { message?: string }) {
  return (
    <div className="notice">
      <span className="dot warn" />
      {message}
    </div>
  );
}
