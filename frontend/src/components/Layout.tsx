import type { ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";

import { useLive } from "../lib/LiveContext";
import { relativeSeconds } from "../lib/format";
import { Pill } from "./ui";

const NAV = [
  { to: "/", label: "Overview", icon: "shield" },
  { to: "/stream", label: "Live stream", icon: "activity" },
  { to: "/analytics", label: "Traffic analytics", icon: "chart" },
  { to: "/attacks", label: "Attack monitoring", icon: "target" },
  { to: "/model", label: "Model monitoring", icon: "cpu" },
  { to: "/explorer", label: "Event explorer", icon: "search" },
  { to: "/sensors", label: "Sensor health", icon: "antenna" },
] as const;

const TITLES: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Live security overview", subtitle: "Sensor · detection · model status" },
  "/stream": { title: "Live prediction stream", subtitle: "Every record processed by the pipeline" },
  "/analytics": { title: "Real-time traffic analytics", subtitle: "Volume, distribution and top talkers" },
  "/attacks": { title: "Attack monitoring", subtitle: "Detections with supporting evidence" },
  "/model": { title: "Model monitoring", subtitle: "Live Zeek classifier vs CICIDS2017 batch model" },
  "/explorer": { title: "Network event explorer", subtitle: "Search, filter, inspect and export" },
  "/sensors": { title: "Sensor monitoring", subtitle: "Zeek, ingestion, database, API and WebSocket" },
};

function Icon({ name }: { name: string }) {
  const common = {
    width: 17,
    height: 17,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.7,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
  switch (name) {
    case "shield":
      return (
        <svg {...common}>
          <path d="M12 3 5 6v5.5c0 4.4 2.9 8.2 7 9.5 4.1-1.3 7-5.1 7-9.5V6l-7-3Z" />
          <path d="m9 12 2 2 4-4" />
        </svg>
      );
    case "activity":
      return (
        <svg {...common}>
          <path d="M3 12h3l2.5-7 4 14 2.5-7H21" />
        </svg>
      );
    case "chart":
      return (
        <svg {...common}>
          <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />
        </svg>
      );
    case "target":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="8" />
          <circle cx="12" cy="12" r="3.4" />
          <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
        </svg>
      );
    case "cpu":
      return (
        <svg {...common}>
          <rect x="6" y="6" width="12" height="12" rx="2" />
          <path d="M10 2v3M14 2v3M10 19v3M14 19v3M2 10h3M2 14h3M19 10h3M19 14h3" />
        </svg>
      );
    case "search":
      return (
        <svg {...common}>
          <circle cx="11" cy="11" r="7" />
          <path d="m20 20-3.5-3.5" />
        </svg>
      );
    case "antenna":
      return (
        <svg {...common}>
          <path d="M12 20v-8" />
          <circle cx="12" cy="9" r="2.2" />
          <path d="M7.5 4.5a7 7 0 0 0 0 9.9M16.5 4.5a7 7 0 0 1 0 9.9" />
        </svg>
      );
    default:
      return null;
  }
}

export function Layout({ children }: { children: ReactNode }) {
  const live = useLive();
  const location = useLocation();
  const meta = TITLES[location.pathname] ?? TITLES["/"];
  const replayRecords = live.overview?.sensor?.replay_records ?? 0;
  const sensorMode = replayRecords > 0 ? "replay" : live.sensor?.mode ?? "unknown";
  const modelLoaded = live.model?.loaded ?? false;
  const lastEvent = live.overview?.seconds_since_last_event;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="#24d4e2" strokeWidth="1.6">
              <path d="M12 3 5 6v5.5c0 4.4 2.9 8.2 7 9.5 4.1-1.3 7-5.1 7-9.5V6l-7-3Z" />
              <path d="m9 12 2 2 4-4" stroke="#8d6bff" />
            </svg>
          </div>
          <div>
            <div className="brand-title">NDR SENTINEL</div>
            <div className="brand-sub">network defence</div>
          </div>
        </div>

        <div className="nav-label">Monitoring</div>
        <nav className="nav">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <Icon name={item.icon} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="row">
            <span>WS</span>
            <span style={{ color: live.connected ? "var(--green)" : "var(--red)" }}>
              {live.connected ? "connected" : "offline"}
            </span>
          </div>
          <div className="row">
            <span>sensor</span>
            <span>{live.sensor?.sensor_id ?? "—"}</span>
          </div>
          <div className="row">
            <span>mode</span>
            <span>{sensorMode}</span>
          </div>
          <div className="row">
            <span>model</span>
            <span style={{ color: modelLoaded ? "var(--green)" : "var(--amber)" }}>
              {modelLoaded ? "loaded" : "unavailable"}
            </span>
          </div>
          <div className="row">
            <span>last event</span>
            <span>{relativeSeconds(lastEvent)}</span>
          </div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div>
            <div className="page-title">{meta.title}</div>
            <div className="page-subtitle">{meta.subtitle}</div>
          </div>
          <div className="topbar-spacer" />
          <div className="status-cluster">
            <Pill
              text={live.connected ? "live" : "reconnecting"}
              tone={live.connected ? "ok" : "bad"}
              pulse={live.connected}
            />
            <Pill text={`sensor ${sensorMode}`} tone={sensorMode === "live" ? "ok" : "warn"} />
            <Pill text={`model ${modelLoaded ? "online" : "offline"}`} tone={modelLoaded ? "info" : "bad"} />
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
