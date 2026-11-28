import { useState } from "react";
import type { ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";

import { useAuth } from "../lib/auth";
import { useLive } from "../lib/LiveContext";
import { relativeSeconds } from "../lib/format";
import { Pill } from "./ui";

const NAV = [
  { to: "/", label: "Security overview", icon: "shield" },
  { to: "/live", label: "Live monitoring", icon: "activity" },
  { to: "/threats", label: "Threat detection", icon: "target" },
  { to: "/investigate", label: "Investigation", icon: "search" },
  { to: "/sensors", label: "Network sensors", icon: "antenna" },
  { to: "/models", label: "Model monitoring", icon: "cpu" },
  { to: "/system", label: "System health", icon: "pulse" },
] as const;

const SECONDARY = [{ to: "/analytics", label: "Traffic analytics", icon: "chart" }] as const;

const TITLES: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Security overview", subtitle: "Platform-wide detection posture, from stored events only" },
  "/live": { title: "Live network monitoring", subtitle: "Records as Zeek ingests them, with model output" },
  "/threats": { title: "Threat detection", subtitle: "Attack records with severity, model and evidence" },
  "/investigate": { title: "Detection investigation", subtitle: "Search, inspect, paginate and export stored detections" },
  "/sensors": { title: "Network sensors", subtitle: "Liveness from ingestion timestamps, not row existence" },
  "/models": { title: "Model monitoring", subtitle: "CICIDS2017 classifier and experimental Zeek model" },
  "/system": { title: "System health", subtitle: "Components, database, WebSocket and deployed build" },
  "/analytics": { title: "Traffic analytics", subtitle: "Volume, distribution and top talkers from the database" },
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
    case "pulse":
      return (
        <svg {...common}>
          <path d="M2 12h4l2-6 3 12 2.5-6H22" />
        </svg>
      );
    default:
      return null;
  }
}

export function Layout({ children }: { children: ReactNode }) {
  const live = useLive();
  const auth = useAuth();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const meta = TITLES[location.pathname] ?? TITLES["/"];
  const overview = live.hello;
  const cicids = overview?.models?.cicids;
  const zeek = overview?.models?.zeek;
  const commit = overview?.app?.build?.commit?.slice(0, 7) ?? "—";
  const sensorOnline = (overview?.sensors?.online ?? 0) > 0;

  return (
    <div className={`shell ${menuOpen ? "menu-open" : ""}`}>
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
            <div className="brand-sub">security operations</div>
          </div>
          <button type="button" className="menu-button" onClick={() => setMenuOpen((open) => !open)} aria-label="Menu">
            ☰
          </button>
        </div>

        <div className="nav-label">Operate</div>
        <nav className="nav">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <Icon name={item.icon} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="nav-label">Analyse</div>
        <nav className="nav">
          {SECONDARY.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <Icon name={item.icon} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="row">
            <span>alerts ws</span>
            <span style={{ color: live.connected ? "var(--green)" : "var(--amber)" }}>
              {live.connected ? "streaming" : "reconnecting"}
            </span>
          </div>
          <div className="row">
            <span>sensors</span>
            <span>
              {overview ? `${overview.sensors.online}/${overview.sensors.total} online` : "—"}
            </span>
          </div>
          <div className="row">
            <span>cicids</span>
            <span style={{ color: cicids?.loaded ? "var(--green)" : "var(--red)" }}>
              {cicids?.loaded ? "loaded" : "unavailable"}
            </span>
          </div>
          <div className="row">
            <span>zeek model</span>
            <span style={{ color: zeek?.loaded ? "var(--amber)" : "var(--red)" }}>
              {zeek?.loaded ? "loaded · exp" : "unavailable"}
            </span>
          </div>
          <div className="row">
            <span>build</span>
            <span className="mono">{commit}</span>
          </div>
          <div className="row">
            <span>last event</span>
            <span>{relativeSeconds(overview?.activity?.seconds_since_event ?? null)}</span>
          </div>
          <button type="button" className="sign-out" onClick={() => void auth.signOut()}>
            Sign out
          </button>
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
              text={live.connected ? "live stream" : "stream offline"}
              tone={live.connected ? "ok" : "warn"}
              pulse={live.connected}
            />
            <Pill
              text={sensorOnline ? "sensor online" : "sensor silent"}
              tone={sensorOnline ? "ok" : "warn"}
              title={overview?.sensors.items?.[0]?.status_reason}
            />
            <Pill
              text={`cicids ${cicids?.loaded ? "ready" : "down"}`}
              tone={cicids?.loaded ? "info" : "bad"}
            />
            <Pill
              text={`zeek ${zeek?.loaded ? "exp" : "down"}`}
              tone={zeek?.loaded ? "warn" : "bad"}
              title="Zeek model trained on synthetic records; experimental"
            />
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
