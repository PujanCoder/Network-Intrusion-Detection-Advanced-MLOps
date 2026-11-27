import { useMemo, useState } from "react";

import { EventTable, useMergedEvents } from "../components/EventTable";
import { EventDrawer } from "../components/EventDrawer";
import { EmptyState, Panel, Pill, StatCard } from "../components/ui";
import type { NetworkEvent } from "../lib/api";
import { getJson } from "../lib/api";
import { useLive } from "../lib/LiveContext";
import { formatNumber, relativeSeconds } from "../lib/format";
import { usePolled } from "../lib/usePolled";

export function StreamPage() {
  const live = useLive();
  const [selected, setSelected] = useState<NetworkEvent | null>(null);
  const [paused, setPaused] = useState(false);
  const [onlyMalicious, setOnlyMalicious] = useState(false);
  const [query, setQuery] = useState("");
  const initial = usePolled<{ items: NetworkEvent[] }>(() => getJson("/api/events?limit=150"), 60000);

  const merged = useMergedEvents(live.events, initial.data?.items ?? [], 500);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return merged.filter((event) => {
      if (onlyMalicious && !event.is_malicious) return false;
      if (!needle) return true;
      return [event.src_ip, event.dst_ip, event.prediction, event.proto, event.service, event.explanation]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [merged, onlyMalicious, query]);

  const togglePause = () => {
    const next = !paused;
    setPaused(next);
    live.setPaused(next);
  };

  const lastEvent = live.overview?.seconds_since_last_event;

  return (
    <>
      <div className="grid cols-4">
        <StatCard label="Session events" value={formatNumber(live.sessionEvents)} accent="cyan" />
        <StatCard label="Session attacks" value={formatNumber(live.sessionAttacks)} accent="red" />
        <StatCard label="Stream state" value={paused ? "paused" : live.connected ? "live" : "offline"} accent={live.connected ? "green" : "amber"} small />
        <StatCard
          label="Last event"
          value={relativeSeconds(lastEvent)}
          foot={`${formatNumber(live.overview?.total_events)} events persisted`}
          accent="violet"
          small
        />
      </div>

      <Panel
        title="Prediction stream"
        hint={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Pill text={`${filtered.length} shown`} tone="neutral" />
            <Pill
              text={`${formatNumber(live.overview?.unclassified)} unclassified`}
              tone={(live.overview?.unclassified ?? 0) > 0 ? "warn" : "neutral"}
            />
          </div>
        }
      >
        <div className="controls" style={{ marginBottom: 12 }}>
          <button className={`btn ${paused ? "primary" : ""}`} onClick={togglePause}>
            {paused ? "Resume stream" : "Pause stream"}
          </button>
          <button className="btn ghost" onClick={() => live.clearEvents()}>
            Clear buffer
          </button>
          <label style={{ display: "inline-flex", gap: 7, alignItems: "center", fontSize: 12.5 }}>
            <input type="checkbox" checked={onlyMalicious} onChange={(event) => setOnlyMalicious(event.target.checked)} />
            Attacks only
          </label>
          <input
            className="input"
            placeholder="Filter visible rows (IP, prediction, protocol…)"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            style={{ minWidth: 300 }}
          />
          <span className="mono dim" style={{ marginLeft: "auto" }}>
            {live.connected ? "websocket connected" : "websocket reconnecting"}
            {live.reconnects > 0 ? ` · ${live.reconnects} reconnect(s)` : ""}
          </span>
        </div>

        {filtered.length ? (
          <EventTable events={filtered} onSelect={setSelected} />
        ) : merged.length ? (
          <EmptyState title="No rows match the current filters." detail="Clear the filter to see the full stream." />
        ) : (
          <EmptyState
            title="No new network events received."
            detail="The dashboard never fabricates traffic. Start Zeek capture or replay a PCAP and rows will appear here automatically."
          />
        )}
      </Panel>

      <EventDrawer event={selected} onClose={() => setSelected(null)} />
    </>
  );
}
