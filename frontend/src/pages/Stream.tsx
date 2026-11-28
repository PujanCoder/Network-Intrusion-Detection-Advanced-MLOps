import { useEffect, useMemo, useState } from "react";

import { DetectionDrawer } from "../components/EventDrawer";
import { DetectionTable } from "../components/EventTable";
import { ErrorBox, KeyValue, Loading, NoEventsNotice, Panel, Pill, StatCard } from "../components/ui";
import { api, type Detection } from "../lib/api";
import { relativeFrom, relativeSeconds } from "../lib/format";
import { useLive } from "../lib/LiveContext";
import { usePolled } from "../lib/usePolled";

export function StreamPage() {
  const live = useLive();
  const [openId, setOpenId] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [feed, setFeed] = useState<Detection[]>([]);

  const polled = usePolled(() => api.live(100), live.connected ? 15000 : 3000, [live.connected]);

  useEffect(() => {
    setFeed(polled.data?.records ?? []);
  }, [polled.data]);

  const { setPaused: applyPause } = live;
  useEffect(() => {
    applyPause(paused);
  }, [paused, applyPause]);

  const rows = useMemo(() => {
    const merged = new Map<string, Detection>();
    for (const record of live.events) merged.set(record.id, record);
    for (const record of feed) if (!merged.has(record.id)) merged.set(record.id, record);
    return [...merged.values()].sort((a, b) => (b.ts ?? "").localeCompare(a.ts ?? "")).slice(0, 300);
  }, [live.events, feed]);

  const attacks = rows.filter((row) => row.is_attack).length;

  return (
    <>
      <ErrorBox error={polled.error} />
      <div className="stat-grid">
        <StatCard
          label="Connection"
          value={live.connected ? "streaming" : "polling"}
          accent={live.connected ? "green" : "amber"}
          foot={`${live.reconnects} reconnect(s)`}
        />
        <StatCard label="Rows held" value={rows.length.toLocaleString()} foot="client-side buffer" />
        <StatCard label="Session events" value={live.sessionEvents.toLocaleString()} accent="violet" foot="received since page load" />
        <StatCard label="Session attacks" value={live.sessionAttacks.toLocaleString()} accent="red" foot="is_attack = true" />
        <StatCard
          label="Last event"
          value={relativeFrom(polled.data?.last_event_ts ?? null)}
          accent="cyan"
          foot={polled.data?.no_new_events ? "no events stored yet" : "server timestamp"}
        />
        <StatCard
          label="Last update"
          value={relativeSeconds(live.lastMessageAt ? (Date.now() - live.lastMessageAt) / 1000 : null)}
          foot="websocket message or poll"
        />
      </div>

      {polled.data?.no_new_events && <NoEventsNotice message="No new network events received." />}

      <div className="toolbar">
        <div className="toolbar-group">
          <button type="button" className={`chip-button ${paused ? "active" : ""}`} onClick={() => setPaused((value) => !value)}>
            {paused ? "resume" : "pause"}
          </button>
          <button
            type="button"
            className="chip-button"
            onClick={() => {
              live.clearEvents();
              setFeed([]);
            }}
          >
            clear
          </button>
        </div>
        <div className="toolbar-group">
          <Pill
            text={live.connected ? "websocket authenticated" : "websocket offline"}
            tone={live.connected ? "ok" : "warn"}
            pulse={live.connected}
          />
          <span className="muted tiny">
            {attacks} of {rows.length} rows are attacks
          </span>
        </div>
      </div>

      <Panel
        title="Live detection stream"
        hint={paused ? "paused — buffer continues in the background" : "newest first, no refresh required"}
        className="flush"
      >
        {polled.loading && !rows.length ? <Loading label="Loading stream" /> : (
          <DetectionTable
            rows={rows}
            onOpen={setOpenId}
            emptyTitle="No new network events received."
            emptyDetail="Run a sensor or push a Zeek record; rows appear here as they are scored."
          />
        )}
      </Panel>

      <Panel title="Stream health" hint="server-side facts about the feed">
        <KeyValue
          rows={[
            ["WebSocket clients", String(polled.data?.websocket.clients ?? 0)],
            ["WebSocket available", String(polled.data?.websocket.available ?? false)],
            ["Broadcasts sent", String(polled.data?.websocket.broadcasts ?? 0)],
            ["Stored detections", String(polled.data?.total ?? 0)],
            ["Seconds since last event", String(polled.data?.seconds_since_event ?? "—")],
            ["Polling interval", live.connected ? "15 s (websocket primary)" : "3 s (polling fallback)"],
          ]}
        />
      </Panel>

      <DetectionDrawer id={openId} onClose={() => setOpenId(null)} />
    </>
  );
}
