import { useEffect, useState } from "react";

import { DetectionDrawer } from "../components/EventDrawer";
import { DetectionTable } from "../components/EventTable";
import { ErrorBox, KeyValue, Loading, Panel } from "../components/ui";
import { api, type DetectionPage, type Severity } from "../lib/api";
import { formatNumber, toLocalInput } from "../lib/format";
import { usePolled } from "../lib/usePolled";

const PAGE_SIZE = 25;
const SEVERITIES: (Severity | "")[] = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function ExplorerPage() {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [source, setSource] = useState<"zeek" | "cicids" | "">("");
  const [status, setStatus] = useState<"scored" | "unclassified" | "">("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [offset, setOffset] = useState(0);
  const [openId, setOpenId] = useState<string | null>(null);

  const result = usePolled(
    () =>
      api.detections({
        limit: PAGE_SIZE,
        offset,
        q: search || null,
        severity: severity || null,
        source: source || null,
        status: status || null,
        start: start ? new Date(start).toISOString() : null,
        end: end ? new Date(end).toISOString() : null,
      }),
    15000,
    [offset, search, severity, source, status, start, end],
  );

  useEffect(() => {
    setOffset(0);
  }, [search, severity, source, status, start, end]);

  const data: DetectionPage | null = result.data;
  const total = data?.total ?? 0;
  const pageIndex = Math.floor(offset / PAGE_SIZE) + 1;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const exportQuery = {
    q: search || null,
    severity: severity || null,
    source: source || null,
    status: status || null,
    start: start ? new Date(start).toISOString() : null,
    end: end ? new Date(end).toISOString() : null,
  };

  return (
    <>
      <ErrorBox error={result.error} />

      <Panel title="Filters" hint="all queries run against the database; nothing is cached">
        <form
          className="filter-grid"
          onSubmit={(event) => {
            event.preventDefault();
            setSearch(query.trim());
          }}
        >
          <label>
            <span>IP, label, service or sensor</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="192.0.2.10"
              maxLength={128}
            />
          </label>
          <label>
            <span>Severity</span>
            <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | "")}>
              {SEVERITIES.map((option) => (
                <option key={option || "any"} value={option}>
                  {option || "any"}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Model</span>
            <select value={source} onChange={(event) => setSource(event.target.value as "zeek" | "cicids" | "")}>
              <option value="">any</option>
              <option value="zeek">zeek (experimental)</option>
              <option value="cicids">cicids</option>
            </select>
          </label>
          <label>
            <span>Status</span>
            <select value={status} onChange={(event) => setStatus(event.target.value as "scored" | "unclassified" | "")}>
              <option value="">any</option>
              <option value="scored">scored</option>
              <option value="unclassified">unclassified</option>
            </select>
          </label>
          <label>
            <span>From</span>
            <input type="datetime-local" value={start} max={toLocalInput(new Date())} onChange={(event) => setStart(event.target.value)} />
          </label>
          <label>
            <span>To</span>
            <input type="datetime-local" value={end} max={toLocalInput(new Date())} onChange={(event) => setEnd(event.target.value)} />
          </label>
          <div className="filter-actions">
            <button type="submit" className="button primary">
              Search
            </button>
            <button
              type="button"
              className="button"
              onClick={() => {
                setQuery("");
                setSearch("");
                setSeverity("");
                setSource("");
                setStatus("");
                setStart("");
                setEnd("");
              }}
            >
              Clear
            </button>
            <a className="button" href={api.exportUrl(exportQuery)} download>
              Export CSV
            </a>
          </div>
        </form>
      </Panel>

      <div className="toolbar">
        <div className="toolbar-group">
          <span className="mono">{formatNumber(total)} matching records</span>
          <span className="muted tiny">
            page {pageIndex} / {pageCount}
          </span>
        </div>
        <div className="toolbar-group">
          <button
            type="button"
            className="chip-button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            previous
          </button>
          <button
            type="button"
            className="chip-button"
            disabled={!data?.has_more}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            next
          </button>
        </div>
      </div>

      <Panel title="Detections" hint="click a row to inspect the stored record" className="flush">
        {result.loading && !data ? (
          <Loading label="Loading detections" />
        ) : (
          <DetectionTable
            rows={data?.items ?? []}
            onOpen={setOpenId}
            emptyTitle="No records match these filters"
            emptyDetail="Widen the time range or clear the search to see stored detections."
          />
        )}
      </Panel>

      <Panel title="Query contract" hint="parameters accepted by /api/v1/detections">
        <KeyValue
          rows={[
            ["Pagination", "limit 1–200, offset ≥ 0, sort ts_desc | ts_asc"],
            ["Filters", "source, label, severity, status, sensor_id, model, q"],
            ["Time range", "start / end as ISO-8601 or epoch seconds"],
            ["Export", "/api/v1/detections/export with the same filters (CSV, authenticated)"],
          ]}
        />
      </Panel>

      <DetectionDrawer id={openId} onClose={() => setOpenId(null)} />
    </>
  );
}
