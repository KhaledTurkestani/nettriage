import { useState } from "react";

import { type Config, type Overview, getCapture, startRun } from "../api";
import { Loading, Notice, RunList, Stat } from "../components/bits";
import { ObjectTable } from "../components/DataTable";
import { bytes, count, every, protocol, span, timeOnly } from "../format";
import { go, useLoad } from "../hooks";

/** Flows per time bucket, as bars. The numbers are in the table underneath for anyone who cannot see it. */
function Timeline({ overview }: { overview: Overview }) {
  const peak = Math.max(1, ...overview.timeline.map((bucket) => bucket.flows));
  const first = overview.timeline[0];
  const last = overview.timeline[overview.timeline.length - 1];
  return (
    <figure className="timeline">
      <div className="bars" role="img" aria-label={`Flows over time, peak ${count(peak)} per ${every(overview.timeline_bucket_seconds)}`}>
        {overview.timeline.map((bucket) => (
          <div
            key={bucket.start}
            className="bar"
            style={{ height: `${Math.max(2, (bucket.flows / peak) * 100)}%` }}
            title={`${timeOnly(bucket.start)}: ${count(bucket.flows)} flows from ${count(bucket.src_ips)} sources`}
          />
        ))}
      </div>
      <figcaption className="muted small bar-axis">
        <span>{timeOnly(first?.start)}</span>
        <span>
          flows per {every(overview.timeline_bucket_seconds)}, peak {count(peak)}
        </span>
        <span>{timeOnly(last?.start)}</span>
      </figcaption>
    </figure>
  );
}

function Investigate({ captureId, config }: { captureId: string; config: Config }) {
  const [model, setModel] = useState(config.default_model);
  const [budget, setBudget] = useState(config.default_max_tool_calls);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const run = await startRun({ capture_id: captureId, model, max_tool_calls: budget });
      go(`/runs/${encodeURIComponent(run.run_id)}`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : String(problem));
      setBusy(false);
    }
  }

  if (!config.can_investigate) {
    return (
      <Notice>
        {config.read_only
          ? "This server is read-only: it shows stored investigations and cannot start new ones."
          : "No API key is configured on the server, so new investigations cannot be started. Stored ones can still be opened."}
      </Notice>
    );
  }
  const chosen = config.models.find((m) => m.id === model);
  return (
    <form
      className="card form"
      onSubmit={(event) => {
        event.preventDefault();
        void start();
      }}
    >
      <label>
        Model
        <select value={model} onChange={(event) => setModel(event.target.value)} disabled={busy}>
          {config.models.map((m) => (
            <option key={m.id} value={m.id}>
              {m.id}
              {m.id === config.default_model ? " (cheapest)" : ""}
            </option>
          ))}
        </select>
      </label>
      <label>
        Tool calls allowed
        <input
          type="number"
          min={1}
          max={config.max_tool_calls_limit}
          value={budget}
          disabled={busy}
          onChange={(event) => setBudget(Math.max(1, Math.min(config.max_tool_calls_limit, Number(event.target.value) || 1)))}
        />
      </label>
      <p className="muted small">
        This calls the Claude API and is billed to the server's key
        {chosen ? ` ($${chosen.input_per_mtok} in / $${chosen.output_per_mtok} out per million tokens)` : ""}. On the
        cheapest model a run has cost 1 to 3 cents and takes a minute or two.
      </p>
      <button className="primary" type="submit" disabled={busy}>
        {busy ? "Starting…" : "Investigate this capture"}
      </button>
      {error && <Notice kind="error">{error}</Notice>}
    </form>
  );
}

export function CapturePage({ id, config }: { id: string; config: Config | null }) {
  const capture = useLoad(() => getCapture(id), id);
  if (capture.loading) return <Loading what="the capture" />;
  if (capture.error || !capture.data) return <Notice kind="error">{capture.error ?? "No such capture."}</Notice>;
  const data = capture.data;
  const overview = data.overview;

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <a href="#/">Captures</a> <span aria-hidden="true">/</span> <span className="mono">{data.id}</span>
      </nav>
      <div className="page-head">
        <h1 className="mono">{data.id}</h1>
        <p className="muted">
          {data.source === "pcap" ? "Read from a packet capture" : "Read from flow records (no packet contents)"}
          {data.original_name && data.original_name !== "case" ? ` · ${data.original_name}` : ""}
        </p>
      </div>
      <dl className="stats">
        <Stat label="Flows" value={count(data.flow_count)} />
        <Stat label="Time span" value={span(data.first_ts, data.last_ts)} />
        <Stat label="DNS messages" value={count(data.dns_count)} />
        <Stat label="HTTP requests" value={count(data.http_count)} />
      </dl>

      <div className="columns">
        <section aria-label="What is in the capture">
          {!overview && <Notice>This capture has no flows to summarise.</Notice>}
          {overview && (
            <>
              <h2>Traffic over time</h2>
              <Timeline overview={overview} />
              <h2>Busiest sources</h2>
              <ObjectTable
                caption="Busiest sources"
                rows={overview.top_sources.map((row) => ({
                  source: row.src_ip,
                  flows: row.flows,
                  "hosts reached": row.dst_ips,
                  "ports reached": row.dst_ports,
                  payload: bytes(row.bytes),
                }))}
              />
              <h2>Busiest destinations</h2>
              <ObjectTable
                caption="Busiest destinations"
                rows={overview.top_destinations.map((row) => ({
                  destination: row.dst_ip,
                  flows: row.flows,
                  "sources seen": row.src_ips,
                  "ports used": row.dst_ports,
                }))}
              />
              <h2>Busiest ports</h2>
              <ObjectTable
                caption="Busiest destination ports"
                rows={overview.top_destination_ports.map((row) => ({
                  port: `${row.dst_port} ${protocol(row.protocol)}`,
                  flows: row.flows,
                  "sources seen": row.src_ips,
                }))}
              />
            </>
          )}
        </section>

        <aside aria-label="Investigations of this capture">
          <h2>Investigate</h2>
          <p className="lead">
            The agent queries this capture, checks what a classifier flags, and writes a report whose claims cite
            flows.
          </p>
          {config ? <Investigate captureId={data.id} config={config} /> : <Loading what="settings" />}
          <h2>Earlier investigations</h2>
          <RunList runs={data.run_list} showCapture={false} />
        </aside>
      </div>
    </>
  );
}
