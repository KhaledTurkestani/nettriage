import { useEffect, useRef, useState } from "react";

import { type RunEvent, type RunRecord, followRun, getRun } from "../api";
import { Loading, Notice, Stat, VerdictBadge } from "../components/bits";
import { FlowDrawer } from "../components/FlowDrawer";
import { type FlowRequest, ReportView } from "../components/ReportView";
import { Steps } from "../components/Steps";
import { money, plural, seconds } from "../format";
import { useLoad } from "../hooks";

// How long each step stays on screen during a replay, before the next one appears.
const REPLAY_MS = { model: 1100, tool: 650, other: 500 };

function useReplay(events: RunEvent[]) {
  // `shown` is how many events are revealed. null means all of them: the run as it ended.
  const [shown, setShown] = useState<number | null>(null);
  const [speed, setSpeed] = useState(1);

  useEffect(() => {
    if (shown === null) return;
    if (shown >= events.length) {
      setShown(null);
      return;
    }
    const kind = events[shown].type;
    const wait = (kind === "model" ? REPLAY_MS.model : kind === "tool" ? REPLAY_MS.tool : REPLAY_MS.other) / speed;
    const timer = window.setTimeout(() => setShown((n) => (n === null ? null : n + 1)), wait);
    return () => window.clearTimeout(timer);
  }, [shown, speed, events]);

  return {
    playing: shown !== null,
    visible: shown === null ? events : events.slice(0, shown),
    start: () => setShown(0),
    stop: () => setShown(null),
    speed,
    setSpeed,
  };
}

function Header({ record, events, live }: { record: RunRecord; events: RunEvent[]; live: boolean }) {
  const toolCalls = events.filter((event) => event.type === "tool").length;
  const took = seconds(record.started_at, record.finished_at);
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <a href="#/">Captures</a> <span aria-hidden="true">/</span>{" "}
        <a className="mono" href={`#/captures/${encodeURIComponent(record.capture_id)}`}>
          {record.capture_id}
        </a>{" "}
        <span aria-hidden="true">/</span> investigation
      </nav>
      <div className="page-head">
        <h1>
          Investigation of <span className="mono">{record.capture_id}</span>
        </h1>
        <VerdictBadge verdict={record.report?.verdict ?? null} status={live ? "running" : record.status} />
      </div>
      <dl className="stats">
        <Stat label="Model" value={<span className="mono">{record.model}</span>} />
        <Stat label="Effort" value={record.effort} />
        {record.prompt && <Stat label="Prompt version" value={record.prompt} />}
        <Stat
          label="Tool calls"
          value={record.max_tool_calls ? `${toolCalls} of ${record.max_tool_calls}` : String(toolCalls)}
        />
        {took !== null && <Stat label="Took" value={`${took} s`} />}
        {!live && record.cost_usd !== undefined && <Stat label="Cost" value={money(record.cost_usd)} />}
      </dl>
    </>
  );
}

export function RunPage({ id }: { id: string }) {
  const loaded = useLoad(() => getRun(id), id);
  const record = loaded.data;
  const live = record?.status === "running";
  const [streamed, setStreamed] = useState<RunEvent[]>([]);
  const [lost, setLost] = useState(false);
  const [flows, setFlows] = useState<FlowRequest | null>(null);

  // While the run is in progress, its events arrive over a stream. When the stream ends the
  // stored record is loaded, which holds the report after the evidence check.
  const reload = loaded.reload;
  useEffect(() => {
    if (!live) return;
    setStreamed([]);
    setLost(false);
    return followRun(
      id,
      0,
      (event) => setStreamed((before) => (before.some((seen) => seen.n === event.n) ? before : [...before, event])),
      reload,
      () => setLost(true),
    );
  }, [id, live, reload]);

  const events = live ? streamed : (record?.events ?? []);
  const replay = useReplay(live ? [] : events);
  const moving = live || replay.playing;

  // When a run or a replay ends, the report has just appeared at the top: go back to it.
  const wasMoving = useRef(false);
  useEffect(() => {
    if (wasMoving.current && !moving) window.scrollTo({ top: 0 });
    wasMoving.current = moving;
  }, [moving]);

  if (loaded.loading && !record) return <Loading what="the investigation" />;
  if (loaded.error || !record) return <Notice kind="error">{loaded.error ?? "No such investigation."}</Notice>;

  const visible = live ? events : replay.visible;

  return (
    <>
      <Header record={record} events={visible} live={live} />
      {lost && <Notice kind="error">The connection to the server was lost. Reload the page to pick the run up again.</Notice>}

      <div className={`columns run${flows ? " has-drawer" : ""}`}>
        <section aria-labelledby="steps-title">
          <div className="section-head">
            <h2 id="steps-title">What the agent did</h2>
            {!live && events.length > 0 && (
              <div className="replay">
                {replay.playing ? (
                  <>
                    <label className="muted small">
                      Speed{" "}
                      <select value={replay.speed} onChange={(event) => replay.setSpeed(Number(event.target.value))}>
                        <option value={1}>1×</option>
                        <option value={3}>3×</option>
                        <option value={8}>8×</option>
                      </select>
                    </label>
                    <button type="button" onClick={replay.stop}>
                      Skip to the end
                    </button>
                  </>
                ) : (
                  <button type="button" onClick={replay.start}>
                    Replay step by step
                  </button>
                )}
              </div>
            )}
          </div>
          <p className="lead">
            {live
              ? "The run is in progress. Steps appear as they happen."
              : "Every model turn and every tool call, in order. Open a step to see the query and what came back."}
          </p>
          {visible.length === 0 && <p className="muted">{live ? "Waiting for the first step…" : "No steps yet."}</p>}
          <Steps events={visible} follow={moving} />
          {moving && (
            <p className="muted working" role="status">
              {live ? "Working…" : `Replaying: step ${visible.length} of ${events.length}`}
            </p>
          )}
        </section>

        <section aria-labelledby="report-title">
          <div className="section-head">
            <h2 id="report-title">Report</h2>
          </div>
          {moving ? (
            <div className="card">
              <p className="muted">The report appears here when the run ends and its evidence has been checked.</p>
            </div>
          ) : (
            <ReportView record={record} onFlows={setFlows} />
          )}
        </section>
      </div>

      {flows && <FlowDrawer captureId={record.capture_id} request={flows} onClose={() => setFlows(null)} />}
      <p className="muted small run-id">
        Run <span className="mono">{record.run_id}</span> · {plural(events.length, "recorded step")}
      </p>
    </>
  );
}
