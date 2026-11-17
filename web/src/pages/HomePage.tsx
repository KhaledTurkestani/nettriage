import { useState } from "react";

import { type Capture, type CaptureKind, type Config, listCaptures, listRuns } from "../api";
import { Loading, Notice, RunList } from "../components/bits";
import { Upload } from "../components/Upload";
import { count, plural, span } from "../format";
import { useLoad } from "../hooks";

const KIND_WORDS: Record<CaptureKind, string> = {
  upload: "Uploaded",
  dataset: "Dataset day",
  "eval case": "Eval case",
};

function CaptureRow({ capture }: { capture: Capture }) {
  return (
    <li>
      <a className="row" href={`#/captures/${encodeURIComponent(capture.id)}`}>
        <span className="row-main">
          <span className="mono strong">{capture.id}</span>
          <span className="muted">
            {KIND_WORDS[capture.kind]} · {plural(capture.flow_count, "flow")} · {span(capture.first_ts, capture.last_ts)}
          </span>
        </span>
        <span className="muted row-end">{capture.runs ? plural(capture.runs, "investigation") : ""}</span>
      </a>
    </li>
  );
}

export function HomePage({ config }: { config: Config | null }) {
  const captures = useLoad(listCaptures, "captures");
  const runs = useLoad(listRuns, "runs");
  const [showCases, setShowCases] = useState(false);

  const all = captures.data ?? [];
  const cases = all.filter((c) => c.kind === "eval case");
  const own = all.filter((c) => c.kind !== "eval case");
  const shown = (showCases ? cases : own).slice().sort((a, b) => a.id.localeCompare(b.id));

  return (
    <div className="columns">
      <section aria-labelledby="captures-title">
        <div className="section-head">
          <h1 id="captures-title">Captures</h1>
          {cases.length > 0 && (
            <div className="tabs" role="tablist" aria-label="Which captures to show">
              <button role="tab" aria-selected={!showCases} onClick={() => setShowCases(false)}>
                Captures <span className="muted">{count(own.length)}</span>
              </button>
              <button role="tab" aria-selected={showCases} onClick={() => setShowCases(true)}>
                Eval cases <span className="muted">{count(cases.length)}</span>
              </button>
            </div>
          )}
        </div>
        <p className="lead">
          A capture is recorded network traffic, stored as a table of flows. Open one to see what is in it and to have
          the agent investigate it.
        </p>
        {config?.can_upload && !showCases && <Upload config={config} />}
        {captures.loading && <Loading what="captures" />}
        {captures.error && <Notice kind="error">{captures.error}</Notice>}
        {captures.data && shown.length === 0 && (
          <p className="muted">
            {showCases ? "No eval cases have been built." : "No captures yet. Add one above, or ingest one from the command line."}
          </p>
        )}
        {showCases && cases.length > 0 && (
          <p className="muted small">
            Eval cases are five-minute slices of the dataset with addresses replaced and times shifted. Their answers
            are kept away from the agent and from this page.
          </p>
        )}
        <ul className="rows">
          {shown.map((capture) => (
            <CaptureRow key={capture.id} capture={capture} />
          ))}
        </ul>
      </section>

      <section aria-labelledby="runs-title">
        <div className="section-head">
          <h2 id="runs-title">Investigations</h2>
        </div>
        <p className="lead">Each one is kept with every step the agent took, so it can be replayed.</p>
        {runs.loading && <Loading what="investigations" />}
        {runs.error && <Notice kind="error">{runs.error}</Notice>}
        {runs.data && <RunList runs={runs.data} />}
      </section>
    </div>
  );
}
