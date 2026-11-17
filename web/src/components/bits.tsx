import type { ReactNode } from "react";

import type { RunStatus, RunSummary, Verdict } from "../api";
import { STATUS_WORDS, VERDICT_WORDS, clock, money, plural } from "../format";

export function VerdictBadge({ verdict, status }: { verdict: Verdict | null; status: RunStatus }) {
  if (status !== "completed" || !verdict) {
    return <span className={`badge badge-${status}`}>{STATUS_WORDS[status]}</span>;
  }
  return <span className={`badge badge-${verdict}`}>{VERDICT_WORDS[verdict]}</span>;
}

export function Notice({ kind = "info", children }: { kind?: "info" | "error"; children: ReactNode }) {
  return (
    <p className={`notice notice-${kind}`} role={kind === "error" ? "alert" : "status"}>
      {children}
    </p>
  );
}

export function Loading({ what }: { what: string }) {
  return <p className="muted loading">Loading {what}…</p>;
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="stat">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

export function RunList({ runs, showCapture = true }: { runs: RunSummary[]; showCapture?: boolean }) {
  if (!runs.length) return <p className="muted">None yet.</p>;
  return (
    <ul className="rows">
      {runs.map((run) => (
        <li key={run.run_id}>
          <a className="row" href={`#/runs/${encodeURIComponent(run.run_id)}`}>
            <VerdictBadge verdict={run.verdict} status={run.status} />
            <span className="row-main">
              {showCapture && <span className="mono">{run.capture_id}</span>}
              <span className="muted">
                {run.status === "running"
                  ? `${plural(run.tool_calls, "tool call")} so far`
                  : `${plural(run.findings, "finding")} · ${plural(run.tool_calls, "tool call")} · ${money(run.cost_usd)}`}
              </span>
            </span>
            <span className="muted row-end">{clock(run.started_at)}</span>
          </a>
        </li>
      ))}
    </ul>
  );
}
