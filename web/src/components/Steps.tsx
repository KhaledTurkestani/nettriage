import { useEffect, useRef } from "react";

import type { CheckEvent, ModelEvent, RunEvent, ToolEvent } from "../api";
import { VERDICT_WORDS, count, oneLine, plural } from "../format";
import { DataTable, ObjectTable } from "./DataTable";

type Json = Record<string, unknown>;

function parse(text: string): Json | null {
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : null;
  } catch {
    return null;
  }
}

const isRows = (value: unknown): value is Json[] =>
  Array.isArray(value) && value.length > 0 && value.every((row) => row && typeof row === "object" && !Array.isArray(row));

const TOOL_WORDS: Record<string, string> = {
  capture_overview: "Looked at the capture overview",
  classify_flows: "Ran the classifier",
  run_sql: "Ran a query",
};

function toolTitle(event: ToolEvent): string {
  if (event.name === "run_sql" && typeof event.input.query === "string") return oneLine(event.input.query, 96);
  if (event.name === "classify_flows") {
    const where = typeof event.input.where === "string" ? event.input.where.trim() : "";
    return where ? `Classifier on flows where ${oneLine(where, 70)}` : "Classifier on every flow";
  }
  return TOOL_WORDS[event.name] ?? event.name;
}

function toolResult(event: ToolEvent, output: Json | null): string {
  if (event.is_error) return "error";
  if (!output) return "";
  if (event.name === "run_sql" && typeof output.rows_returned === "number") {
    return `${plural(output.rows_returned, "row")}${output.truncated ? ", more exist" : ""}`;
  }
  if (event.name === "classify_flows" && typeof output.flows_flagged === "number") {
    return `${count(output.flows_flagged)} of ${count(output.flows_scored as number)} flagged`;
  }
  if (event.name === "capture_overview" && typeof output.flows === "number") return plural(output.flows, "flow");
  return "";
}

function ToolOutput({ event, output }: { event: ToolEvent; output: Json | null }) {
  if (event.is_error || !output) return <pre className={`code${event.is_error ? " is-error" : ""}`}>{event.output}</pre>;
  if (Array.isArray(output.columns) && Array.isArray(output.rows)) {
    return (
      <>
        <DataTable columns={output.columns as string[]} rows={output.rows as unknown[][]} caption="Query result" />
        {typeof output.note === "string" && <p className="muted small">{output.note}</p>}
      </>
    );
  }
  // Anything else: show each list of rows as a table, and the rest as plain values.
  const tables = Object.entries(output).filter(([, value]) => isRows(value)) as [string, Json[]][];
  const facts = Object.entries(output).filter(([, value]) => value !== null && typeof value !== "object");
  const lists = Object.entries(output).filter(
    ([, value]) => Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string"),
  ) as [string, string[]][];
  return (
    <>
      {facts.length > 0 && (
        <dl className="facts">
          {facts.map(([key, value]) => (
            <div key={key}>
              <dt>{key.replace(/_/g, " ")}</dt>
              <dd>{typeof value === "number" ? count(value) : String(value)}</dd>
            </div>
          ))}
        </dl>
      )}
      {tables.map(([key, rows]) => (
        <div key={key}>
          <h4>{key.replace(/_/g, " ")}</h4>
          <ObjectTable rows={rows} caption={key.replace(/_/g, " ")} />
        </div>
      ))}
      {lists.map(([key, items]) => (
        <div key={key}>
          <h4>{key.replace(/_/g, " ")}</h4>
          <ul className="plain">
            {items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      ))}
    </>
  );
}

function ToolStep({ event }: { event: ToolEvent }) {
  const output = parse(event.output);
  const query = event.name === "run_sql" && typeof event.input.query === "string" ? event.input.query : null;
  return (
    <details className={`step step-tool${event.is_error ? " is-error" : ""}`}>
      <summary>
        <span className="step-kind">{event.name}</span>
        <span className={`step-title${query ? " mono is-query" : ""}`}>{toolTitle(event)}</span>
        <span className="step-meta">
          {toolResult(event, output)} · {event.ms < 1000 ? `${Math.round(event.ms)} ms` : `${(event.ms / 1000).toFixed(1)} s`}
        </span>
      </summary>
      <div className="step-body">
        {query && <pre className="code">{query}</pre>}
        <ToolOutput event={event} output={output} />
      </div>
    </details>
  );
}

function ModelStep({ event, corrected }: { event: ModelEvent; corrected: boolean }) {
  const names = event.tool_calls.map((call) => call.name);
  const kinds = [...new Set(names)];
  const asked =
    kinds.length === 1 ? (names.length === 1 ? kinds[0] : `${names.length} x ${kinds[0]}`) : kinds.join(", ");
  const title = names.length
    ? `Decided to call ${asked}`
    : event.stop_reason === "refusal"
      ? "Declined to continue"
      : corrected
        ? "Corrected the report"
        : "Wrote the report";
  const thinking = event.thinking.join("\n\n").trim();
  const used = event.usage;
  const input = used.input_tokens + used.cache_read_input_tokens + used.cache_creation_input_tokens;
  return (
    <details className="step step-model" open={Boolean(thinking)}>
      <summary>
        <span className="step-kind">model</span>
        <span className="step-title">{title}</span>
        <span className="step-meta">
          {count(input)} in · {count(used.output_tokens)} out
        </span>
      </summary>
      <div className="step-body">
        {thinking ? (
          <p className="thinking">{thinking}</p>
        ) : (
          <p className="muted small">The model gave no summary of its reasoning for this turn.</p>
        )}
        <p className="muted small">
          {count(used.cache_read_input_tokens)} of {count(input)} input tokens were read from the prompt cache. Answered
          by {event.served_by}.
        </p>
      </div>
    </details>
  );
}

function CheckStep({ event }: { event: CheckEvent }) {
  const ok = event.rejected.length === 0;
  return (
    <div className={`step step-line${ok ? "" : " is-error"}`}>
      <span className="step-kind">check</span>
      <span className="step-title">
        Evidence check{event.round > 1 ? " after the correction" : ""}: every cited flow was looked up.{" "}
        {ok
          ? `${plural(event.findings, "finding")} passed.`
          : `${event.rejected.length} of ${plural(event.findings, "finding")} rejected${event.round > 1 ? " and removed" : " and sent back once"}.`}
      </span>
      {!ok && (
        <ul className="plain step-problems">
          {event.rejected.map((item) => (
            <li key={item.finding}>
              <strong>{item.finding}</strong>: {item.problems.join(" ")}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** The investigation, step by step. Model text and tool output are shown as text only. */
export function Steps({ events, follow }: { events: RunEvent[]; follow: boolean }) {
  const end = useRef<HTMLDivElement>(null);
  // Keep the newest step in view, but only for a viewer who is already there: someone who has
  // scrolled up to read an earlier step is left where they are.
  const atNewest = useRef(true);
  useEffect(() => {
    const onScroll = () => {
      const marker = end.current?.getBoundingClientRect();
      atNewest.current = !marker || marker.top <= window.innerHeight + 240;
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  useEffect(() => {
    if (follow && atNewest.current) end.current?.scrollIntoView({ block: "nearest" });
  }, [events.length, follow]);

  // A model turn that follows a rejected evidence check is the one correction it is allowed.
  const sentBack = events.find((event) => event.type === "evidence_check" && event.rejected.length > 0)?.n ?? Infinity;

  return (
    <div className="steps">
      {events.map((event) => {
        switch (event.type) {
          case "model":
            return <ModelStep key={event.n} event={event} corrected={event.n > sentBack} />;
          case "tool":
            return <ToolStep key={event.n} event={event} />;
          case "evidence_check":
            return <CheckStep key={event.n} event={event} />;
          case "report":
            return (
              <div key={event.n} className="step step-line">
                <span className="step-kind">report</span>
                <span className="step-title">
                  Report accepted: {VERDICT_WORDS[event.verdict] ?? event.verdict}, {plural(event.findings, "finding")}.
                </span>
              </div>
            );
          case "end":
            return event.status === "completed" ? null : (
              <div key={event.n} className="step step-line is-error">
                <span className="step-kind">ended</span>
                <span className="step-title">{event.error ?? `The run ended: ${event.status}.`}</span>
              </div>
            );
        }
      })}
      <div ref={end} />
    </div>
  );
}
