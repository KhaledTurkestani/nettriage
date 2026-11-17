import type { Finding, RunRecord } from "../api";
import { ATTACK_WORDS, VERDICT_WORDS, clock, count, money, plural } from "../format";

export type FlowRequest = { ids: number[]; focus?: number; title: string };

function FindingCard({
  finding,
  number,
  onFlows,
}: {
  finding: Finding;
  number: number;
  onFlows: (request: FlowRequest) => void;
}) {
  const all = [...new Set(finding.evidence.flatMap((item) => item.flow_ids))].sort((a, b) => a - b);
  return (
    <article className={`finding sev-${finding.severity}`}>
      <header>
        <h3>
          <span className="muted">{number}.</span> {finding.title}
        </h3>
        <div className="chips">
          <span className="chip">{ATTACK_WORDS[finding.attack_type] ?? finding.attack_type}</span>
          <span className={`chip chip-sev-${finding.severity}`}>severity {finding.severity}</span>
          <span className="chip">confidence {finding.confidence}</span>
        </div>
      </header>
      <p className="who">
        <span className="mono">{finding.attacker_ips.join(", ")}</span>
        <span className="arrow" aria-label="against">
          →
        </span>
        <span className="mono">{finding.victim_ips.join(", ") || "no single target"}</span>
      </p>
      <p className="muted small">
        {clock(finding.first_seen)} to {clock(finding.last_seen)}
      </p>
      <p>{finding.description}</p>
      <h4>Evidence</h4>
      <ol className="evidence">
        {finding.evidence.map((item, index) => (
          <li key={index}>
            <p>{item.claim}</p>
            <div className="flow-ids" aria-label="Cited flows">
              {item.flow_ids.map((id) => (
                <button
                  key={id}
                  type="button"
                  className="flow-id"
                  title={`Show flow ${id}`}
                  onClick={() => onFlows({ ids: item.flow_ids, focus: id, title: item.claim })}
                >
                  {id}
                </button>
              ))}
            </div>
          </li>
        ))}
      </ol>
      <button type="button" className="link" onClick={() => onFlows({ ids: all, title: finding.title })}>
        Show all {plural(all.length, "cited flow")}
      </button>
    </article>
  );
}

function checkNote(record: RunRecord): string | null {
  const check = record.validation;
  if (!check || check.findings_reported == null) return null;
  if (check.findings_reported === 0) return "The report made no findings, so there was no evidence to check.";
  const parts = [`Every flow the report cites was looked up in the capture. ${plural(check.findings_kept ?? 0, "finding")} of ${check.findings_reported} kept`];
  if (check.rejected_on_first_check) parts.push(`${check.rejected_on_first_check} sent back for correction`);
  if (check.findings_removed) parts.push(`${check.findings_removed} removed`);
  return `${parts.join(", ")}.`;
}

/** The checked report. Clicking a flow number shows the flow it stands for. */
export function ReportView({ record, onFlows }: { record: RunRecord; onFlows: (request: FlowRequest) => void }) {
  const report = record.report;
  if (!report) {
    return (
      <div className="card">
        <p>
          <strong>No report.</strong> {record.error ?? "The run ended without one."}
        </p>
      </div>
    );
  }
  const note = checkNote(record);
  const used = record.usage;
  return (
    <div className="report">
      <div className={`verdict verdict-${report.verdict}`}>
        <span className="verdict-word">{VERDICT_WORDS[report.verdict]}</span>
        <span>{plural(report.findings.length, "finding")}</span>
      </div>
      <p className="summary">{report.summary}</p>

      {report.findings.map((finding, index) => (
        <FindingCard key={index} finding={finding} number={index + 1} onFlows={onFlows} />
      ))}

      {report.limitations.length > 0 && (
        <section>
          <h3>Limitations and open leads</h3>
          <ul className="limits">
            {report.limitations.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="card quiet">
        {note && <p>{note}</p>}
        {used && (
          <p className="muted small">
            {plural(record.api_calls ?? 0, "model call")}, {plural(record.tool_calls ?? 0, "tool call")},{" "}
            {count(used.input_tokens + used.cache_read_input_tokens + used.cache_creation_input_tokens)} input and{" "}
            {count(used.output_tokens)} output tokens. Cost at list prices: {money(record.cost_usd)}.
            {record.fallback_used ? ` A fallback model answered part of this run (${(record.served_by ?? []).join(", ")}).` : ""}
          </p>
        )}
      </section>
    </div>
  );
}
