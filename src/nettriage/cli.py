"""Command line: ingest files into captures and look at what was stored."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import duckdb
import typer

from . import schema, store
from .ingest import IngestError

app = typer.Typer(help="NetTriage: investigate network traffic.", no_args_is_help=True, add_completion=False)
ingest_app = typer.Typer(help="Turn an input file into a stored capture.", no_args_is_help=True)
app.add_typer(ingest_app, name="ingest")

IdOption = Annotated[Optional[str], typer.Option("--id", help="Capture id. Generated from the file name if omitted.")]
OverwriteOption = Annotated[bool, typer.Option("--overwrite", help="Replace an existing capture with the same id.")]


def _fail(message: str) -> None:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def _print_meta(meta: store.CaptureMeta) -> None:
    rows = [
        ("capture", meta.id),
        ("source", f"{meta.source} ({meta.original_name})"),
        ("flows", f"{meta.flow_count:,}"),
        ("dns", f"{meta.dns_count:,}"),
        ("http", f"{meta.http_count:,}"),
        ("first flow", meta.first_ts),
        ("last flow", meta.last_ts),
        ("labels", "yes (kept outside the database)" if meta.has_labels else "no"),
    ]
    rows += [(key.replace("_", " "), value) for key, value in meta.notes.items()]
    width = max(len(key) for key, _ in rows)
    for key, value in rows:
        typer.echo(f"{key:<{width}}  {value}")


def _print_table(columns: list[str], rows: list[tuple]) -> None:
    cells = [[("" if v is None else str(v)) for v in row] for row in rows]
    widths = [min(40, max(len(c), *(len(r[i]) for r in cells))) if cells else len(c) for i, c in enumerate(columns)]
    line = "  ".join(c.ljust(w) for c, w in zip(columns, widths))
    typer.echo(line)
    typer.echo("  ".join("-" * w for w in widths))
    for row in cells:
        typer.echo("  ".join(v[:w].ljust(w) for v, w in zip(row, widths)))


@ingest_app.command("csv")
def ingest_csv(
    path: Annotated[Path, typer.Argument(help="A CICFlowMeter flow CSV, e.g. a CIC-IDS2017 labelled-flows file.")],
    capture_id: IdOption = None,
    clock: Annotated[str, typer.Option(help="Timestamp clock: auto, 24h or 12h-working-hours.")] = "auto",
    overwrite: OverwriteOption = False,
) -> None:
    """Ingest a CICFlowMeter flow CSV."""
    from .ingest.cic_csv import ingest_cic_csv

    if clock not in ("auto", "24h", "12h-working-hours"):
        _fail("--clock must be auto, 24h or 12h-working-hours.")
    try:
        meta = ingest_cic_csv(path, capture_id, clock=clock, overwrite=overwrite)  # type: ignore[arg-type]
    except (IngestError, store.CaptureError) as exc:
        _fail(str(exc))
    _print_meta(meta)


@ingest_app.command("pcap")
def ingest_pcap_file(
    path: Annotated[Path, typer.Argument(help="A pcap or pcapng file.")],
    capture_id: IdOption = None,
    max_packets: Annotated[Optional[int], typer.Option(help="Stop after this many packets.")] = None,
    overwrite: OverwriteOption = False,
) -> None:
    """Ingest a packet capture."""
    from .ingest.pcap import ingest_pcap

    try:
        meta = ingest_pcap(path, capture_id, max_packets=max_packets, overwrite=overwrite)
    except (IngestError, store.CaptureError) as exc:
        _fail(str(exc))
    _print_meta(meta)


@app.command("list")
def list_captures() -> None:
    """List stored captures, newest first."""
    metas = store.list_captures()
    if not metas:
        typer.echo("No captures yet. Add one with: nettriage ingest csv FILE  or  nettriage ingest pcap FILE")
        return
    _print_table(
        ["id", "source", "flows", "dns", "http", "labels", "first_ts"],
        [(m.id, m.source, m.flow_count, m.dns_count, m.http_count, "yes" if m.has_labels else "no", m.first_ts)
         for m in metas],
    )


@app.command("show")
def show(capture_id: str) -> None:
    """Show one capture's details."""
    try:
        _print_meta(store.load_meta(capture_id))
    except store.CaptureError as exc:
        _fail(str(exc))


@app.command("query")
def query(
    capture_id: str,
    sql: Annotated[str, typer.Argument(help="A SELECT over the flows, dns and http tables.")],
    limit: Annotated[int, typer.Option(help="Maximum rows to print.")] = 50,
) -> None:
    """Run read-only SQL against a capture."""
    try:
        con = store.connect_readonly(capture_id)
    except store.CaptureError as exc:
        _fail(str(exc))
    try:
        cursor = con.execute(sql)
        columns = [d[0] for d in cursor.description or []]
        rows = cursor.fetchmany(limit + 1)
    except duckdb.Error as exc:
        _fail(str(exc).splitlines()[0])
    finally:
        con.close()
    _print_table(columns, rows[:limit])
    if len(rows) > limit:
        typer.echo(f"... more rows not shown (limit {limit})")


@app.command("train")
def train(
    captures: Annotated[list[str], typer.Argument(help="Labelled captures to learn from, e.g. monday tuesday.")],
    out: Annotated[Optional[Path], typer.Option(help="Where to write the model. Default: the model directory.")] = None,
    unseen_test: Annotated[bool, typer.Option(help="Also test each attack as if never seen (slower).")] = True,
) -> None:
    """Train the flow classifier on labelled captures and write its model card."""
    from .classifier import ClassifierError
    from .classifier.model import model_dir
    from .classifier.train import train_model

    target = out or model_dir()
    try:
        card = train_model(captures, target, unseen_test=unseen_test, progress=typer.echo)
    except ClassifierError as exc:
        _fail(str(exc))
    test = card["held_out_test"]
    typer.echo(f"\nmodel      {card['id']}  ({card['iterations']} rounds, written to {target})")
    typer.echo(f"trained on {card['training']['flows']:,} flows; tested on {test['flows']:,} held-out flows")
    typer.echo(
        f"held-out   precision {test['precision']}  recall {test['recall']}  "
        f"false positives {test['false_positives']:,} ({test['false_positives_per_100k_benign']} per 100k benign)"
    )
    if card["unseen_attack_test"]:
        typer.echo("\nAttacks the model was not trained on (share flagged):")
        _print_table(
            ["attack", "held-out flows", "flagged", "share", "called"],
            [(r["label"], r["held_out_flows"], r["flagged"], r["recall"], r["mostly_called"])
             for r in card["unseen_attack_test"]],
        )


@app.command("classify")
def classify(
    capture_id: str,
    where: Annotated[Optional[str], typer.Option(help="SQL condition over flows, e.g. \"dst_port = 22\".")] = None,
    top: Annotated[int, typer.Option(help="How many sources and targets to list.")] = 5,
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Score a capture's flows with the trained classifier."""
    import json

    from .classifier import ClassifierError
    from .classifier.model import classify_flows

    try:
        result = classify_flows(capture_id, where, top=top)
    except ClassifierError as exc:
        _fail(str(exc))
    if as_json:
        typer.echo(json.dumps(result, indent=2))
        return
    typer.echo(f"model    {result['model']['id']}")
    typer.echo(f"scored   {result['flows_scored']:,} flows")
    typer.echo(f"flagged  {result['flows_flagged']:,}")
    if result["by_family"]:
        typer.echo("")
        _print_table(["family", "flows", "median_score"],
                     [(r["family"], r["flows"], r["median_score"]) for r in result["by_family"]])
    for title, key in (("sources", "src_ip"), ("targets", "dst_ip")):
        rows = result[f"top_{title}"]
        if rows:
            typer.echo(f"\nTop {title} of flagged flows:")
            _print_table(
                [key, "flagged", "of", "families", "first_seen", "example flow ids"],
                [(r[key], r["flagged_flows"], r["all_flows"], ", ".join(r["families"]), r["first_seen"],
                  " ".join(str(i) for i in r["example_flow_ids"])) for r in rows],
            )
    for caveat in result["caveats"]:
        typer.echo(f"note: {caveat}")


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Read KEY=VALUE lines from a .env file, without overriding variables that are already set."""
    from . import settings

    settings.load_dotenv(path)


def _print_report(record: dict) -> None:
    report = record.get("report")
    if not report:
        typer.echo(f"No report: {record.get('error') or record['status']}")
        return
    typer.echo(f"\nVERDICT  {report['verdict'].replace('_', ' ')}")
    typer.echo(f"\n{report['summary']}")
    for number, finding in enumerate(report["findings"], start=1):
        typer.echo(f"\n{number}. {finding['title']}")
        typer.echo(f"   type {finding['attack_type']}, severity {finding['severity']}, "
                   f"confidence {finding['confidence']}")
        typer.echo(f"   attacker {', '.join(finding['attacker_ips'])}  ->  victim {', '.join(finding['victim_ips'])}")
        typer.echo(f"   from {finding['first_seen']} to {finding['last_seen']}")
        typer.echo(f"   {finding['description']}")
        for item in finding["evidence"]:
            typer.echo(f"   - {item['claim']}  [flows {', '.join(str(i) for i in item['flow_ids'])}]")
    if report["limitations"]:
        typer.echo("\nLimitations")
        for limitation in report["limitations"]:
            typer.echo(f"  - {limitation}")


def _print_run_stats(record: dict) -> None:
    check, usage = record.get("validation") or {}, record["usage"]
    if check:
        typer.echo(
            f"\nevidence check  {check['findings_kept']} of {check['findings_reported']} findings kept, "
            f"{check['rejected_on_first_check']} rejected at first, {check['findings_removed']} removed"
        )
    cost = record.get("cost_usd")
    typer.echo(
        f"usage           {record['api_calls']} model calls, {record['tool_calls']} tool calls, "
        f"{usage['input_tokens'] + usage['cache_read_input_tokens'] + usage['cache_creation_input_tokens']:,} "
        f"input and {usage['output_tokens']:,} output tokens"
    )
    typer.echo("cost            " + (f"about ${cost:.3f} at list prices" if cost is not None else "price not known"))
    if record.get("fallback_used"):
        typer.echo(f"note            a fallback model answered part of this run: {', '.join(record['served_by'])}")


@app.command("investigate")
def investigate_capture(
    target: Annotated[str, typer.Argument(help="A capture id, or a pcap or flow CSV file to ingest first.")],
    model: Annotated[str, typer.Option(
        help="Claude model id, e.g. claude-haiku-5-5 (cheapest), claude-sonnet-5-5 or claude-opus-5-5.",
    )] = "claude-haiku-5-5",
    effort: Annotated[Optional[str], typer.Option(
        help="How hard the model thinks: low, medium, high, xhigh or max. The default depends on the model.",
    )] = None,
    max_tool_calls: Annotated[int, typer.Option(help="Tool-call budget for the run.")] = 30,
    prompt: Annotated[Optional[str], typer.Option(
        help="System prompt version, e.g. baseline or v1. Default: the current one.",
    )] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the full run record as JSON.")] = False,
) -> None:
    """Investigate a capture with the agent. This calls the Claude API and is billed to your key."""
    import json

    from .agent import AgentError
    from .agent.loop import default_effort, investigate
    from .agent.prompts import CURRENT
    from .agent.runs import save_run, to_record

    _load_dotenv()
    effort = effort or default_effort(model)
    prompt = prompt or CURRENT
    capture_id = target
    if Path(target).is_file():
        try:
            if Path(target).suffix.lower() == ".csv":
                from .ingest.cic_csv import ingest_cic_csv
                capture_id = ingest_cic_csv(Path(target)).id
            else:
                from .ingest.pcap import ingest_pcap
                capture_id = ingest_pcap(Path(target)).id
        except (IngestError, store.CaptureError) as exc:
            _fail(str(exc))
        typer.echo(f"Ingested {Path(target).name} as capture {capture_id}.", err=True)

    def progress(event: dict) -> None:
        if event["type"] == "tool":
            detail = " ".join(str(next(iter(event["input"].values()), "")).split())[:80]
            typer.echo(f"  {event['name']:<16} {detail}{'  (error)' if event['is_error'] else ''}", err=True)
        elif event["type"] == "evidence_check" and event["rejected"]:
            typer.echo(f"  evidence check   {len(event['rejected'])} finding(s) rejected", err=True)

    typer.echo(
        f"Investigating {capture_id} with {model} (effort {effort}, up to {max_tool_calls} tool calls). "
        "This run is billed to your API key.", err=True,
    )
    try:
        run = investigate(capture_id, model=model, effort=effort, max_tool_calls=max_tool_calls, prompt=prompt,
                          on_event=progress)
    except AgentError as exc:
        _fail(str(exc))
    path = save_run(run)
    record = to_record(run)
    if as_json:
        typer.echo(json.dumps(record, indent=2, ensure_ascii=False))
    else:
        _print_report(record)
        _print_run_stats(record)
        typer.echo(f"saved           {path}")
    if run.status != "completed":
        raise typer.Exit(code=2 if run.status == "refused" else 1)


@app.command("runs")
def list_runs() -> None:
    """List stored investigations, newest first."""
    from .agent.runs import list_runs as stored_runs

    runs = stored_runs()
    if not runs:
        typer.echo("No runs yet. Start one with: nettriage investigate CAPTURE")
        return
    _print_table(
        ["run", "status", "verdict", "findings", "tool calls", "cost"],
        [(r["run_id"], r["status"], r["verdict"], r["findings"], r["tool_calls"],
          "" if r["cost_usd"] is None else f"${r['cost_usd']:.3f}") for r in runs],
    )


@app.command("report")
def show_report(run_id: str) -> None:
    """Print the report of a stored investigation."""
    from .agent import AgentError
    from .agent.runs import load_run

    try:
        record = load_run(run_id)
    except AgentError as exc:
        _fail(str(exc))
    _print_report(record)
    _print_run_stats(record)


eval_app = typer.Typer(help="Build, run and score the eval cases.", no_args_is_help=True)
app.add_typer(eval_app, name="eval")


@eval_app.command("build")
def eval_build() -> None:
    """Rebuild every case in evals/cases.json from the ingested dataset days."""
    from .agent.loop import DEFAULT_MAX_TOOL_CALLS, first_message
    from .evals import EvalError
    from .evals.cases import MANIFEST, build_case, cases_markdown, load_manifest

    try:
        specs, seed = load_manifest()
        truths = [build_case(spec, seed) for spec in specs]
    except (EvalError, store.CaptureError) as exc:
        _fail(str(exc))
    prompts = {t["id"]: first_message(store.load_meta(t["id"]), DEFAULT_MAX_TOOL_CALLS) for t in truths}
    review = MANIFEST.with_name("CASES.md")
    review.write_text(cases_markdown(truths, prompts), encoding="utf-8")
    typer.echo(f"Built {len(truths)} cases ({sum(t['flows'] for t in truths):,} flows). Review them in {review}")


@eval_app.command("check")
def eval_check() -> None:
    """Check the grader against three made-up analysts. Needs no model and costs nothing."""
    from .evals.runner import self_check

    result = self_check()
    ok = (result["answer_key"] == result["cases"] and result["silent"] == result["clean_cases"]
          and result["accuser"] == 0)
    typer.echo(f"cases           {result['cases']} ({result['clean_cases']} clean)")
    typer.echo(f"answer key      passes {result['answer_key']}   (must be all {result['cases']})")
    typer.echo(f"always silent   passes {result['silent']}   (must be the {result['clean_cases']} clean cases)")
    typer.echo(f"always accuses  passes {result['accuser']}   (must be 0)")
    typer.echo("The grader tells them apart." if ok else "The grader is NOT working as intended.")
    if not ok:
        raise typer.Exit(code=1)


@eval_app.command("run")
def eval_run(
    variant: Annotated[str, typer.Option(help="Where results go: baseline, v1, v2, ...")] = "baseline",
    prompt: Annotated[Optional[str], typer.Option(
        help="System prompt version. Default: the one this variant already used, else the version named "
             "like the variant, else the current one.",
    )] = None,
    model: Annotated[str, typer.Option(help="Claude model id.")] = "claude-haiku-5-5",
    effort: Annotated[Optional[str], typer.Option(help="low, medium, high, xhigh or max.")] = None,
    reps: Annotated[int, typer.Option(help="Times to run each case.")] = 1,
    concurrency: Annotated[int, typer.Option(help="Cases to run at once.")] = 3,
    timeout_s: Annotated[float, typer.Option(help="Wall-clock limit per case, in seconds.")] = 600.0,
    cases: Annotated[Optional[str], typer.Option(help="Comma-separated case ids. Default: every case.")] = None,
    case_set: Annotated[Optional[str], typer.Option("--set", help="Only the dev or the test cases.")] = None,
) -> None:
    """Run the agent on the cases and grade it. This calls the Claude API and is billed to your key."""
    from .agent import AgentError
    from .agent.loop import make_client
    from .evals import EvalError
    from .evals.runner import run_eval

    _load_dotenv()
    try:
        client = make_client(max_retries=5, timeout=300.0)
        counts = run_eval(variant, client=client, prompt=prompt, model=model, effort=effort, reps=reps,
                          concurrency=concurrency, timeout_s=timeout_s, case_set=case_set,
                          case_ids=cases.split(",") if cases else None, progress=typer.echo)
    except (AgentError, EvalError) as exc:
        _fail(str(exc))
    typer.echo(f"ran {counts['ran']} (scored {counts['scored']}, not scored {counts['not_scored']}); "
               f"{counts['already_done']} were already done")


@eval_app.command("report")
def eval_report(
    variant: Annotated[str, typer.Option(help="baseline, v1, v2, ...")] = "baseline",
    regrade: Annotated[bool, typer.Option("--regrade", help="Grade the stored runs again first.")] = False,
) -> None:
    """Print the scoreboard for a finished run and save it as SCOREBOARD.md."""
    from .evals import EvalError
    from .evals import runner
    from .evals.grade import scoreboard_markdown
    from .evals.review import review_markdown

    try:
        if regrade:
            typer.echo(f"regraded {runner.regrade(variant)} runs", err=True)
        sets = runner.sets_with_results(variant)
        title = f"NetTriage eval scoreboard: {variant}"
        if len(sets) == 1:
            text = scoreboard_markdown(runner.load_scoreboard(variant), title)
        else:
            # One table per set, and no table over both: a prompt may have been fitted to the dev cases.
            text = "\n".join([f"# {title}", ""] + [
                scoreboard_markdown(runner.load_scoreboard(variant, name), SET_TITLES[name], level=2) for name in sets])
    except EvalError as exc:
        _fail(str(exc))
    (runner.variant_dir(variant) / "SCOREBOARD.md").write_text(text, encoding="utf-8")
    review = runner.variant_dir(variant) / "REVIEW.md"
    review.write_text(review_markdown(variant), encoding="utf-8")
    typer.echo(text)
    typer.echo(f"Case-by-case grading: {review}", err=True)


SET_TITLES = {
    "dev": "Dev cases (read while the prompt was being written)",
    "test": "Test cases (only scored, never read while changing the prompt)",
}


@eval_app.command("compare")
def eval_compare(
    old: Annotated[str, typer.Argument(help="The variant to compare against, e.g. baseline.")],
    new: Annotated[str, typer.Argument(help="The variant being judged, e.g. v1.")],
) -> None:
    """Compare two finished variants case by case and save the result as COMPARE.md. Costs nothing."""
    from .evals import EvalError
    from .evals import runner
    from .evals.grade import compare_markdown

    try:
        sets = [name for name in runner.sets_with_results(old) if name in runner.sets_with_results(new)]
        if not sets:
            _fail(f"{old!r} and {new!r} have no case set in common.")
        parts = [f"# {new} against {old}", ""]
        # The test set comes first: it is the one a claim can rest on.
        for name in sorted(sets, key=lambda n: n != "test"):
            parts.append(compare_markdown(runner.compare(old, new, name), old, new, SET_TITLES[name], level=2))
        spent = runner.spend()
    except EvalError as exc:
        _fail(str(exc))
    parts.append("Spent so far, failed attempts included: "
                 + ", ".join(f"{name} ${cost:.2f}" for name, cost in spent.items())
                 + f"; ${sum(spent.values()):.2f} in total.\n")
    text = "\n".join(parts)
    path = runner.FLOW_DIR / "COMPARE.md"
    path.write_text(text, encoding="utf-8")
    typer.echo(text)
    typer.echo(f"Saved as {path}", err=True)


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option(help="Address to listen on. Keep 127.0.0.1 unless the server is read-only.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to listen on.")] = 8000,
) -> None:
    """Start the web page and the API behind it, and print the address to open."""
    import uvicorn

    from . import settings

    if host not in ("127.0.0.1", "localhost") and not settings.read_only():
        typer.echo("warning: the page has no login. Anyone who can reach this address can upload captures and "
                   "start investigations on your API key. Set NETTRIAGE_READ_ONLY=1 to prevent that.", err=True)
    typer.echo(f"NetTriage is at http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}  (Ctrl+C stops it)")
    uvicorn.run("nettriage.api.main:app", host=host, port=port, log_level="warning")


@app.command("schema")
def show_schema() -> None:
    """Describe the tables every capture has."""
    for table, columns in schema.TABLES.items():
        typer.echo(f"\n{table}")
        for column in columns:
            typer.echo(f"  {column.name:<18} {column.type:<10} {column.doc}")


if __name__ == "__main__":
    app()
