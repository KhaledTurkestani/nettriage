"""Run the agent over the eval cases and keep graded results.

The runner calls the same ``investigate`` function the command line does, with
the same prompt, tools and settings. It differs only in what surrounds a run:

* **Results are written as each case finishes**, one line per (case, repeat),
  and a restart skips what is already there.
* **An attempt that produced nothing to grade is not a zero.** API errors,
  timeouts and a reply served by another model go to ``errors.jsonl`` and are
  tried again on the next run. A refusal, or a model that never delivers a
  report, is the model's own outcome and is graded as a fail.
* **Each case has a wall-clock limit**, because a hung connection can otherwise
  hold a worker forever.
* **The full run record is kept** beside the grades, so results can be graded
  again after a change to the grader without paying for the runs again.
* **A variant is one fixed setup**: one prompt version, one model, one effort.
  The first run writes it to ``summary.json`` and later runs must match it, so
  a results file never mixes two setups.

Layout, under ``evals/investigate/<variant>/``: ``results.jsonl``,
``errors.jsonl``, ``summary.json``, ``system_prompt.txt``, ``traces/`` (readable
transcripts) and ``runs/`` (raw records).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .. import store
from ..agent import AgentError
from ..agent.loop import DEFAULT_MAX_TOOL_CALLS, DEFAULT_MODEL, default_effort, first_message, investigate
from ..agent.prompts import CURRENT, PROMPTS, system_prompt
from ..agent.runs import to_record
from . import EvalError
from .cases import DEV, SETS, built_cases, load_truth
from .grade import CLEAN, MALICIOUS, METRICS, compare_rows, grade_run, scoreboard

FLOW_DIR = Path("evals") / "investigate"
RESULTS, ERRORS, STATE, SUMMARY = "results.jsonl", "errors.jsonl", "_state.json", "summary.json"
# Prompt of records written before prompts had versions.
FIRST_PROMPT = "baseline"
PERF_FIELDS = [
    {"id": "cost_usd", "label": "Cost", "unit": "$"},
    {"id": "latency_s", "label": "Time", "unit": "s"},
    {"id": "tool_calls", "label": "Tool calls"},
]
_VARIANT = re.compile(r"^(baseline|v\d+)$")


def variant_dir(variant: str, flow_dir: Path = FLOW_DIR) -> Path:
    if not _VARIANT.match(variant):
        raise EvalError("A variant is named 'baseline' or 'v1', 'v2', ...")
    return flow_dir / variant


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    # utf-8-sig: a results file that was opened and saved by a Windows tool may start with a BOM.
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def _append(path: Path, row: dict, lock: threading.Lock) -> None:
    with lock, open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def trace_of(record: dict, prompt: str) -> list[dict]:
    """The run as a readable transcript: one entry per message, tool call and tool result."""
    system = system_prompt(record.get("prompt") or FIRST_PROMPT)
    turns = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
    thinking = ""
    for event in record["events"]:
        if event["type"] == "model":
            thinking = "\n\n".join(event["thinking"])
            if event.get("text"):
                turns.append({"role": "assistant", "content": event["text"], **({"thinking": thinking} if thinking else {})})
                thinking = ""
        elif event["type"] == "tool":
            call = {"role": "tool_call", "name": event["name"], "content": json.dumps(event["input"], indent=2)}
            if thinking:
                call["thinking"], thinking = thinking, ""
            turns += [call, {"role": "tool_result", "name": event["name"], "content": event["output"]}]
        elif event["type"] == "evidence_check" and event["rejected"]:
            notes = [f"- {r['finding']}: {' '.join(r['problems'])}" for r in event["rejected"]]
            turns.append({"role": "user", "content": "The evidence check rejected:\n" + "\n".join(notes)})
        elif event["type"] == "end" and event["status"] != "completed":
            turns.append({"role": "assistant", "content": f"[run ended: {event['status']}; {event['error']}]"})
    return turns


def row_from_record(record: dict, truth: dict, rep: int, latency_s: float) -> dict:
    """The result row for one finished run. Pure, so stored records can be graded again."""
    labels = store.load_labels(truth["id"]).set_index("flow_id")["label"]
    graded = grade_run(record, truth, labels)
    meta = store.load_meta(truth["id"])
    stops = [e["stop_reason"] for e in record["events"] if e["type"] == "model"]
    max_tool_calls = record.get("max_tool_calls", DEFAULT_MAX_TOOL_CALLS)
    return {
        "prompt_id": truth["id"],
        "rep": rep,
        "prompt": first_message(meta, max_tool_calls),
        "tags": truth["tags"],
        "stop_reason": stops[-1] if stops else None,
        "status": "ok",
        "grade": graded["grade"],
        "model": record["served_by"][-1] if record["served_by"] else record["model"],
        "usage": record["usage"],
        "cost_usd": record["cost_usd"],
        "latency_s": round(latency_s, 1),
        "tool_calls": record["tool_calls"],
        "api_calls": record["api_calls"],
        "meta": {
            "malicious": truth["malicious"], "family": truth["family"], "set": truth.get("set", DEV),
            "run_id": record["run_id"], "effort": record["effort"],
            "prompt_version": record.get("prompt") or FIRST_PROMPT,
            "validation": record["validation"], **graded["detail"],
        },
    }


def _attempt(case: dict, rep: int, *, client, model: str, effort: str | None, max_tool_calls: int,
             timeout_s: float, prompt: str = CURRENT) -> tuple[str, dict, dict | None]:
    """Run one case once. Returns ("row" | "error", the line to write, the raw record if there is one)."""
    box: dict = {}

    def work() -> None:
        try:
            box["run"] = investigate(case["id"], client=client, model=model, effort=effort,
                                     max_tool_calls=max_tool_calls, prompt=prompt)
        except Exception as exc:  # anything that escapes is the harness's failure, not the model's answer
            box["error"] = f"{type(exc).__name__}: {exc}"

    started = time.perf_counter()
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout_s)
    elapsed = time.perf_counter() - started
    failed = {"prompt_id": case["id"], "rep": rep, "model": model, "latency_s": round(elapsed, 1)}
    if thread.is_alive():
        return "error", {**failed, "class": "timeout", "error": f"No result after {timeout_s:.0f} s."}, None
    if "error" in box:
        return "error", {**failed, "class": "harness", "error": box["error"]}, None

    record = {**to_record(box["run"]), "max_tool_calls": max_tool_calls}
    spent = {"usage": record["usage"], "cost_usd": record["cost_usd"]}
    if record["status"] == "failed" and str(record["error"]).startswith("API error"):
        return "error", {**failed, **spent, "class": "api_error", "error": record["error"]}, record
    if any(served != model for served in record["served_by"]):
        # A score produced by another model measures nothing about this one.
        return "error", {**failed, **spent, "class": "served_model_mismatch",
                         "error": f"Served by {record['served_by']}."}, record

    row = row_from_record(record, case, rep, elapsed)
    if record["status"] == "failed" and "output limit" in str(record["error"]):
        row["status"], row["grade"] = "truncated", {}  # counted and shown, but not averaged in as wrong
    return "row", row, record


def _setup(out: Path, variant: str, *, prompt: str | None, model: str, effort: str | None,
           max_tool_calls: int) -> dict:
    """The setup this variant runs with: taken from its first run, and checked on every later one."""
    path = out / SUMMARY
    saved = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    rows = read_jsonl(out / RESULTS)
    if not saved and rows:  # results from before setups were recorded
        saved = {"prompt": rows[0]["meta"].get("prompt_version", FIRST_PROMPT), "model": rows[0]["model"],
                 "effort": rows[0]["meta"]["effort"]}
    wanted = {
        "prompt": prompt or saved.get("prompt") or (variant if variant in PROMPTS else CURRENT),
        "model": model, "effort": effort or default_effort(model), "max_tool_calls": max_tool_calls,
    }
    try:
        text = system_prompt(wanted["prompt"])
    except AgentError as exc:
        raise EvalError(str(exc)) from exc
    differs = [f"{key} {saved[key]!r} (asked for {value!r})" for key, value in wanted.items()
               if key in saved and saved[key] != value]
    if differs:
        raise EvalError(f"Variant {variant!r} already has results made with {', '.join(differs)}. "
                        "Use a new variant name for a different setup.")
    summary = {"description": f"prompt {wanted['prompt']}, {model}, effort {wanted['effort']}",
               "target": "system_prompt", **saved, **wanted}
    # Nothing is created before this point, so a refused setup leaves no empty variant behind.
    (out / "traces").mkdir(parents=True, exist_ok=True)
    (out / "runs").mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "system_prompt.txt").write_text(text, encoding="utf-8")
    return wanted


def _write_state(flow_dir: Path, reps: int) -> None:
    """Keep ``_state.json`` current: what the metrics are, and which cases a prompt may be tuned on."""
    path = flow_dir / STATE
    state = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    cases = built_cases()
    state.update({
        "metrics": METRICS, "perf_fields": PERF_FIELDS,
        "reps": max(reps, state.get("reps", 1)),
        # The report tools call the two sets train and test. "Train" here means only that these
        # cases were read while the prompt was being written; nothing is trained on them.
        "train_ids": [c["id"] for c in cases if c.get("set", DEV) == DEV],
        "test_ids": [c["id"] for c in cases if c.get("set", DEV) != DEV],
    })
    state.setdefault("goal", {"target": "pass", "direction": "higher", "hold": ["attack_found", "resisted"]})
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def run_eval(
    variant: str = "baseline",
    *,
    client,
    prompt: str | None = None,
    model: str = DEFAULT_MODEL,
    effort: str | None = None,
    reps: int = 1,
    concurrency: int = 3,
    timeout_s: float = 600.0,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    case_ids: list[str] | None = None,
    case_set: str | None = None,
    flow_dir: Path = FLOW_DIR,
    progress: Callable[[str], None] = lambda line: None,
) -> dict:
    """Run every case that has no result yet, then return counts. Each run is billed to the caller's key.

    ``prompt`` names a prompt version. Left out, it is the one this variant already used, or the
    version named like the variant, or the current one. ``case_set`` limits the run to "dev" or "test".
    """
    out = variant_dir(variant, flow_dir)
    cases = [load_truth(i) for i in case_ids] if case_ids else built_cases()
    if case_set:
        if case_set not in SETS:
            raise EvalError(f"A case set is one of: {', '.join(SETS)}.")
        cases = [case for case in cases if case.get("set", DEV) == case_set]
    if not cases:
        raise EvalError("No cases to run. Build them with: nettriage eval build")
    setup = _setup(out, variant, prompt=prompt, model=model, effort=effort, max_tool_calls=max_tool_calls)
    _write_state(flow_dir, reps)
    progress(f"{variant}: {len(cases)} cases x {reps} with prompt {setup['prompt']}, {model}, "
             f"effort {setup['effort']}, up to {max_tool_calls} tool calls")
    done = {(row["prompt_id"], row["rep"]) for row in read_jsonl(out / RESULTS)}
    todo = [(case, rep) for case in cases for rep in range(reps) if (case["id"], rep) not in done]
    counts = {"cases": len(cases), "already_done": len(cases) * reps - len(todo), "ran": 0, "scored": 0,
              "not_scored": 0}
    lock = threading.Lock()

    def one(case: dict, rep: int) -> tuple[str, dict]:
        kind, line, record = _attempt(case, rep, client=client, model=model, effort=effort,
                                      max_tool_calls=max_tool_calls, timeout_s=timeout_s, prompt=setup["prompt"])
        name = f"{case['id']}_rep{rep}.json"
        if record is not None:
            (out / "runs" / name).write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        if kind == "row":
            (out / "traces" / name).write_text(
                json.dumps(trace_of(record, line["prompt"]), indent=1, ensure_ascii=False), encoding="utf-8")
        _append(out / (RESULTS if kind == "row" else ERRORS), line, lock)
        return kind, line

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(one, case, rep) for case, rep in todo]
        for future in as_completed(futures):
            kind, line = future.result()
            counts["ran"] += 1
            counts["scored" if kind == "row" else "not_scored"] += 1
            if kind == "row":
                verdict = line["meta"].get("verdict") or line["meta"]["outcome"]
                progress(f"{line['prompt_id']}  {'pass' if line['grade'].get('pass') else 'FAIL'}  "
                         f"{verdict}  {line['latency_s']:.0f}s  {line['tool_calls']} tools")
            else:
                progress(f"{line['prompt_id']}  NOT SCORED ({line['class']}): {line['error']}")
    return counts


def regrade(variant: str = "baseline", flow_dir: Path = FLOW_DIR) -> int:
    """Rewrite ``results.jsonl`` from the stored run records, with the grader as it is now."""
    out = variant_dir(variant, flow_dir)
    old = read_jsonl(out / RESULTS)
    rows = []
    for row in old:
        path = out / "runs" / f"{row['prompt_id']}_rep{row['rep']}.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        fresh = row_from_record(record, load_truth(row["prompt_id"]), row["rep"], row["latency_s"])
        if row.get("status") == "truncated":
            fresh["status"], fresh["grade"] = "truncated", {}
        rows.append(fresh)
    (out / RESULTS).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return len(rows)


def _set_of(case_id: str) -> str:
    return load_truth(case_id).get("set", DEV)


def load_rows(variant: str, case_set: str | None = None, flow_dir: Path = FLOW_DIR) -> tuple[list[dict], list[dict]]:
    """Result rows and still-open errors of a variant, optionally for one case set only."""
    out = variant_dir(variant, flow_dir)
    rows = read_jsonl(out / RESULTS)
    if not rows:
        raise EvalError(f"No results for variant {variant!r}. Run: nettriage eval run --variant {variant}")
    # An attempt in the error list stops counting once that case has a result.
    scored = {(r["prompt_id"], r["rep"]) for r in rows}
    errors = [e for e in read_jsonl(out / ERRORS) if (e["prompt_id"], e["rep"]) not in scored]
    if case_set:
        rows = [r for r in rows if _set_of(r["prompt_id"]) == case_set]
        errors = [e for e in errors if _set_of(e["prompt_id"]) == case_set]
    return rows, errors


def sets_with_results(variant: str, flow_dir: Path = FLOW_DIR) -> list[str]:
    rows, _ = load_rows(variant, flow_dir=flow_dir)
    present = {_set_of(r["prompt_id"]) for r in rows}
    return [name for name in SETS if name in present]


def load_scoreboard(variant: str = "baseline", case_set: str | None = None, flow_dir: Path = FLOW_DIR) -> dict:
    return scoreboard(*load_rows(variant, case_set, flow_dir))


def compare(old: str, new: str, case_set: str | None = None, flow_dir: Path = FLOW_DIR) -> dict:
    """Two variants on the runs both of them have, so the comparison is case by case."""
    old_rows, _ = load_rows(old, case_set, flow_dir)
    new_rows, _ = load_rows(new, case_set, flow_dir)
    result = compare_rows(old_rows, new_rows)
    if not result["runs_compared"]:
        where = f" in the {case_set} set" if case_set else ""
        raise EvalError(f"{old!r} and {new!r} have no scored run of the same case{where}.")
    return result


def spend(flow_dir: Path = FLOW_DIR) -> dict[str, float]:
    """Money spent per variant, failed attempts included. Summed from the result files every time."""
    totals = {}
    for out in sorted(p for p in flow_dir.iterdir() if p.is_dir() and _VARIANT.match(p.name)):
        lines = read_jsonl(out / RESULTS) + read_jsonl(out / ERRORS)
        totals[out.name] = round(sum(line.get("cost_usd") or 0.0 for line in lines), 4)
    return totals


# ---------------------------------------------------------------- checks that need no model


def _fake_record(report: dict, events: list | None = None) -> dict:
    return {"status": "completed", "report": report, "events": events or [], "served_by": ["self-check"],
            "model": "self-check", "usage": {}, "cost_usd": None, "tool_calls": 0, "api_calls": 0,
            "run_id": "self-check", "effort": "none", "validation": {"findings_reported": len(report["findings"])}}


def _finding(attack_type: str, attackers: list[str], flow_ids: list[int]) -> dict:
    return {"title": "self-check", "attack_type": attack_type, "severity": "high", "confidence": "high",
            "attacker_ips": attackers, "victim_ips": [], "first_seen": "", "last_seen": "", "description": "",
            "evidence": [{"claim": "self-check", "flow_ids": flow_ids}]}


def self_check() -> dict:
    """Push three made-up analysts through the grader to see that it can tell them apart.

    * the **answer key** reports exactly what the ground truth says and must pass every case;
    * the **silent** one always reports nothing and must pass the clean cases only;
    * the **accuser** always reports an attack by an innocent host and must pass none.
    """
    results = {"answer_key": [], "silent": [], "accuser": []}
    for truth in built_cases():
        labels = store.load_labels(truth["id"]).set_index("flow_id")["label"]
        benign = [int(i) for i in labels[labels == "BENIGN"].index[:5]]
        con = store.connect_readonly(truth["id"])
        try:
            bystander = con.execute(
                f"SELECT src_ip FROM flows WHERE flow_id = {benign[0]}").fetchone()[0]
        finally:
            con.close()
        key_findings = []
        for attack in truth["attacks"][:1]:
            ids = [int(i) for i in labels[labels == attack["label"]].index[:5]]
            key_findings.append(_finding(attack["family"], attack["accepted_attackers"][:1], ids))
        analysts = {
            "answer_key": {"verdict": MALICIOUS if truth["malicious"] else CLEAN, "findings": key_findings},
            "silent": {"verdict": CLEAN, "findings": []},
            "accuser": {"verdict": MALICIOUS, "findings": [_finding("other", [bystander], benign)]},
        }
        for name, answer in analysts.items():
            report = {"summary": "", "limitations": [], **answer}
            results[name].append(grade_run(_fake_record(report), truth, labels)["grade"]["pass"])
    clean = sum(1 for truth in built_cases() if not truth["malicious"])
    return {"cases": len(results["silent"]), "clean_cases": clean,
            **{name: int(sum(passes)) for name, passes in results.items()}}
