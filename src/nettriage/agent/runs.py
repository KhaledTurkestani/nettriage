"""Records of finished investigations.

Each run is one JSON file under ``<data dir>/runs/<run id>/run.json``: the
report, the evidence-check outcome, token usage, and every step in order. The
web UI's timeline and the replay mode read these files; so will the evals.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from .. import store
from . import AgentError
from .loop import Investigation

RUN_FILE = "run.json"
_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")


def runs_dir() -> Path:
    return store.data_dir() / "runs"


def to_record(run: Investigation) -> dict:
    record = asdict(run)
    record["report"] = run.report.model_dump() if run.report else None
    return record


def save_run(run: Investigation) -> Path:
    directory = runs_dir() / run.run_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / RUN_FILE
    path.write_text(json.dumps(to_record(run), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_run(run_id: str) -> dict:
    # Run ids become directory names, so anything outside a safe alphabet is refused.
    if not isinstance(run_id, str) or not _RUN_ID.match(run_id):
        raise AgentError(f"No run named {run_id!r}.")
    path = runs_dir() / run_id / RUN_FILE
    if not path.is_file():
        raise AgentError(f"No run named {run_id!r}.")
    return json.loads(path.read_text(encoding="utf-8"))


def list_runs() -> list[dict]:
    """Short summaries of stored runs, newest first."""
    root = runs_dir()
    if not root.is_dir():
        return []
    summaries = []
    for child in root.iterdir():
        path = child / RUN_FILE
        if not path.is_file():
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        report = record.get("report") or {}
        summaries.append({
            "run_id": record["run_id"],
            "capture_id": record["capture_id"],
            "status": record["status"],
            "verdict": report.get("verdict"),
            "findings": len(report.get("findings", [])),
            "tool_calls": record["tool_calls"],
            "cost_usd": record.get("cost_usd"),
            "started_at": record["started_at"],
        })
    return sorted(summaries, key=lambda s: s["started_at"], reverse=True)
