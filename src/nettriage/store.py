"""On-disk capture store.

Each capture is a directory under ``<data dir>/captures/<capture id>/``:

* ``capture.duckdb``  the ``flows``, ``dns`` and ``http`` tables
* ``meta.json``       where the capture came from and a few counts
* ``labels.parquet``  ground-truth labels, only for labelled datasets

Labels live outside the database on purpose. The agent's tools only ever get
``connect_readonly``, which cannot read other files, so an investigation can
never peek at the answer it is being graded on.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pandas as pd

from . import schema

DB_FILE = "capture.duckdb"
META_FILE = "meta.json"
LABELS_FILE = "labels.parquet"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class CaptureError(Exception):
    """A capture could not be read or written."""


@dataclass
class CaptureMeta:
    id: str
    source: str  # "cic_csv" or "pcap"
    original_name: str
    created_at: str
    flow_count: int
    dns_count: int
    http_count: int
    first_ts: str | None
    last_ts: str | None
    has_labels: bool
    notes: dict = field(default_factory=dict)


def data_dir() -> Path:
    return Path(os.environ.get("NETTRIAGE_DATA_DIR", "data"))


def captures_dir() -> Path:
    return data_dir() / "captures"


def validate_capture_id(capture_id: str) -> str:
    """Capture ids become directory names, so only a safe alphabet is allowed."""
    if not isinstance(capture_id, str) or not _ID_RE.match(capture_id):
        raise CaptureError(
            f"Invalid capture id {capture_id!r}: use 1-64 characters from a-z, 0-9, '-' and '_', "
            "starting with a letter or digit."
        )
    return capture_id


def new_capture_id(name: str | None = None) -> str:
    """Make a fresh id, readable when a file name is given."""
    slug = re.sub(r"[^a-z0-9]+", "-", Path(name).stem.lower()).strip("-")[:40].strip("-") if name else ""
    suffix = uuid.uuid4().hex[:6]
    return f"{slug}-{suffix}" if slug else f"cap-{suffix}"


def capture_dir(capture_id: str) -> Path:
    return captures_dir() / validate_capture_id(capture_id)


def _sql_path(path: Path) -> str:
    return str(path).replace("\\", "/").replace("'", "''")


def _insert(con: duckdb.DuckDBPyConnection, table: str, frame: pd.DataFrame | None) -> None:
    con.execute(schema.create_table_sql(table))
    if frame is None or frame.empty:
        return
    columns = schema.column_names(table)
    missing = [c for c in columns if c not in frame.columns]
    if missing:
        raise CaptureError(f"Table {table!r} is missing columns: {', '.join(missing)}")
    column_list = ", ".join(columns)
    con.register("incoming", frame[columns])
    try:
        con.execute(f"INSERT INTO {table} ({column_list}) SELECT {column_list} FROM incoming")
    finally:
        con.unregister("incoming")


def write_capture(
    capture_id: str,
    *,
    source: str,
    original_name: str,
    flows: pd.DataFrame,
    dns: pd.DataFrame | None = None,
    http: pd.DataFrame | None = None,
    labels: pd.DataFrame | None = None,
    notes: dict | None = None,
    overwrite: bool = False,
) -> CaptureMeta:
    """Write a capture to disk. Nothing is left behind if writing fails."""
    final_dir = capture_dir(capture_id)
    if final_dir.exists() and not overwrite:
        raise CaptureError(f"Capture {capture_id!r} already exists. Pass overwrite to replace it.")

    captures_dir().mkdir(parents=True, exist_ok=True)
    tmp_dir = captures_dir() / f".tmp-{capture_id}-{uuid.uuid4().hex[:8]}"
    tmp_dir.mkdir()
    try:
        con = duckdb.connect(str(tmp_dir / DB_FILE))
        try:
            _insert(con, "flows", flows)
            _insert(con, "dns", dns)
            _insert(con, "http", http)
            flow_count, first_ts, last_ts = con.execute(
                "SELECT count(*), min(ts), max(ts) FROM flows"
            ).fetchone()
            dns_count = con.execute("SELECT count(*) FROM dns").fetchone()[0]
            http_count = con.execute("SELECT count(*) FROM http").fetchone()[0]
        finally:
            con.close()

        has_labels = labels is not None and not labels.empty
        if has_labels:
            mem = duckdb.connect()
            try:
                mem.register("incoming", labels[["flow_id", "label"]])
                mem.execute(
                    "COPY (SELECT CAST(flow_id AS BIGINT) AS flow_id, CAST(label AS VARCHAR) AS label "
                    f"FROM incoming ORDER BY flow_id) TO '{_sql_path(tmp_dir / LABELS_FILE)}' (FORMAT parquet)"
                )
            finally:
                mem.close()

        meta = CaptureMeta(
            id=capture_id,
            source=source,
            original_name=original_name,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            flow_count=flow_count,
            dns_count=dns_count,
            http_count=http_count,
            first_ts=first_ts.isoformat() if first_ts else None,
            last_ts=last_ts.isoformat() if last_ts else None,
            has_labels=has_labels,
            notes=notes or {},
        )
        (tmp_dir / META_FILE).write_text(json.dumps(asdict(meta), indent=2), encoding="utf-8")

        if final_dir.exists():
            shutil.rmtree(final_dir)
        os.replace(tmp_dir, final_dir)
        return meta
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def load_meta(capture_id: str) -> CaptureMeta:
    path = capture_dir(capture_id) / META_FILE
    if not path.is_file():
        raise CaptureError(f"No capture named {capture_id!r}.")
    return CaptureMeta(**json.loads(path.read_text(encoding="utf-8")))


def list_captures() -> list[CaptureMeta]:
    """All captures, newest first."""
    root = captures_dir()
    if not root.is_dir():
        return []
    metas = []
    for child in root.iterdir():
        if child.is_dir() and not child.name.startswith(".") and (child / META_FILE).is_file():
            metas.append(CaptureMeta(**json.loads((child / META_FILE).read_text(encoding="utf-8"))))
    return sorted(metas, key=lambda m: m.created_at, reverse=True)


def connect_readonly(capture_id: str) -> duckdb.DuckDBPyConnection:
    """Open a capture for querying, with no way to write or to reach other files.

    This is the only connection the agent's tools may use. The database is
    read-only, file and network access from SQL is disabled (no ``read_csv``,
    ``COPY``, ``ATTACH`` or extension loading), memory is capped so a runaway
    query fails instead of exhausting the machine, and the configuration is
    locked so a query cannot switch any of that back on.
    """
    path = capture_dir(capture_id) / DB_FILE
    if not path.is_file():
        raise CaptureError(f"No capture named {capture_id!r}.")
    con = duckdb.connect(
        str(path),
        read_only=True,
        config={
            "enable_external_access": "false",
            "autoinstall_known_extensions": "false",
            "autoload_known_extensions": "false",
            "memory_limit": "2GB",
        },
    )
    con.execute("SET lock_configuration = true")
    return con


def load_labels(capture_id: str) -> pd.DataFrame:
    """Ground-truth labels for a labelled capture. For evals only, never for the agent."""
    path = capture_dir(capture_id) / LABELS_FILE
    if not path.is_file():
        raise CaptureError(f"Capture {capture_id!r} has no labels.")
    con = duckdb.connect()
    try:
        return con.execute(f"SELECT flow_id, label FROM read_parquet('{_sql_path(path)}')").df()
    finally:
        con.close()
