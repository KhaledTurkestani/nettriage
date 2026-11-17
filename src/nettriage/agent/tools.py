"""The tools the agent can call.

Every tool reads the capture through ``store.connect_readonly`` and nothing
else: no writes, no files, no network. Results are bounded (rows, cell width,
total size) and queries are interrupted after a time limit, so one careless
query cannot flood the model's context or hang a run.

The capture's file name and id are never shown to the model. Dataset files are
often named after the attack they contain.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal

import duckdb

from .. import store
from ..classifier import ClassifierError
from ..classifier.model import FlowModel, classify_flows

MAX_ROWS = 50
MAX_CELL_CHARS = 200
MAX_OUTPUT_CHARS = 12_000
MAX_QUERY_CHARS = 4_000
SQL_TIMEOUT_SECONDS = 20.0
READ_KEYWORDS = ("select", "with", "describe", "summarize")

# Definitions are sent on every request and are part of the cached prompt prefix: keep the
# order and the text stable. strict + additionalProperties make the API hold inputs to the
# schema; eager_input_streaming is the documented default for streamed requests with client
# tools, and is why run_tool validates every input itself before running anything.
TOOLS: list[dict] = [
    {
        "name": "capture_overview",
        "description": (
            "Summary of the capture: time span, flow counts, protocols, busiest sources, destinations and "
            "ports, a coarse timeline, and the most common HTTP hosts, user agents and DNS names when the "
            "capture has them. Call this first, once, to decide where to look."
        ),
        "strict": True,
        "eager_input_streaming": True,
        "input_schema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    },
    {
        "name": "run_sql",
        "description": (
            "Run one read-only DuckDB query (SELECT or WITH) over the tables flows, dns and http. Use it to test "
            "a hypothesis and to collect the flow_id values you will cite. At most 50 rows come back, so "
            "aggregate with GROUP BY and use ORDER BY and LIMIT rather than listing flows. A query that runs "
            "longer than 20 seconds is stopped."
        ),
        "strict": True,
        "eager_input_streaming": True,
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "A single SELECT or WITH statement."}},
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "classify_flows",
        "description": (
            "Score flows with a machine-learning classifier and get the sources and targets with the most "
            "flagged flows, with example flow ids. Call it early for leads, and again with a filter to look at "
            "one host or port. It recognises attack types it was trained on and misses others: flows it does "
            "not flag are not thereby benign, so also look for attacks yourself with run_sql."
        ),
        "strict": True,
        "eager_input_streaming": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "where": {
                    "type": "string",
                    "description": (
                        "SQL condition over the flows table, e.g. \"dst_port = 22\" or "
                        "\"src_ip = '10.0.0.5'\". Pass an empty string to score every flow."
                    ),
                }
            },
            "required": ["where"],
            "additionalProperties": False,
        },
    },
]
TOOL_NAMES = tuple(tool["name"] for tool in TOOLS)


@dataclass
class ToolResult:
    content: str
    is_error: bool = False


def _error(message: str) -> ToolResult:
    return ToolResult(content=message, is_error=True)


def _plain(value):
    """A DuckDB value as something JSON can hold, with long text cut short."""
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value[:MAX_ROWS]]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    text = str(value)
    return text if len(text) <= MAX_CELL_CHARS else text[:MAX_CELL_CHARS] + "..."


def _dump(payload: dict) -> str:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _query(con: duckdb.DuckDBPyConnection, sql: str, limit: int | None = None) -> tuple[list[str], list[tuple]]:
    cursor = con.execute(sql)
    columns = [d[0] for d in cursor.description or []]
    return columns, (cursor.fetchmany(limit) if limit else cursor.fetchall())


def run_sql(capture_id: str, query: str, timeout: float | None = None) -> ToolResult:
    """Run one read-only query with a row cap and a time limit."""
    text = query.strip().rstrip(";").strip()
    if not text:
        return _error("The query is empty.")
    if len(text) > MAX_QUERY_CHARS:
        return _error(f"The query is longer than {MAX_QUERY_CHARS} characters.")
    # The first word decides, after any opening parentheses: "(SELECT ...) UNION ALL (SELECT ...)"
    # is an ordinary read. This check only gives a clear message; the read-only connection is
    # what actually prevents writes.
    first_word = re.match(r"[(\s]*([A-Za-z]+)", text)
    if first_word is None or first_word.group(1).lower() not in READ_KEYWORDS:
        return _error("Only SELECT or WITH queries are allowed. The capture is read-only.")

    con = store.connect_readonly(capture_id)
    timer = threading.Timer(SQL_TIMEOUT_SECONDS if timeout is None else timeout, con.interrupt)
    timer.start()
    try:
        columns, rows = _query(con, text, MAX_ROWS + 1)
    except duckdb.InterruptException:
        return _error(
            f"The query was stopped after {SQL_TIMEOUT_SECONDS if timeout is None else timeout:g} seconds. "
            "Make it cheaper: filter first, aggregate, avoid joining large tables without a condition."
        )
    except duckdb.Error as exc:
        return _error(f"Query failed: {str(exc).splitlines()[0]}")
    finally:
        timer.cancel()
        con.close()

    truncated = len(rows) > MAX_ROWS
    out_rows = [[_plain(v) for v in row] for row in rows[:MAX_ROWS]]
    payload = {"columns": columns, "rows": out_rows, "rows_returned": len(out_rows), "truncated": truncated}
    while len(_dump(payload)) > MAX_OUTPUT_CHARS and payload["rows"]:
        payload["rows"] = payload["rows"][: len(payload["rows"]) // 2]
        payload["rows_returned"] = len(payload["rows"])
        payload["truncated"] = True
    if payload["truncated"]:
        payload["note"] = "More rows exist. Aggregate, or add ORDER BY and LIMIT, to see what matters."
    return ToolResult(_dump(payload))


def capture_overview(capture_id: str) -> ToolResult:
    """What is in the capture, in one screen."""
    meta = store.load_meta(capture_id)
    con = store.connect_readonly(capture_id)
    try:
        first, last, flows, flagged = con.execute(
            "SELECT min(ts), max(ts), count(*), count(syn_count) FROM flows"
        ).fetchone()
        span = max(1.0, (last - first).total_seconds())
        bucket = max(1, math.ceil(span / 12))

        def table(sql: str) -> list[dict]:
            columns, rows = _query(con, sql)
            return [dict(zip(columns, (_plain(v) for v in row))) for row in rows]

        payload = {
            "source": "packet capture" if meta.source == "pcap" else "flow records (no packet contents)",
            "first_flow": _plain(first),
            "last_flow": _plain(last),
            "flows": flows,
            "dns_rows": meta.dns_count,
            "http_rows": meta.http_count,
            "tcp_flag_counts_available": bool(flagged),
            "protocols": table("SELECT protocol, count(*) AS flows FROM flows GROUP BY 1 ORDER BY 2 DESC"),
            "top_sources": table(
                "SELECT src_ip, count(*) AS flows, count(DISTINCT dst_ip) AS dst_ips, "
                "count(DISTINCT dst_port) AS dst_ports, sum(fwd_bytes + bwd_bytes) AS bytes "
                "FROM flows GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
            ),
            "top_destinations": table(
                "SELECT dst_ip, count(*) AS flows, count(DISTINCT src_ip) AS src_ips, "
                "count(DISTINCT dst_port) AS dst_ports FROM flows GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
            ),
            "top_destination_ports": table(
                "SELECT dst_port, protocol, count(*) AS flows, count(DISTINCT src_ip) AS src_ips "
                "FROM flows GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10"
            ),
            "timeline": table(
                f"SELECT time_bucket(INTERVAL {bucket} SECOND, ts) AS start, count(*) AS flows, "
                "count(DISTINCT src_ip) AS src_ips FROM flows GROUP BY 1 ORDER BY 1"
            ),
            "timeline_bucket_seconds": bucket,
        }
        # What the traffic said, when the capture has it. This text was written by whoever
        # generated the traffic; like every tool result it is data for the model, not instructions.
        if meta.http_count:
            payload["http"] = {
                "top_hosts": table("SELECT host, count(*) AS requests FROM http GROUP BY 1 ORDER BY 2 DESC LIMIT 5"),
                "top_user_agents": table(
                    "SELECT user_agent, count(*) AS requests, count(DISTINCT src_ip) AS clients "
                    "FROM http GROUP BY 1 ORDER BY 2 DESC LIMIT 5"
                ),
            }
        if meta.dns_count:
            payload["dns"] = {
                "top_queries": table(
                    "SELECT query, count(*) AS messages FROM dns WHERE NOT is_response GROUP BY 1 ORDER BY 2 DESC LIMIT 5"
                ),
            }
    finally:
        con.close()
    return ToolResult(_dump(payload))


def _classify(capture_id: str, where: str, model: FlowModel | None) -> ToolResult:
    try:
        result = classify_flows(capture_id, where.strip() or None, top=5, model=model)
    except ClassifierError as exc:
        return _error(str(exc))
    result.pop("capture", None)  # the id may give the answer away
    return ToolResult(_dump(result))


def run_tool(capture_id: str, name: str, tool_input, *, model: FlowModel | None = None) -> tuple[ToolResult, float]:
    """Validate a tool call, run it, and return the result with the time it took in milliseconds.

    Never raises for anything the model did: a bad name, a malformed input or a
    failing query all come back as an error result the model can react to.
    """
    started = time.perf_counter()
    if not isinstance(tool_input, dict):
        result = _error("The tool input must be a JSON object.")
    elif name == "capture_overview":
        result = capture_overview(capture_id)
    elif name == "run_sql":
        query = tool_input.get("query")
        result = run_sql(capture_id, query) if isinstance(query, str) else _error("'query' must be a string.")
    elif name == "classify_flows":
        where = tool_input.get("where", "")
        if not isinstance(where, str) or len(where) > MAX_QUERY_CHARS:
            result = _error("'where' must be a string of at most 4000 characters.")
        else:
            result = _classify(capture_id, where, model)
    else:
        result = _error(f"Unknown tool {name!r}. Available tools: {', '.join(TOOL_NAMES)}.")
    return result, (time.perf_counter() - started) * 1000
