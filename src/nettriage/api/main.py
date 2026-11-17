"""HTTP API and the web page.

What the page can do goes through here: list and upload captures, start an
investigation, follow it live, read stored investigations and look up the
flows a report cites.

Three things are treated as hostile:

* **Uploaded files.** Size is capped while the bytes arrive, the name is never
  used as a path, and only the capture formats the ingest code knows are taken.
* **Other web pages.** An investigation costs money, so a page on another site
  must not be able to start one through the visitor's browser. Requests that
  change anything are refused when they come from another origin, and the
  server only answers to the host names it was told about.
* **Everything a run produced.** Tool output and report text were written by a
  model reading attacker-controlled traffic. The API passes them on as JSON
  strings and the page shows them as text, never as markup.

Ground-truth labels are not served by any endpoint.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import uuid
from dataclasses import asdict
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.datastructures import Headers
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__, settings, store
from ..agent import AgentError
from ..agent.loop import (
    DEFAULT_MAX_TOOL_CALLS, DEFAULT_MODEL, EFFORTS, PRICES, default_effort, make_client,
)
from ..agent.prompts import CURRENT, PROMPTS
from ..agent.runs import list_runs, load_run
from ..agent.tools import capture_overview
from ..ingest import IngestError
from .live import LiveRuns

STATIC_DIR = Path(__file__).parent / "static"
UPLOAD_SUFFIXES = {".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap", ".csv": "csv"}
# A capture read from packets is cut off here, so one upload cannot keep the server busy for hours.
MAX_UPLOAD_PACKETS = 2_000_000
MAX_FLOW_IDS = 200
MAX_TOOL_CALLS_LIMIT = 60
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

live_runs = LiveRuns()


class SameOriginWrites:
    """Refuse requests that change something when another site's page sent them."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] not in SAFE_METHODS:
            headers = Headers(scope=scope)
            origin = headers.get("origin")
            foreign = bool(origin) and urlsplit(origin).netloc != headers.get("host")
            if foreign or headers.get("sec-fetch-site") == "cross-site":
                response = JSONResponse({"detail": "Requests from other sites are not accepted."}, status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


app = FastAPI(
    title="NetTriage API",
    version=__version__,
    description="Investigate network captures with an AI agent.",
)
app.add_middleware(SameOriginWrites)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts())
api = APIRouter(prefix="/api")


def _plain(value):
    """A database value as something JSON can hold."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    return value


def _meta_or_404(capture_id: str) -> store.CaptureMeta:
    try:
        return store.load_meta(capture_id)
    except store.CaptureError:
        raise HTTPException(404, "No such capture.") from None


def _kind(meta: store.CaptureMeta) -> str:
    try:
        is_case = (store.data_dir() / "cases" / f"{meta.id}.json").is_file()
    except OSError:
        is_case = False
    return "eval case" if is_case else ("dataset" if meta.has_labels else "upload")


def _capture_json(meta: store.CaptureMeta, runs: dict[str, int] | None = None) -> dict:
    data = asdict(meta)
    data.pop("has_labels")  # whether an answer key exists is not the page's business
    return {**data, "kind": _kind(meta), "runs": (runs or {}).get(meta.id, 0)}


def _writable() -> None:
    if settings.read_only():
        raise HTTPException(403, "This server is read-only: it shows stored investigations and accepts nothing new.")


# ---------------------------------------------------------------- reading


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@api.get("/config")
def config() -> dict:
    """What this server can do, for the page to decide which buttons to show."""
    read_only = settings.read_only()
    return {
        "version": __version__,
        "read_only": read_only,
        "can_investigate": not read_only and settings.api_key_configured(),
        "can_upload": not read_only,
        "max_upload_mb": settings.max_upload_bytes() // (1024 * 1024),
        "upload_suffixes": sorted(UPLOAD_SUFFIXES),
        "default_model": DEFAULT_MODEL,
        "models": [{"id": model, "default_effort": default_effort(model),
                    "input_per_mtok": cards[0][1]["input"], "output_per_mtok": cards[0][1]["output"]}
                   for model, cards in sorted(PRICES.items(), key=lambda item: item[1][0][1]["input"])],
        "prompt": CURRENT,
        "prompts": list(PROMPTS),
        "default_max_tool_calls": DEFAULT_MAX_TOOL_CALLS,
        "max_tool_calls_limit": MAX_TOOL_CALLS_LIMIT,
    }


@api.get("/captures")
def captures() -> list[dict]:
    counts: dict[str, int] = {}
    for run in list_runs():
        counts[run["capture_id"]] = counts.get(run["capture_id"], 0) + 1
    return [_capture_json(meta, counts) for meta in store.list_captures()]


@api.get("/captures/{capture_id}")
def capture(capture_id: str) -> dict:
    meta = _meta_or_404(capture_id)
    result = capture_overview(capture_id)
    return {**_capture_json(meta), "overview": None if result.is_error else json.loads(result.content),
            "run_list": [run for run in list_runs() if run["capture_id"] == capture_id]}


@api.get("/captures/{capture_id}/flows")
def flows(capture_id: str, ids: str) -> dict:
    """The flows with the given ids: what a report's evidence points at."""
    _meta_or_404(capture_id)
    try:
        wanted = sorted({int(part) for part in ids.split(",") if part.strip()})
    except ValueError:
        raise HTTPException(422, "ids must be whole numbers separated by commas.") from None
    if not wanted or len(wanted) > MAX_FLOW_IDS:
        raise HTTPException(422, f"Give between 1 and {MAX_FLOW_IDS} flow ids.")
    con = store.connect_readonly(capture_id)
    try:
        marks = ", ".join("?" for _ in wanted)
        cursor = con.execute(f"SELECT * FROM flows WHERE flow_id IN ({marks}) ORDER BY flow_id", wanted)
        columns = [d[0] for d in cursor.description]
        rows = [[_plain(value) for value in row] for row in cursor.fetchall()]
    finally:
        con.close()
    found = {row[columns.index("flow_id")] for row in rows}
    return {"columns": columns, "rows": rows, "missing": [i for i in wanted if i not in found]}


@api.get("/runs")
def runs() -> list[dict]:
    stored = list_runs()
    known = {run["run_id"] for run in stored}
    running = [{"run_id": run.run_id, "capture_id": run.capture_id, "status": "running", "verdict": None,
                "findings": 0, "tool_calls": sum(1 for e in run.events if e["type"] == "tool"), "cost_usd": None,
                "started_at": None} for run in live_runs.running() if run.run_id not in known]
    return running + stored


@api.get("/runs/{run_id}")
def run(run_id: str) -> dict:
    try:
        return load_run(run_id)
    except AgentError:
        live = live_runs.get(run_id)
        if live is None:
            raise HTTPException(404, "No such investigation.") from None
        # Started from the page and not stored yet: the page follows it through the event stream.
        return {"run_id": live.run_id, "capture_id": live.capture_id, "status": "running", "report": None,
                "events": [], **live.settings}


@api.get("/runs/{run_id}/events")
def run_events(run_id: str, request: Request, after: int = 0) -> StreamingResponse:
    """The run's events as a server-sent event stream: live while it runs, the stored ones afterwards."""
    last_seen = request.headers.get("last-event-id", "")
    if last_seen.isdigit():
        after = max(after, int(last_seen))  # a browser reconnecting says where it got to
    live = live_runs.get(run_id)
    if live is None:
        try:
            stored = load_run(run_id)["events"]
        except AgentError:
            raise HTTPException(404, "No such investigation.") from None
        source = iter(stored[max(0, after):])
    else:
        source = live.stream(after)

    def lines():
        for event in source:
            if event is None:
                yield ": still running\n\n"
            else:
                yield f"id: {event['n']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(lines(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------- changing


def _ingest(path: Path, kind: str, capture_id: str) -> store.CaptureMeta:
    if kind == "csv":
        from ..ingest.cic_csv import ingest_cic_csv
        return ingest_cic_csv(path, capture_id)
    from ..ingest.pcap import ingest_pcap
    return ingest_pcap(path, capture_id, max_packets=MAX_UPLOAD_PACKETS)


@api.post("/captures", status_code=201)
async def upload_capture(request: Request, name: str) -> dict:
    """Store an uploaded packet capture or flow CSV. The file is the request body, sent as it is."""
    _writable()
    kind = UPLOAD_SUFFIXES.get(Path(name).suffix.lower())
    if kind is None:
        raise HTTPException(415, f"Upload a file ending in {', '.join(sorted(UPLOAD_SUFFIXES))}.")
    limit = settings.max_upload_bytes()
    too_large = HTTPException(413, f"The file is larger than {limit // (1024 * 1024)} MB.")
    if request.headers.get("content-length", "0").isdigit() and int(request.headers.get("content-length", "0")) > limit:
        raise too_large

    # The name the user gave is only a label. The file is stored under a name made here, in a
    # folder made here, and removed once it has been read.
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).stem).strip("._")[:60] or "capture"
    folder = store.data_dir() / "uploads" / uuid.uuid4().hex
    folder.mkdir(parents=True)
    path = folder / f"{label}{Path(name).suffix.lower()}"
    try:
        size = 0
        with open(path, "wb") as handle:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise too_large
                handle.write(chunk)
        if size == 0:
            raise HTTPException(400, "The upload is empty.")
        try:
            meta = await run_in_threadpool(_ingest, path, kind, store.new_capture_id(label))
        except (IngestError, store.CaptureError) as exc:
            raise HTTPException(400, f"That file could not be read as a capture: {exc}") from None
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return _capture_json(meta)


class StartRun(BaseModel):
    capture_id: str
    model: str = DEFAULT_MODEL
    effort: str | None = None
    max_tool_calls: int = Field(DEFAULT_MAX_TOOL_CALLS, ge=1, le=MAX_TOOL_CALLS_LIMIT)
    prompt: str | None = None


@api.post("/runs", status_code=202)
def start_run(body: StartRun) -> dict:
    """Start an investigation. It calls the Claude API and is billed to the server's key."""
    _writable()
    _meta_or_404(body.capture_id)
    if body.model not in PRICES:
        raise HTTPException(422, f"Unknown model. Choose one of: {', '.join(PRICES)}.")
    effort = body.effort or default_effort(body.model)
    prompt = body.prompt or CURRENT
    if effort not in EFFORTS or prompt not in PROMPTS:
        raise HTTPException(422, "Unknown effort or prompt version.")
    if not settings.api_key_configured():
        raise HTTPException(409, "No API key is configured on the server. Put ANTHROPIC_API_KEY in its .env file.")
    try:
        live = live_runs.start(body.capture_id, client=make_client(max_retries=3, timeout=300.0), model=body.model,
                               effort=effort, max_tool_calls=body.max_tool_calls, prompt=prompt)
    except AgentError as exc:
        raise HTTPException(429 if "already running" in str(exc) else 409, str(exc)) from None
    return {"run_id": live.run_id, "capture_id": live.capture_id, "status": "running", **live.settings}


app.include_router(api)


@app.exception_handler(store.CaptureError)
async def capture_error(request: Request, exc: store.CaptureError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=400)


# ---------------------------------------------------------------- the page

NOT_BUILT = """<!doctype html><meta charset="utf-8"><title>NetTriage</title>
<body style="font: 16px/1.5 system-ui; max-width: 40rem; margin: 4rem auto; padding: 0 1rem">
<h1>NetTriage</h1>
<p>The server is running, but the web page has not been built yet.</p>
<p>Build it once with <code>npm ci</code> and <code>npm run build</code> in the <code>web</code> folder,
then reload. The API is described at <a href="/docs">/docs</a>.</p>"""

if (STATIC_DIR / "index.html").is_file():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="page")
else:
    @app.get("/", include_in_schema=False)
    def not_built() -> HTMLResponse:
        return HTMLResponse(NOT_BUILT)
