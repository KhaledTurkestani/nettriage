"""The HTTP API behind the web page, tested offline with a scripted model."""

import json
import threading

import pytest
from fastapi.testclient import TestClient

from nettriage import store
from nettriage.agent import AgentError
from nettriage.api import main as api_main
from nettriage.api.live import LiveRun, LiveRuns
from nettriage.api.main import app
from tests.test_agent import CAPTURE, FakeApi, case, report_turn, report_with, scan_finding, tools_turn  # noqa: F401

client = TestClient(app)


@pytest.fixture(autouse=True)
def no_real_credentials(tmp_path, monkeypatch):
    """Run in an empty folder with no key: a test must never find a real .env or reach the real API."""
    monkeypatch.chdir(tmp_path)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "NETTRIAGE_READ_ONLY", "NETTRIAGE_MAX_UPLOAD_MB"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(api_main, "live_runs", LiveRuns())


def sse_events(text: str) -> list[dict]:
    return [json.loads(line[len("data: "):]) for line in text.splitlines()
            if line.startswith("data: ") and line != "data: {}"]


# ---------------------------------------------------------------- reading


def test_config_says_what_the_server_can_do_and_never_shows_the_key(monkeypatch):
    config = client.get("/api/config").json()
    assert (config["can_investigate"], config["can_upload"], config["read_only"]) == (False, True, False)
    assert config["default_model"] == "claude-haiku-5-5" and config["models"][0]["id"] == "claude-haiku-5-5"
    assert config["prompt"] in config["prompts"] and config["max_upload_mb"] == 200

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
    with_key = client.get("/api/config")
    assert with_key.json()["can_investigate"] is True and "sk-test" not in with_key.text

    monkeypatch.setenv("NETTRIAGE_READ_ONLY", "1")
    locked = client.get("/api/config").json()
    assert (locked["can_investigate"], locked["can_upload"], locked["read_only"]) == (False, False, True)


def test_a_key_in_the_env_file_counts_as_configured(tmp_path):
    (tmp_path / ".env").write_text("# comment\nANTHROPIC_API_KEY='sk-test-from-file'\n", encoding="utf-8")
    assert client.get("/api/config").json()["can_investigate"] is True


def test_captures_are_listed_with_their_kind_and_without_the_answer_key(case):
    listed, = client.get("/api/captures").json()
    assert (listed["id"], listed["flow_count"], listed["kind"], listed["runs"]) == (CAPTURE, 140, "upload", 0)
    assert "has_labels" not in listed

    detail = client.get(f"/api/captures/{CAPTURE}").json()
    assert detail["overview"]["flows"] == 140 and detail["overview"]["top_sources"][0]["dst_ports"] > 50
    assert detail["run_list"] == []
    for missing in ("nope", "..", "UPPER", "a" * 80):
        assert client.get(f"/api/captures/{missing}").status_code == 404


def test_cited_flows_can_be_looked_up(case):
    ids = case.scan_ids[:3]
    found = client.get(f"/api/captures/{CAPTURE}/flows", params={"ids": ",".join(map(str, [*ids, 99999]))}).json()
    assert found["columns"][0] == "flow_id" and [row[0] for row in found["rows"]] == ids
    assert found["missing"] == [99999]
    assert isinstance(found["rows"][0][found["columns"].index("ts")], str)

    for bad in ("", "1;DROP TABLE flows", "one", ",".join(map(str, range(1, 300)))):
        assert client.get(f"/api/captures/{CAPTURE}/flows", params={"ids": bad}).status_code == 422
    assert client.get("/api/captures/nope/flows", params={"ids": "1"}).status_code == 404
    # Labels are not a table, and no endpoint serves them.
    assert all("label" not in column for column in found["columns"])


# ---------------------------------------------------------------- uploads


def test_an_uploaded_flow_file_becomes_a_capture(cic_csv, data_dir):
    response = client.post("/api/captures", params={"name": "Office Monday.csv"}, content=cic_csv.read_bytes())
    assert response.status_code == 201, response.text
    made = response.json()
    assert made["flow_count"] == 4 and made["id"].startswith("office-monday-") and made["original_name"] == "Office_Monday.csv"
    assert [c["id"] for c in client.get("/api/captures").json()] == [made["id"]]
    assert not any((data_dir / "uploads").iterdir())  # the uploaded file is not kept


def test_an_uploaded_packet_capture_is_read_for_dns_and_http_too(sample_pcap):
    response = client.post("/api/captures", params={"name": "sample.pcap"}, content=sample_pcap.read_bytes())
    assert response.status_code == 201, response.text
    assert response.json()["dns_count"] >= 1 and response.json()["http_count"] >= 1 and response.json()["kind"] == "upload"


def test_uploads_that_are_refused(cic_csv, data_dir, monkeypatch):
    body = cic_csv.read_bytes()
    assert client.post("/api/captures", params={"name": "notes.txt"}, content=body).status_code == 415
    assert client.post("/api/captures", params={"name": "empty.csv"}, content=b"").status_code == 400
    garbage = client.post("/api/captures", params={"name": "broken.pcap"}, content=b"this is not a capture file")
    assert garbage.status_code == 400 and "could not be read" in garbage.json()["detail"]
    assert client.post("/api/captures", content=body).status_code == 422  # a name is required

    monkeypatch.setenv("NETTRIAGE_MAX_UPLOAD_MB", "1")
    assert client.post("/api/captures", params={"name": "big.csv"}, content=b"x" * (1024 * 1024 + 1)).status_code == 413

    monkeypatch.setenv("NETTRIAGE_READ_ONLY", "1")
    assert client.post("/api/captures", params={"name": "day.csv"}, content=body).status_code == 403
    assert client.get("/api/captures").json() == []
    assert not any((data_dir / "uploads").iterdir())


def test_the_name_of_an_upload_is_only_a_label(cic_csv, data_dir):
    response = client.post("/api/captures", params={"name": "..\\..\\evil/../../x.csv"}, content=cic_csv.read_bytes())
    assert response.status_code == 201
    made = response.json()
    assert store.validate_capture_id(made["id"]) and "/" not in made["original_name"] and ".." not in made["original_name"]
    assert sorted(p.name for p in data_dir.iterdir()) == ["captures", "uploads"]  # nothing written elsewhere


# ---------------------------------------------------------------- other sites


def test_another_site_cannot_change_anything_through_the_visitors_browser(cic_csv):
    body = cic_csv.read_bytes()
    for headers in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
        refused = client.post("/api/captures", params={"name": "day.csv"}, content=body, headers=headers)
        assert refused.status_code == 403
        assert client.post("/api/runs", json={"capture_id": "x"}, headers=headers).status_code == 403
    assert client.get("/api/captures").json() == []
    # The page itself sends its own origin, and reading is never blocked by this rule.
    same = client.post("/api/captures", params={"name": "day.csv"}, content=body, headers={"Origin": "http://testserver"})
    assert same.status_code == 201
    assert client.get("/api/captures", headers={"Origin": "https://evil.example"}).status_code == 200
    # A page that points its own host name at this server is refused outright.
    assert client.get("/api/captures", headers={"Host": "evil.example"}).status_code == 400


# ---------------------------------------------------------------- investigations


def test_starting_an_investigation_needs_a_key_a_capture_and_sane_settings(case, monkeypatch):
    assert client.post("/api/runs", json={"capture_id": CAPTURE}).status_code == 409  # no key
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
    assert client.post("/api/runs", json={"capture_id": "nope"}).status_code == 404
    for bad in ({"model": "gpt-4"}, {"effort": "extreme"}, {"prompt": "v99"}, {"max_tool_calls": 0},
                {"max_tool_calls": 500}):
        assert client.post("/api/runs", json={"capture_id": CAPTURE, **bad}).status_code == 422, bad
    monkeypatch.setenv("NETTRIAGE_READ_ONLY", "1")
    assert client.post("/api/runs", json={"capture_id": CAPTURE}).status_code == 403
    assert client.get("/api/runs").json() == []


def test_an_investigation_started_from_the_page_can_be_followed_and_is_stored(case, monkeypatch):
    api = FakeApi(
        tools_turn(("capture_overview", {}), thinking="Look first."),
        tools_turn(("run_sql", {"query": "SELECT count(*) AS n FROM flows"})),
        report_turn(report_with(scan_finding(case))),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
    monkeypatch.setattr(api_main, "make_client", lambda **options: api.client())

    started = client.post("/api/runs", json={"capture_id": CAPTURE, "max_tool_calls": 5, "prompt": "v1"})
    assert started.status_code == 202, started.text
    run_id = started.json()["run_id"]
    assert started.json() == {"run_id": run_id, "capture_id": CAPTURE, "status": "running",
                              "model": "claude-haiku-5-5", "effort": "high", "max_tool_calls": 5, "prompt": "v1"}

    stream = client.get(f"/api/runs/{run_id}/events")
    assert stream.headers["content-type"].startswith("text/event-stream")
    events = sse_events(stream.text)
    assert [e["type"] for e in events] == ["model", "tool", "model", "tool", "model", "evidence_check", "report", "end"]
    assert [e["n"] for e in events] == list(range(1, 9)) and events[-1]["status"] == "completed"
    assert events[0]["thinking"] == ["Look first."] and events[1]["name"] == "capture_overview"
    assert stream.text.rstrip().endswith("event: done\ndata: {}")
    assert api.requests[0].body["system"].startswith("You are NetTriage") and len(api.requests) == 3

    # Once the stream has ended the run is on disk, under the id the page was given at the start.
    stored = client.get(f"/api/runs/{run_id}").json()
    assert stored["status"] == "completed" and stored["report"]["verdict"] == "malicious_activity"
    assert stored["prompt"] == "v1" and stored["max_tool_calls"] == 5 and stored["events"] == events
    listed, = client.get("/api/runs").json()
    assert (listed["run_id"], listed["verdict"], listed["findings"]) == (run_id, "malicious_activity", 1)
    assert client.get("/api/captures").json()[0]["runs"] == 1
    assert client.get(f"/api/captures/{CAPTURE}").json()["run_list"][0]["run_id"] == run_id

    # A page that reconnects says how far it got and is sent the rest.
    later = sse_events(client.get(f"/api/runs/{run_id}/events", params={"after": 6}).text)
    resumed = sse_events(client.get(f"/api/runs/{run_id}/events", headers={"Last-Event-ID": "7"}).text)
    assert [e["n"] for e in later] == [7, 8] and [e["n"] for e in resumed] == [8]
    for missing in ("nope-20200101-000000-abcd", "../x", "UPPER"):
        assert client.get(f"/api/runs/{missing}").status_code == 404
        assert client.get(f"/api/runs/{missing}/events").status_code == 404


def test_a_run_that_fails_ends_its_stream_with_the_reason(case, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
    monkeypatch.setattr(api_main, "make_client", lambda **options: FakeApi(status=500).client())
    run_id = client.post("/api/runs", json={"capture_id": CAPTURE}).json()["run_id"]
    events = sse_events(client.get(f"/api/runs/{run_id}/events").text)
    assert events[-1]["type"] == "end" and events[-1]["status"] == "failed" and "API error" in events[-1]["error"]
    assert client.get(f"/api/runs/{run_id}").json()["status"] == "failed"


def test_only_a_few_investigations_run_at_once():
    release, runs = threading.Event(), LiveRuns(max_running=1)

    def slow(capture_id, *, on_event, run_id, **settings):
        on_event({"n": 1, "type": "model"})
        release.wait(5)
        raise AgentError("stopped by the test")

    settings = {"client": None, "model": "m", "effort": "low", "max_tool_calls": 3, "prompt": "v1"}
    first = runs.start("day", run=slow, **settings)
    with pytest.raises(AgentError, match="already running"):
        runs.start("day", run=slow, **settings)
    assert [run.run_id for run in runs.running()] == [first.run_id] and runs.get(first.run_id) is first

    release.set()
    events = list(first.stream())
    assert [e["type"] for e in events] == ["model", "end"] and events[-1]["error"] == "stopped by the test"
    assert runs.running() == []
    second = runs.start("day", run=slow, **settings)  # a slot is free again
    assert second.run_id != first.run_id and list(second.stream())[-1]["status"] == "failed"


def test_a_viewer_who_arrives_late_still_sees_every_event():
    live = LiveRun("run-1", "day", {})
    live.add({"n": 1, "type": "model"})
    stream = live.stream(heartbeat=0.01)
    assert next(stream) == {"n": 1, "type": "model"}
    assert next(stream) is None  # nothing new yet: a keep-alive, not the end
    live.add({"n": 2, "type": "end"})
    live.finish()
    assert list(stream) == [{"n": 2, "type": "end"}]
    assert list(live.stream()) == live.events and list(live.stream(after=1)) == live.events[1:]


def test_the_root_serves_a_page():
    page = client.get("/")
    assert page.status_code == 200 and "NetTriage" in page.text and "text/html" in page.headers["content-type"]
