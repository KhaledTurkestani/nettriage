import re

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from nettriage import __version__
from nettriage.api.main import app as api
from nettriage.cli import app as cli

runner = CliRunner()


def test_health():
    response = TestClient(api).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_captures_endpoint_lists_what_was_ingested(cic_csv):
    client = TestClient(api)
    assert client.get("/api/captures").json() == []

    assert runner.invoke(cli, ["ingest", "csv", str(cic_csv), "--id", "day"]).exit_code == 0
    listed = client.get("/api/captures").json()
    assert [(c["id"], c["flow_count"], c["kind"]) for c in listed] == [("day", 4, "dataset")]


def test_cli_ingest_csv_then_query(cic_csv):
    result = runner.invoke(cli, ["ingest", "csv", str(cic_csv), "--id", "day"])
    assert result.exit_code == 0, result.output
    assert re.search(r"^flows\s+4$", result.output, re.MULTILINE)
    assert re.search(r"^rows dropped\s+3$", result.output, re.MULTILINE)

    result = runner.invoke(cli, ["query", "day", "SELECT dst_port, count(*) AS n FROM flows GROUP BY 1 ORDER BY 1"])
    assert result.exit_code == 0, result.output
    assert result.output.split() == ["dst_port", "n", "--------", "-", "22", "1", "53", "1", "80", "2"]

    assert "day" in runner.invoke(cli, ["list"]).output


def test_cli_ingest_pcap(sample_pcap):
    result = runner.invoke(cli, ["ingest", "pcap", str(sample_pcap), "--id", "sample"])
    assert result.exit_code == 0, result.output
    assert re.search(r"^dns\s+2$", result.output, re.MULTILINE)
    assert re.search(r"^http\s+1$", result.output, re.MULTILINE)


def test_cli_reports_errors_without_a_traceback(cic_csv, tmp_path):
    runner.invoke(cli, ["ingest", "csv", str(cic_csv), "--id", "day"])

    blocked = runner.invoke(cli, ["query", "day", "SELECT * FROM read_csv('secrets.csv')"])
    assert blocked.exit_code == 1 and "Error:" in blocked.output

    duplicate = runner.invoke(cli, ["ingest", "csv", str(cic_csv), "--id", "day"])
    assert duplicate.exit_code == 1 and "already exists" in duplicate.output

    missing = runner.invoke(cli, ["show", "nope"])
    assert missing.exit_code == 1 and "No capture named" in missing.output


def test_cli_schema_documents_every_table():
    output = runner.invoke(cli, ["schema"]).output
    for name in ("flows", "dns", "http", "flow_id", "user_agent"):
        assert name in output


def test_cli_serve_starts_the_page_on_localhost_and_warns_when_exposed(monkeypatch):
    import uvicorn

    started = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: started.append((app, options["host"], options["port"])))
    monkeypatch.delenv("NETTRIAGE_READ_ONLY", raising=False)

    local = runner.invoke(cli, ["serve"])
    assert local.exit_code == 0 and "http://localhost:8000" in local.output and "warning" not in local.output
    exposed = runner.invoke(cli, ["serve", "--host", "0.0.0.0", "--port", "9000"])
    assert "no login" in exposed.output and "http://localhost:9000" in exposed.output
    monkeypatch.setenv("NETTRIAGE_READ_ONLY", "1")
    assert "warning" not in runner.invoke(cli, ["serve", "--host", "0.0.0.0"]).output
    assert started == [("nettriage.api.main:app", "127.0.0.1", 8000), ("nettriage.api.main:app", "0.0.0.0", 9000),
                       ("nettriage.api.main:app", "0.0.0.0", 8000)]
