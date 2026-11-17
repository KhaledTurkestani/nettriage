import duckdb
import pytest

from nettriage import store
from nettriage.ingest.cic_csv import ingest_cic_csv, read_cic_csv


@pytest.mark.parametrize("bad", ["", "../etc", "a/b", "a\\b", "Upper", ".hidden", "x" * 65, "has space"])
def test_unsafe_capture_ids_are_rejected(bad):
    with pytest.raises(store.CaptureError):
        store.capture_dir(bad)


def test_generated_ids_are_valid_and_readable():
    capture_id = store.new_capture_id("Friday-WorkingHours-Afternoon DDos.pcap_ISCX.csv")
    # The name part is capped at 40 characters, then a short random suffix is added.
    assert capture_id.startswith("friday-workinghours-afternoon-ddos-pcap-")
    assert "--" not in capture_id
    assert store.validate_capture_id(capture_id) == capture_id
    assert store.new_capture_id().startswith("cap-")


def test_existing_capture_is_not_replaced_unless_asked(cic_csv):
    ingest_cic_csv(cic_csv, "day")
    with pytest.raises(store.CaptureError, match="already exists"):
        ingest_cic_csv(cic_csv, "day")
    assert ingest_cic_csv(cic_csv, "day", overwrite=True).flow_count == 4


def test_failed_write_leaves_nothing_behind(cic_csv, data_dir):
    flows = read_cic_csv(cic_csv).flows.drop(columns=["dst_port"])
    with pytest.raises(store.CaptureError, match="dst_port"):
        store.write_capture("broken", source="cic_csv", original_name="x.csv", flows=flows)
    assert list((data_dir / "captures").iterdir()) == []
    assert store.list_captures() == []


def test_list_and_load(cic_csv):
    assert store.list_captures() == []
    ingest_cic_csv(cic_csv, "one")
    ingest_cic_csv(cic_csv, "two")
    assert {m.id for m in store.list_captures()} == {"one", "two"}
    assert store.load_meta("one").original_name == cic_csv.name
    with pytest.raises(store.CaptureError):
        store.load_meta("missing")


@pytest.mark.parametrize("sql", [
    "INSERT INTO flows (flow_id) VALUES (999)",
    "DELETE FROM flows",
    "DROP TABLE flows",
    "CREATE TABLE notes (a INTEGER)",
    "SELECT * FROM read_csv('{labels}')",
    "SELECT * FROM read_parquet('{labels}')",
    "SELECT * FROM '{labels}'",
    "COPY flows TO '{out}'",
    "ATTACH '{out}' AS other",
    "SET enable_external_access = true",
    "SET memory_limit = '64GB'",
    "INSTALL httpfs",
])
def test_readonly_connection_cannot_write_or_reach_other_files(cic_csv, data_dir, sql):
    """The agent's tools get this connection. It must not be able to read the labels."""
    ingest_cic_csv(cic_csv, "day")
    labels = (data_dir / "captures" / "day" / store.LABELS_FILE)
    assert labels.is_file()

    statement = sql.format(
        labels=str(labels).replace("\\", "/"),
        out=str(data_dir / "out.db").replace("\\", "/"),
    )
    con = store.connect_readonly("day")
    try:
        with pytest.raises(duckdb.Error):
            con.execute(statement).fetchall()
        assert con.execute("SELECT count(*) FROM flows").fetchone()[0] == 4
    finally:
        con.close()
    assert not (data_dir / "out.db").exists()
