"""The flow classifier, on small synthetic captures (no dataset needed)."""

import json
import re
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest
from typer.testing import CliRunner

from nettriage import schema, store
from nettriage.classifier import ClassifierError
from nettriage.classifier.dataset import family_of, held_out, is_attempted, load_labelled
from nettriage.classifier.features import FEATURES, check_columns
from nettriage.classifier.model import CARD_FILE, MODEL_FILE, classify_flows, load_model
from nettriage.classifier.train import train_model
from nettriage.cli import app as cli
from nettriage.ingest.pcap import ingest_pcap
from tests.conftest import FLOODER, SCANNER, VICTIM, synthetic_flows, write_labelled

runner = CliRunner()

@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """Two labelled captures and a model trained on them, built once for this file."""
    root = tmp_path_factory.mktemp("classifier")
    rng = np.random.default_rng(0)
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("NETTRIAGE_DATA_DIR", str(root / "data"))
        write_labelled("attacks", [
            (synthetic_flows(rng, 900, "web"), "BENIGN"),
            (synthetic_flows(rng, 400, "scan"), "Portscan"),
            (synthetic_flows(rng, 400, "flood"), "DoS Hulk"),
            (synthetic_flows(rng, 40, "web"), "DoS Hulk - Attempted"),
        ])
        write_labelled("quiet", [(synthetic_flows(rng, 600, "web"), "BENIGN")])
        card = train_model(["attacks", "quiet"], root / "model")
    return SimpleNamespace(data=root / "data", model=root / "model", card=card)


@pytest.fixture
def env(trained, monkeypatch):
    monkeypatch.setenv("NETTRIAGE_DATA_DIR", str(trained.data))
    monkeypatch.setenv("NETTRIAGE_MODEL_DIR", str(trained.model))
    return trained


@pytest.mark.parametrize("label, family", [
    ("BENIGN", "benign"),
    ("FTP-Patator", "brute_force"),
    ("SSH-Patator", "brute_force"),
    ("DoS Hulk", "dos"),
    ("DoS slowloris", "dos"),
    ("DDoS", "dos"),
    ("Portscan", "port_scan"),
    ("PortScan", "port_scan"),
    ("Infiltration - Portscan", "port_scan"),
    ("Web Attack - XSS", "web_attack"),
    ("Web Attack - Sql Injection", "web_attack"),
    ("Botnet", "botnet"),
    ("Bot", "botnet"),
    ("Heartbleed", "other"),
    ("Infiltration", "other"),
    # Flows that belong to an attack run but carry nothing malicious count as benign.
    ("DoS Hulk - Attempted", "benign"),
    ("Web Attack - Brute Force - Attempted", "benign"),
])
def test_labels_map_to_families(label, family):
    assert family_of(label) == family
    assert is_attempted(label) == label.endswith("Attempted")


def test_every_second_five_minute_block_is_held_out():
    ts = pd.Series(pd.to_datetime([
        "2017-07-04 12:00:00", "2017-07-04 12:04:59.999999", "2017-07-04 12:05:00",
        "2017-07-04 12:09:59", "2017-07-04 12:10:00", "2017-07-04 23:55:00",
    ], format="ISO8601"))
    assert held_out(ts).tolist() == [False, False, True, True, False, True]


def test_the_model_never_sees_addresses_ports_or_times():
    assert not {"flow_id", "ts", "src_ip", "src_port", "dst_ip", "dst_port"} & set(FEATURES)
    assert set(FEATURES) < set(schema.column_names("flows"))
    with pytest.raises(ClassifierError, match="Not columns"):
        check_columns(["duration_us", "1; DROP TABLE flows"])


def test_training_uses_only_the_training_blocks(env):
    frame = load_labelled(["attacks", "quiet"], FEATURES)
    card = env.card

    assert card["training"]["flows"] == int((~frame["held_out"]).sum())
    assert card["held_out_test"]["flows"] == int(frame["held_out"].sum())
    assert card["training"]["attempted_flows_counted_as_benign"] == int((frame["attempted"] & ~frame["held_out"]).sum())
    assert card["classes"] == ["benign", "dos", "port_scan"]
    assert card["features"] == list(FEATURES)
    assert (env.model / MODEL_FILE).is_file() and (env.model / CARD_FILE).is_file()


def test_held_out_results_are_in_the_model_card(env):
    test = env.card["held_out_test"]
    assert test["recall"] >= 0.95 and test["precision"] >= 0.95
    assert test["right_family_share"] >= 0.95
    assert set(test["attack_free_captures"]) == {"quiet"}
    assert test["attack_free_captures"]["quiet"]["false_positives"] <= 3
    by_label = {row["label"]: row for row in test["by_label"]}
    assert by_label["DoS Hulk - Attempted"]["counted_as"] == "benign"
    assert by_label["Portscan"]["mostly_called"] == "port_scan"


def test_each_attack_is_also_tested_as_if_never_seen(env):
    unseen = {row["label"]: row for row in env.card["unseen_attack_test"]}
    assert set(unseen) == {"Portscan", "DoS Hulk"}
    for row in unseen.values():
        # Each family has one label here, so removing the label removes the family.
        assert row["family_still_in_training"] is False
        assert 0 <= row["flagged"] <= row["held_out_flows"]
        assert row["mostly_called"] != row["family"]
    # The weakness this test measures is spelled out for whoever reads a result.
    assert any("not evidence of benign" in caveat for caveat in env.card["caveats"])


def test_classify_flows_points_at_the_attackers(env):
    result = classify_flows("attacks")
    json.dumps(result)  # the agent receives this as JSON

    assert result["flows_scored"] == 1740
    assert 700 <= result["flows_flagged"] <= 840
    assert {row["family"] for row in result["by_family"]} == {"dos", "port_scan"}
    sources = {row["src_ip"]: row for row in result["top_sources"]}
    assert set(sources) >= {SCANNER, FLOODER}
    assert sources[SCANNER]["families"].get("port_scan", 0) >= 380
    assert sources[SCANNER]["distinct_dst_ports"] > 100
    assert result["top_targets"][0]["dst_ip"] == VICTIM

    con = store.connect_readonly("attacks")
    try:
        ids = ", ".join(str(i) for i in sources[FLOODER]["example_flow_ids"])
        cited = con.execute(f"SELECT DISTINCT src_ip FROM flows WHERE flow_id IN ({ids})").fetchall()
    finally:
        con.close()
    assert cited == [(FLOODER,)]


def test_classify_flows_takes_a_filter(env):
    result = classify_flows("attacks", "dst_port = 80")
    assert result["flows_scored"] == 400 and result["filter"] == "dst_port = 80"
    assert [row["src_ip"] for row in result["top_sources"]] == [FLOODER]

    nothing = classify_flows("attacks", "dst_port = 9")
    assert (nothing["flows_scored"], nothing["flows_flagged"], nothing["top_sources"]) == (0, 0, [])


@pytest.mark.parametrize("where", [
    "dst_port = 80; DROP TABLE flows",
    "not valid sql (",
    "flow_id IN (SELECT flow_id FROM read_parquet('labels.parquet'))",
])
def test_classify_flows_rejects_bad_filters(env, where):
    with pytest.raises(ClassifierError):
        classify_flows("attacks", where)


def test_unknown_capture_is_reported(env):
    with pytest.raises(ClassifierError, match="No capture named"):
        classify_flows("nope")


def test_packet_captures_are_scored_with_a_warning(env, sample_pcap):
    ingest_pcap(sample_pcap, "sample")
    result = classify_flows("sample")
    assert result["flows_scored"] == 3
    assert any("read from packets" in caveat for caveat in result["caveats"])
    assert not any("used to train" in caveat for caveat in result["caveats"])
    # A capture the model learned from says so.
    assert any("used to train" in caveat for caveat in classify_flows("attacks")["caveats"])


def test_a_changed_model_file_is_refused(env, tmp_path):
    copy = tmp_path / "model"
    copy.mkdir()
    (copy / CARD_FILE).write_bytes((env.model / CARD_FILE).read_bytes())
    (copy / MODEL_FILE).write_bytes((env.model / MODEL_FILE).read_bytes() + b"x")
    with pytest.raises(ClassifierError, match="hash"):
        load_model(copy)


def test_a_model_from_another_library_version_is_refused(env, tmp_path):
    copy = tmp_path / "model"
    copy.mkdir()
    card = json.loads((env.model / CARD_FILE).read_text(encoding="utf-8"))
    card["library"]["scikit-learn"] = "0.24.2"
    (copy / CARD_FILE).write_text(json.dumps(card), encoding="utf-8")
    (copy / MODEL_FILE).write_bytes((env.model / MODEL_FILE).read_bytes())
    with pytest.raises(ClassifierError, match="scikit-learn 0.24.2"):
        load_model(copy)


def test_missing_model_says_how_to_get_one(tmp_path):
    with pytest.raises(ClassifierError, match="nettriage train"):
        load_model(tmp_path / "nothing-here")


def test_training_needs_labels_and_attacks(env):
    with pytest.raises(ClassifierError, match="at least one attack family"):
        train_model(["quiet"], env.model.parent / "unused")


def test_cli_classify(env):
    result = runner.invoke(cli, ["classify", "attacks", "--where", "dst_port = 80"])
    assert result.exit_code == 0, result.output
    assert re.search(r"^scored\s+400 flows$", result.output, re.MULTILINE)
    assert FLOODER in result.output and "dos" in result.output

    as_json = runner.invoke(cli, ["classify", "attacks", "--json"])
    assert json.loads(as_json.output)["flows_scored"] == 1740

    bad = runner.invoke(cli, ["classify", "attacks", "--where", "nonsense ("])
    assert bad.exit_code == 1 and "Error:" in bad.output


def test_cli_train(env, tmp_path):
    out = tmp_path / "model"
    result = runner.invoke(cli, ["train", "attacks", "quiet", "--out", str(out), "--no-unseen-test"])
    assert result.exit_code == 0, result.output
    assert "held-out   precision" in result.output
    assert load_model(out).card["unseen_attack_test"] is None
