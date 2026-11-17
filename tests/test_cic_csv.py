from datetime import datetime

import pytest

from nettriage import store
from nettriage.ingest import IngestError
from nettriage.ingest.cic_csv import FLAG_COLUMNS, FLAGS_DROPPED, FLAGS_KEPT, ingest_cic_csv, read_cic_csv
from tests.conftest import CIC_HEADER, IMPROVED_HEADER, cic_row, improved_row

# A flow in the improved edition's format; values are plausible, not copied from the dataset.
TCP_FLOW = {
    "id": 1, "Src IP": "172.16.0.1", "Src Port": 52108, "Dst IP": "192.168.10.50", "Dst Port": 21, "Protocol": 6,
    "Timestamp": "2017-07-04 12:17:52.838272", "Flow Duration": 2_000_000,
    "Total Fwd Packet": 6, "Total Bwd packets": 5, "Total Length of Fwd Packet": 30, "Total Length of Bwd Packet": 120,
    "SYN Flag Count": 2, "FIN Flag Count": 2, "ACK Flag Count": 10,
    "FWD Init Win Bytes": 29200, "Bwd Init Win Bytes": 28960,
    "Label": "FTP-Patator - Attempted", "Attempted Category": 2,
}


def write_csv(tmp_path, *rows):
    path = tmp_path / "day.csv"
    path.write_text("\n".join([CIC_HEADER, *rows]) + "\n", encoding="latin-1")
    return path


def improved_csv(tmp_path, *rows):
    path = tmp_path / "tuesday.csv"
    path.write_text("\n".join([IMPROVED_HEADER, *(improved_row(r) for r in rows)]) + "\n", encoding="utf-8")
    return path


def test_reads_the_usable_rows_in_time_order(cic_csv):
    result = read_cic_csv(cic_csv)
    flows = result.flows

    assert list(flows["flow_id"]) == [1, 2, 3, 4]
    assert list(flows["ts"]) == [
        datetime(2017, 7, 7, 9, 5),
        datetime(2017, 7, 7, 10, 15),
        datetime(2017, 7, 7, 13, 5),   # written as 1:05
        datetime(2017, 7, 7, 15, 30),  # written as 3:30
    ]
    assert list(flows["dst_port"]) == [53, 80, 22, 80]
    assert result.notes == {
        "rows_in_file": 7,
        "rows_dropped": 3,
        "arp_frames_dropped": 0,
        "clock": "12h-working-hours",
        "negative_durations_zeroed": 0,
        "tcp_flags": FLAGS_DROPPED,
    }


def test_maps_dataset_columns_to_canonical_ones(cic_csv):
    flows = read_cic_csv(cic_csv).flows
    web = flows.iloc[1]

    assert (web["src_ip"], web["src_port"], web["dst_ip"]) == ("172.16.0.1", 41000, "192.168.10.50")
    assert web["protocol"] == 6
    assert web["duration_us"] == 5_000_000
    assert (web["fwd_pkts"], web["bwd_pkts"], web["fwd_bytes"], web["bwd_bytes"]) == (10, 8, 900, 4000)
    assert web["bwd_pkt_len_max"] == 1460
    assert web["flow_iat_max_us"] == 5000
    assert web["init_fwd_win"] == 8192
    # Rates are recomputed from bytes and duration, not read from the file's NaN.
    assert web["bytes_per_s"] == pytest.approx(4900 / 5)
    assert web["pkts_per_s"] == pytest.approx(18 / 5)


def test_infinity_and_missing_windows_become_null(cic_csv):
    flows = read_cic_csv(cic_csv).flows
    dns, ddos = flows.iloc[0], flows.iloc[3]

    assert ddos["duration_us"] == 0
    assert ddos[["bytes_per_s", "pkts_per_s"]].isna().all()
    assert dns[["init_fwd_win", "init_bwd_win"]].isna().all()


def test_dataset_flag_markers_are_stored_as_null(cic_csv):
    # Like the real dataset, the fixture has 0 or 1 in every flag column, even for an
    # 18-packet TCP flow. Those are not counts, so none of them may reach the database.
    result = read_cic_csv(cic_csv)
    assert result.flows[list(FLAG_COLUMNS)].isna().all().all()
    assert result.notes["tcp_flags"] == FLAGS_DROPPED


def test_real_flag_counts_are_kept(tmp_path):
    path = write_csv(
        tmp_path,
        cic_row("10.0.0.1", 1, "10.0.0.2", 80, 6, "03/07/2017 14:20:00", 90_000, 10, 8, 900, 4000,
                flags=(2, 2, 0, 5, 17)),
        cic_row("10.0.0.1", 2, "10.0.0.2", 81, 6, "03/07/2017 14:20:05", 10, 1, 1, 0, 0, flags=(0, 1, 1, 0, 1)),
    )
    result = read_cic_csv(path)
    busy, refused = result.flows.iloc[0], result.flows.iloc[1]
    assert (busy["fin_count"], busy["syn_count"], busy["psh_count"], busy["ack_count"]) == (2, 2, 5, 17)
    assert (refused["syn_count"], refused["rst_count"]) == (1, 1)
    assert result.notes["tcp_flags"] == FLAGS_KEPT


def test_flag_values_are_kept_when_no_flow_is_long_enough_to_judge(tmp_path):
    path = write_csv(
        tmp_path,
        cic_row("10.0.0.1", 1, "10.0.0.2", 22, 6, "03/07/2017 14:20:00", 10, 1, 1, 0, 0),
        cic_row("10.0.0.1", 2, "10.0.0.2", 53, 17, "03/07/2017 14:20:01", 10, 4, 4, 200, 800, flags=(0, 0, 0, 0, 0)),
    )
    result = read_cic_csv(path)
    assert result.flows.iloc[0]["syn_count"] == 1
    assert result.notes["tcp_flags"] == FLAGS_KEPT


def test_negative_durations_become_zero(tmp_path):
    # As in the dataset: two packets captured out of order, 13 microseconds apart.
    path = write_csv(
        tmp_path,
        cic_row("10.0.0.1", 1, "10.0.0.2", 80, 6, "03/07/2017 14:20:00", -13, 2, 0, 12, 0,
                rate="-923076.9", flow_iat=(-13.0, 0.0, -13)),
        cic_row("10.0.0.1", 2, "10.0.0.2", 80, 6, "03/07/2017 14:20:05", 10, 1, 1, 0, 0),
    )
    result = read_cic_csv(path)
    odd, normal = result.flows.iloc[0], result.flows.iloc[1]
    assert (odd["duration_us"], odd["flow_iat_mean_us"], odd["flow_iat_max_us"]) == (0, 0, 0)
    assert odd[["bytes_per_s", "pkts_per_s"]].isna().all()
    assert (normal["duration_us"], normal["flow_iat_max_us"]) == (10, 5000)
    assert result.notes["negative_durations_zeroed"] == 1


def test_labels_are_split_off_cleaned_and_aligned(cic_csv):
    result = read_cic_csv(cic_csv)
    assert "label" not in result.flows.columns
    assert list(result.labels["flow_id"]) == [1, 2, 3, 4]
    assert list(result.labels["label"]) == ["BENIGN", "Web Attack - Brute Force", "PortScan", "DDoS"]


def test_clock_is_left_alone_when_the_file_uses_24_hours(tmp_path):
    path = tmp_path / "day.csv"
    path.write_text("\n".join([
        CIC_HEADER,
        cic_row("10.0.0.1", 1, "10.0.0.2", 80, 6, "03/07/2017 03:00:10", 10, 1, 1, 0, 0),
        cic_row("10.0.0.1", 2, "10.0.0.2", 80, 6, "03/07/2017 14:20:00", 10, 1, 1, 0, 0),
    ]), encoding="latin-1")
    result = read_cic_csv(path)
    assert list(result.flows["ts"]) == [datetime(2017, 7, 3, 3, 0, 10), datetime(2017, 7, 3, 14, 20)]
    assert result.notes["clock"] == "24h"


def test_clock_can_be_forced(cic_csv):
    flows = read_cic_csv(cic_csv, clock="24h").flows
    assert [t.hour for t in flows["ts"]] == [1, 3, 9, 10]


def test_newer_cicflowmeter_column_names_are_accepted(tmp_path):
    header = (
        "Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,"
        "TotLen Fwd Pkts,TotLen Bwd Pkts,Fwd Pkt Len Max,Fwd Pkt Len Mean,Fwd Pkt Len Std,Bwd Pkt Len Max,"
        "Bwd Pkt Len Mean,Bwd Pkt Len Std,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Fwd IAT Mean,Bwd IAT Mean,"
        "SYN Flag Cnt,FIN Flag Cnt,RST Flag Cnt,PSH Flag Cnt,ACK Flag Cnt,Init Fwd Win Byts,Init Bwd Win Byts"
    )
    row = "10.0.0.1,1234,10.0.0.2,443,6,14/02/2018 08:31:01,2000000,3,2,300,900,150,100,10,600,450,20," \
          "500,50,900,400,600,1,0,0,1,4,29200,-1"
    path = tmp_path / "newer.csv"
    path.write_text(header + "\n" + row + "\n", encoding="utf-8")

    result = read_cic_csv(path)
    flow = result.flows.iloc[0]
    assert result.labels is None
    assert flow["ts"] == datetime(2018, 2, 14, 8, 31, 1)
    assert (flow["fwd_bytes"], flow["bwd_bytes"], flow["ack_count"]) == (300, 900, 4)
    assert result.notes["tcp_flags"] == FLAGS_KEPT
    assert flow["init_fwd_win"] == 29200 and flow.isna()["init_bwd_win"]
    assert flow["bytes_per_s"] == pytest.approx(600)


def test_improved_edition_columns_are_recognised(tmp_path):
    dns = {
        "id": 2, "Src IP": "192.168.10.5", "Src Port": 60000, "Dst IP": "192.168.10.3", "Dst Port": 53,
        "Protocol": 17, "Timestamp": "2017-07-04 11:53:44.398274", "Flow Duration": 300,
        "Total Fwd Packet": 1, "Total Bwd packets": 1, "Total Length of Fwd Packet": 40,
        "Total Length of Bwd Packet": 120, "Label": "BENIGN", "Attempted Category": -1,
    }
    result = read_cic_csv(improved_csv(tmp_path, TCP_FLOW, dns))
    udp, tcp = result.flows.iloc[0], result.flows.iloc[1]

    assert tcp["ts"] == datetime(2017, 7, 4, 12, 17, 52, 838272)
    assert (tcp["src_ip"], tcp["src_port"], tcp["dst_ip"], tcp["dst_port"]) == ("172.16.0.1", 52108, "192.168.10.50", 21)
    assert (tcp["fwd_pkts"], tcp["bwd_pkts"], tcp["fwd_bytes"], tcp["bwd_bytes"]) == (6, 5, 30, 120)
    assert (tcp["syn_count"], tcp["fin_count"], tcp["ack_count"]) == (2, 2, 10)
    assert (tcp["init_fwd_win"], tcp["init_bwd_win"]) == (29200, 28960)
    # This edition writes 0, not -1, as the window of a flow that is not TCP.
    assert udp[["init_fwd_win", "init_bwd_win"]].isna().all()
    assert list(result.labels["label"]) == ["BENIGN", "FTP-Patator - Attempted"]
    assert (result.notes["clock"], result.notes["tcp_flags"]) == ("24h", FLAGS_KEPT)


def test_backward_window_is_null_only_when_nothing_came_back(tmp_path):
    unanswered = {**TCP_FLOW, "Dst Port": 23, "Total Fwd Packet": 1, "Total Bwd packets": 0,
                  "Bwd Init Win Bytes": 0, "Timestamp": "2017-07-04 12:00:00.000001"}
    # A closed port answers with RST and a zero window: a real value, to be kept.
    refused = {**TCP_FLOW, "Dst Port": 24, "Total Fwd Packet": 1, "Total Bwd packets": 1,
               "Bwd Init Win Bytes": 0, "Timestamp": "2017-07-04 12:00:01.000001"}
    flows = read_cic_csv(improved_csv(tmp_path, unanswered, refused)).flows
    assert flows.isna()["init_bwd_win"].tolist() == [True, False]
    assert flows.iloc[1]["init_bwd_win"] == 0
    assert flows["init_fwd_win"].tolist() == [29200, 29200]


def test_arp_frames_read_as_flows_are_dropped(tmp_path):
    arp = {"id": 2, "Src IP": "8.6.0.1", "Dst IP": "8.0.6.4", "Protocol": 0, "Timestamp": "2017-07-04 11:54:12.355218",
           "Flow Duration": 106_007_973, "Total Fwd Packet": 26, "Label": "BENIGN", "Attempted Category": -1}
    # Protocol 0 with real addresses is real traffic (here an IGMP report) and stays.
    igmp = {"id": 3, "Src IP": "192.168.10.8", "Dst IP": "224.0.0.22", "Protocol": 0,
            "Timestamp": "2017-07-04 11:55:00.000001", "Flow Duration": 500, "Total Fwd Packet": 2,
            "Label": "BENIGN", "Attempted Category": -1}
    result = read_cic_csv(improved_csv(tmp_path, TCP_FLOW, arp, igmp))

    assert list(result.flows["src_ip"]) == ["192.168.10.8", "172.16.0.1"]
    assert list(result.labels["label"]) == ["BENIGN", "FTP-Patator - Attempted"]
    assert (result.notes["arp_frames_dropped"], result.notes["rows_dropped"]) == (1, 1)


def test_iso_timestamps_are_never_shifted(tmp_path):
    # Early UTC hours look like a 12-hour clock, but ISO timestamps never drop AM/PM.
    early = {**TCP_FLOW, "Timestamp": "2017-07-04 03:00:10.000001"}
    late = {**TCP_FLOW, "id": 2, "Timestamp": "2017-07-04 11:20:00.500000"}
    result = read_cic_csv(improved_csv(tmp_path, early, late))
    assert [t.hour for t in result.flows["ts"]] == [3, 11]
    assert result.notes["clock"] == "24h"


def test_file_without_addresses_is_rejected_with_a_helpful_message(tmp_path):
    path = tmp_path / "ml.csv"
    path.write_text(" Destination Port, Flow Duration, Label\n80,10,BENIGN\n", encoding="utf-8")
    with pytest.raises(IngestError, match="GeneratedLabelledFlows"):
        read_cic_csv(path)


def test_ingest_stores_labels_outside_the_database(cic_csv):
    meta = ingest_cic_csv(cic_csv, "friday")
    assert (meta.source, meta.flow_count, meta.has_labels) == ("cic_csv", 4, True)
    assert meta.first_ts == "2017-07-07T09:05:00"

    con = store.connect_readonly("friday")
    try:
        tables = {r[0] for r in con.execute("SELECT table_name FROM information_schema.tables").fetchall()}
        columns = {r[0] for r in con.execute("DESCRIBE flows").fetchall()}
        udp = con.execute("SELECT count(*) FROM flows WHERE protocol = 17").fetchone()[0]
    finally:
        con.close()
    assert tables == {"flows", "dns", "http"}
    assert "label" not in columns
    assert udp == 1

    labels = store.load_labels("friday")
    assert dict(zip(labels["flow_id"], labels["label"]))[4] == "DDoS"


def test_unknown_values_are_null_in_the_database(cic_csv):
    ingest_cic_csv(cic_csv, "friday")
    con = store.connect_readonly("friday")
    try:
        no_flags, no_window, no_rate = con.execute(
            "SELECT count(*) FILTER (WHERE syn_count IS NULL AND ack_count IS NULL),"
            " count(*) FILTER (WHERE init_fwd_win IS NULL),"
            " count(*) FILTER (WHERE bytes_per_s IS NULL) FROM flows"
        ).fetchone()
    finally:
        con.close()
    assert (no_flags, no_window, no_rate) == (4, 1, 1)
