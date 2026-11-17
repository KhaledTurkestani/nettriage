import statistics

import pytest

from nettriage.ingest.flowmeter import (
    PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, FlowTable, PacketInfo,
)

CLIENT = ("10.0.0.5", 50000)
SERVER = ("93.184.216.34", 80)


def pkt(ms, src, dst, payload=0, flags=0, window=None, proto=PROTO_TCP):
    return PacketInfo(
        ts_us=ms * 1000, src_ip=src[0], dst_ip=dst[0], src_port=src[1], dst_port=dst[1],
        protocol=proto, payload_len=payload, tcp_flags=flags, tcp_window=window,
    )


def tcp_session(start=0):
    c, s, t = CLIENT, SERVER, start
    return [
        pkt(t + 0, c, s, flags=TCP_SYN, window=64240),
        pkt(t + 10, s, c, flags=TCP_SYN | TCP_ACK, window=65535),
        pkt(t + 20, c, s, flags=TCP_ACK, window=64240),
        pkt(t + 30, c, s, payload=100, flags=TCP_PSH | TCP_ACK, window=64240),
        pkt(t + 50, s, c, payload=1000, flags=TCP_PSH | TCP_ACK, window=65535),
        pkt(t + 60, s, c, payload=500, flags=TCP_PSH | TCP_ACK, window=65535),
        pkt(t + 70, c, s, flags=TCP_ACK, window=64240),
        pkt(t + 80, c, s, flags=TCP_FIN | TCP_ACK, window=64240),
        pkt(t + 90, s, c, flags=TCP_FIN | TCP_ACK, window=65535),
        pkt(t + 100, c, s, flags=TCP_ACK, window=64240),
    ]


def run(packets):
    table = FlowTable()
    indexes = [table.add(p) for p in packets]
    rows, ids = table.finish()
    return rows, [ids[i] for i in indexes]


def test_tcp_session_becomes_one_flow_with_expected_features():
    rows, _ = run(tcp_session())
    assert len(rows) == 1
    f = rows[0]

    assert (f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"]) == (*CLIENT, *SERVER)
    assert f["protocol"] == PROTO_TCP
    assert f["flow_id"] == 1
    assert f["duration_us"] == 100_000
    assert (f["fwd_pkts"], f["bwd_pkts"]) == (6, 4)
    assert (f["fwd_bytes"], f["bwd_bytes"]) == (100, 1500)
    assert f["bwd_pkt_len_max"] == 1000
    assert f["bwd_pkt_len_mean"] == pytest.approx(375)
    assert f["bwd_pkt_len_std"] == pytest.approx(statistics.stdev([0, 1000, 500, 0]))
    assert f["fwd_pkt_len_mean"] == pytest.approx(100 / 6)
    assert f["flow_iat_mean_us"] == pytest.approx(100_000 / 9)
    assert f["flow_iat_max_us"] == 20_000
    assert (f["syn_count"], f["fin_count"], f["rst_count"], f["psh_count"], f["ack_count"]) == (2, 2, 0, 3, 9)
    assert (f["init_fwd_win"], f["init_bwd_win"]) == (64240, 65535)
    assert f["bytes_per_s"] == pytest.approx(16_000)
    assert f["pkts_per_s"] == pytest.approx(100)


def test_reused_five_tuple_after_teardown_starts_a_new_flow():
    rows, flow_ids = run(tcp_session(0) + tcp_session(200))
    assert len(rows) == 2
    assert flow_ids == [1] * 10 + [2] * 10
    assert [r["fwd_pkts"] for r in rows] == [6, 6]


def test_reset_ends_the_flow():
    packets = [
        pkt(0, CLIENT, SERVER, flags=TCP_SYN),
        pkt(5, SERVER, CLIENT, flags=TCP_RST | TCP_ACK),
        pkt(50, CLIENT, SERVER, flags=TCP_SYN),
    ]
    rows, flow_ids = run(packets)
    assert flow_ids == [1, 1, 2]
    assert rows[0]["rst_count"] == 1


def test_flow_is_cut_120_seconds_after_it_started():
    a, b = ("10.0.0.5", 5000), ("10.0.0.9", 9999)
    packets = [
        pkt(0, a, b, payload=10, proto=PROTO_UDP),
        pkt(120_000, a, b, payload=10, proto=PROTO_UDP),  # exactly at the limit: same flow
        pkt(120_001, a, b, payload=10, proto=PROTO_UDP),  # past it: new flow
    ]
    rows, flow_ids = run(packets)
    assert flow_ids == [1, 1, 2]
    assert rows[0]["duration_us"] == 120_000_000
    assert rows[0]["init_fwd_win"] is None


def test_first_packet_decides_who_the_initiator_is():
    rows, _ = run([pkt(0, SERVER, CLIENT, payload=5, flags=TCP_PSH | TCP_ACK)])
    assert (rows[0]["src_ip"], rows[0]["dst_ip"]) == (SERVER[0], CLIENT[0])
    assert (rows[0]["fwd_bytes"], rows[0]["bwd_bytes"]) == (5, 0)


def test_single_packet_flow_has_no_rates():
    rows, _ = run([pkt(0, CLIENT, SERVER, flags=TCP_SYN)])
    f = rows[0]
    assert f["duration_us"] == 0
    assert f["bytes_per_s"] is None and f["pkts_per_s"] is None
    assert f["flow_iat_mean_us"] == 0 and f["fwd_pkt_len_std"] == 0


def test_flow_ids_follow_start_time_across_interleaved_flows():
    other = ("10.0.0.7", 51000)
    packets = [
        pkt(0, CLIENT, SERVER, flags=TCP_SYN),
        pkt(1, other, SERVER, flags=TCP_SYN),
        pkt(2, SERVER, CLIENT, flags=TCP_SYN | TCP_ACK),
        pkt(3, SERVER, other, flags=TCP_SYN | TCP_ACK),
    ]
    rows, flow_ids = run(packets)
    assert flow_ids == [1, 2, 1, 2]
    assert [r["src_ip"] for r in rows] == [CLIENT[0], other[0]]


def test_out_of_order_packets_never_give_negative_gaps():
    packets = [
        pkt(10, CLIENT, SERVER, payload=1, proto=PROTO_UDP),
        pkt(5, SERVER, CLIENT, payload=1, proto=PROTO_UDP),
        pkt(20, CLIENT, SERVER, payload=1, proto=PROTO_UDP),
    ]
    rows, _ = run(packets)
    assert rows[0]["flow_iat_mean_us"] >= 0
    assert rows[0]["duration_us"] == 10_000
