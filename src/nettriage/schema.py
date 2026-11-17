"""Canonical tables stored in every capture database.

Both ingest paths (CICFlowMeter CSV and packet capture) write exactly these
columns with exactly these meanings, so everything downstream (the classifier,
the agent's tools, the evals) can ignore where a capture came from.

Units follow the CIC-IDS2017 dataset: times in microseconds, sizes in payload
bytes (headers excluded).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    doc: str


FLOW_COLUMNS: tuple[Column, ...] = (
    Column("flow_id", "BIGINT", "Row id, unique within the capture. Cite this as evidence."),
    Column("ts", "TIMESTAMP", "Time of the flow's first packet, in UTC unless the source file used local time."),
    Column("src_ip", "VARCHAR", "Initiator address (sender of the first packet)."),
    Column("src_port", "INTEGER", "Initiator port."),
    Column("dst_ip", "VARCHAR", "Responder address."),
    Column("dst_port", "INTEGER", "Responder port."),
    Column("protocol", "INTEGER", "IP protocol number: 6 = TCP, 17 = UDP, 1 = ICMP, 0 = other. Ports are 0 unless TCP or UDP."),
    Column("duration_us", "BIGINT", "First packet to last packet, in microseconds."),
    Column("fwd_pkts", "BIGINT", "Packets from initiator to responder."),
    Column("bwd_pkts", "BIGINT", "Packets from responder to initiator."),
    Column("fwd_bytes", "BIGINT", "Payload bytes from initiator to responder."),
    Column("bwd_bytes", "BIGINT", "Payload bytes from responder to initiator."),
    Column("fwd_pkt_len_max", "DOUBLE", "Largest forward payload, in bytes."),
    Column("fwd_pkt_len_mean", "DOUBLE", "Mean forward payload, in bytes."),
    Column("fwd_pkt_len_std", "DOUBLE", "Sample standard deviation of forward payloads."),
    Column("bwd_pkt_len_max", "DOUBLE", "Largest backward payload, in bytes."),
    Column("bwd_pkt_len_mean", "DOUBLE", "Mean backward payload, in bytes."),
    Column("bwd_pkt_len_std", "DOUBLE", "Sample standard deviation of backward payloads."),
    Column("flow_iat_mean_us", "DOUBLE", "Mean gap between consecutive packets, microseconds."),
    Column("flow_iat_std_us", "DOUBLE", "Sample standard deviation of packet gaps, microseconds."),
    Column("flow_iat_max_us", "DOUBLE", "Longest gap between consecutive packets, microseconds."),
    Column("fwd_iat_mean_us", "DOUBLE", "Mean gap between forward packets, microseconds."),
    Column("bwd_iat_mean_us", "DOUBLE", "Mean gap between backward packets, microseconds."),
    Column("syn_count", "INTEGER", "Packets with the TCP SYN flag. NULL if the source has no real flag counts."),
    Column("fin_count", "INTEGER", "Packets with the TCP FIN flag. NULL if the source has no real flag counts."),
    Column("rst_count", "INTEGER", "Packets with the TCP RST flag. NULL if the source has no real flag counts."),
    Column("psh_count", "INTEGER", "Packets with the TCP PSH flag. NULL if the source has no real flag counts."),
    Column("ack_count", "INTEGER", "Packets with the TCP ACK flag. NULL if the source has no real flag counts."),
    Column("init_fwd_win", "INTEGER", "TCP window of the first forward packet. NULL if unknown or not TCP."),
    Column("init_bwd_win", "INTEGER", "TCP window of the first backward packet. NULL if none came back or not TCP."),
    Column("bytes_per_s", "DOUBLE", "Payload bytes per second, both directions. NULL if duration is 0."),
    Column("pkts_per_s", "DOUBLE", "Packets per second, both directions. NULL if duration is 0."),
)

DNS_COLUMNS: tuple[Column, ...] = (
    Column("dns_id", "BIGINT", "Row id, unique within the capture."),
    Column("flow_id", "BIGINT", "The flow this message belongs to."),
    Column("ts", "TIMESTAMP", "Time of the packet."),
    Column("src_ip", "VARCHAR", "Sender of this message."),
    Column("dst_ip", "VARCHAR", "Receiver of this message."),
    Column("is_response", "BOOLEAN", "False for a query, true for a response."),
    Column("query", "VARCHAR", "Queried name. Untrusted text taken from the packet."),
    Column("qtype", "VARCHAR", "Record type asked for, e.g. A, AAAA, TXT."),
    Column("rcode", "INTEGER", "Response code (0 = no error, 3 = NXDOMAIN). NULL for queries."),
    Column("answers", "VARCHAR", "Answer records, comma separated. Untrusted text."),
)

HTTP_COLUMNS: tuple[Column, ...] = (
    Column("http_id", "BIGINT", "Row id, unique within the capture."),
    Column("flow_id", "BIGINT", "The flow this request belongs to."),
    Column("ts", "TIMESTAMP", "Time of the packet carrying the request line."),
    Column("src_ip", "VARCHAR", "Client address."),
    Column("dst_ip", "VARCHAR", "Server address."),
    Column("dst_port", "INTEGER", "Server port."),
    Column("method", "VARCHAR", "Request method, e.g. GET."),
    Column("host", "VARCHAR", "Host header. Untrusted text taken from the packet."),
    Column("uri", "VARCHAR", "Request target. Untrusted text taken from the packet."),
    Column("user_agent", "VARCHAR", "User-Agent header. Untrusted text taken from the packet."),
)

TABLES: dict[str, tuple[Column, ...]] = {
    "flows": FLOW_COLUMNS,
    "dns": DNS_COLUMNS,
    "http": HTTP_COLUMNS,
}


def column_names(table: str) -> list[str]:
    return [c.name for c in TABLES[table]]


def create_table_sql(table: str) -> str:
    cols = ",\n  ".join(f"{c.name} {c.type}" for c in TABLES[table])
    return f"CREATE TABLE {table} (\n  {cols}\n)"
