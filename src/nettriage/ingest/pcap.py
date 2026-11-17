"""Ingest a packet capture (pcap or pcapng).

One pass over the file feeds three things: the flow meter, a DNS table and an
HTTP request table. Everything is done with scapy's offline reader, so there is
no dependency on tshark, tcpdump or a capture driver.

Text pulled out of packets (DNS names, HTTP hosts, paths and user agents) is
attacker-controlled. It is stored as plain data, with control characters
removed and length capped, and must always be treated as untrusted downstream.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from .. import schema, store
from . import IngestError
from .flowmeter import PROTO_TCP, PROTO_UDP, FlowTable, PacketInfo

# scapy logs warnings at import time when no capture driver is installed; we only read files.
for _name in ("scapy.runtime", "scapy.loading"):
    logging.getLogger(_name).setLevel(logging.ERROR)

from scapy.error import Scapy_Exception  # noqa: E402
from scapy.layers.dns import DNS  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

MAX_TEXT = 512
MAX_URI = 1024
_EPOCH = datetime(1970, 1, 1)

_HTTP_METHODS = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
)
_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
}


@dataclass
class PcapResult:
    flows: pd.DataFrame
    dns: pd.DataFrame
    http: pd.DataFrame
    notes: dict


def clean_text(value, limit: int = MAX_TEXT) -> str:
    """Decode packet bytes to printable text of bounded length."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    return text[:limit]


def parse_http_request(payload: bytes) -> dict | None:
    """Parse the request line and a few headers from the start of a TCP payload.

    Works on any port. Returns None when the payload is not an HTTP/1.x request.
    """
    if not payload.startswith(_HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) < 3 or not parts[-1].startswith(b"HTTP/1."):
        return None
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            headers.setdefault(name.strip().lower(), value.strip())
    return {
        "method": clean_text(parts[0], 16),
        "uri": clean_text(b" ".join(parts[1:-1]), MAX_URI),
        "host": clean_text(headers.get(b"host", b"")),
        "user_agent": clean_text(headers.get(b"user-agent", b"")),
    }


def _first(items):
    """First element of a scapy record list, or None when it is empty."""
    try:
        return items[0]
    except (IndexError, TypeError, KeyError):
        return None


def _dns_row(dns) -> dict | None:
    question = _first(dns.qd)
    if question is None:
        return None
    answers = []
    if dns.qr:
        try:
            for record in dns.an or []:
                data = getattr(record, "rdata", None)
                if isinstance(data, (list, tuple)):
                    data = b" ".join(d if isinstance(d, bytes) else str(d).encode() for d in data)
                if data is not None:
                    answers.append(clean_text(data, 128).rstrip("."))
        except TypeError:
            pass
    qtype = int(question.qtype)
    return {
        "is_response": bool(dns.qr),
        "query": clean_text(question.qname).rstrip("."),
        "qtype": _QTYPES.get(qtype, str(qtype)),
        "rcode": int(dns.rcode) if dns.qr else None,
        "answers": ", ".join(answers)[:MAX_URI],
    }


def _payload_len(ip, l4, is_tcp: bool) -> int:
    """Transport payload size from the header fields, so link-layer padding is not counted."""
    l4_len = 0
    if ip.version == 4:
        if ip.len:
            l4_len = ip.len - (ip.ihl or 5) * 4
    elif ip.nh in (PROTO_TCP, PROTO_UDP):
        l4_len = ip.plen or 0
    if l4_len <= 0:
        # Segmentation offload leaves the IP length at 0; fall back to what was captured.
        return len(bytes(l4.payload))
    header = (l4.dataofs or 5) * 4 if is_tcp else 8
    return max(0, l4_len - header)


def _ts(ts_us: int) -> datetime:
    return _EPOCH + timedelta(microseconds=ts_us)


def read_pcap(path: str | Path, max_packets: int | None = None) -> PcapResult:
    """Read a capture file into the canonical ``flows``, ``dns`` and ``http`` frames."""
    path = Path(path)
    table = FlowTable()
    dns_rows: list[dict] = []
    http_rows: list[dict] = []
    seen = used = 0
    truncated = False

    # The file is opened here rather than by scapy: when scapy rejects a file it leaves its own
    # handle open, and on Windows an open file cannot be deleted, so a refused upload would stay
    # on disk.
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise IngestError(f"{path.name} could not be opened: {exc}") from exc
    try:
        reader = PcapReader(handle)
    except (Scapy_Exception, OSError, EOFError, ValueError) as exc:
        handle.close()
        raise IngestError(f"{path.name} is not a readable pcap or pcapng file: {exc}") from exc

    try:
        with reader:
            for pkt in reader:
                if max_packets is not None and seen >= max_packets:
                    truncated = True
                    break
                seen += 1

                ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                if ip is None:
                    continue
                tcp = ip.getlayer(TCP)
                udp = None if tcp is not None else ip.getlayer(UDP)
                l4 = tcp if tcp is not None else udp
                if l4 is None:
                    continue

                is_tcp = tcp is not None
                ts_us = int(pkt.time * 1_000_000)
                payload_len = _payload_len(ip, l4, is_tcp)
                info = PacketInfo(
                    ts_us=ts_us,
                    src_ip=str(ip.src),
                    dst_ip=str(ip.dst),
                    src_port=int(l4.sport),
                    dst_port=int(l4.dport),
                    protocol=PROTO_TCP if is_tcp else PROTO_UDP,
                    payload_len=payload_len,
                    tcp_flags=int(l4.flags) if is_tcp else 0,
                    tcp_window=int(l4.window) if is_tcp else None,
                )
                flow_index = table.add(info)
                used += 1

                if is_tcp:
                    if payload_len:
                        request = parse_http_request(bytes(l4.payload)[:payload_len])
                        if request:
                            http_rows.append({
                                "flow_index": flow_index, "ts": _ts(ts_us),
                                "src_ip": info.src_ip, "dst_ip": info.dst_ip,
                                "dst_port": info.dst_port, **request,
                            })
                else:
                    dns = l4.getlayer(DNS)
                    if dns is not None:
                        row = _dns_row(dns)
                        if row:
                            dns_rows.append({
                                "flow_index": flow_index, "ts": _ts(ts_us),
                                "src_ip": info.src_ip, "dst_ip": info.dst_ip, **row,
                            })
    except (Scapy_Exception, EOFError, ValueError) as exc:
        raise IngestError(f"{path.name} could not be read to the end: {exc}") from exc

    flow_rows, flow_ids = table.finish()
    if not flow_rows:
        raise IngestError(f"{path.name} contains no TCP or UDP packets over IP.")

    def finish(rows: list[dict], table_name: str, id_column: str) -> pd.DataFrame:
        for number, row in enumerate(rows, start=1):
            row[id_column] = number
            row["flow_id"] = flow_ids[row.pop("flow_index")]
        return pd.DataFrame(rows, columns=schema.column_names(table_name))

    notes = {
        "packets_read": seen,
        "packets_used": used,
        "packets_skipped": seen - used,
        "truncated": truncated,
    }
    return PcapResult(
        flows=pd.DataFrame(flow_rows, columns=schema.column_names("flows")),
        dns=finish(dns_rows, "dns", "dns_id"),
        http=finish(http_rows, "http", "http_id"),
        notes=notes,
    )


def ingest_pcap(
    path: str | Path,
    capture_id: str | None = None,
    *,
    max_packets: int | None = None,
    overwrite: bool = False,
) -> store.CaptureMeta:
    """Read a capture file and store it as a capture."""
    path = Path(path)
    result = read_pcap(path, max_packets=max_packets)
    return store.write_capture(
        capture_id or store.new_capture_id(path.name),
        source="pcap",
        original_name=path.name,
        flows=result.flows,
        dns=result.dns,
        http=result.http,
        notes=result.notes,
        overwrite=overwrite,
    )
