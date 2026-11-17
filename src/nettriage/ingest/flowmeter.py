"""Group packets into bidirectional flows and compute the canonical features.

This is a small, deterministic flow meter with CICFlowMeter's conventions, so
flows extracted here line up with the CIC-IDS2017 dataset:

* a flow is keyed by the 5-tuple, in both directions;
* "forward" is the direction of the flow's first packet;
* sizes are payload bytes, times are microseconds;
* a flow is cut once a packet arrives more than 120 s after the flow started.

One deliberate difference: the 2017 CICFlowMeter ended a TCP flow at the first
FIN, which leaves the rest of the teardown as a bogus extra flow. Here a TCP
flow ends on RST, or on the ACK that follows a FIN from each side.

The module knows nothing about scapy; it consumes plain ``PacketInfo`` records,
which keeps it easy to test.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

FLOW_TIMEOUT_US = 120_000_000

PROTO_TCP = 6
PROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True, slots=True)
class PacketInfo:
    """The few facts about one packet that the flow meter needs."""

    ts_us: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    payload_len: int
    tcp_flags: int = 0
    tcp_window: int | None = None


class _Stats:
    """Running count, sum, maximum and sample standard deviation."""

    __slots__ = ("n", "total", "sumsq", "max")

    def __init__(self) -> None:
        self.n = 0
        self.total = 0
        self.sumsq = 0
        self.max = 0

    def add(self, value: int) -> None:
        self.n += 1
        self.total += value
        self.sumsq += value * value
        if value > self.max:
            self.max = value

    @property
    def mean(self) -> float:
        return self.total / self.n if self.n else 0.0

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        variance = (self.sumsq - self.total * self.total / self.n) / (self.n - 1)
        return math.sqrt(variance) if variance > 0 else 0.0


class _Flow:
    __slots__ = (
        "index", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "start_ts", "last_ts", "last_fwd_ts", "last_bwd_ts",
        "fwd_len", "bwd_len", "flow_iat", "fwd_iat", "bwd_iat",
        "syn", "fin", "rst", "psh", "ack",
        "init_fwd_win", "init_bwd_win", "fin_fwd", "fin_bwd", "closed",
    )

    def __init__(self, index: int, first: PacketInfo) -> None:
        self.index = index
        self.src_ip = first.src_ip
        self.src_port = first.src_port
        self.dst_ip = first.dst_ip
        self.dst_port = first.dst_port
        self.protocol = first.protocol
        self.start_ts = first.ts_us
        self.last_ts: int | None = None
        self.last_fwd_ts: int | None = None
        self.last_bwd_ts: int | None = None
        self.fwd_len = _Stats()
        self.bwd_len = _Stats()
        self.flow_iat = _Stats()
        self.fwd_iat = _Stats()
        self.bwd_iat = _Stats()
        self.syn = self.fin = self.rst = self.psh = self.ack = 0
        self.init_fwd_win: int | None = None
        self.init_bwd_win: int | None = None
        self.fin_fwd = False
        self.fin_bwd = False
        self.closed = False
        self.add(first)

    def add(self, p: PacketInfo) -> None:
        forward = p.src_ip == self.src_ip and p.src_port == self.src_port

        # Captures can hold slightly out-of-order packets; never record a negative gap.
        if self.last_ts is not None:
            self.flow_iat.add(max(0, p.ts_us - self.last_ts))
        self.last_ts = p.ts_us if self.last_ts is None else max(self.last_ts, p.ts_us)

        if forward:
            if self.last_fwd_ts is not None:
                self.fwd_iat.add(max(0, p.ts_us - self.last_fwd_ts))
            self.last_fwd_ts = p.ts_us
            self.fwd_len.add(p.payload_len)
        else:
            if self.last_bwd_ts is not None:
                self.bwd_iat.add(max(0, p.ts_us - self.last_bwd_ts))
            self.last_bwd_ts = p.ts_us
            self.bwd_len.add(p.payload_len)

        if p.protocol != PROTO_TCP:
            return

        flags = p.tcp_flags
        both_fins_before = self.fin_fwd and self.fin_bwd
        if flags & TCP_SYN:
            self.syn += 1
        if flags & TCP_FIN:
            self.fin += 1
            if forward:
                self.fin_fwd = True
            else:
                self.fin_bwd = True
        if flags & TCP_RST:
            self.rst += 1
        if flags & TCP_PSH:
            self.psh += 1
        if flags & TCP_ACK:
            self.ack += 1

        if p.tcp_window is not None:
            if forward and self.init_fwd_win is None:
                self.init_fwd_win = p.tcp_window
            elif not forward and self.init_bwd_win is None:
                self.init_bwd_win = p.tcp_window

        # The connection is over on a reset, or on the ACK that answers the second FIN.
        if flags & TCP_RST or (both_fins_before and not flags & TCP_FIN):
            self.closed = True

    def to_row(self) -> dict:
        assert self.last_ts is not None
        duration = self.last_ts - self.start_ts
        seconds = duration / 1_000_000
        total_bytes = self.fwd_len.total + self.bwd_len.total
        total_pkts = self.fwd_len.n + self.bwd_len.n
        return {
            "ts": _EPOCH + timedelta(microseconds=self.start_ts),
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration_us": duration,
            "fwd_pkts": self.fwd_len.n,
            "bwd_pkts": self.bwd_len.n,
            "fwd_bytes": self.fwd_len.total,
            "bwd_bytes": self.bwd_len.total,
            "fwd_pkt_len_max": float(self.fwd_len.max),
            "fwd_pkt_len_mean": self.fwd_len.mean,
            "fwd_pkt_len_std": self.fwd_len.std,
            "bwd_pkt_len_max": float(self.bwd_len.max),
            "bwd_pkt_len_mean": self.bwd_len.mean,
            "bwd_pkt_len_std": self.bwd_len.std,
            "flow_iat_mean_us": self.flow_iat.mean,
            "flow_iat_std_us": self.flow_iat.std,
            "flow_iat_max_us": float(self.flow_iat.max),
            "fwd_iat_mean_us": self.fwd_iat.mean,
            "bwd_iat_mean_us": self.bwd_iat.mean,
            "syn_count": self.syn,
            "fin_count": self.fin,
            "rst_count": self.rst,
            "psh_count": self.psh,
            "ack_count": self.ack,
            "init_fwd_win": self.init_fwd_win,
            "init_bwd_win": self.init_bwd_win,
            "bytes_per_s": total_bytes / seconds if duration > 0 else None,
            "pkts_per_s": total_pkts / seconds if duration > 0 else None,
        }


class FlowTable:
    """Feed packets in capture order with ``add``; collect the flows with ``finish``."""

    def __init__(self, flow_timeout_us: int = FLOW_TIMEOUT_US) -> None:
        self._timeout = flow_timeout_us
        self._active: dict[tuple, _Flow] = {}
        self._done: list[_Flow] = []
        self._next_index = 0

    def add(self, p: PacketInfo) -> int:
        """Add one packet. Returns a provisional index for the flow it joined.

        Provisional indexes are turned into final ``flow_id`` values by ``finish``.
        """
        a = (p.src_ip, p.src_port)
        b = (p.dst_ip, p.dst_port)
        key = (p.protocol, a, b) if a <= b else (p.protocol, b, a)

        flow = self._active.get(key)
        if flow is not None and (flow.closed or p.ts_us - flow.start_ts > self._timeout):
            self._done.append(flow)
            flow = None

        if flow is None:
            flow = _Flow(self._next_index, p)
            self._next_index += 1
            self._active[key] = flow
        else:
            flow.add(p)
        return flow.index

    def finish(self) -> tuple[list[dict], dict[int, int]]:
        """Close every flow.

        Returns the flow rows ordered by start time with ``flow_id`` assigned from
        1, and a mapping from provisional index to ``flow_id``.
        """
        flows = self._done + list(self._active.values())
        self._done = []
        self._active = {}
        flows.sort(key=lambda f: (f.start_ts, f.index))

        rows: list[dict] = []
        ids: dict[int, int] = {}
        for flow_id, flow in enumerate(flows, start=1):
            ids[flow.index] = flow_id
            rows.append({"flow_id": flow_id, **flow.to_row()})
        return rows, ids
