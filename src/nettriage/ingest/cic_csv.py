"""Ingest a CICFlowMeter flow CSV, such as the CIC-IDS2017 labelled flows.

The published CSVs are messy, and this module absorbs the mess so nothing
downstream has to:

* header names carry stray spaces and differ between CICFlowMeter versions;
* files are not valid UTF-8 (one label contains a Windows-1252 dash);
* rate columns contain ``Infinity`` and ``NaN``;
* some files end in hundreds of thousands of empty rows;
* CIC-IDS2017 timestamps use a 12-hour clock with no AM/PM marker;
* a few flows per file have a negative duration (packets captured out of order);
* the TCP flag "count" columns of CIC-IDS2017 are not counts (see _flags_are_counts);
* ARP frames show up as flows between two made-up addresses (see ARP_ARTEFACT).

Checked against two published editions: the original feature-only files
(MachineLearningCVE, 2,830,743 rows) and the improved edition by Liu, Engelen
et al. (CNS 2022, 2,099,976 rows), which has real flag counts, UTC timestamps
and corrected labels.

Ground-truth labels are split off and returned separately; they never go into
the capture database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import numpy as np
import pandas as pd

from .. import schema, store
from . import IngestError
from .flowmeter import PROTO_TCP

Clock = Literal["auto", "24h", "12h-working-hours"]

# Canonical column -> accepted source names (after normalising, see _norm).
# The first entry is the CIC-IDS2017 name; the others are newer CICFlowMeter spellings.
ALIASES: dict[str, tuple[str, ...]] = {
    "src_ip": ("source_ip", "src_ip"),
    "src_port": ("source_port", "src_port"),
    "dst_ip": ("destination_ip", "dst_ip"),
    "dst_port": ("destination_port", "dst_port"),
    "protocol": ("protocol",),
    "ts": ("timestamp",),
    "duration_us": ("flow_duration",),
    "fwd_pkts": ("total_fwd_packets", "tot_fwd_pkts", "total_fwd_packet"),
    "bwd_pkts": ("total_backward_packets", "tot_bwd_pkts", "total_bwd_packets"),
    "fwd_bytes": ("total_length_of_fwd_packets", "totlen_fwd_pkts", "total_length_of_fwd_packet"),
    "bwd_bytes": ("total_length_of_bwd_packets", "totlen_bwd_pkts", "total_length_of_bwd_packet"),
    "fwd_pkt_len_max": ("fwd_packet_length_max", "fwd_pkt_len_max"),
    "fwd_pkt_len_mean": ("fwd_packet_length_mean", "fwd_pkt_len_mean"),
    "fwd_pkt_len_std": ("fwd_packet_length_std", "fwd_pkt_len_std"),
    "bwd_pkt_len_max": ("bwd_packet_length_max", "bwd_pkt_len_max"),
    "bwd_pkt_len_mean": ("bwd_packet_length_mean", "bwd_pkt_len_mean"),
    "bwd_pkt_len_std": ("bwd_packet_length_std", "bwd_pkt_len_std"),
    "flow_iat_mean_us": ("flow_iat_mean",),
    "flow_iat_std_us": ("flow_iat_std",),
    "flow_iat_max_us": ("flow_iat_max",),
    "fwd_iat_mean_us": ("fwd_iat_mean",),
    "bwd_iat_mean_us": ("bwd_iat_mean",),
    "syn_count": ("syn_flag_count", "syn_flag_cnt"),
    "fin_count": ("fin_flag_count", "fin_flag_cnt"),
    "rst_count": ("rst_flag_count", "rst_flag_cnt"),
    "psh_count": ("psh_flag_count", "psh_flag_cnt"),
    "ack_count": ("ack_flag_count", "ack_flag_cnt"),
    "init_fwd_win": ("init_win_bytes_forward", "init_fwd_win_byts", "fwd_init_win_bytes"),
    "init_bwd_win": ("init_win_bytes_backward", "init_bwd_win_byts", "bwd_init_win_bytes"),
}
OPTIONAL = {"init_fwd_win", "init_bwd_win"}
IDENTITY = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "ts")
LABEL_NAMES = ("label",)
TIME_COLUMNS = (
    "duration_us", "flow_iat_mean_us", "flow_iat_std_us", "flow_iat_max_us", "fwd_iat_mean_us", "bwd_iat_mean_us",
)
FLAG_COLUMNS = ("syn_count", "fin_count", "rst_count", "psh_count", "ack_count")
FLAGS_KEPT = "counts"
FLAGS_DROPPED = "not real counts in this file; stored as NULL"

# CICFlowMeter reads ARP frames as if they were IPv4 packets. The bytes it takes for the two
# addresses are the EtherType plus the start of the ARP header (08 06 00 01, then 08 00 06 04),
# so every such row has protocol 0 and exactly this address pair. They are not flows.
ARP_ARTEFACT = ("8.6.0.1", "8.0.6.4")

# (format, can hide a 12-hour clock). Only the day-first style of the original CIC-IDS2017
# files is known to drop AM/PM; ISO timestamps, as in the improved edition, never do.
_TS_FORMATS = (
    ("%d/%m/%Y %H:%M:%S", True),
    ("%d/%m/%Y %H:%M", True),
    ("%Y-%m-%d %H:%M:%S.%f", False),
    ("%Y-%m-%d %H:%M:%S", False),
    ("%d/%m/%Y %I:%M:%S %p", False),
)


@dataclass
class CicCsvResult:
    flows: pd.DataFrame
    labels: pd.DataFrame | None
    notes: dict


def _norm(name: str) -> str:
    """' Total Length of Fwd Packets' -> 'total_length_of_fwd_packets'."""
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _parse_timestamps(raw: pd.Series) -> tuple[pd.Series, bool]:
    """Parse timestamps; also say whether any used a format that can hide a 12-hour clock."""
    text = raw.astype("string").str.strip()
    out = pd.Series(pd.NaT, index=text.index, dtype="datetime64[us]")
    may_be_12h = False
    for fmt, ambiguous in _TS_FORMATS:
        todo = out.isna() & text.notna()
        if not todo.any():
            break
        parsed = pd.to_datetime(text[todo], format=fmt, errors="coerce")
        out[todo] = parsed.astype("datetime64[us]")
        may_be_12h = may_be_12h or (ambiguous and bool(parsed.notna().any()))
    return out, may_be_12h


def _fix_clock(ts: pd.Series, clock: Clock, may_be_12h: bool = True) -> tuple[pd.Series, str]:
    """Undo a 12-hour clock that was written without AM/PM.

    The original CIC-IDS2017 files were captured during working hours, so an
    hour from 1 to 7 can only mean the afternoon. In ``auto`` mode the shift is
    applied only when the file looks like a 12-hour clock: its timestamps use
    the dataset's day-first style, no hour is above 12, and some hour is below 8.
    """
    hours = ts.dt.hour
    if clock == "24h":
        return ts, "24h"
    if clock == "auto" and not (may_be_12h and (hours.max() <= 12) and (hours.min() < 8)):
        return ts, "24h"
    afternoon = (hours >= 1) & (hours <= 7)
    return ts.where(~afternoon, ts + pd.Timedelta(hours=12)), "12h-working-hours"


def _flags_are_counts(flows: pd.DataFrame) -> bool:
    """Tell real per-flow flag counts from the 0/1 markers of the original CIC-IDS2017 files.

    Checked against all 2,830,743 published rows: no flag column ever exceeds 1,
    the "SYN Flag Count" column equals "Fwd PSH Flags" on every row, and only a
    fifth of long TCP conversations show an ACK. Those values would mislead an
    analyst, so the caller stores NULL instead.

    Real counts are easy to recognise: a TCP flow of four or more packets
    repeats some flag (nearly every packet carries ACK), so most such flows have
    a count above 1. With no such flow in the file there is nothing to judge by,
    and the values are kept.
    """
    busy = (flows["protocol"] == PROTO_TCP) & (flows["fwd_pkts"] + flows["bwd_pkts"] >= 4)
    if not busy.any():
        return True
    repeated = (flows.loc[busy, list(FLAG_COLUMNS)] > 1).any(axis=1)
    return bool(repeated.mean() >= 0.5)


def _clean_label(value: str) -> str:
    """'Web Attack \\x96 Brute Force' -> 'Web Attack - Brute Force'."""
    text = re.sub(r"[^\x20-\x7e]+", "-", str(value))
    return re.sub(r"\s+", " ", text).strip()


def read_cic_csv(path: str | Path, clock: Clock = "auto") -> CicCsvResult:
    """Read a CICFlowMeter CSV into the canonical ``flows`` frame plus labels."""
    path = Path(path)
    try:
        # latin-1 never fails to decode, which matters because the files are not clean UTF-8.
        raw = pd.read_csv(path, encoding="latin-1", low_memory=False, skipinitialspace=True)
    except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise IngestError(f"Could not read {path.name} as CSV: {exc}") from exc

    raw.columns = [_norm(c) for c in raw.columns]
    rows_in_file = len(raw)
    raw = raw.dropna(how="all")

    resolved: dict[str, str] = {}
    for canonical, names in ALIASES.items():
        found = next((n for n in names if n in raw.columns), None)
        if found:
            resolved[canonical] = found
    missing = [c for c in ALIASES if c not in resolved and c not in OPTIONAL]
    if missing:
        raise IngestError(
            f"{path.name} does not look like a CICFlowMeter flow CSV with addresses. "
            f"Missing columns for: {', '.join(missing)}. "
            "For CIC-IDS2017 use the 'GeneratedLabelledFlows' files; the "
            "'MachineLearningCVE' files have no IP addresses or timestamps."
        )

    flows = pd.DataFrame(index=raw.index)
    flows["src_ip"] = raw[resolved["src_ip"]].astype("string").str.strip()
    flows["dst_ip"] = raw[resolved["dst_ip"]].astype("string").str.strip()
    flows["ts"], may_be_12h = _parse_timestamps(raw[resolved["ts"]])
    for canonical in ALIASES:
        if canonical in ("src_ip", "dst_ip", "ts"):
            continue
        if canonical in resolved:
            values = pd.to_numeric(raw[resolved[canonical]], errors="coerce")
            flows[canonical] = values.replace([np.inf, -np.inf], np.nan)
        else:
            flows[canonical] = np.nan

    arp = (
        (flows["protocol"] == 0)
        & (flows["src_ip"] == ARP_ARTEFACT[0]).fillna(False).astype(bool)
        & (flows["dst_ip"] == ARP_ARTEFACT[1]).fillna(False).astype(bool)
    )
    keep = flows[list(IDENTITY)].notna().all(axis=1) & ~arp
    label_column = next((n for n in LABEL_NAMES if n in raw.columns), None)
    label_values = raw.loc[keep, label_column] if label_column else None
    flows = flows[keep].copy()
    if flows.empty:
        raise IngestError(f"{path.name} has no usable flow rows.")

    flows["ts"], clock_used = _fix_clock(flows["ts"], clock, may_be_12h)

    # A TCP window is unknown when the flow meter says so (-1 in the original files), when the
    # flow is not TCP (the improved edition writes 0 there), or when no packet came back.
    for column in ("init_fwd_win", "init_bwd_win"):
        known = (flows[column] >= 0) & (flows["protocol"] == PROTO_TCP)
        if column == "init_bwd_win":
            known &= flows["bwd_pkts"] > 0
        flows[column] = flows[column].where(known)

    # A handful of flows per file have a duration of a few microseconds below zero, with
    # gaps to match, because their packets were captured out of order. Zero is the closest
    # truthful value, and it gives them NULL rates like any other zero-length flow.
    negative_durations = int((flows["duration_us"] < 0).sum())
    for column in TIME_COLUMNS:
        flows[column] = flows[column].clip(lower=0)

    flags = FLAGS_KEPT
    if not _flags_are_counts(flows):
        flows[list(FLAG_COLUMNS)] = np.nan
        flags = FLAGS_DROPPED

    # Rates are recomputed rather than read: the file's own columns hold Infinity for
    # zero-length flows, and we want exactly the same definition as the pcap path.
    seconds = (flows["duration_us"] / 1_000_000).where(flows["duration_us"] > 0)
    flows["bytes_per_s"] = (flows["fwd_bytes"] + flows["bwd_bytes"]) / seconds
    flows["pkts_per_s"] = (flows["fwd_pkts"] + flows["bwd_pkts"]) / seconds

    # Order by time. The sort is stable, so rows sharing a timestamp keep file order.
    order = flows["ts"].argsort(kind="stable")
    flows = flows.iloc[order].reset_index(drop=True)
    flows.insert(0, "flow_id", np.arange(1, len(flows) + 1, dtype="int64"))
    flows = flows[schema.column_names("flows")]

    labels = None
    if label_values is not None:
        ordered = label_values.iloc[order].reset_index(drop=True)
        labels = pd.DataFrame({"flow_id": flows["flow_id"], "label": ordered.map(_clean_label)})

    notes = {
        "rows_in_file": rows_in_file,
        "rows_dropped": rows_in_file - len(flows),
        "arp_frames_dropped": int(arp.sum()),
        "clock": clock_used,
        "negative_durations_zeroed": negative_durations,
        "tcp_flags": flags,
    }
    return CicCsvResult(flows=flows, labels=labels, notes=notes)


def ingest_cic_csv(
    path: str | Path,
    capture_id: str | None = None,
    *,
    clock: Clock = "auto",
    overwrite: bool = False,
) -> store.CaptureMeta:
    """Read a CICFlowMeter CSV and store it as a capture."""
    path = Path(path)
    result = read_cic_csv(path, clock=clock)
    return store.write_capture(
        capture_id or store.new_capture_id(path.name),
        source="cic_csv",
        original_name=path.name,
        flows=result.flows,
        labels=result.labels,
        notes=result.notes,
        overwrite=overwrite,
    )
