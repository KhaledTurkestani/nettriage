"""Labelled flows for training and testing the classifier.

Three decisions live here, because every number the classifier reports depends
on them:

* **Families.** The dataset's fifteen attack labels are grouped into six attack
  families plus ``benign``; several labels have too few flows to be a class.
* **"Attempted" flows count as benign**, as the dataset's authors recommend.
  They belong to an attack run but carry nothing malicious, such as a
  handshake with no payload, and are indistinguishable from normal traffic.
* **The split is by time, not at random.** Each day is cut into 5-minute blocks
  and every second block is held out. A random split would put near-identical
  flows from the same attack burst on both sides. Held-out blocks are also the
  only place eval cases for the agent may come from, so that the agent is never
  graded on flows its classifier was trained on.
"""

from __future__ import annotations

from collections.abc import Sequence

import pandas as pd

from .. import store
from . import ClassifierError
from .features import check_columns

BENIGN = "benign"
FAMILIES = (BENIGN, "brute_force", "dos", "port_scan", "web_attack", "botnet", "other")
ATTEMPTED_SUFFIX = " - attempted"
BLOCK_MINUTES = 5
SPLIT_RULE = (
    f"Each day is cut into {BLOCK_MINUTES}-minute blocks counted from 00:00 UTC. Even blocks "
    "(00:00, 00:10, ...) are for training; odd blocks (00:05, 00:15, ...) are held out."
)


def is_attempted(label: str) -> bool:
    return str(label).strip().lower().endswith(ATTEMPTED_SUFFIX)


def family_of(label: str) -> str:
    """Map a dataset label (original or improved CIC-IDS2017 edition) to a family."""
    text = str(label).strip().lower()
    if text == "benign" or text.endswith(ATTEMPTED_SUFFIX):
        return BENIGN
    if "patator" in text:
        return "brute_force"
    if text.startswith(("dos", "ddos")):
        return "dos"
    if "portscan" in text or "port scan" in text:  # also "Infiltration - Portscan"
        return "port_scan"
    if text.startswith("web attack"):
        return "web_attack"
    if text.startswith("bot"):
        return "botnet"
    return "other"  # Heartbleed, Infiltration: a few dozen flows in the whole week


def held_out(ts: pd.Series) -> pd.Series:
    """True for flows that start in a held-out (odd) time block."""
    minute_of_day = ts.dt.hour * 60 + ts.dt.minute
    return (minute_of_day // BLOCK_MINUTES) % 2 == 1


def load_labelled(capture_ids: Sequence[str], columns: Sequence[str]) -> pd.DataFrame:
    """Flows of labelled captures joined with their ground truth.

    Reads the labels file, so this is for training and evaluation only; nothing
    on the agent's side may call it.
    """
    columns = check_columns(columns)
    if not capture_ids:
        raise ClassifierError("No captures given.")
    parts = []
    for capture_id in capture_ids:
        try:
            labels = store.load_labels(capture_id)
            con = store.connect_readonly(capture_id)
        except store.CaptureError as exc:
            raise ClassifierError(str(exc)) from exc
        try:
            flows = con.execute(f"SELECT flow_id, ts, {', '.join(columns)} FROM flows ORDER BY flow_id").df()
        finally:
            con.close()
        frame = flows.merge(labels, on="flow_id", how="inner", validate="one_to_one")
        if len(frame) != len(flows):
            raise ClassifierError(f"Capture {capture_id!r}: {len(flows) - len(frame)} flows have no label.")
        frame.insert(0, "capture", capture_id)
        parts.append(frame)

    frame = pd.concat(parts, ignore_index=True)
    families = {label: family_of(label) for label in frame["label"].unique()}
    attempted = {label: is_attempted(label) for label in families}
    frame["family"] = frame["label"].map(families)
    frame["attempted"] = frame["label"].map(attempted)
    frame["held_out"] = held_out(frame["ts"])
    return frame
