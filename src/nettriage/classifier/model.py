"""Load a trained flow classifier and run it over a capture.

``classify_flows`` is the function the agent's tool wraps. It returns
aggregates and a few example flow ids, never whole tables, and it reads the
capture through the same locked read-only connection as every other tool.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

from .. import store
from . import ClassifierError
from .dataset import BENIGN
from .features import check_columns, to_matrix

MODEL_FILE = "model.joblib"
CARD_FILE = "model_card.json"
CONTEXT_COLUMNS = ("flow_id", "ts", "src_ip", "dst_ip", "dst_port")
FLAG_COLUMNS = ("syn_count", "fin_count", "rst_count", "psh_count", "ack_count")


def model_dir() -> Path:
    return Path(os.environ.get("NETTRIAGE_MODEL_DIR", "models/flow-classifier"))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def score_matrix(classifier, matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Per flow: the probability that it is not benign, and its most likely attack family."""
    classes = [str(c) for c in classifier.classes_]
    if BENIGN not in classes or len(classes) < 2:
        raise ClassifierError("The model needs a 'benign' class and at least one attack family.")
    proba = classifier.predict_proba(matrix)
    benign = classes.index(BENIGN)
    attack_classes = np.array([c for c in classes if c != BENIGN])
    attack_proba = np.delete(proba, benign, axis=1)
    return 1.0 - proba[:, benign], attack_classes[attack_proba.argmax(axis=1)]


@dataclass
class FlowModel:
    classifier: object
    card: dict

    @property
    def features(self) -> list[str]:
        return list(self.card["features"])

    @property
    def threshold(self) -> float:
        return float(self.card["threshold"])

    def score(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Columns ``score`` (0 to 1) and ``family`` for every row of ``frame``."""
        score, family = score_matrix(self.classifier, to_matrix(frame, self.features))
        return pd.DataFrame({"score": score, "family": family}, index=frame.index)


def load_model(directory: str | Path | None = None) -> FlowModel:
    """Load a model written by ``nettriage train``.

    The model file is a pickle, which runs code when loaded, so only load models
    you trained yourself. The card records the file's hash and the library
    version; a mismatch on either is refused rather than risked.
    """
    import joblib
    import sklearn

    directory = Path(directory) if directory else model_dir()
    card_path, model_path = directory / CARD_FILE, directory / MODEL_FILE
    if not card_path.is_file() or not model_path.is_file():
        raise ClassifierError(f"No trained model in {directory}. Train one with: nettriage train CAPTURE...")
    card = json.loads(card_path.read_text(encoding="utf-8"))
    if file_sha256(model_path) != card.get("model_sha256"):
        raise ClassifierError(f"{model_path} does not match the hash in its model card; refusing to load it.")
    trained_with = str(card.get("library", {}).get("scikit-learn", ""))
    if trained_with.split(".")[:2] != sklearn.__version__.split(".")[:2]:
        raise ClassifierError(
            f"The model was trained with scikit-learn {trained_with}, but {sklearn.__version__} is installed. "
            "Retrain it, or install the matching version."
        )
    return FlowModel(classifier=joblib.load(model_path), card=card)


def _iso(value) -> str | None:
    return None if pd.isna(value) else pd.Timestamp(value).isoformat()


def _group_summary(flagged: pd.DataFrame, key: str, other: str, totals: pd.Series, top: int) -> list[dict]:
    rows = []
    for value, group in flagged.groupby(key, sort=False):
        rows.append({
            key: value,
            "flagged_flows": int(len(group)),
            "all_flows": int(totals.get(value, 0)),
            "families": {str(k): int(v) for k, v in group["family"].value_counts().items()},
            f"distinct_{other}": int(group[other].nunique()),
            "distinct_dst_ports": int(group["dst_port"].nunique()),
            "first_seen": _iso(group["ts"].min()),
            "last_seen": _iso(group["ts"].max()),
            "example_flow_ids": [int(i) for i in group.nlargest(5, "score")["flow_id"]],
        })
    rows.sort(key=lambda r: r["flagged_flows"], reverse=True)
    return rows[:top]


def classify_flows(
    capture_id: str,
    where: str | None = None,
    *,
    top: int = 10,
    model: FlowModel | None = None,
) -> dict:
    """Score the flows of a capture and summarise what looks malicious.

    ``where`` is an optional SQL condition over the ``flows`` table, for example
    ``dst_port = 22`` or ``src_ip = '10.0.0.5' AND ts >= '2017-07-04 12:00'``.
    The result holds counts per attack family and the sources and targets with
    the most flagged flows, each with example ``flow_id`` values to cite.
    """
    model = model or load_model()
    if where is not None and ";" in where:
        raise ClassifierError("The filter must be a single SQL condition without ';'.")
    columns = check_columns(list(dict.fromkeys([*CONTEXT_COLUMNS, *model.features, *FLAG_COLUMNS])))
    sql = f"SELECT {', '.join(columns)} FROM flows"
    if where and where.strip():
        sql += f" WHERE ({where})"

    try:
        meta = store.load_meta(capture_id)
        con = store.connect_readonly(capture_id)
    except store.CaptureError as exc:
        raise ClassifierError(str(exc)) from exc
    try:
        frame = con.execute(sql).df()
    except duckdb.Error as exc:
        raise ClassifierError(f"Could not select flows: {str(exc).splitlines()[0]}") from exc
    finally:
        con.close()

    caveats = list(model.card.get("caveats", []))
    if capture_id in model.card.get("training", {}).get("captures", []):
        caveats.append(
            "Half of this capture's 5-minute blocks were used to train the model, so results on it are optimistic."
        )
    if meta.source == "pcap":
        caveats.append(
            "This capture was read from packets. The model was trained on dataset flows, and how closely "
            "the two kinds of features agree has not been measured."
        )
    if len(frame) and frame[list(FLAG_COLUMNS)].isna().all().all():
        caveats.append("This capture has no TCP flag counts, which the model relies on; treat scores as weak hints.")

    result = {
        "capture": capture_id,
        "filter": where or None,
        "model": {"id": model.card["id"], "families": model.card["classes"], "threshold": model.threshold},
        "flows_scored": int(len(frame)),
        "flows_flagged": 0,
        "by_family": [],
        "top_sources": [],
        "top_targets": [],
        "caveats": caveats,
    }
    if frame.empty:
        return result

    frame = frame.join(model.score(frame))
    flagged = frame[frame["score"] >= model.threshold]
    result["flows_flagged"] = int(len(flagged))
    result["by_family"] = [
        {"family": str(family), "flows": int(len(group)), "median_score": round(float(group["score"].median()), 3)}
        for family, group in sorted(flagged.groupby("family"), key=lambda item: -len(item[1]))
    ]
    result["top_sources"] = _group_summary(flagged, "src_ip", "dst_ip", frame["src_ip"].value_counts(), top)
    result["top_targets"] = _group_summary(flagged, "dst_ip", "src_ip", frame["dst_ip"].value_counts(), top)
    return result
