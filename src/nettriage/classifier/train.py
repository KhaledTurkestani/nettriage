"""Train the flow classifier and measure it honestly.

Two tests go into every model card:

* **Held-out blocks**: the same attacks as in training, at different minutes.
  This is the easy test, and its numbers flatter the model.
* **Unseen attacks**: for each attack label in turn, a model is trained with
  that label removed and then asked to flag it. This shows what the classifier
  does with a tool it has never met, which is the situation that matters.
"""

from __future__ import annotations

import json
import platform
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from . import ClassifierError
from .dataset import BENIGN, BLOCK_MINUTES, SPLIT_RULE, load_labelled
from .features import FEATURES, to_matrix
from .model import CARD_FILE, MODEL_FILE, file_sha256, score_matrix

THRESHOLD = 0.5
PARAMS = {
    "max_iter": 200,
    "learning_rate": 0.1,
    "max_leaf_nodes": 31,
    # Not optional. Without it the leaf values blow up once the easy classes are fitted: on the
    # dataset the training loss rose from 0.76 to 8.9 within twelve rounds, and a model run for
    # 200 rounds flagged 15% of benign flows. With it the loss falls smoothly to 0.0001.
    "l2_regularization": 1.0,
    "early_stopping": True,
    "validation_fraction": 0.1,
    "n_iter_no_change": 10,
}
# Tried and dropped, because neither changed held-out results beyond noise: weighting rare
# families up (42 to 45 false positives against 36 without), and adding dst_port as a feature
# (recall 0.9973 against 0.9969). The simpler, port-blind model is the one that ships.


def fit(train: pd.DataFrame, features: Sequence[str], *, seed: int = 0, **overrides):
    from sklearn.ensemble import HistGradientBoostingClassifier

    present = set(train["family"])
    if BENIGN not in present or len(present) < 2:
        raise ClassifierError("Training needs benign flows and at least one attack family.")
    classifier = HistGradientBoostingClassifier(**{**PARAMS, **overrides}, random_state=seed)
    classifier.fit(to_matrix(train, features), train["family"].to_numpy())
    return classifier


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate(classifier, test: pd.DataFrame, features: Sequence[str], threshold: float = THRESHOLD) -> dict:
    """Score labelled flows the model has not seen."""
    score, family = score_matrix(classifier, to_matrix(test, features))
    flagged = score >= threshold
    truth = (test["family"] != BENIGN).to_numpy()
    tp, fp, fn = int((flagged & truth).sum()), int((flagged & ~truth).sum()), int((~flagged & truth).sum())
    benign = int((~truth).sum())
    right_family = int((flagged & truth & (family == test["family"].to_numpy())).sum())

    by_label = []
    work = pd.DataFrame({
        "label": test["label"].to_numpy(), "truth": test["family"].to_numpy(), "flagged": flagged, "family": family,
    })
    for label, group in work.groupby("label", sort=False):
        hits = group[group["flagged"]]
        by_label.append({
            "label": label,
            "counted_as": group["truth"].iloc[0],
            "flows": int(len(group)),
            "flagged": int(len(hits)),
            "flagged_share": _ratio(len(hits), len(group)),
            "mostly_called": hits["family"].mode().iloc[0] if len(hits) else None,
        })
    by_label.sort(key=lambda row: (row["counted_as"] == BENIGN, -row["flows"]))

    quiet = {}
    for capture, group in test.assign(flagged=flagged).groupby("capture", sort=False):
        if (group["family"] == BENIGN).all() and not group["attempted"].any():
            quiet[capture] = {"flows": int(len(group)), "false_positives": int(group["flagged"].sum())}

    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    return {
        "flows": int(len(test)),
        "malicious_flows": tp + fn,
        "benign_flows": benign,
        "precision": precision,
        "recall": recall,
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision and recall else None,
        "false_positives": fp,
        "false_positives_per_100k_benign": round(fp / benign * 100_000, 1) if benign else None,
        "right_family_share": _ratio(right_family, tp),
        "attack_free_captures": quiet,
        "by_label": by_label,
    }


def unseen_attack_test(
    frame: pd.DataFrame,
    features: Sequence[str],
    *,
    threshold: float = THRESHOLD,
    min_flows: int = 20,
    progress: Callable[[str], None] = lambda message: None,
    **fit_args,
) -> list[dict]:
    """For each attack label: train without it, then see how much of it gets flagged."""
    train, test = frame[~frame["held_out"]], frame[frame["held_out"]]
    attacks = test.loc[test["family"] != BENIGN, "label"].value_counts()
    results = []
    for label, count in attacks.items():
        if count < min_flows:
            continue
        progress(f"unseen-attack test: training without {label!r}")
        without = train[train["label"] != label]
        if without["family"].nunique() < 2:
            continue
        classifier = fit(without, features, **fit_args)
        rows = test[test["label"] == label]
        score, family = score_matrix(classifier, to_matrix(rows, features))
        flagged = score >= threshold
        results.append({
            "label": label,
            "family": rows["family"].iloc[0],
            "family_still_in_training": bool((without["family"] == rows["family"].iloc[0]).any()),
            "held_out_flows": int(len(rows)),
            "flagged": int(flagged.sum()),
            "recall": _ratio(int(flagged.sum()), len(rows)),
            "mostly_called": pd.Series(family[flagged]).mode().iloc[0] if flagged.any() else None,
        })
    return results


def train_model(
    capture_ids: Sequence[str],
    out_dir: str | Path,
    *,
    features: Sequence[str] = FEATURES,
    unseen_test: bool = True,
    seed: int = 0,
    progress: Callable[[str], None] = lambda message: None,
) -> dict:
    """Train on the training blocks of the given captures, test, and write model and card."""
    import joblib
    import sklearn

    features = list(features)
    progress(f"loading {len(capture_ids)} capture(s)")
    frame = load_labelled(capture_ids, features)
    train, test = frame[~frame["held_out"]], frame[frame["held_out"]]
    if train.empty or test.empty:
        raise ClassifierError("The captures do not cover both training and held-out time blocks.")

    progress(f"training on {len(train):,} flows")
    classifier = fit(train, features, seed=seed)
    progress(f"testing on {len(test):,} held-out flows")
    held_out_result = evaluate(classifier, test, features)
    unseen = unseen_attack_test(frame, features, seed=seed, progress=progress) if unseen_test else None

    caveats = [
        "Scores come from flow behaviour only; the model never sees addresses, ports or times.",
        "It was trained on one week of traffic from one network. Treat a flag as a lead to check, not a verdict.",
    ]
    if unseen:
        shares = [row["recall"] for row in unseen]
        missed = sum(1 for share in shares if share < 0.05)
        caveats.append(
            f"It mostly recognises attacks it was trained on. Of {len(unseen)} attack types removed from training "
            f"in turn, it flagged between {min(shares):.0%} and {max(shares):.0%} of their flows, and almost none "
            f"for {missed} of them. A flow that is not flagged is not evidence of benign traffic."
        )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / MODEL_FILE
    joblib.dump(classifier, model_path, compress=3)
    digest = file_sha256(model_path)
    card = {
        "id": f"flow-gbm-{digest[:12]}",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model_sha256": digest,
        "algorithm": "sklearn.ensemble.HistGradientBoostingClassifier",
        "params": {**PARAMS, "seed": seed},
        "iterations": int(classifier.n_iter_),
        "library": {"scikit-learn": sklearn.__version__, "python": platform.python_version()},
        "features": features,
        "classes": [str(c) for c in classifier.classes_],
        "threshold": THRESHOLD,
        "training": {
            "captures": list(capture_ids),
            "flows": int(len(train)),
            "by_family": {str(k): int(v) for k, v in train["family"].value_counts().items()},
            "attempted_flows_counted_as_benign": int(train["attempted"].sum()),
        },
        "split": {"block_minutes": BLOCK_MINUTES, "rule": SPLIT_RULE},
        "held_out_test": held_out_result,
        "unseen_attack_test": unseen,
        "caveats": caveats,
    }
    (out_dir / CARD_FILE).write_text(json.dumps(card, indent=2), encoding="utf-8")
    return card
