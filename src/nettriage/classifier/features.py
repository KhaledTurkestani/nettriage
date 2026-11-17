"""Which flow columns the classifier sees.

Addresses, ports and times are left out on purpose. A model given them learns
"traffic from 172.16.0.1 to port 21 is an attack", which is true of the dataset
and useless anywhere else. What remains describes how a flow behaves.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
import pandas as pd

from .. import schema
from . import ClassifierError

IDENTITY = ("flow_id", "ts", "src_ip", "src_port", "dst_ip", "dst_port")
FEATURES: tuple[str, ...] = tuple(c.name for c in schema.FLOW_COLUMNS if c.name not in IDENTITY)


def check_columns(columns: Sequence[str]) -> list[str]:
    """Column names go into SQL text, so only names from the schema are accepted."""
    known = set(schema.column_names("flows"))
    unknown = [c for c in columns if c not in known]
    if unknown:
        raise ClassifierError(f"Not columns of the flows table: {', '.join(unknown)}")
    return list(columns)


def to_matrix(frame: pd.DataFrame, features: Sequence[str]) -> np.ndarray:
    """Feature values as floats, with NaN where the capture has NULL."""
    missing = [f for f in features if f not in frame.columns]
    if missing:
        raise ClassifierError(f"Feature columns missing from the data: {', '.join(missing)}")
    return frame[list(features)].to_numpy(dtype="float64", na_value=np.nan)
