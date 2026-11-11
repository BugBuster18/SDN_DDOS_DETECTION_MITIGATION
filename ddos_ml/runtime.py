"""Shared model loading and live feature-frame helpers used by the Ryu app."""
from __future__ import annotations

import json
import os
from pathlib import Path

import joblib
import pandas as pd

from .features import FEATURE_COLUMNS, live_flow_features


def load_model(model_dir: str | Path | None = None, *, allow_demo: bool | None = None):
    base = Path(model_dir or os.environ.get("DDOS_MODEL_DIR", "artifacts/production"))
    metadata_path = base / "model_metadata.json"
    if not metadata_path.is_file():
        raise FileNotFoundError(
            f"Model metadata not found in {base}. Run training first; "
            "see README.md (Step 4)."
        )

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    model_filename = metadata.get("model_file", "random_forest.joblib")
    if not isinstance(model_filename, str) or Path(model_filename).name != model_filename:
        raise ValueError("Invalid model filename in model_metadata.json.")

    model_path = base / model_filename
    if not model_path.is_file():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    if metadata.get("feature_columns") != FEATURE_COLUMNS:
        raise ValueError("Model feature schema does not match the live controller feature schema.")
    if allow_demo is None:
        allow_demo = os.environ.get("DDOS_ALLOW_DEMO_MODEL", "0").lower() in {"1", "true", "yes"}
    if metadata.get("demo_synthetic_data") and not allow_demo:
        raise RuntimeError(
            "This model was trained on synthetic demo data. It is blocked from live use. "
            "Train with labelled real traffic and set DDOS_MODEL_DIR to that production model directory."
        )
    return joblib.load(model_path), metadata


def live_feature_frame(flow_rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([live_flow_features(row) for row in flow_rows], columns=FEATURE_COLUMNS)
