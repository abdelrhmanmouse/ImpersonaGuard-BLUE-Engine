"""Inference on the URL notebook's engineered numeric feature rows.

No raw-URL feature extractor exists in the inspected source. This interface
therefore accepts the complete 111-field numeric feature map; it does not
fetch DNS, WHOIS, TLS, ASN, redirect, or search-index data.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from numbers import Real

import joblib
import numpy as np
import pandas as pd


_ARTIFACTS_DIR = Path(os.environ.get("BLUE_ENGINE_ARTIFACTS_DIR", Path(__file__).parent / "artifacts")).expanduser()
DEFAULT_MODEL_PATH = Path(os.environ.get(
    "BLUE_ENGINE_LEGACY_URL_MODEL_PATH",
    _ARTIFACTS_DIR / "url_phishing_inference" / "url_phishing_model.joblib",
)).expanduser()


def load_url_phishing_artifact(model_path: str | Path | None = None) -> dict:
    path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
    if not path.is_file():
        raise FileNotFoundError(f"URL phishing fitted artifact not found: {path}")
    artifact = joblib.load(path)
    if not isinstance(artifact, dict) or not {"model", "metadata"}.issubset(artifact):
        raise ValueError("URL phishing artifact is missing required model metadata")
    return artifact


def predict_url_features(features: dict, model_path: str | Path | None = None) -> dict:
    """Predict from one complete URL feature row; null values use fitted imputation."""
    if not isinstance(features, dict):
        raise ValueError("features must be a JSON object mapping feature names to numbers or null")
    artifact = load_url_phishing_artifact(model_path)
    names = artifact["metadata"]["feature_names"]
    actual = set(features)
    expected = set(names)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing {len(missing)} required feature(s)")
        if extra:
            parts.append(f"unknown {len(extra)} feature(s)")
        raise ValueError("invalid URL feature schema: " + "; ".join(parts))

    row: dict[str, float] = {}
    for name in names:
        value = features[name]
        if value is None:
            row[name] = np.nan
        elif isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"feature {name!r} must be a number or null")
        else:
            number = float(value)
            row[name] = number if math.isfinite(number) else np.nan

    frame = pd.DataFrame([row], columns=names)
    model = artifact["model"]
    prediction = int(model.predict(frame)[0])
    classes = list(model.classes_)
    score = float(model.predict_proba(frame)[0, classes.index(1)]) if 1 in classes else None
    return {
        "prediction": prediction,
        "label": artifact["metadata"]["label_mapping"][str(prediction)],
        "score": score,
        "score_kind": "phishing_class_probability" if score is not None else None,
        "model_name": artifact["metadata"]["model_name"],
        "input_kind": "engineered_numeric_features",
        "interpretation": "model output for supplied engineered features; no raw-URL parsing or network feature retrieval was performed",
    }
