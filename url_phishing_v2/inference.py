"""Local-only inference for the separately trained v2 artifact."""

from __future__ import annotations

import os
from pathlib import Path

import joblib
import pandas as pd

try:  # package import
    from .features import FEATURE_NAMES, SCHEMA_VERSION, extract_url_features
except ImportError:  # direct script/test discovery from this directory
    from features import FEATURE_NAMES, SCHEMA_VERSION, extract_url_features


DEFAULT_ARTIFACT = Path(os.environ.get(
    "BLUE_ENGINE_URL_V2_MODEL_PATH",
    Path(__file__).parent / "artifacts" / "url_phishing_v2.joblib",
)).expanduser()


def predict_url(raw_url: str, artifact_path: Path = DEFAULT_ARTIFACT) -> dict:
    """Run the v2 model on one URL; this function performs no external requests."""
    if not artifact_path.is_file():
        raise FileNotFoundError(f"v2 model artifact not found: {artifact_path}")
    payload = joblib.load(artifact_path)
    metadata = payload.get("metadata", {})
    if metadata.get("schema_version") != SCHEMA_VERSION or tuple(metadata.get("feature_names", ())) != FEATURE_NAMES:
        raise ValueError("Artifact feature schema/version mismatch")
    features = extract_url_features(raw_url)
    row = pd.DataFrame([features], columns=FEATURE_NAMES, dtype="int64")
    model = payload.get("model")
    probabilities = model.predict_proba(row)[0]
    classes = list(model.classes_)
    phishing_score = float(probabilities[classes.index(1)])
    label = int(model.predict(row)[0])
    return {
        "label": label,
        "class": "phishing" if label == 1 else "legitimate",
        "phishing_score": phishing_score,
        "schema_version": SCHEMA_VERSION,
    }
