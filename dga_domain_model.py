"""Inference for the notebook's domain-string DGA baseline.

This is separate from brand similarity and the TypoDS typosquatting classifier.
It classifies normalized domain strings using the notebook's char-TF-IDF and
Logistic Regression pipeline; it does not inspect DNS traffic.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from urllib.parse import urlsplit

import joblib
import pandas as pd


_ARTIFACTS_DIR = Path(os.environ.get("BLUE_ENGINE_ARTIFACTS_DIR", Path(__file__).parent / "artifacts")).expanduser()
DEFAULT_MODEL_PATH = Path(os.environ.get(
    "BLUE_ENGINE_DGA_MODEL_PATH",
    _ARTIFACTS_DIR / "dga_domain_inference" / "dga_domain_model.joblib",
)).expanduser()


def normalize_dga_domain(value: object) -> str:
    """Normalize a domain-like string using the notebook's transformations."""
    if value is None:
        raise ValueError("domain must not be None")
    raw = str(value).strip().lower()
    if not raw:
        raise ValueError("domain must not be empty")
    if "://" in raw:
        raw = urlsplit(raw).netloc
    else:
        raw = raw.split("/", 1)[0]
    raw = raw.split("@")[-1]
    if ":" in raw:
        raw = raw.split(":", 1)[0]
    raw = raw.strip(".")
    if not raw:
        raise ValueError("domain must contain a hostname")
    try:
        raw = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc
    if len(raw) > 253 or any(not label or len(label) > 63 for label in raw.split(".")):
        raise ValueError("domain is not a valid hostname")
    if any(not re.fullmatch(r"[a-z0-9-]+", label) or label.startswith("-") or label.endswith("-")
           for label in raw.split(".")):
        raise ValueError("domain is not a valid hostname")
    return raw


def load_dga_artifact(model_path: str | Path | None = None) -> dict:
    path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
    if not path.is_file():
        raise FileNotFoundError(f"DGA fitted artifact not found: {path}")
    artifact = joblib.load(path)
    required = {"model", "metadata"}
    if not isinstance(artifact, dict) or not required.issubset(artifact):
        raise ValueError("DGA artifact is missing required model metadata")
    return artifact


def predict_dga_domain(domain: object, model_path: str | Path | None = None) -> dict:
    """Return a domain-string DGA score and thresholded label."""
    normalized = normalize_dga_domain(domain)
    artifact = load_dga_artifact(model_path)
    model = artifact["model"]
    score = float(model.predict_proba(pd.Series([normalized]))[0, 1])
    threshold = float(artifact["metadata"]["threshold"])
    prediction = int(score >= threshold)
    label = artifact["metadata"]["label_mapping"][str(prediction)]
    return {
        "input": str(domain),
        "normalized_domain": normalized,
        "prediction": prediction,
        "label": label,
        "score": score,
        "score_kind": "dga_class_probability",
        "threshold": threshold,
        "model_name": artifact["metadata"]["model_name"],
        "interpretation": "domain-string experiment output; not DNS-activity analysis or confirmation of maliciousness",
    }
