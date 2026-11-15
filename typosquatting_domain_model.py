"""Single-domain typosquatting ML inference helpers.

This component is deliberately separate from the existing DGA and
brand-similarity detectors. Its model predicts the dataset's binary domain
label; it does not confirm that a domain is malicious in the wild.
"""

from __future__ import annotations

import re
import os
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import tldextract


_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True, cache_dir=None)
_ARTIFACTS_DIR = Path(os.environ.get("BLUE_ENGINE_ARTIFACTS_DIR", Path(__file__).parent / "artifacts")).expanduser()
DEFAULT_MODEL_PATH = Path(os.environ.get(
    "BLUE_ENGINE_TYPOSQUATTING_MODEL_PATH",
    _ARTIFACTS_DIR / "typosquatting_experiment" / "typods_dataset_ts" / "final_model.joblib",
)).expanduser()
FEATURE_NAMES = (
    "hostname_length",
    "sld_length",
    "tld_length",
    "label_count",
    "subdomain_count",
    "hyphen_count",
    "digit_count",
    "letter_count",
    "unique_char_ratio",
    "vowel_ratio",
    "digit_ratio",
    "hyphen_ratio",
    "entropy_bits",
)


def normalize_domain(value: object) -> str:
    """Return a lowercase ASCII hostname from a URL/domain input."""
    if value is None:
        raise ValueError("domain must not be None")
    raw = str(value).strip()
    if not raw:
        raise ValueError("domain must not be empty")
    if "://" not in raw:
        raw = "//" + raw
    host = (urlsplit(raw).hostname or "").strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"could not extract a hostname from {value!r}")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDN hostname: {value!r}") from exc
    if len(host) > 253 or any(not part or len(part) > 63 for part in host.split(".")):
        raise ValueError(f"invalid hostname: {value!r}")
    if any(not re.fullmatch(r"[a-z0-9-]+", part) or part.startswith("-") or part.endswith("-")
           for part in host.split(".")):
        raise ValueError(f"invalid hostname: {value!r}")
    return host


def _components(host: str) -> tuple[str, str, str, int]:
    ext = _EXTRACT(host)
    sld = ext.domain or host.split(".")[0]
    return sld, ext.suffix, ext.subdomain, len(host.split("."))


def domain_to_features(value: object) -> np.ndarray:
    """Create stable numeric lexical features for one domain."""
    host = normalize_domain(value)
    sld, suffix, subdomain, label_count = _components(host)
    letters = sum(ch.isalpha() for ch in host)
    digits = sum(ch.isdigit() for ch in host)
    hyphens = host.count("-")
    n = max(len(host), 1)
    counts = np.asarray([host.count(ch) for ch in set(host)], dtype=float)
    probabilities = counts / counts.sum() if counts.size else np.asarray([1.0])
    entropy = float(-(probabilities * np.log2(probabilities)).sum())
    return np.asarray([
        len(host), len(sld), len(suffix), label_count,
        len([part for part in subdomain.split(".") if part]) if subdomain else 0,
        hyphens, digits, letters, len(set(host)) / n,
        sum(ch in "aeiou" for ch in host) / max(letters, 1),
        digits / n, hyphens / n, entropy,
    ], dtype=float)


def domains_to_features(values) -> np.ndarray:
    rows = [domain_to_features(value) for value in values]
    return np.vstack(rows) if rows else np.empty((0, len(FEATURE_NAMES)), dtype=float)


def predict_typosquatting_domain(domain: object, model_path: str | None = None) -> dict:
    """Load the saved model and return a structured single-domain prediction."""
    return TyposquattingDomainClassifier(model_path).predict_one(domain)


class TyposquattingDomainClassifier:
    """Loaded model wrapper using training-time normalization and sklearn pipeline."""

    def __init__(self, model_path: str | None = None):
        import joblib

        if model_path is None:
            model_path = str(DEFAULT_MODEL_PATH)
        self.model_path = str(model_path)
        self.artifact = joblib.load(self.model_path)
        self.model = self.artifact["model"]

    def predict_one(self, domain: object) -> dict:
        import pandas as pd

        host = normalize_domain(domain)
        score = float(self.model.predict_proba(pd.Series([host]))[0, 1])
        threshold = float(self.artifact["threshold"])
        prediction = int(score >= threshold)
        return {
            "input": str(domain),
            "normalized_domain": host,
            "prediction": prediction,
            "label": self.artifact["label_mapping"][str(prediction)],
            "score": score,
            "threshold": threshold,
            "model_name": self.artifact["model_name"],
            "interpretation": "dataset-trained typosquatting class prediction; not independent confirmation of maliciousness",
        }

    def predict_many(self, domains) -> list[dict]:
        import pandas as pd

        values = list(domains)
        hosts = [normalize_domain(value) for value in values]
        scores = self.model.predict_proba(pd.Series(hosts))[:, 1]
        threshold = float(self.artifact["threshold"])
        return [
            {
                "input": str(value),
                "normalized_domain": host,
                "prediction": int(score >= threshold),
                "label": self.artifact["label_mapping"][str(int(score >= threshold))],
                "score": float(score),
                "threshold": threshold,
                "model_name": self.artifact["model_name"],
                "interpretation": "dataset-trained typosquatting class prediction; not independent confirmation of maliciousness",
            }
            for value, host, score in zip(values, hosts, scores)
        ]


def assess_domain_similarity(domain: object, ml_classifier=None, brand_detector=None) -> dict:
    """Run existing brand-similarity rules and ML as separate outputs.

    The two detectors remain distinguishable: a lexical brand alert is not
    blended into or substituted for the trained model's prediction.
    """
    from typosquatting_detector import TyposquattingDetector

    detector = brand_detector or TyposquattingDetector()
    rule_result = detector.detect(domain).to_dict()
    classifier = ml_classifier or TyposquattingDomainClassifier()
    try:
        ml_result = classifier.predict_one(domain)
    except ValueError as exc:
        ml_result = {"input": str(domain), "normalized_domain": "", "prediction": None,
                     "label": "invalid_input", "score": None,
                     "threshold": float(classifier.artifact["threshold"]),
                     "model_name": classifier.artifact["model_name"], "error": str(exc)}
    return {"input": str(domain), "brand_similarity_rule": rule_result,
            "typosquatting_ml": ml_result}



