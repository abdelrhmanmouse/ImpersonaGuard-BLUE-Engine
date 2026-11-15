"""FastAPI wrapper around the experimental text phishing baseline."""

from __future__ import annotations

import json
import math
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import joblib
from fastapi import FastAPI, HTTPException
from sklearn.svm import LinearSVC
from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from email_detection.domains import best_trusted_match, extract_sender_domain, normalize_domain
from email_detection.header_forensics import analyze_email_header

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = Path(os.environ.get("BLUE_ENGINE_EMAIL_MODEL_PATH", ROOT / "artifacts" / "best_baseline.joblib")).expanduser()
DEFAULT_METADATA_PATH = Path(os.environ.get("BLUE_ENGINE_EMAIL_METADATA_PATH", ROOT / "artifacts" / "best_model_metadata.json")).expanduser()


class DetectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email_text: StrictStr = Field(min_length=1, max_length=100_000)
    sender_address: StrictStr | None = None
    claimed_domain: StrictStr | None = None
    expected_domain: StrictStr | None = None

    @field_validator("email_text")
    @classmethod
    def nonblank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("email_text must not be blank")
        return value

    @field_validator("expected_domain", "claimed_domain")
    @classmethod
    def valid_optional_domain(cls, value: str | None) -> str | None:
        if value is not None:
            normalize_domain(value)
        return value


class HeaderForensicsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    raw_header: StrictStr = Field(min_length=1, max_length=100_000)
    expected_domain: StrictStr | None = None

    @field_validator("raw_header")
    @classmethod
    def nonblank_header(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("raw_header must not be blank")
        return value

    @field_validator("expected_domain")
    @classmethod
    def valid_expected_domain(cls, value: str | None) -> str | None:
        if value is not None:
            normalize_domain(value)
        return value


class DomainSimilarity(BaseModel):
    sender_domain: str
    expected_domain: str
    similarity: float
    relation: Literal["exact_match", "sender_is_subdomain", "lookalike_candidate", "unrelated"]
    reason: str
    heuristic_threshold: float
    comparison_source: Literal["request_expected_domain", "configured_trusted_domains"]


AuthenticationStatus = Literal[
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown"
]


class AuthenticationStatuses(BaseModel):
    spf: AuthenticationStatus
    dkim: AuthenticationStatus
    dmarc: AuthenticationStatus


class HeaderFinding(BaseModel):
    rule_id: str
    severity: Literal["info", "medium", "high"]
    score_contribution: int = Field(ge=0, le=100)
    explanation: str


class HeaderForensicsResponse(BaseModel):
    from_address: str | None
    from_domain: str | None
    reply_to_address: str | None
    reply_to_domain: str | None
    sender_address: str | None
    sender_domain: str | None
    return_path: str | None
    return_path_domain: str | None
    authentication: AuthenticationStatuses
    authentication_sources: dict[str, str]
    threat_score: int = Field(ge=0, le=100)
    risk_level: Literal["Low", "Medium", "High"]
    findings: list[HeaderFinding]
    recommendations: list[str]
    limitations: list[str]
    domain_similarity: DomainSimilarity | None
    domain_similarity_reason: str | None


class DetectionResponse(BaseModel):
    verdict: Literal["phishing", "benign"]
    score: float
    score_kind: Literal["linear_svm_decision_margin"]
    model: str
    domain_similarity: DomainSimilarity | None
    domain_similarity_reason: str | None
    claimed_domain: str | None
    signals: list[dict]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    model_loaded: bool
    model: str | None
    model_error: Literal["artifact_missing", "artifact_invalid", "model_load_failed"] | None


def _read_trusted_domains() -> list[str]:
    raw = os.getenv("EMAIL_DETECTION_TRUSTED_DOMAINS", "")
    domains = []
    for value in raw.split(","):
        if value.strip():
            domains.append(normalize_domain(value))
    return sorted(set(domains))


def create_app(
    model_pipeline=None,
    metadata: dict | None = None,
    model_path: Path = DEFAULT_MODEL_PATH,
    metadata_path: Path = DEFAULT_METADATA_PATH,
    trusted_domains: list[str] | None = None,
) -> FastAPI:
    configured_trusted = [normalize_domain(domain) for domain in trusted_domains] if trusted_domains is not None else _read_trusted_domains()
    state = {"pipeline": model_pipeline, "metadata": metadata or {}, "load_error": None}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if state["pipeline"] is None:
            try:
                pipeline = joblib.load(model_path)
                loaded_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if not hasattr(pipeline, "decision_function"):
                    raise ValueError("The configured model does not provide decision_function.")
                if "threshold" not in loaded_metadata or "model" not in loaded_metadata:
                    raise ValueError("Model metadata must include model and validation threshold.")
                if loaded_metadata["model"] != "linear_svm" or not isinstance(
                    pipeline.named_steps["classifier"], LinearSVC
                ):
                    raise ValueError("This API response schema requires the saved Linear SVM baseline.")
                threshold = float(loaded_metadata["threshold"])
                if not math.isfinite(threshold):
                    raise ValueError("Model metadata threshold must be a finite number.")
                state["pipeline"] = pipeline
                state["metadata"] = loaded_metadata
            except FileNotFoundError:
                state["load_error"] = "artifact_missing"
            except (ValueError, json.JSONDecodeError, TypeError, KeyError):
                state["load_error"] = "artifact_invalid"
            except Exception:
                state["load_error"] = "model_load_failed"
        yield

    app = FastAPI(title="ImpersonaGuard Email Detection", version="0.1.0", lifespan=lifespan)

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        loaded = state["pipeline"] is not None
        return HealthResponse(status="ok" if loaded else "degraded", model_loaded=loaded,
                              model=state["metadata"].get("model") if loaded else None,
                              model_error=state["load_error"])

    @app.post("/detect", response_model=DetectionResponse)
    def detect(request: DetectRequest) -> DetectionResponse:
        pipeline = state["pipeline"]
        if pipeline is None:
            raise HTTPException(status_code=503, detail="Model artifact unavailable; inspect /health and restore the baseline artifact.")
        try:
            sender_domain = extract_sender_domain(request.sender_address) if request.sender_address else ""
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            score = float(pipeline.decision_function([request.email_text])[0])
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Model inference failed.") from exc
        threshold = float(state["metadata"]["threshold"])
        verdict = "phishing" if score >= threshold else "benign"
        domain_result, domain_reason = best_trusted_match(sender_domain, request.expected_domain, configured_trusted)
        signals = [{"name": "text_classifier", "verdict": verdict, "score_kind": "linear_svm_decision_margin"}]
        if domain_result is not None and domain_result["relation"] == "lookalike_candidate":
            signals.append({"name": "lookalike_domain_similarity", "value": domain_result["similarity"],
                            "note": "Heuristic signal; it does not change the text model verdict."})
        elif domain_reason:
            signals.append({"name": "domain_comparison_unavailable", "reason": domain_reason})
        return DetectionResponse(
            verdict=verdict, score=score, score_kind="linear_svm_decision_margin",
            model=str(state["metadata"].get("model", "linear_svm")),
            domain_similarity=domain_result, domain_similarity_reason=domain_reason,
            claimed_domain=request.claimed_domain, signals=signals,
        )

    @app.post("/analyze-headers", response_model=HeaderForensicsResponse)
    def analyze_headers(request: HeaderForensicsRequest) -> HeaderForensicsResponse:
        try:
            return HeaderForensicsResponse.model_validate(
                analyze_email_header(
                    request.raw_header,
                    expected_domain=request.expected_domain,
                    trusted_domains=configured_trusted,
                )
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return app


app = create_app()
