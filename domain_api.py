"""Small local HTTP adapter for the existing DGA and TypoDS inference helpers.

Uses only the Python standard library for transport. Model preprocessing,
thresholds, and response dictionaries remain in the existing inference code.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ARTIFACTS_DIR = Path(os.environ.get("BLUE_ENGINE_ARTIFACTS_DIR", PROJECT_ROOT / "artifacts")).expanduser()
DGA_MODEL_PATH = ARTIFACTS_DIR / "dga_domain_inference" / "dga_domain_model.joblib"
TYPO_MODEL_PATH = ARTIFACTS_DIR / "typosquatting_experiment" / "typods_dataset_ts" / "final_model.joblib"
LEGACY_URL_MODEL_PATH = ARTIFACTS_DIR / "url_phishing_inference" / "url_phishing_model.joblib"
V2_URL_MODEL_PATH = Path(os.environ.get(
    "BLUE_ENGINE_URL_V2_MODEL_PATH",
    PROJECT_ROOT / "url_phishing_v2" / "artifacts" / "url_phishing_v2.joblib",
)).expanduser()
MAX_REQUEST_BYTES = 256_000
DOMAIN_ROUTE_METHODS = {
    "/api/v1/domain-health": {"get"},
    "/api/v1/dga/predict": {"post"},
    "/api/v1/typosquatting/predict": {"post"},
    "/api/v1/url-phishing-v2/predict": {"post"},
    "/api/v1/url-phishing/predict": {"post"},
    "/api/v1/analyze": {"post"},
}


def _predict_dga(domain: str) -> dict:
    from dga_domain_model import predict_dga_domain

    return predict_dga_domain(domain, model_path=DGA_MODEL_PATH)


def _predict_typosquatting(domain: str) -> dict:
    from typosquatting_domain_model import predict_typosquatting_domain

    return predict_typosquatting_domain(domain, model_path=str(TYPO_MODEL_PATH))


def _predict_url_v2(url: str) -> dict:
    from url_phishing_v2.inference import predict_url

    return predict_url(url, artifact_path=V2_URL_MODEL_PATH)


def _predict_url_legacy(features: dict) -> dict:
    from url_phishing_inference import predict_url_features

    return predict_url_features(features, model_path=LEGACY_URL_MODEL_PATH)


def _call_email_service(path: str, payload: dict) -> dict:
    """Call the existing loopback email API; no request leaves this machine."""
    body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    request = Request(
        f"http://127.0.0.1:8000{path}", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        exc.close()
        if 400 <= exc.code < 500:
            raise ValueError(f"Email service rejected its input with HTTP {exc.code}") from exc
        raise RuntimeError(f"Email service returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Email service on 127.0.0.1:8000 is unavailable") from exc


def _aggregate(payload: dict) -> dict:
    evidence_keys = {"url", "url_features", "domain", "email_text", "raw_header"}
    allowed = evidence_keys | {"sender_address", "claimed_domain", "expected_domain"}
    results = {
        "email_text": {"status": "not_run", "reason": "evidence_not_supplied"},
        "email_header": {"status": "not_run", "reason": "evidence_not_supplied"},
        "dga": {"status": "not_run", "reason": "evidence_not_supplied"},
        "typosquatting": {"status": "not_run", "reason": "evidence_not_supplied"},
        "url_phishing_v2": {"status": "not_run", "reason": "evidence_not_supplied"},
        "url_phishing_legacy": {"status": "not_run", "reason": "evidence_not_supplied"},
    }
    warnings: list[str] = []
    unsupported = sorted(set(payload) - allowed)
    if unsupported:
        warnings.append("Unsupported input fields: " + ", ".join(unsupported))
    omitted = sorted(evidence_keys - set(payload))
    if omitted:
        warnings.append("Evidence not supplied: " + ", ".join(omitted))
    attempted: list[str] = []

    def run(name: str, callback: Callable[[], dict]) -> None:
        attempted.append(name)
        try:
            results[name] = {"status": "completed", "result": callback()}
        except FileNotFoundError:
            results[name] = {"status": "failed", "error": "Model artifact is unavailable"}
            warnings.append(f"{name} failed; other results are preserved")
        except ValueError as exc:
            results[name] = {"status": "invalid_input", "error": str(exc)}
            warnings.append(f"{name} rejected its input: {exc}")
        except Exception as exc:
            results[name] = {"status": "failed", "error": f"{type(exc).__name__}: inference unavailable"}
            warnings.append(f"{name} failed; other results are preserved")

    if "url" in payload:
        run("url_phishing_v2", lambda: _predict_url_v2(payload["url"]))
    if "url_features" in payload:
        run("url_phishing_legacy", lambda: _predict_url_legacy(payload["url_features"]))
    if "domain" in payload:
        run("dga", lambda: _predict_dga(payload["domain"]))
        run("typosquatting", lambda: _predict_typosquatting(payload["domain"]))
    if "email_text" in payload:
        email_fields = {key: payload[key] for key in ("email_text", "sender_address", "claimed_domain", "expected_domain") if key in payload}
        run("email_text", lambda: _call_email_service("/detect", email_fields))
    elif any(key in payload for key in ("sender_address", "claimed_domain")):
        warnings.append("sender_address and claimed_domain require email_text and were not used")
    if "raw_header" in payload:
        header_fields = {key: payload[key] for key in ("raw_header", "expected_domain") if key in payload}
        run("email_header", lambda: _call_email_service("/analyze-headers", header_fields))
    elif "expected_domain" in payload and "email_text" not in payload:
        warnings.append("expected_domain requires email_text or raw_header and was not used")

    completed = [item for item in results.values() if item["status"] == "completed"]
    failed = [item for item in results.values() if item["status"] in {"failed", "invalid_input"}]
    if not completed:
        analysis_status = "not_assessed" if not attempted else "unavailable"
    elif failed:
        analysis_status = "partial"
    else:
        analysis_status = "complete"

    labels = []
    findings = []
    high_risk = False
    medium_risk = False
    uncalibrated = False
    for component, item in results.items():
        if item["status"] != "completed":
            continue
        result = item["result"]
        if component == "url_phishing_v2":
            warnings.append("URL Phishing V2 showed substantial false positives in its documented external evaluation and is not production-ready.")
        label = str(result.get("class", result.get("label", result.get("verdict", ""))))
        if label:
            labels.append({"model": component, "label": label})
            findings.append({"model": component, "label": label})
        normalized = label.strip().lower()
        high_risk |= normalized in {"phishing", "dga", "typo", "typosquatting"}
        if result.get("risk_level") == "High":
            high_risk = True
        if result.get("risk_level") == "Medium":
            medium_risk = True
        similarity = result.get("domain_similarity")
        if isinstance(similarity, dict) and similarity.get("relation") == "lookalike_candidate":
            medium_risk = True
        if result.get("score_kind") == "linear_svm_decision_margin":
            uncalibrated = True
        if isinstance(result.get("findings"), list):
            for finding in result["findings"]:
                findings.append({"model": component, "evidence": finding})
    if high_risk:
        risk = "high"
    elif medium_risk:
        risk = "medium"
    else:
        risk = "unresolved"
    warnings.append("Model scores have different meanings and are not averaged or compared.")
    warnings.append("This aggregator does not assess score calibration; treat each score as model-specific output.")
    if uncalibrated:
        warnings.append("Email text score is an uncalibrated LinearSVC decision margin, not a probability.")
    warnings.append("A negative result from one detector does not establish that the input is safe.")
    return {
        "analysis_status": analysis_status,
        "risk_category": risk,
        "risk_rule": "high if any completed model reports a phishing/DGA/typo label or header High; otherwise medium for header Medium or a lookalike-domain signal; otherwise unresolved",
        "per_model": results,
        "findings": findings,
        "labels": labels,
        "warnings": warnings,
    }


class DomainInferenceHandler(BaseHTTPRequestHandler):
    """Serve the two existing domain-string predictors as JSON endpoints."""

    server_version = "BLUEEngineDomainAPI/1.0"
    predictors: dict[str, Callable[[str], dict]] = {
        "/api/v1/dga/predict": _predict_dga,
        "/api/v1/typosquatting/predict": _predict_typosquatting,
    }

    def log_message(self, format: str, *args: object) -> None:
        # Avoid logging request bodies or hostnames; only report the route/status.
        super().log_message(format, *args)

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path != "/api/v1/domain-health":
            self._send_json(404, {"detail": "Not found"})
            return
        components = {"dga": DGA_MODEL_PATH.is_file(), "typosquatting": TYPO_MODEL_PATH.is_file()}
        self._send_json(200, {"status": "ok" if all(components.values()) else "degraded", "components": components})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path not in self.predictors and path not in {
            "/api/v1/url-phishing-v2/predict",
            "/api/v1/url-phishing/predict",
            "/api/v1/analyze",
        }:
            self._send_json(404, {"detail": "Not found"})
            return

        if self.headers.get_content_type() != "application/json":
            self._send_json(415, {"detail": "Content-Type must be application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(400, {"detail": "A valid Content-Length is required"})
            return
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send_json(413, {"detail": "Request body is too large"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"detail": "Request body must be valid UTF-8 JSON"})
            return
        if not isinstance(payload, dict):
            self._send_json(422, {"detail": "Request body must be a JSON object"})
            return
        if path == "/api/v1/analyze":
            try:
                self._send_json(200, _aggregate(payload))
            except (TypeError, ValueError) as exc:
                self._send_json(422, {"detail": str(exc)})
            return

        if path == "/api/v1/url-phishing-v2/predict":
            key = "url"
            predictor = _predict_url_v2
        elif path == "/api/v1/url-phishing/predict":
            key = "features"
            predictor = _predict_url_legacy
        else:
            key = "domain"
            predictor = self.predictors[path]
        if set(payload) != {key}:
            self._send_json(422, {"detail": f"Request must contain only '{key}'"})
            return
        valid_type = isinstance(payload[key], dict) if key == "features" else isinstance(payload[key], str)
        if not valid_type:
            self._send_json(422, {"detail": f"{key} must be a {'JSON object' if key == 'features' else 'string'}"})
            return
        try:
            result = predictor(payload[key])
        except (ValueError, TypeError) as exc:
            self._send_json(422, {"detail": str(exc)})
            return
        except FileNotFoundError:
            self._send_json(503, {"detail": "Model artifact is unavailable"})
            return
        except Exception:
            self._send_json(503, {"detail": "Model inference is unavailable"})
            return
        self._send_json(200, result)


def make_server(host: str = "127.0.0.1", port: int = 8001) -> ThreadingHTTPServer:
    """Build a local-only server by default."""
    return ThreadingHTTPServer((host, port), DomainInferenceHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    server = make_server(args.host, args.port)
    print(f"BLUE Engine domain inference listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
