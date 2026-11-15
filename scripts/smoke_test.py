"""Exercise the local BLUE Engine APIs using only loopback HTTP requests."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from url_phishing_inference import load_url_phishing_artifact  # noqa: E402

EMAIL = "http://127.0.0.1:8000"
DOMAIN = "http://127.0.0.1:8001"


def call(method: str, url: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Cannot reach {url}; start both services and place required artifacts first") from exc


def expect(status: int, expected: int, route: str, result: dict) -> None:
    if status != expected:
        raise AssertionError(f"{route}: expected HTTP {expected}, received {status}: {result}")
    print(f"PASS {route} HTTP {status}: {json.dumps(result, ensure_ascii=False, sort_keys=True)}")


def main() -> int:
    # FastAPI documentation and health/detection/header routes.
    status, result = call("GET", f"{EMAIL}/health")
    expect(status, 200, "GET /health", result)
    if result.get("model_loaded") is not True:
        raise AssertionError("Email model is not loaded; verify email artifact and metadata paths")
    with urlopen(f"{EMAIL}/docs", timeout=15) as response:
        if response.status != 200 or b"Swagger UI" not in response.read():
            raise AssertionError("GET /docs did not return FastAPI Swagger UI")
        print(f"PASS GET /docs HTTP {response.status}: FastAPI Swagger UI available")
    status, result = call("POST", f"{EMAIL}/detect", {"email_text": "Urgent: verify your account password now"})
    expect(status, 200, "POST /detect", result)
    status, result = call("POST", f"{EMAIL}/analyze-headers", {
        "raw_header": "From: security@example.test\r\nReply-To: other@example.test\r\nSubject: Account alert",
        "expected_domain": "example.test",
    })
    expect(status, 200, "POST /analyze-headers", result)

    # Domain API and each model-backed endpoint.
    status, result = call("GET", f"{DOMAIN}/api/v1/domain-health")
    expect(status, 200, "GET /api/v1/domain-health", result)
    if not all(result.get("components", {}).values()):
        raise AssertionError("DGA/Typosquatting artifacts are missing")
    for route, domain in (("/api/v1/dga/predict", "quiet-cobalt-basin.example"),
                          ("/api/v1/typosquatting/predict", "paypa1.com")):
        status, result = call("POST", DOMAIN + route, {"domain": domain})
        expect(status, 200, f"POST {route}", result)

    status, result = call("POST", f"{DOMAIN}/api/v1/url-phishing-v2/predict", {"url": "https://example.com/login"})
    expect(status, 200, "POST /api/v1/url-phishing-v2/predict", result)
    status, result = call("POST", f"{DOMAIN}/api/v1/url-phishing-v2/predict", {"url": "ftp://example.com"})
    expect(status, 422, "POST /api/v1/url-phishing-v2/predict (invalid URL)", result)

    artifact = load_url_phishing_artifact()
    features = {name: 0 for name in artifact["metadata"]["feature_names"]}
    status, result = call("POST", f"{DOMAIN}/api/v1/url-phishing/predict", {"features": features})
    expect(status, 200, "POST /api/v1/url-phishing/predict (111-field schema fixture)", result)
    if result.get("input_kind") != "engineered_numeric_features":
        raise AssertionError("Legacy endpoint did not report engineered feature-map input")

    status, result = call("POST", f"{DOMAIN}/api/v1/analyze", {
        "email_text": "Urgent: verify your account password now",
        "domain": "example.test",
        "url": "https://example.com/login",
    })
    expect(status, 200, "POST /api/v1/analyze", result)
    if result.get("analysis_status") not in {"complete", "partial"}:
        raise AssertionError("Aggregator did not return a completed or partial analysis")
    print("Smoke test completed. Model outputs are demonstrations, not accuracy evidence.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL smoke test: {exc}", file=sys.stderr)
        raise SystemExit(1)
