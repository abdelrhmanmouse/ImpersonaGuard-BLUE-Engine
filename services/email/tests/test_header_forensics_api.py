from pathlib import Path
import sys

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from email_detection.api import create_app  # noqa: E402


def test_header_forensics_route_is_additive_and_explainable():
    with TestClient(create_app(trusted_domains=["example.com"])) as client:
        response = client.post("/analyze-headers", json={
            "raw_header": (
                "From: Support <support@example.com>\r\n"
                "Reply-To: Reply <reply@untrusted.example>\r\n"
                "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\r\n"
            )
        })
    assert response.status_code == 200
    report = response.json()
    assert report["from_domain"] == "example.com"
    assert report["reply_to_domain"] == "untrusted.example"
    assert report["authentication"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert report["threat_score"] == 15
    assert any(f["rule_id"] == "REPLY_TO_DOMAIN_MISMATCH" for f in report["findings"])


def test_header_forensics_route_rejects_invalid_expected_domain():
    with TestClient(create_app()) as client:
        response = client.post("/analyze-headers", json={
            "raw_header": "From: a@example.com\r\n",
            "expected_domain": "localhost",
        })
    assert response.status_code == 422


def test_header_forensics_route_validates_required_and_malformed_requests():
    with TestClient(create_app()) as client:
        missing = client.post("/analyze-headers", json={})
        blank = client.post("/analyze-headers", json={"raw_header": "  \r\n"})
        wrong_type = client.post("/analyze-headers", json={"raw_header": 7})
        malformed_header = client.post("/analyze-headers", json={"raw_header": "not a header field\r\n"})

    assert missing.status_code == 422
    assert blank.status_code == 422
    assert wrong_type.status_code == 422
    assert malformed_header.status_code == 200
    assert "MALFORMED_HEADER_BLOCK" in {finding["rule_id"] for finding in malformed_header.json()["findings"]}


def test_existing_text_endpoint_schema_and_route_remain_registered():
    app = create_app()
    schema = app.openapi()
    paths = schema["paths"]
    assert "/detect" in paths
    assert "/analyze-headers" in paths
    response_schema = paths["/analyze-headers"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert response_schema["$ref"].endswith("/HeaderForensicsResponse")
    assert set(schema["components"]["schemas"]["AuthenticationStatuses"]["properties"]) == {"spf", "dkim", "dmarc"}

