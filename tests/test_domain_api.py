"""Local HTTP smoke tests for the existing DGA and TypoDS inference functions."""

from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from domain_api import make_server  # noqa: E402


class DomainApiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(
            (ROOT / "docs/API_Integration_Contract.yaml").read_text(encoding="utf-8")
        )
        cls.schemas = cls.contract["components"]["schemas"]
        cls.server = make_server(port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, method: str, path: str, payload: dict | None = None, content_type: str = "application/json"):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": content_type} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        result = json.loads(data) if data else None
        connection.close()
        return response.status, result

    def test_health_reports_existing_artifacts(self):
        status, result = self.request("GET", "/api/v1/domain-health")
        self.assertEqual(status, 200)
        self.assertEqual(set(result), set(self.schemas["DomainHealthResponse"]["required"]))
        self.assertEqual(set(result["components"]), set(self.schemas["DomainHealthResponse"]["properties"]["components"]["required"]))
        self.assertEqual(result, {"status": "ok", "components": {"dga": True, "typosquatting": True}})

    def test_dga_endpoint_runs_existing_artifact(self):
        example = json.loads((ROOT / "examples/dga_request.json").read_text())
        self.assertEqual(set(example), set(self.schemas["DomainPredictRequest"]["required"]))
        status, result = self.request("POST", "/api/v1/dga/predict", example)
        self.assertEqual(status, 200)
        self.assertEqual(set(result), set(self.schemas["DgaPrediction"]["required"]))
        self.assertEqual(result["input"], example["domain"])
        self.assertEqual(result["score_kind"], "dga_class_probability")
        self.assertIn(result["label"], {"legit", "dga"})
        self.assertIn(result["prediction"], {0, 1})
        self.assertGreaterEqual(result["score"], 0.0)
        self.assertLessEqual(result["score"], 1.0)

    def test_typosquatting_endpoint_runs_existing_artifact(self):
        example = json.loads((ROOT / "examples/typosquatting_request.json").read_text())
        self.assertEqual(set(example), set(self.schemas["DomainPredictRequest"]["required"]))
        status, result = self.request("POST", "/api/v1/typosquatting/predict", example)
        self.assertEqual(status, 200)
        self.assertEqual(set(result), set(self.schemas["TyposquattingPrediction"]["required"]))
        self.assertEqual(result["input"], example["domain"])
        self.assertIn(result["label"], {"Typo", "NotTypo"})
        self.assertIn(result["prediction"], {0, 1})
        self.assertGreaterEqual(result["score"], 0.0)
        self.assertLessEqual(result["score"], 1.0)
        self.assertIn("threshold", result)

    def test_v2_raw_url_endpoint_and_invalid_input(self):
        status, result = self.request("POST", "/api/v1/url-phishing-v2/predict", {"url": "https://example.com/login"})
        self.assertEqual(status, 200)
        self.assertIn(result["class"], {"phishing", "legitimate"})
        self.assertEqual(result["schema_version"], "1.0.0")
        status, error = self.request("POST", "/api/v1/url-phishing-v2/predict", {"url": "ftp://example.com"})
        self.assertEqual(status, 422)
        self.assertIn("detail", error)

    def test_legacy_endpoint_requires_complete_feature_map(self):
        from url_phishing_inference import load_url_phishing_artifact

        names = load_url_phishing_artifact()["metadata"]["feature_names"]
        features = {name: 0 for name in names}
        status, result = self.request("POST", "/api/v1/url-phishing/predict", {"features": features})
        self.assertEqual(status, 200)
        self.assertEqual(result["input_kind"], "engineered_numeric_features")
        self.assertEqual(result["label"], "Legitimate" if result["prediction"] == 0 else "Phishing")
        status, error = self.request("POST", "/api/v1/url-phishing/predict", {"features": {}})
        self.assertEqual(status, 422)
        self.assertIn("detail", error)

    def test_aggregator_runs_only_applicable_models_and_preserves_partial_results(self):
        status, result = self.request("POST", "/api/v1/analyze", {"url": "https://example.com/login", "domain": "bad..domain"})
        self.assertEqual(status, 200)
        self.assertEqual(result["analysis_status"], "partial")
        self.assertEqual(result["per_model"]["url_phishing_v2"]["status"], "completed")
        self.assertEqual(result["per_model"]["dga"]["status"], "invalid_input")
        self.assertEqual(result["per_model"]["typosquatting"]["status"], "invalid_input")
        self.assertEqual(result["per_model"]["email_text"]["status"], "not_run")
        expected_risk = "high" if result["per_model"]["url_phishing_v2"]["result"]["class"] == "phishing" else "unresolved"
        self.assertEqual(result["risk_category"], expected_risk)
        self.assertTrue(any("not establish" in warning for warning in result["warnings"]))

    def test_aggregator_reports_unavailable_email_service_and_missing_evidence(self):
        with patch("domain_api._call_email_service", side_effect=RuntimeError("Email service on 127.0.0.1:8000 is unavailable")):
            status, result = self.request("POST", "/api/v1/analyze", {"email_text": "safe example"})
        self.assertEqual(status, 200)
        self.assertEqual(result["analysis_status"], "unavailable")
        self.assertEqual(result["per_model"]["email_text"]["status"], "failed")
        self.assertTrue(any("Evidence not supplied" in warning for warning in result["warnings"]))

    def test_invalid_input_and_unknown_route_are_rejected(self):
        status, result = self.request("POST", "/api/v1/dga/predict", {"domain": "bad..domain"})
        self.assertEqual(status, 422)
        self.assertIn("detail", result)
        status, result = self.request("POST", "/api/v1/typosquatting/predict", {"domain": 7})
        self.assertEqual(status, 422)
        status, _ = self.request("POST", "/not-a-route", {"domain": "example.test"})
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
