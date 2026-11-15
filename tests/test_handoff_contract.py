"""Check the handoff contract against the actual FastAPI application schema."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EMAIL_ROOT = ROOT / "services" / "email"
HANDOFF_ROOT = ROOT
sys.path.insert(0, str(EMAIL_ROOT / "src"))
sys.path.insert(0, str(HANDOFF_ROOT))

from email_detection.api import app  # noqa: E402
from domain_api import DOMAIN_ROUTE_METHODS  # noqa: E402


class HandoffContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(
            (ROOT / "docs/API_Integration_Contract.yaml").read_text(encoding="utf-8")
        )
        cls.runtime = app.openapi()

    def test_implemented_paths_and_methods_match(self):
        expected = {
            "/health": {"get"}, "/detect": {"post"}, "/analyze-headers": {"post"},
            **DOMAIN_ROUTE_METHODS,
        }
        for path, methods in expected.items():
            self.assertEqual(set(self.contract["paths"][path]), methods)
        for path in ("/health", "/detect", "/analyze-headers"):
            self.assertEqual(set(self.runtime["paths"][path]), expected[path])
        for path, methods in DOMAIN_ROUTE_METHODS.items():
            if path in self.runtime["paths"]:
                self.fail(f"Domain endpoint {path} should remain in the separate standard-library service")

    def test_implemented_component_schemas_match_runtime(self):
        names = (
            "HealthResponse", "DetectRequest", "DetectionResponse", "HeaderForensicsRequest",
            "HeaderForensicsResponse", "HTTPValidationError", "ValidationError",
            "DomainSimilarity", "AuthenticationStatuses", "HeaderFinding",
        )
        contract_schemas = self.contract["components"]["schemas"]
        runtime_schemas = self.runtime["components"]["schemas"]
        for name in names:
            with self.subTest(schema=name):
                self.assertEqual(contract_schemas[name], runtime_schemas[name])

    def test_unimplemented_paths_are_labeled_proposed(self):
        actual_paths = set(self.runtime["paths"]) | set(DOMAIN_ROUTE_METHODS)
        for path, operations in self.contract["paths"].items():
            if path not in actual_paths:
                for operation in operations.values():
                    self.assertIn("PROPOSED / NOT IMPLEMENTED", operation["summary"])


if __name__ == "__main__":
    unittest.main()
