"""Runtime checks for the independent domain and URL-feature inference paths."""

from __future__ import annotations

import csv
import os
import unittest
from pathlib import Path

from dga_domain_model import predict_dga_domain
from typosquatting_detector import TyposquattingDetector
from typosquatting_domain_model import TyposquattingDomainClassifier
from url_phishing_inference import load_url_phishing_artifact, predict_url_features


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = Path(os.environ.get("BLUE_ENGINE_ARTIFACTS_DIR", ROOT / "artifacts"))


class DomainSimilarityRuntimeTests(unittest.TestCase):
    def test_brand_similarity_valid_and_invalid_inputs(self):
        detector = TyposquattingDetector()
        exact = detector.detect("https://www.google.com/account")
        self.assertEqual(exact.normalized_hostname, "www.google.com")
        self.assertFalse(exact.possible_typosquatting)

        lookalike = detector.detect("paypa1.com")
        self.assertTrue(lookalike.possible_typosquatting)
        self.assertGreaterEqual(lookalike.similarity_score, 0.86)

        invalid = detector.detect("")
        self.assertEqual(invalid.detection_reason, "invalid_or_empty_input")
        self.assertEqual(invalid.normalized_hostname, "")


class TyposquattingModelRuntimeTests(unittest.TestCase):
    def test_saved_prediction_rows_and_new_inputs(self):
        classifier = TyposquattingDomainClassifier()
        rows_path = ARTIFACTS / "typosquatting_experiment/typods_dataset_ts/test_predictions.csv"
        with rows_path.open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        # Reproduce the same parity fixture selection as the original audit.
        saved_inputs = ["diplomaticourier.com", "hauserwirth.com", "target.com", "hoistory.com"]
        outputs = classifier.predict_many(saved_inputs)
        for domain, output in zip(saved_inputs, outputs):
            row = next(r for r in rows if r["original_input_domain"] == domain)
            self.assertEqual(output["label"], row["predicted_label"])
            self.assertAlmostEqual(output["score"], float(row["score_typo"]), delta=1e-12)
            self.assertEqual(output["prediction"], int(output["score"] >= output["threshold"]))

        for value in ("https://paypa1.example/login", "Google.com", "ordinary-harbor.example", "xn--80ak6aa92e.com"):
            output = classifier.predict_one(value)
            self.assertTrue({"normalized_domain", "prediction", "label", "score", "threshold"}.issubset(output))
            self.assertGreaterEqual(output["score"], 0.0)
            self.assertLessEqual(output["score"], 1.0)

    def test_invalid_inputs_raise_value_error(self):
        classifier = TyposquattingDomainClassifier()
        for value in ("", None, "bad..domain"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                classifier.predict_one(value)


class DgaRuntimeTests(unittest.TestCase):
    def test_new_inputs_and_invalid_handling(self):
        for value in ("quiet-cobalt-basin.example", "https://r4nd0m-string.test/path"):
            result = predict_dga_domain(value)
            self.assertEqual(result["score_kind"], "dga_class_probability")
            self.assertIn(result["label"], {"legit", "dga"})
            self.assertEqual(result["prediction"], int(result["score"] >= result["threshold"]))
            self.assertGreaterEqual(result["score"], 0.0)
            self.assertLessEqual(result["score"], 1.0)
        for value in ("", None, "...", "bad..domain"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                predict_dga_domain(value)


class UrlFeatureRuntimeTests(unittest.TestCase):
    def test_feature_row_inference_and_schema_errors(self):
        artifact = load_url_phishing_artifact()
        names = artifact["metadata"]["feature_names"]
        # Synthetic values exercise the input contract and fitted pipeline only.
        row = {name: 0 for name in names}
        row["length_url"] = 47
        row["domain_length"] = 16
        row["time_response"] = None
        output = predict_url_features(row)
        self.assertEqual(output["input_kind"], "engineered_numeric_features")
        self.assertIn(output["label"], {"Legitimate", "Phishing"})
        self.assertGreaterEqual(output["score"], 0.0)
        self.assertLessEqual(output["score"], 1.0)

        with self.assertRaisesRegex(ValueError, "missing"):
            predict_url_features({})
        invalid = dict(row)
        invalid[names[0]] = "not numeric"
        with self.assertRaisesRegex(ValueError, "must be a number or null"):
            predict_url_features(invalid)

    def test_raw_url_is_rejected_until_feature_generation_exists(self):
        # This negative check keeps the current contract explicit: the model
        # consumes engineered feature maps, not raw URL strings.
        with self.assertRaisesRegex(ValueError, "features must be a JSON object"):
            predict_url_features("https://example.test/path")


if __name__ == "__main__":
    unittest.main()
