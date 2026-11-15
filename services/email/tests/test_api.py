import numpy as np
from fastapi.testclient import TestClient
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from email_detection.api import create_app


def make_pipeline():
    texts = [
        "team meeting notes and lunch schedule",
        "project agenda for tomorrow meeting",
        "urgent verify account password now click link",
        "claim prize update bank account immediately",
    ]
    labels = np.array([0, 0, 1, 1])
    pipeline = Pipeline([("tfidf", TfidfVectorizer()), ("classifier", LinearSVC(random_state=42))])
    pipeline.fit(texts, labels)
    return pipeline


def client():
    return TestClient(create_app(
        model_pipeline=make_pipeline(),
        metadata={"model": "linear_svm", "threshold": 0.0},
        trusted_domains=["paypal.com"],
    ))


def test_health_and_suspicious_email_response():
    with client() as api:
        assert api.get("/health").json() == {
            "status": "ok", "model_loaded": True, "model": "linear_svm", "model_error": None
        }
        response = api.post("/detect", json={
            "email_text": "urgent verify account password now click link",
            "sender_address": "service@paypa1.com",
            "claimed_domain": "paypal.com",
        })
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "phishing"
    assert body["score_kind"] == "linear_svm_decision_margin"
    assert body["domain_similarity"]["relation"] == "lookalike_candidate"
    assert any(signal["name"] == "lookalike_domain_similarity" for signal in body["signals"])


def test_benign_text_and_domain_comparison_unavailable_explanation():
    with client() as api:
        response = api.post("/detect", json={"email_text": "team meeting notes and lunch schedule"})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "benign"
    assert body["domain_similarity"] is None
    assert body["domain_similarity_reason"] == "sender_address_not_provided"


def test_invalid_inputs_are_rejected():
    with client() as api:
        assert api.post("/detect", json={"email_text": "   "}).status_code == 422
        assert api.post("/detect", json={"email_text": "hello", "sender_address": "bad"}).status_code == 422
        assert api.post("/detect", json={"email_text": "hello", "expected_domain": "localhost"}).status_code == 422


def test_missing_model_returns_degraded_health_and_503(tmp_path):
    with TestClient(create_app(model_path=tmp_path / "missing.joblib", metadata_path=tmp_path / "missing.json")) as api:
        health = api.get("/health").json()
        assert health["status"] == "degraded"
        assert health["model_error"] == "artifact_missing"
        assert api.post("/detect", json={"email_text": "hello"}).status_code == 503


def test_invalid_model_artifact_is_reported_without_partial_load(tmp_path):
    artifact = tmp_path / "invalid.joblib"
    artifact.write_text("not a joblib artifact", encoding="utf-8")
    with TestClient(create_app(model_path=artifact, metadata_path=tmp_path / "missing.json")) as api:
        health = api.get("/health").json()
        assert health["status"] == "degraded"
        assert health["model_loaded"] is False
        assert health["model_error"] == "artifact_invalid"
        assert api.post("/detect", json={"email_text": "hello"}).status_code == 503
