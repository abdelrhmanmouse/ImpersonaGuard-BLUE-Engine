# Email Header Forensics — Requirements and Audit

Evidence labels: **CONFIRMED FROM SOURCE**, **INFERRED — NEEDS REVIEW**, **NEEDS CONFIRMATION**, **NOT FOUND**.

## A. Model Overview
Deterministic parser and heuristic scorer, not trained AI. Implemented in `src/email_detection/header_forensics.py`, exposed at `POST /analyze-headers`. Parses supplied RFC-style headers; does not DNS query or cryptographically verify DKIM.

## B. Data and Labels
No training data, labels, split or model artifact. `Email Header Forensics/examples.json` and tests use synthetic examples. Authentication values are reported claims in supplied headers.

## C. Preprocessing and Features
Python email Parser, headersonly; parse From, Reply-To, Sender, Return-Path; normalize domains; parse SPF/DKIM/DMARC from Authentication-Results and Received-SPF. Conflicting values become unknown; missing values are unknown. Default weights: SPF fail20, DKIM fail20, DMARC fail25, Reply-To mismatch15, Sender/From mismatch10, lookalike10; authentication cap45; score cap100; bands Low0–29, Medium30–59, High60–100. Heuristic is not probability.

## D. Model Configuration
No trained model. `ScoreConfig` supports configurable weights, auth cap and risk bands. Standard library parser plus project domain helper; FastAPI/Pydantic for HTTP. Dependencies declared in Email Detection project requirements.

## E. Evaluation Results
No predictive metrics. Unit/API tests verify behavior (including score 15 on synthetic Reply-To mismatch), not detection accuracy.

## F. Inference Contract
Implemented `POST /analyze-headers`: required strict nonblank `raw_header` string 1–100000 chars; optional nullable `expected_domain`; extra fields forbidden. Response includes parsed addresses/domains, authentication statuses/sources, threat score, risk level, findings, recommendations, limitations, optional domain similarity/reason. Malformed header block is conservatively reported and returns 200; invalid request/domain 422. Works even if text model unavailable.

## G. Software Integration Requirements
Expected/trusted domains must come from trusted caller context. Supplied auth claims are not independently verified and may be forged. Avoid raw-header logging/retention. No auth implementation found.

## H. Acceptance Tests
Existing `tests/test_header_forensics_api.py` covers valid parse, expected-domain error, required/blank/type validation, malformed header handling and schema. Add conflicting auth, oversized input, score boundaries, privacy and trust-context tests.
