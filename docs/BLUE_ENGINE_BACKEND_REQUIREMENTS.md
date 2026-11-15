# ImpersonaGuard Blue Engine — Backend Integration Notes

## What the Blue Engine currently provides

The Blue Engine exposes two local HTTP services:

- **Email service — port 8000:** FastAPI documentation is available at `/docs`.
  - `GET /health`
  - `POST /detect`
  - `POST /analyze-headers`
- **Domain and aggregation service — port 8001**
  - `GET /api/v1/domain-health`
  - `POST /api/v1/dga/predict`
  - `POST /api/v1/typosquatting/predict`
  - `POST /api/v1/url-phishing-v2/predict`
  - `POST /api/v1/url-phishing/predict`
  - `POST /api/v1/analyze`

The aggregator calls the Email service at `127.0.0.1:8000` when email text or headers are included. Start the Email service before using those aggregator features. The request and response contract is in [`API_Integration_Contract.yaml`](API_Integration_Contract.yaml).

## Scores and risk output

The current API does **not** provide a single calibrated 0–100 score across all models. Each model returns its own score with a `score_kind`; those scores must not be averaged or treated as comparable probabilities.

The aggregator returns a deterministic `risk_category` (`high`, `medium`, or `unresolved`), per-model results, findings, execution statuses, and warnings. This category is an advisory triage rule, not a calibrated risk score. A negative result from one detector does not mean the input is safe.

Header Forensics has a 0–100 `threat_score`, but it is a heuristic indicator. The Email text model returns an uncalibrated LinearSVC decision margin, not a probability.

## Inputs and outputs

- **Email detection:** `email_text`; optionally `sender_address`, `claimed_domain`, and `expected_domain`. Returns a `verdict`, model-specific `score` and `score_kind`, and available signals.
- **Header Forensics:** `raw_header`; optionally `expected_domain`. Returns parsed header fields, authentication statuses, risk level, heuristic score, findings, and limitations. It does not independently verify SPF, DKIM, or DMARC.
- **DGA and Typosquatting:** `domain`. Each returns its own label and model-specific score.
- **URL Phishing V2:** raw HTTP or HTTPS `url`. This model is experimental and has a known false-positive problem.
- **Legacy URL Phishing:** `features`, containing the complete 111-feature map expected by the saved artifact. It does **not** accept raw URLs; a verified raw-URL feature extractor is unavailable.
- **Aggregator:** accepts any supported subset of `email_text`, `raw_header`, `domain`, `url`, and `url_features`. It runs only applicable components and preserves other results if a component fails.

Exact schemas are in the API contract. Example bodies are in the [`examples`](../examples/) directory.

## Example aggregator request

```json
{
  "email_text": "Urgent: verify your account password now",
  "domain": "example.test",
  "url": "https://example.com/login"
}
```

A local smoke test with this request returned `analysis_status: "complete"` and `risk_category: "high"`. It returned separate results for Email, DGA, Typosquatting, and URL V2, with warnings explaining that scores have different meanings and that URL V2 is not production-ready. This is an observed smoke-test result, **not** an accuracy claim or a guaranteed expected verdict.

## Errors and missing data

- Invalid request fields or malformed input return HTTP 422 on the relevant endpoint.
- Missing model artifacts or unavailable inference can return HTTP 503.
- In the aggregator, missing evidence is marked `not_run`; invalid input and failed components are reported per model. Other successful results are retained, and the overall status can be `partial` or `unavailable`.
- No authentication mechanism was found in these APIs. The Backend should handle authorization and audit requirements.

## Items to agree on

The current endpoint schemas are documented and tested. The Backend and AI teams still need to agree on ownership, delivery dates, artifact access, and whether the Backend requires a unified 0–100 score. If it does, that needs a defined and validated scoring contract; the current models’ scores should not be combined arbitrarily. No temporary mock endpoint is included yet.

Required model artifacts are not included in the handoff repository; they must be obtained through an authorized delivery channel. Clean-machine installation has not been verified.
