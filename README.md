# BLUE Engine AI — Local API Handoff

This folder is a standalone source handoff for the working local APIs. It contains the actual service and inference source, tests, request examples, and an integration contract. **It does not contain fitted model artifacts or training datasets.** A clean-machine install has not been verified. Runtime inference requires the authorized artifact files listed in [Artifact delivery](docs/ARTIFACT_DELIVERY.md).

## Services and entry points

| Service | Source / entry point | Routes | Port |
|---|---|---|---:|
| Email Detection and Header Forensics | `services/email/src/email_detection/api.py` (FastAPI app `email_detection.api:app`) | `GET /health`, `POST /detect`, `POST /analyze-headers`; FastAPI `/docs` and `/openapi.json` | 8000 |
| Domain, URL and aggregate API | `domain_api.py` (standard-library HTTP server) | `GET /api/v1/domain-health`; `POST /api/v1/dga/predict`; `POST /api/v1/typosquatting/predict`; `POST /api/v1/url-phishing-v2/predict`; `POST /api/v1/url-phishing/predict`; `POST /api/v1/analyze` | 8001 |

Model wrappers are included as `dga_domain_model.py`, `typosquatting_domain_model.py`, `url_phishing_inference.py`, and `url_phishing_v2/inference.py`. The API invokes these existing functions. The copied Email service modules are under `services/email/src/email_detection/`. No Login Anomaly Detection implementation is included.

The Email service should be started before the Domain service when using `/api/v1/analyze` with email text or headers. The aggregator calls only `http://127.0.0.1:8000` for those evidence types; it does not make calls to external hosts. The services bind to loopback by default.

## Environment setup (PowerShell)

Use Python 3.12 for Email and Python 3.11 for the Domain API. Separate environments are intentional: the recorded dependency constraints differ. The following are setup instructions; they have **not** been verified as a clean-machine install.

From this directory:

```powershell
py -3.12 -m venv .venv-email
\.venv-email\Scripts\python.exe -m pip install -r requirements-email.txt
py -3.11 -m venv .venv-domain
\.venv-domain\Scripts\python.exe -m pip install -r requirements-domain-inference.txt
```

`requirements-email.txt` supports Python 3.10–3.12. `requirements-domain-inference.txt` records the exact versions used by the available Python 3.11 runtime, not a proven cross-platform lockfile. `requirements.txt` is a convenience include for the Domain runtime only. No packages need to be installed globally. Do not rely on the original developer's virtual-environment launcher.

## Obtain runtime artifacts

Before starting the services, obtain the model files from the project owner through an authorized internal channel and place them at the package-relative paths in [docs/ARTIFACT_DELIVERY.md](docs/ARTIFACT_DELIVERY.md). The files are excluded from Git by `.gitignore`; this repository does not establish redistribution rights. Email additionally needs its matching metadata JSON. The Domain service health response reports DGA and Typosquatting artifact availability; `/health` reports Email model loading. URL endpoints return service unavailable if their artifact is missing.

Default artifact paths are package-relative. Optional environment variables can override them: `BLUE_ENGINE_ARTIFACTS_DIR`, `BLUE_ENGINE_EMAIL_MODEL_PATH`, `BLUE_ENGINE_EMAIL_METADATA_PATH`, and `BLUE_ENGINE_URL_V2_MODEL_PATH`. `.env.example` documents the variables, but the applications do not automatically load `.env` files.

## Start both APIs

Open two PowerShell windows in this directory. Start Email first:

```powershell
\.venv-email\Scripts\python.exe -m uvicorn email_detection.api:app --app-dir services/email/src --host 127.0.0.1 --port 8000
```

Then start Domain:

```powershell
\.venv-domain\Scripts\python.exe domain_api.py --host 127.0.0.1 --port 8001
```

Email's interactive API docs are at `http://127.0.0.1:8000/docs`. The Domain API uses the Python standard library and has no FastAPI `/docs`; its request/response contract is in [docs/API_Integration_Contract.yaml](docs/API_Integration_Contract.yaml).

## Requests

From a third PowerShell window at this directory, use the included request examples:

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe -X POST http://127.0.0.1:8000/detect -H "Content-Type: application/json" --data-binary "@examples/email_spam_request.json"
curl.exe -X POST http://127.0.0.1:8000/analyze-headers -H "Content-Type: application/json" --data-binary "@examples/email_header_request.json"
curl.exe http://127.0.0.1:8001/api/v1/domain-health
curl.exe -X POST http://127.0.0.1:8001/api/v1/dga/predict -H "Content-Type: application/json" --data-binary "@examples/dga_request.json"
curl.exe -X POST http://127.0.0.1:8001/api/v1/typosquatting/predict -H "Content-Type: application/json" --data-binary "@examples/typosquatting_request.json"
curl.exe -X POST http://127.0.0.1:8001/api/v1/url-phishing-v2/predict -H "Content-Type: application/json" --data-binary "@examples/url_phishing_v2_request.json"
curl.exe -X POST http://127.0.0.1:8001/api/v1/analyze -H "Content-Type: application/json" --data-binary "@examples/analyze_request.json"
```

The Email response includes a `verdict` and model-specific score; the LinearSVC `decision_margin` is not a probability. Header Forensics returns structured findings and authentication status based on the supplied header text; it does not independently verify SPF, DKIM, or DMARC. DGA and Typosquatting responses include their labels, scores, and model-specific fields. V2 returns `label`, `class`, `phishing_score`, and `schema_version`.

### URL contracts

- **V2**: `POST /api/v1/url-phishing-v2/predict` accepts `{"url":"https://example.com/login"}` and extracts its own 34 lexical features. It is a separate experimental model with a documented external false-positive problem; it is not production-ready.
- **Legacy**: `POST /api/v1/url-phishing/predict` accepts `{"features": { ... }}` containing exactly the 111 feature names in the saved artifact metadata, with numeric or null values according to the inference wrapper. It does **not** accept a raw URL. No verified raw-URL extractor is available. `examples/url_phishing_request.json` is intentionally an invalid empty-map illustration, not a successful request. A complete request requires the authorized artifact so the caller can read `metadata.feature_names`; never invent values to represent a real URL.

To exercise the legacy endpoint's **schema only** after placing the artifact, construct a zero-filled map from its actual metadata and send it directly (this is not a real URL feature row and its prediction has no security meaning):

```powershell
$legacyBody = & .\.venv-domain\Scripts\python.exe -c "import json; from url_phishing_inference import load_url_phishing_artifact; print(json.dumps({'features': {name: 0 for name in load_url_phishing_artifact()['metadata']['feature_names']}}))"
curl.exe -X POST http://127.0.0.1:8001/api/v1/url-phishing/predict -H "Content-Type: application/json" --data-raw $legacyBody
```

### Aggregator

`POST /api/v1/analyze` accepts any supported subset of `url`, `url_features`, `domain`, `email_text`, and `raw_header`. Optional email fields are `sender_address`, `claimed_domain`, and `expected_domain`. Only applicable inference functions/services run. The response contains `analysis_status`, `risk_category`, `per_model` statuses/results, `findings`, and `warnings`. A failed component does not discard other results. Scores are not averaged or compared because they have different meanings; warnings identify uncalibrated output and missing evidence. A negative output never means “safe”; the fallback category is `unresolved`.

Example request:

```json
{"url":"https://example.com/login","domain":"example.test","email_text":"Urgent: verify your account password now"}
```

Example response shape (values abbreviated; labels/scores depend on the supplied input and current artifact):

```json
{"analysis_status":"complete","risk_category":"unresolved","per_model":{"email_text":{"status":"completed","result":{"verdict":"...","score":"model-specific"}},"dga":{"status":"completed","result":{"label":"...","score":"model-specific"}},"typosquatting":{"status":"completed","result":{"label":"...","score":"model-specific"}},"url_phishing_v2":{"status":"completed","result":{"label":0,"class":"...","phishing_score":0.0,"schema_version":"1.0.0"}},"email_header":{"status":"not_run","reason":"evidence_not_supplied"},"url_phishing_legacy":{"status":"not_run","reason":"evidence_not_supplied"}},"findings":[],"warnings":["Model scores have different meanings and are not averaged or compared."]}
```

The deterministic category rule is: `high` if any completed classifier emits a phishing/DGA/typo label or Header Forensics reports High; otherwise `medium` for Header Medium or a lookalike-domain signal; otherwise `unresolved`. These categories are triage rules, not calibrated risk probabilities.

## Tests and local smoke check

With the two environments above, run:

```powershell
\.venv-email\Scripts\python.exe -B -m pytest -p no:cacheprovider services/email/tests
\.venv-email\Scripts\python.exe -B -m unittest discover -s tests -p test_handoff_contract.py -v
\.venv-domain\Scripts\python.exe -m unittest discover -s tests -p test_domain_api.py -v
\.venv-domain\Scripts\python.exe -m unittest discover -s tests -p test_inference_components.py -v
\.venv-domain\Scripts\python.exe scripts/smoke_test.py
```

The HTTP smoke script requires both services running and all five required model artifacts present. It uses only loopback endpoints, verifies success and invalid URL behavior, and exercises the 111-field API with a zero-filled **schema fixture only**. It does not validate model accuracy. If artifacts are unavailable, run static contract checks and Email's header-only tests, but do not report model routes as verified.

Verified in the package copy on 2026-10-26 using the existing Python 3.12.14 Email environment and Python 3.11.1 Domain environment; no dependency installation was performed: Email/header `26 passed` (one Starlette deprecation warning), contract consistency `3 passed`, Domain HTTP tests `8 passed`, and inference component tests `6 passed`. Both API processes were then started locally and `scripts/smoke_test.py` passed all 11 checks: Email health/docs/detect/header, Domain health/DGA/Typosquatting/V2 success and invalid URL/legacy schema fixture/aggregator. These results use artifacts from the parent workspace via temporary environment-variable overrides; the artifacts are not present in the package. The smoke run demonstrates tested runtime behavior only, not model accuracy, clean-machine installation, or deployment readiness. Exact verification commands and representative outputs are in [docs/LOCAL_VALIDATION.md](docs/LOCAL_VALIDATION.md). Older audit files in `audit/` are historical evidence and may predate this standalone source copy; this README and the current source/test suite describe the included implementation.

## Known limitations

- URL Phishing V2 is experimental due to substantial external false positives; do not use it as a production verdict.
- Legacy URL Phishing requires the complete ordered 111-feature map and has no verified raw URL feature extraction.
- DGA classifies domain strings; it does not inspect DNS behavior.
- Header Forensics analyzes supplied header claims and heuristics; it does not contact mail infrastructure.
- Login Anomaly Detection remains pending and is excluded.
- Artifacts and data are excluded from this repository. Clean installation on another machine, artifact redistribution rights, and production readiness have not been verified.
