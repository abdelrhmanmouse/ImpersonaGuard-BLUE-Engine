# Inference Readiness Audit

Date: 2026-10-24
Project root: repository root (all source paths below are relative).
Scope: URL Phishing Detection, DGA Detection, Typosquatting Detection, Email Spam/Phishing Text, Email Header Forensics. Login Anomaly Detection is excluded.

## Execution boundaries

No training code, source modules, model artifacts, or datasets were changed. No models were retrained. All route requests used FastAPI `TestClient` in-process; no server was exposed and no external requests were made. Test execution used the existing `git/Email Detection/.venv/Lib/site-packages` through bundled Python 3.12.14, with `-B` and pytest cache disabled. This avoided bytecode and pytest-cache writes, but was not a newly created isolated environment. The checked-in `.venv\Scripts\python.exe` is a stale launcher and reports `No Python at '<missing Python executable from a prior user-specific runtime>'`.

## 1. Implemented FastAPI route tests

### In-process test method

Executed from `git/Email Detection`, with bundled Python and its existing site-packages on `PYTHONPATH`:

```python
import sys
sys.path.insert(0, 'src')
from fastapi.testclient import TestClient
from email_detection.api import create_app
with TestClient(create_app()) as client:
    h = client.get('/health')
    d = client.post('/detect', json={
        'email_text': 'Please review the attached project update.',
        'sender_address': 'updates@example.test',
        'claimed_domain': 'example.test',
        'expected_domain': 'example.test'})
    a = client.post('/analyze-headers', json={
        'raw_header': 'From: Support <support@example.test>\r\nAuthentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass\r\n',
        'expected_domain': 'example.test'})
    print(h.status_code, h.json())
    print(d.status_code, d.json())
    print(a.status_code, a.json())
```

### Actual results

- `GET /health`: **200**, `{"status":"ok","model_loaded":true,"model":"linear_svm","model_error":null}`. Since `create_app()` used default paths and startup lifecycle, this verifies the API loaded the saved email artifact and metadata in this runtime.
- `POST /detect`: **200**, actual response verdict `benign`, score `-1.2602952583451852`, score kind `linear_svm_decision_margin`, model `linear_svm`. Exact-match domain similarity was returned for `example.test`. This is one real inference on synthetic text, not a quality evaluation.
- `POST /analyze-headers`: **200**, parsed `From` as `support@example.test`, returned recorded SPF/DKIM/DMARC `pass`, score `0`, risk `Low`, and limitations stating supplied authentication statuses are not independently verified. This verifies one synthetic header request.

The actual Pydantic request classes also validated `examples/email_spam_request.json` and `examples/email_header_request.json`. Models forbid extra fields, so explanatory `_note` keys cannot be included in these request bodies.

### Existing test suite

Command from `git/Email Detection`:

```powershell
$env:PYTHONPATH=(Resolve-Path '.venv\Lib\site-packages').Path
& '<host-bundled Python 3.12.14 executable>' -B -m pytest -p no:cacheprovider tests/test_api.py tests/test_header_forensics_api.py tests/test_header_forensics.py
```

Result: **26 passed, 1 warning**, in 4.30s. Warning: Starlette `anyio.abc.BlockingPortal` deprecation. This verifies selected local API/header tests, not deployment readiness.

### Request contract notes (`git/Email Detection/src/email_detection/api.py`)

- `DetectRequest`: required strict nonblank `email_text` length 1–100000; optional nullable `sender_address`, `claimed_domain`, `expected_domain`; extra fields forbidden. Claimed/expected domains are normalized if non-null. A malformed nonempty sender yields 422; empty sender is falsy in route logic and treated as absent.
- `HeaderForensicsRequest`: required strict nonblank `raw_header` length 1–100000; optional nullable `expected_domain`; extra fields forbidden. Malformed header content can be analyzed and returned with a finding; this differs from malformed request data, which is 422.
- No authentication middleware/dependency was found. This is static source inspection, not a security penetration test.

## 2. Saved email model artifact

**Runtime verification:** default `/health` returned `model_loaded=true`; `/detect` returned an actual prediction. Loader reads `artifacts/best_baseline.joblib` and `artifacts/best_model_metadata.json`; source checks `decision_function`, `LinearSVC`, metadata keys and finite threshold. Metadata has model `linear_svm`, threshold `-0.13062904379568877`, mapping Safe Email→0 / Phishing Email→1.

Files: `git/Email Detection/artifacts/best_baseline.joblib`, `git/Email Detection/artifacts/best_model_metadata.json`.

No artifact/metadata loading error occurred through actual route startup. The `.venv\Scripts\python.exe` command failed before Python startup because its interpreter path is stale; bundled Python plus existing site-packages succeeded. No environment rebuild or installation was performed.

## 3. Typosquatting artifact verification

### Wrapper attempt and dependency failure

Attempted project wrapper `TyposquattingDomainClassifier` with bundled Python and available project site-packages. Import failed before wrapper inference:

```text
ModuleNotFoundError: No module named 'tldextract'
```

`typosquatting_domain_model.py` imports `tldextract` at module import time. Root `requirements.txt` and `artifacts/typosquatting_experiment/requirements-typosquatting.txt` declare/pin `tldextract==5.4.0`, but it is absent from the runtime. No package was installed and no environment altered.

### Underlying saved pipeline inference

Loaded `artifacts/typosquatting_experiment/typods_dataset_ts/final_model.joblib` with joblib, called its stored `model.predict_proba` on four normalized inputs from that model's `test_predictions.csv`, and applied the artifact threshold and label map. This tests the serialized sklearn pipeline, not the project input-normalization wrapper.

| Saved test input | Actual label | Actual score | Threshold | Saved CSV label | Score matched saved CSV |
|---|---:|---:|---:|---|---|
| `diplomaticourier.com` | `NotTypo` | 0.3768125285192068 | 0.9223777972589455 | `NotTypo` | Yes (exact) |
| `hauserwirth.com` | `NotTypo` | 0.19353241404508656 | 0.9223777972589455 | `NotTypo` | Yes (floating-point roundoff only) |
| `target.com` | `Typo` | 0.9844265091423384 | 0.9223777972589455 | `Typo` | Yes (exact) |
| `hoistory.com` | `Typo` | 0.9776036356556989 | 0.9223777972589455 | `Typo` | Yes (exact) |

Inputs and saved comparisons are in `artifacts/typosquatting_experiment/typods_dataset_ts/test_predictions.csv`. These are output labels/scores reproduced from the saved test artifact, not independent ground truth. Wrapper readiness remains blocked by missing `tldextract` in this runtime.

## 4. URL Phishing inference gaps

Static inspection only; no URL inference was run. Notebook candidates: `ImpersonaGuard_n.ipynb`, `git/URL Phishing Detection/ImpersonaGuard_URL_Phishing_Report_EN.ipynb`; dataset: `git/URL Phishing Detection/dataset_full.csv`.

What exists:

- In-memory candidates: Random Forest (300 trees), Extra Trees (300), HistGradientBoosting (150 iterations), Logistic Regression, optional LightGBM. Pipelines median-impute; Logistic Regression also scales. Notebook predicts with `.predict()`.
- CSV has **111 numeric engineered feature columns** plus `phishing` target. Feature order/names as read from CSV: `qty_dot_url`, `qty_hyphen_url`, `qty_underline_url`, `qty_slash_url`, `qty_questionmark_url`, `qty_equal_url`, `qty_at_url`, `qty_and_url`, `qty_exclamation_url`, `qty_space_url`, `qty_tilde_url`, `qty_comma_url`, `qty_plus_url`, `qty_asterisk_url`, `qty_hashtag_url`, `qty_dollar_url`, `qty_percent_url`, `qty_tld_url`, `length_url`, `qty_dot_domain`, `qty_hyphen_domain`, `qty_underline_domain`, `qty_slash_domain`, `qty_questionmark_domain`, `qty_equal_domain`, `qty_at_domain`, `qty_and_domain`, `qty_exclamation_domain`, `qty_space_domain`, `qty_tilde_domain`, `qty_comma_domain`, `qty_plus_domain`, `qty_asterisk_domain`, `qty_hashtag_domain`, `qty_dollar_domain`, `qty_percent_domain`, `qty_vowels_domain`, `domain_length`, `domain_in_ip`, `server_client_domain`, `qty_dot_directory`, `qty_hyphen_directory`, `qty_underline_directory`, `qty_slash_directory`, `qty_questionmark_directory`, `qty_equal_directory`, `qty_at_directory`, `qty_and_directory`, `qty_exclamation_directory`, `qty_space_directory`, `qty_tilde_directory`, `qty_comma_directory`, `qty_plus_directory`, `qty_asterisk_directory`, `qty_hashtag_directory`, `qty_dollar_directory`, `qty_percent_directory`, `directory_length`, `qty_dot_file`, `qty_hyphen_file`, `qty_underline_file`, `qty_slash_file`, `qty_questionmark_file`, `qty_equal_file`, `qty_at_file`, `qty_and_file`, `qty_exclamation_file`, `qty_space_file`, `qty_tilde_file`, `qty_comma_file`, `qty_plus_file`, `qty_asterisk_file`, `qty_hashtag_file`, `qty_dollar_file`, `qty_percent_file`, `file_length`, `qty_dot_params`, `qty_hyphen_params`, `qty_underline_params`, `qty_slash_params`, `qty_questionmark_params`, `qty_equal_params`, `qty_at_params`, `qty_and_params`, `qty_exclamation_params`, `qty_space_params`, `qty_tilde_params`, `qty_comma_params`, `qty_plus_params`, `qty_asterisk_params`, `qty_hashtag_params`, `qty_dollar_params`, `qty_percent_params`, `params_length`, `tld_present_params`, `qty_params`, `email_in_url`, `time_response`, `domain_spf`, `asn_ip`, `time_domain_activation`, `time_domain_expiration`, `qty_ip_resolved`, `qty_nameservers`, `qty_mx_servers`, `ttl_hostname`, `tls_ssl_certificate`, `qty_redirects`, `url_google_index`, `domain_google_index`, `url_shortened`.
- Preprocessing in notebook: drop exact duplicate rows; drop missing target; cast target to int; select numeric columns except `phishing`; replace infinities with NaN; stratified 80/20 split; median imputation in each estimator pipeline; StandardScaler only for Logistic Regression. Labels: 0 legitimate / 1 phishing.
- EDA feature examples are not a feature producer. Dataset stores already-engineered values; no raw-URL-to-111-feature implementation was found.

Missing for inference: approved fitted model and preprocessing state (none serialized); chosen candidate; complete ordered/type schema and sentinel/missing policy; raw URL feature-generation code; availability, freshness and failure semantics for DNS/TLS/ASN/WHOIS/redirect/search-index fields; label/score/threshold response contract; callable inference function; artifact metadata/runtime lock; parity fixtures and request validation. Metrics/evaluation CSVs are not a model artifact. No unrelated artifact was reused.

## 5. DGA inference gaps

Static inspection only; no DGA inference was run. Notebook: `Domain Similarity/ImpersonaGuard_Domain_Similarity_Experiments.ipynb`; dataset: `1_Raw_Domain_Dataset_labeled.csv`, columns `Domain`, `class`.

What exists:

- Labels `legit` and `dga`; normalization trims/lowercases, extracts host portion from URL-like strings, strips path/port, attempts IDNA, drops empty values and duplicate normalized domains; `y=0` for exact `legit`, otherwise 1.
- Rule baseline: 15-brand list, `SequenceMatcher` over domain and SLD, in-SLD substring score; threshold 0.72.
- ML candidate: Pipeline of `TfidfVectorizer(analyzer='char', ngram_range=(2,5), min_df=2, max_features=150000, sublinear_tf=True)` and `LogisticRegression(max_iter=2000, class_weight='balanced', random_state=42)`. Fitted only in notebook memory; threshold 0.5.
- Hybrid score: `0.65 * ML probability + 0.35 * rule score`, threshold 0.5.
- Stratified 70/15/15 train/validation/test with seed 42 after deduplication.
- `impersonaguard_domain_results/method_comparison.csv` stores three method rows; `test_predictions.csv` stores 20,089 test rows with domain, actual, rule/ML/hybrid scores and predictions. These are evaluation outputs, not fitted estimators.

Missing for inference: approved model/operating point; fitted TF-IDF vocabulary and logistic estimator (or approved deterministic-rule implementation); callable normalization/prediction function; metadata binding artifact to notebook/data revision; runtime lock and request/response contract. Test CSV cannot predict unseen domains. Saved comparison lacks run ID/hash; reproduce and investigate Rule-Based zero recall and very high ML/Hybrid results before relying on them. “DGA” here is domain-string classification, not DNS telemetry; confirm product intent.

## 6. Other artifact and runtime checks

- Email phishing text: `git/Email Detection/artifacts/best_baseline.joblib` and `best_model_metadata.json` exist and were exercised by `/health` and `/detect`. Runtime route test succeeded; saved model is a LinearSVC text pipeline.
- Typosquatting: `artifacts/typosquatting_experiment/typods_dataset_ts/final_model.joblib` exists; underlying sklearn pipeline reproduced four saved test rows. `tldextract` needed by wrapper is missing from the used runtime. No HTTP route exists.
- Header forensics: no trained artifact is expected; `analyze_email_header` is deterministic and `/analyze-headers` was exercised. It does not independently verify SPF/DKIM/DMARC.
- URL and DGA: no matching saved estimator artifact or inference wrapper was found. Evaluation CSVs are not model artifacts.

## 7. Prioritized remaining work

1. **Email Header Forensics:** approve trusted upstream handling for authentication-result headers, score/risk semantics, privacy/retention and route auth; preserve exact response schema and add operational limits. Route has runtime evidence; upstream trust remains unresolved.
2. **Email Spam/Phishing:** resolve phishing-vs-generic-spam scope; rebuild a reproducible target runtime from declared requirements; approve threshold/cost policy and fresh external holdout; decide auth/privacy controls for `/detect`. One synthetic inference and 26 focused tests passed locally.
3. **Typosquatting:** provide/lock `tldextract==5.4.0` in clean target environment; test wrapper normalization/IDN/error paths and artifact parity; approve threshold vs recall tradeoff and independent target-brand-labelled validation; decide whether an HTTP endpoint is required.
4. **URL Phishing:** implement/document raw URL feature generation for the exact 111 ordered fields, including network-derived value policy; select/save approved fitted pipeline; run fresh holdout; implement inference function, schema and parity tests.
5. **DGA:** confirm objective; reproduce/audit metric CSVs; approve rule/ML/hybrid choice and threshold; persist chosen trained state; implement normalization/inference; establish external/time validation and API contract.

These priorities reflect integration blockers and evidence, not model security effectiveness. No model is claimed production-ready.

## Typosquatting dependency fix and re-validation — 2026-10-24

This addendum supersedes the earlier report's statement that Typosquatting wrapper inference was blocked. Inference now executes in a temporary validation venv described below. The Email Detection project venv remains stale; it was not repaired or overwritten.

### Root cause and dependency declaration

- `typosquatting_domain_model.py` imports `tldextract` at module import. Its constructor configures `TLDExtract(suffix_list_urls=(), cache_dir=None)`, so suffix resolution is local-only and the tested inference does not need an external lookup.
- Root `requirements.txt` and `artifacts/typosquatting_experiment/requirements-typosquatting.txt` already both declare `tldextract==5.4.0`, with `numpy==2.4.6`, `pandas==3.0.6`, `scikit-learn==1.9.1`, `joblib==1.6.0`. These match recorded Typosquatting experiment dependencies. No requirements edit was needed; adding tldextract to the sibling Email Detection service requirements would couple an unrelated module to that API.
- The failure was environment selection/provisioning: `git/Email Detection/.venv/pyvenv.cfg` names base executable `<missing Python executable from a prior user-specific runtime>` and creation command under `<prior user-specific Email Detection environment>`. That base executable no longer exists. This venv was provisioned for Email Detection and lacked tldextract. Invoking its `Scripts\python.exe` failed before startup with `No Python at ...`.
- A local Python 3.11.1 installation already has the exact pinned Typosquatting package versions, including tldextract 5.4.0. It was used read-only; no global package was installed or changed.

### Validation environment and preparation

Created temporary environment:

```powershell
$basePython='<local Python 3.11.1 executable>'
$auditEnv='<temporary Typosquatting audit environment>'
& $basePython -m venv --system-site-packages $auditEnv
& "$auditEnv\Scripts\python.exe" -B -c "import sys,importlib.metadata as m; print(sys.version); print(sys.prefix); print({d:m.version(d) for d in ['numpy','pandas','scikit-learn','joblib','tldextract']})"
```

Observed versions: Python 3.11.1, NumPy 2.4.6, pandas 3.0.6, scikit-learn 1.9.1, joblib 1.6.0, tldextract 5.4.0. No pip install or external URL/network access was used. This is a temporary venv with its own interpreter prefix; `--system-site-packages` exposes the already-installed global dependencies read-only, so it is not hermetic. The environment was created for this audit only; no project dependency or global installation changed.

### Actual inference command and results

From the project root, the temporary venv Python ran with `-B`. The script imported `TyposquattingDomainClassifier` and `predict_typosquatting_domain`, loaded the default artifact, compared four selected rows with `artifacts/typosquatting_experiment/typods_dataset_ts/test_predictions.csv`, asserted output keys, labels, threshold decisions and score parity, called the public function on four new inputs, and expected `ValueError` for invalid inputs. The pipeline loaded as `CharTFIDF_LogisticRegression_C5`.

Saved rows (recorded labels matched; score delta < 1e-12):

| Input | Wrapper label / prediction | Wrapper score | Recorded label / score |
|---|---|---:|---|
| `diplomaticourier.com` | `NotTypo` / 0 | 0.3768125285192068 | `NotTypo` / 0.3768125285192068 |
| `hauserwirth.com` | `NotTypo` / 0 | 0.19353241404508656 | `NotTypo` / 0.1935324140450865 |
| `target.com` | `Typo` / 1 | 0.9844265091423384 | `Typo` / 0.9844265091423384 |
| `hoistory.com` | `Typo` / 1 | 0.9776036356556989 | `Typo` / 0.9776036356556989 |

All four outputs had `input`, `normalized_domain`, `prediction`, `label`, `score`, `threshold`, `model_name`, `interpretation`; scores were within [0,1] and labels followed the stored threshold. New input outputs (model outputs only; not expected labels or accuracy claims):

| Input | Normalized input | Output label | Score |
|---|---|---|---:|
| `https://paypa1.example/login` | `paypa1.example` | `NotTypo` | 0.22544851346048253 |
| `Google.com` | `google.com` | `NotTypo` | 0.05496032100935704 |
| `ordinary-harbor.example` | `ordinary-harbor.example` | `NotTypo` | 0.12300645133540482 |
| `xn--80ak6aa92e.com` | `xn--80ak6aa92e.com` | `NotTypo` | 0.28864286886603546 |

Invalid handling: `''` → `ValueError: domain must not be empty`; `None` → `ValueError: domain must not be None`; `'bad..domain'` → `ValueError: invalid IDN hostname: 'bad..domain'`. No invalid value was accepted. Inputs are synthetic/parser fixtures and do not establish model accuracy. Four saved rows establish parity only for those rows.

### Regression tests and route re-check

Focused suite rerun from `git/Email Detection`:

```powershell
$env:PYTHONPATH=(Resolve-Path '.venv\Lib\site-packages').Path
& '<host-bundled Python 3.12.14 executable>' -B -m pytest -p no:cacheprovider tests/test_api.py tests/test_header_forensics_api.py tests/test_header_forensics.py
```

Result: **26 passed, 0 failed, 0 skipped**, 1 Starlette deprecation warning, 4.64 seconds. Warning: `anyio.abc.BlockingPortal` is deprecated. Tests ran with Python 3.12.14 and Email Detection site-packages; `-B` and `-p no:cacheprovider` avoided bytecode and pytest-cache writes. These tests cover API/header behavior, not Typosquatting.

Re-ran in-process `TestClient(create_app())` against all three routes. `GET /health` → 200, model loaded true, `linear_svm`; `POST /detect` → 200, synthetic message verdict `benign`, margin `-1.2602952583451852`; `POST /analyze-headers` → 200, parsed `From`, SPF/DKIM/DMARC, score 0, risk Low. No server was started; no external requests were made. Typosquatting inference was exercised separately through the actual wrapper in Python 3.11.1.

### Files changed and remaining blockers

- Changed only `BLUE_Engine_AI_Handoff/audit/inference_readiness_report.md`, adding this resolution/retest record. No project requirements file needed correction because both appropriate Typosquatting requirements already pin the compatible dependency.
- No training notebook, training logic, fitted model, original API source, existing route, or test file was modified. Login Anomaly Detection remains excluded.
- Typosquatting wrapper and artifact load and run in the temporary validation venv. The Email Detection venv remains unportable due its stale base-Python path; the temporary venv inherits system packages and is not hermetic. Rebuild intended service environments from declared requirements in an approved build process before deployment.
- Four saved-row parity results and four synthetic new inputs are runtime evidence, not model quality evidence. Validate broader representative data and operating threshold before deployment.
- URL Phishing and DGA remain **NOT READY for new-input inference**: neither has a fitted artifact nor working reusable inference function. Evaluation outputs do not replace fitted artifacts. URL also lacks the raw URL-to-111-feature producer; DGA needs a chosen/persisted model and approved inference contract.

### Typosquatting validation invocation

The actual wrapper test command (executed from the project root; assertion source was supplied on standard input) was:

```powershell
& '<temporary Typosquatting audit environment>\Scripts\python.exe' -B -
```

The Python harness loaded the wrapper and default artifact, read `test_predictions.csv`, selected the first two `NotTypo` and first two `Typo` rows, ran `predict_many`, and asserted each output schema, saved label, and saved score within `1e-12`. It then called `predict_typosquatting_domain` for the four tabled new inputs, asserted required keys and score bounds, and called `predict_one` on `''`, `None`, and `'bad..domain'`, asserting `ValueError` for each.

## Final GitHub handoff review — 2026-10-24

### Final local reruns

From `git/Email Detection`, the focused regression command was run again with Python 3.12.14 and the existing project `.venv\Lib\site-packages` on `PYTHONPATH`:

```powershell
$env:PYTHONPATH=(Resolve-Path '.venv\Lib\site-packages').Path
python -B -m pytest -p no:cacheprovider tests/test_api.py tests/test_header_forensics_api.py tests/test_header_forensics.py
```

Result: **26 passed, 0 failed, 0 skipped**, one Starlette/AnyIO `BlockingPortal` deprecation warning, 4.84 seconds. `python` above represents the host-bundled Python 3.12.14 used for this audit; developer-specific executable paths are intentionally not published. This reused the stale venv's site-packages; it was not a clean environment.

The route smoke test used `TestClient(create_app())`, imported from the actual `src` tree with the same existing site-packages. It loaded both documented email example JSON files and posted them. `/health` returned HTTP 200 with `model_loaded=true`, model `linear_svm`; `/detect` returned HTTP 200, `benign`, score `-1.2602952583451852`, score kind `linear_svm_decision_margin`; `/analyze-headers` returned HTTP 200, parsed `support@example.test`, SPF/DKIM/DMARC `pass`, score 0 and risk `Low`. Source route inspection showed only `GET /health`, `POST /detect`, and `POST /analyze-headers` among these contract routes. All requests were in-process; no external call was made.

One initial smoke-test invocation omitted the project site-packages `PYTHONPATH` and failed with `ModuleNotFoundError: No module named 'fastapi'`. Re-running with the available project site-packages succeeded as described above. This demonstrates that the host interpreter alone is not a prepared environment.

### Contract, documentation and package checks

- `docs/API_Integration_Contract.yaml` was parsed with Python `json.loads`; its declared version is OpenAPI 3.1.0, implemented and proposed paths were enumerated, and local traversal confirmed response-schema `$ref` targets resolve. Its contents are JSON-formatted (YAML 1.2 subset). PyYAML, `openapi_spec_validator`, and `prance` were unavailable, and no package was installed. Formal YAML/OpenAPI validation therefore remains **NOT VERIFIED**.
- Both implemented-route request examples were submitted to the actual route handlers and returned HTTP 200. URL, DGA, and Typosquatting examples remain explicitly illustrative and are not implemented HTTP request schemas.
- A local-path/credential pattern scan over the package returned no matches after machine-specific absolute paths in this report were generalized. This is not a dedicated secrets-scanner result.
- The working directory has no `.git` directory, so Git-tracked contents and `git check-ignore` results could not be verified. Existing `git/Email Detection/.gitignore` excludes `artifacts/`; the email model and metadata are locally present but would not be included through normal Git tracking under that rule. The Typosquatting artifact is locally present outside this package. No artifact was copied, moved, deleted, or changed.
- The handoff API requirements are now component-specific: `requirements.txt` follows Email Detection declared ranges; `requirements-typosquatting.txt` follows the experiment's recorded exact versions. Their compatibility was source-checked; no clean dependency installation was run. URL/DGA still have no validated inference dependency lock.
- Package-local `.gitignore` now excludes local environments, caches, credentials, temporary files, and accidentally copied model/data artifacts.

### Final handoff changes and limits

This review changed `BLUE_Engine_AI_Handoff/README.md` to describe tested routes, tested Typosquatting behavior, setup caveats and artifact omissions; split the Email and Typosquatting dependency declarations into `requirements.txt` and `requirements-typosquatting.txt`; added package-local `.gitignore`; generalized local absolute paths in this report; and added `audit/final_handoff_checklist.md` with statuses and evidence. No training code, notebook, API implementation, test, dataset, or fitted model artifact was changed.

The README gives fresh-environment and local startup commands based on the component's existing instructions, but the clean dependency installation and resulting tests were not executed. A GitHub checkout cannot be assumed to contain model artifacts, and URL Phishing and DGA remain **NOT READY for new-input inference**. The recommended status is **handoff with explicitly documented limitations**, not production approval. See `audit/final_handoff_checklist.md` for remaining blockers and per-check status.

## Implementation and final inference update — 2026-10-24

This section supersedes earlier statements in this report that URL Phishing and DGA had no inference artifacts/functions, and that only the documentation package had changed. This task added local, separately testable inference paths; it did not modify original notebooks or existing Email/Typosquatting fitted artifacts.

- Domain Similarity remains the existing distinct brand-rule detector (`TyposquattingDetector.detect`), now configured not to refresh its suffix list over the network. It was exercised on exact, lookalike, and empty inputs.
- The existing Typosquatting wrapper again passed four saved-row label/score parity checks, four new input checks, and three invalid-input checks in the focused component suite. The saved artifact was not modified.
- `scripts/train_dga_domain_model.py` fit the existing notebook's char-TF-IDF/Logistic Regression candidate on only its 70% training split (93,748 of 133,926 normalized examples); `dga_domain_model.py` loads the fitted pipeline and predicts domain strings. It is not DNS telemetry. No test/validation metrics were computed.
- `scripts/train_url_phishing_feature_model.py` fit the notebook's first Random Forest candidate with its median imputer on only the 69,767-row training split. `url_phishing_inference.py` requires exactly the artifact's 111 engineered numeric features. It does not accept raw URLs or retrieve network-derived features. No test metrics were computed.
- Added runtime tests ran with `py -3.11 -m unittest discover -s tests -p test_inference_components.py -v`: **5 passed**. They included actual artifact loads/predictions plus invalid-input/schema handling. Detailed outputs and limitations are in `audit/implementation_and_test_results.md`.
- Email regression suite rerun from `git/Email Detection`: **26 passed, 0 failed, 0 skipped**, one deprecation warning. It reused existing project site-packages through host Python 3.12.14; it was not a clean install. Existing email API routes were unchanged.
- Local DGA and URL artifact builds ran successfully with Python 3.11.1. Compressed artifact sizes: DGA 2,454,362 bytes; URL 32,042,280 bytes. They and the source datasets are excluded by root ignore rules; no artifacts were published.
- A separate no-system-site-packages venv was created and an offline pip install was attempted. It failed because the local wheel cache lacks `numpy==2.4.6`; no global package changes or external package requests were made. Clean installation remains **NOT VERIFIED**.
- PyYAML `safe_load` parsed the contract, and its shared implemented schemas matched `FastAPI.app.openapi()`. No OpenAPI semantic validator is installed; formal validation remains **NOT VERIFIED**. There is still no `.git` repository, so GitHub tracking and checkout behavior cannot be verified.

The project now has locally tested model execution paths for DGA domain strings and URL engineered-feature rows, but overall integration remains incomplete. Raw URL feature generation, authorized dataset/artifact delivery, clean dependency installation, and repository/GitHub verification are unresolved. No general accuracy or production-readiness claim is made. See `audit/full_functionality_audit.md`, `audit/implementation_and_test_results.md`, and `audit/final_handoff_checklist.md` for the current comprehensive status.

## Raw URL inference and reproducible setup follow-up — 2026-10-24

### Source inspection and exact blocker

Inspected the code and markdown cells in all three available URL notebooks: `ImpersonaGuard_n.ipynb`, `ImpersonaGuard_URL_Train_Test_Accuracy_Comparison.ipynb`, and `git/URL Phishing Detection/ImpersonaGuard_URL_Phishing_Report_EN.ipynb`. Each contains 21 cells. No function/class definitions or raw URL parser/network feature acquisition code were present. The model-training cells instead drop duplicate rows, drop rows with a missing `phishing` label, cast labels to integers, select numeric columns, replace positive/negative infinity with null, and fit an imputer/model pipeline. The report notebook states that its five demo URLs are feature rows because `dataset_full.csv` contains engineered numeric features. A local CSV schema read confirmed 112 all-numeric columns, including `phishing`, no raw-URL-named column, and an exact order match between the 111 non-target columns and the saved artifact metadata.

Inspected `artifacts/url_phishing_inference/url_phishing_model.joblib` with joblib in Python 3.11.1. Its metadata has 111 ordered `feature_names`; the serialized pipeline exposes the same `feature_names_in_` order, a median `SimpleImputer`, and a 111-input `RandomForestClassifier`. This verifies the feature-map model interface and preprocessing artifact, but the artifact contains no definitions for deriving features from raw text. The ordered names include lexical counters/lengths and fields such as `time_response`, `domain_spf`, `asn_ip`, `time_domain_activation`, `time_domain_expiration`, `qty_ip_resolved`, `qty_nameservers`, `qty_mx_servers`, `ttl_hostname`, `tls_ssl_certificate`, `qty_redirects`, `url_google_index`, and `domain_google_index`. Their training-time extraction logic, types beyond numeric matrix input, source provenance, failure behavior, and missing-value semantics cannot be recovered from the notebook or model alone. No replacement generator was written and no URL was opened or fetched.

Added a negative interface test to `tests/test_inference_components.py`: passing a raw URL string to `predict_url_features` raises the documented `ValueError` (`features must be a JSON object`). This confirms current input validation only; it is not a raw URL inference success. The requested raw URL-to-111-features-to-model test cannot be executed until the source feature producer and its data requirements are obtained. No held-out evaluation was run; no feature producer exists to evaluate.

### Dependencies and setup reproducibility

Current successful local domain-inference runtime versions were rechecked with `py -3.11`: Python 3.11.1, NumPy 2.4.6, pandas 3.0.6, scikit-learn 1.9.1, SciPy 1.17.1, joblib 1.6.0, and tldextract 5.4.0. These match `BLUE_Engine_AI_Handoff/requirements-domain-inference.txt` and the versions in the generated DGA/URL artifact metadata. This establishes the versions in the existing interpreter, not compatibility across all platforms or a clean installation. Email retains its separate Python 3.10–3.12 range and package declarations in `git/Email Detection/requirements.txt`; Typosquatting retains its own exact dependency declaration. The Python 3.11.1 interpreter had its packages already installed. No global packages were changed.

The fresh no-system-site-packages venv offline installation remains failed: `python -m pip install --no-index --disable-pip-version-check -r BLUE_Engine_AI_Handoff/requirements-domain-inference.txt` reported no matching distribution for `numpy==2.4.6`. No wheelhouse containing that compatible scientific stack was available. `BLUE_Engine_AI_Handoff/README.md` now documents a fresh venv, online install when authorized, and a wheelhouse prepare/install procedure for offline users. The wheelhouse procedure is documentation only and was not run. The stale local virtual-environment launcher references a machine-specific missing Python path; it is not a reproducible setup source.

### Regression results and scope

After adding the negative raw-input test, the requested suites were rerun:

- Component suite: `py -3.11 -m unittest discover -s tests -p test_inference_components.py -v` — **6 passed**, including actual DGA/Typosquatting/URL feature-map inference and the raw-string rejection check. No test passes raw URL through feature generation because no such generator exists.
- Email API/header suite: from `git/Email Detection`, set `PYTHONPATH` to that component's already existing `.venv\\Lib\\site-packages`, then run `python -B -m pytest -p no:cacheprovider tests/test_api.py tests/test_header_forensics_api.py tests/test_header_forensics.py` — **26 passed, 0 failed, 0 skipped** in the prior final rerun; one Starlette/AnyIO deprecation warning. This existing-stack run is not clean-environment validation.
- Contract suite: with the Email component's site-packages on `PYTHONPATH`, `python -B -m unittest discover -s tests -p test_handoff_contract.py -v` — **3 passed** in the prior final rerun.

The 26 API/header tests, 6 component tests, and 3 contract tests exercise separate areas and must not be summed as independent runtime behaviors. Full command outputs and environment limitations are preserved in `audit/implementation_and_test_results.md`. Existing routes and tested component behavior were not changed.

### Changes and remaining blockers

Changed `tests/test_inference_components.py` only to codify rejection of raw URL strings; corrected the misleading URL/DGA scope comment in `BLUE_Engine_AI_Handoff/requirements.txt`; clarified raw URL limitations and setup instructions in the root and handoff READMEs; and updated this evidence report. No original notebook, training logic, model artifact, or unrelated API route was modified. No request was sent externally and no artifact/dataset was moved, uploaded, or published.

Raw URL inference remains **BLOCKED** on the original 111-field producer/specification (including external-observation policies and typed/missing-value behavior). Clean install remains **NOT VERIFIED** until dependencies install in an isolated environment. Dataset/artifact rights and clean-checkout delivery remain unresolved, particularly DGA/URL provenance and local-only artifacts. These findings do not establish general accuracy or production readiness.
