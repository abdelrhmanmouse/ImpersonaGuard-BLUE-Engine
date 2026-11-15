# Implementation and Test Results

Date: 2026-10-24. Runtime results below were executed locally with no external service calls. No Login Anomaly Detection content is included.

## Changes implemented

- Added `dga_domain_model.py` and `scripts/train_dga_domain_model.py`. The training script reproduces the existing notebook's normalization, 70/15/15 stratified seed-42 split, char n-gram TF-IDF and balanced Logistic Regression. It fits only the training split and saves the fitted vectorizer/classifier together with labels, threshold, dataset digest, split counts, and environment metadata. It refuses to overwrite an existing artifact.
- Added `url_phishing_inference.py` and `scripts/train_url_phishing_feature_model.py`. The builder reproduces notebook row cleanup, numeric fields, infinity handling, stratified seed-42 80/20 split, median-imputer and first candidate Random Forest (300 trees). It fits only 69,767 training rows and does not compute held-out metrics. The predictor requires exactly the 111 numeric feature names stored in artifact metadata; it is not a raw URL predictor. It rejects missing/extra names and nonnumeric types; `null`/nonfinite values use fitted median imputation.
- Added `tests/test_inference_components.py`, five standard-library `unittest` cases for brand rules, TypoDS artifact parity/new/invalid inputs, DGA artifact inference/invalid inputs, and URL feature artifact/schema/error paths.
- Added `tests/test_handoff_contract.py` to check actual route methods, shared schemas against `FastAPI.app.openapi()`, and proposed-route labels.
- Changed `typosquatting_detector.py` to set `tldextract` `suffix_list_urls=()` so rule inference uses its installed suffix snapshot and does not attempt a network refresh.
- Added root `.gitignore` patterns for local environments, caches, credentials, datasets, generated metrics, archives, and model artifacts. Added `BLUE_Engine_AI_Handoff/requirements-domain-inference.txt`; clarified root `requirements.txt` component scope. Email requirements remain in the Email Detection subproject.
- Updated root/project README, handoff README and URL/DGA/Typosquatting requirement docs; added this results report and `audit/full_functionality_audit.md`; updated machine-readable inventory, readiness report, and final checklist.

No original notebook, original training code, Email Detection API, Email source, existing Typosquatting artifact, or existing Email artifact was changed. The new URL/DGA artifacts were generated from local source datasets. Their compressed serializations were compared against uncompressed serializations on the same inputs before replacement; inference outputs were identical. New artifacts are ignored by Git rules and remain local.

## Build commands and results

Environment: `py -3.11` resolved to Python 3.11.1 with already-installed NumPy 2.4.6, pandas 3.0.6, scikit-learn 1.9.1, SciPy 1.17.1, joblib 1.6.0, and tldextract 5.4.0. This was the host interpreter's existing package set, not a clean virtual environment; no global packages were installed or modified.

Commands run from repository root:

```powershell
py -3.11 scripts/train_dga_domain_model.py
py -3.11 scripts/train_url_phishing_feature_model.py
```

Both completed successfully:

- DGA: saved `artifacts/dga_domain_inference/dga_domain_model.joblib`; 93,748 training, 20,089 validation, 20,089 held-out test rows. No validation/test metrics computed and neither split used for fitting.
- URL feature baseline: saved `artifacts/url_phishing_inference/url_phishing_model.joblib`; 69,767 training, 17,442 held-out test rows; 111 features. No metrics computed and test rows not used for fitting or selection.
- The DGA source CSV and the duplicate under `Domain Similarity/Data/` have matching SHA-256 `6C1297CC9A8A3F4A2E78C86F353F80D43B2FD51C58F6134F561BA589E551C26C`. URL source data was present at `git/URL Phishing Detection/dataset_full.csv`; its source/provenance/license were not found.
- After the training scripts were finalized, both were rerun with output redirected to temporary, separate artifact paths. DGA split metadata and two prediction outputs matched the saved artifact; URL split metadata and the same feature-row output matched the saved artifact. The temporary check artifacts were removed; primary artifacts were untouched. No metrics were computed.

The first DGA script invocation failed with `ModuleNotFoundError: No module named 'dga_domain_model'` because Python placed only the `scripts` directory on the import path. The script was corrected to insert the repository root and rerun successfully. This failure and fix are retained in the evidence record; no model file was overwritten.

## Runtime test commands

### Added domain/URL component tests

Command from repository root:

```powershell
py -3.11 -m unittest discover -s tests -p test_inference_components.py -v
```

Final rerun after all implementation changes: **5 passed**, 0 failed, in 9.803 seconds. These tests imported and executed the actual Typosquatting wrapper, Domain Similarity rule detector, DGA artifact pipeline, and URL feature artifact pipeline. They did not mock model inference.

Actual smoke outputs observed during the run:

| Interface/input | Actual output summary | Scope |
|---|---|---|
| Brand rule `google.com` | `possible_typosquatting=false`, score `1.0`, exact trusted registered-domain exemption | Rule behavior only |
| Brand rule `paypa1.com` | `possible_typosquatting=true`, closest brand `paypal.com`, score `1.0`, `lookalike_character_substitution` | Heuristic alert, not ground-truth maliciousness |
| Brand rule empty string | invalid/empty result, no alert, empty normalized host | Invalid input behavior |
| Typo ML `https://paypa1.example/login` | `NotTypo`, score `0.22544851346048253`, threshold `0.9223777972589455` | Actual model output; not an accuracy assertion |
| Typo ML `Google.com` | `NotTypo`, score `0.05496032100935704` | Actual model output; not an accuracy assertion |
| DGA `quiet-cobalt-basin.example` | `legit`, DGA probability `0.016974382629992412`, threshold `0.5` | Synthetic domain-string software fixture |
| DGA `https://r4nd0m-string.test/path` | normalized `r4nd0m-string.test`, `legit`, DGA probability `0.014976833347984117` | Synthetic domain-string software fixture |
| URL feature map (111 synthetic fields; selected values `length_url=47`, `domain_length=16`, `time_response=null`, others zero) | `Phishing`, score `0.85`, score kind `phishing_class_probability` | Feature-schema smoke fixture only; not a raw URL or meaningful real-world example |

Invalid-input assertions passed for DGA empty/None/`...`/`bad..domain`; Typosquatting empty/None/`bad..domain`; URL missing all fields and a nonnumeric feature. URL errors reported schema/type `ValueError`s. The report does not assign expected model labels to synthetic examples.

The test suite reproduced the four prior saved Typosquatting test-row outputs through `predict_many` and compared each predicted label and score to `test_predictions.csv` within `1e-12`:

| Saved input | Actual label | Actual score | Recorded score |
|---|---|---:|---:|
| `diplomaticourier.com` | NotTypo | 0.3768125285192068 | 0.3768125285192068 |
| `hauserwirth.com` | NotTypo | 0.19353241404508656 | 0.1935324140450865 |
| `target.com` | Typo | 0.9844265091423384 | 0.9844265091423384 |
| `hoistory.com` | Typo | 0.9776036356556989 | 0.9776036356556989 |

These four rows are output parity fixtures, not independent labels or model-quality evidence. The four additional Typosquatting inputs exercised by the audit were `https://paypa1.example/login`, `Google.com`, `ordinary-harbor.example`, and `xn--80ak6aa92e.com`; all returned valid output structures and scores in `[0,1]`. Existing invalid wrapper checks expected `ValueError` for empty, `None`, and `bad..domain` and passed.

### Existing email API/header regression suite

Command from `git/Email Detection` (host Python path is not included to avoid publishing local paths):

```powershell
$env:PYTHONPATH=(Resolve-Path '.venv\Lib\site-packages').Path
python -B -m pytest -p no:cacheprovider tests/test_api.py tests/test_header_forensics_api.py tests/test_header_forensics.py
```

The exact invocation used the host-bundled Python 3.12.14 executable. Final rerun result: **26 passed, 0 failed, 0 skipped**, one Starlette/AnyIO `BlockingPortal` deprecation warning, 6.47 seconds. It reused the stale environment's site-packages; it was not an isolated or clean install.

Actual `TestClient(create_app())` smoke request outputs remained: `/health` 200 with email model loaded; `/detect` 200 with `benign`, LinearSVC margin `-1.2602952583451852`; `/analyze-headers` 200 with parsed `support@example.test`, supplied SPF/DKIM/DMARC `pass`, score 0, risk `Low`. The documented email request JSON files were sent to the real route handlers. An initial smoke invocation without site-packages on `PYTHONPATH` failed with `ModuleNotFoundError: fastapi`; rerunning with the existing project site-packages succeeded. No API routes were changed.

### Handoff API contract checks

Command from repository root with Email Detection site-packages on `PYTHONPATH`:

```powershell
$env:PYTHONPATH=(Resolve-Path 'git/Email Detection/.venv/Lib/site-packages').Path
python -B -m unittest discover -s tests -p test_handoff_contract.py -v
```

The exact invocation used host Python 3.12.14. Result: **3 passed**. It compared implemented methods, 10 shared schemas, and labels on the five proposed paths.

The API contract YAML parse command was:

```powershell
py -3.9 -c "import yaml; from pathlib import Path; p=Path('BLUE_Engine_AI_Handoff/docs/API_Integration_Contract.yaml'); d=yaml.safe_load(p.read_text(encoding='utf-8')); assert d['openapi']=='3.1.0'; print('PyYAML parse: PASS; OpenAPI',d['openapi'],'paths',len(d['paths']))"
```

Result: `PyYAML parse: PASS; OpenAPI 3.1.0 paths 8`. No formal OpenAPI validator is installed, so semantic specification validation is not claimed.

## Clean environment and contract validation

A fresh Python 3.11 virtual environment without system-site-packages was created in a temporary location. Exact offline command used:

```powershell
python -m pip install --no-index --disable-pip-version-check -r BLUE_Engine_AI_Handoff/requirements-domain-inference.txt
```

Result: **failed as expected** with `Could not find a version that satisfies the requirement numpy==2.4.6` / `No matching distribution found for numpy==2.4.6`. The local wheel cache contained no required scientific runtime wheels. This was an offline attempt; no package download or global modification occurred. Clean install and clean-environment inference remain **NOT VERIFIED**.

`py -3.11 -m pip check` returned `No broken requirements found` in the already-installed Python 3.11.1 environment; this does not establish a clean installation. Neither `openapi_spec_validator` nor `prance` is installed, so formal OpenAPI semantic validation is **NOT VERIFIED**.

## Artifacts and blockers

Locally present artifact sizes: email `best_baseline.joblib` 1,888,446 bytes plus metadata 273 bytes; existing Typosquatting `final_model.joblib` 762,011 bytes; new DGA model 2,454,362 bytes; new URL-feature model 32,042,280 bytes compressed. Root ignore rules exclude local data/model files, and the Email Detection component ignore rules exclude email `artifacts/`. These rules prevent accidental publication but mean a checkout needs an approved data/artifact provisioning path.

Email has an existing pinned-revision downloader that checks dataset identity, declared LGPL-3.0 metadata and digest, followed by existing audit/training commands to rebuild local model files. Those network-dependent steps were not run. DGA and URL local datasets lack verified provenance/license and are excluded from Git; no authorized distribution/retrieval path was found. The TypoDS data/model also remains local. Ignore patterns were exercised in a disposable temporary Git repository: eight sample data/artifact/secret/cache paths were ignored and README was not. The working directory has no `.git`, so its tracking contents, remote, and clean checkout could not be verified. No datasets/artifacts were published or committed.

A scoped public-document scan found no developer-specific absolute paths; a credential-assignment pattern scan across source/documentation file types returned no file matches. This is not a dedicated secrets-scanner guarantee.

Overall, Domain Similarity, Typosquatting, DGA domain-string scoring, URL engineered-feature scoring, and the email routes now have local tested execution paths. Full product acceptance remains blocked by raw URL feature generation, authorized data/artifact delivery, clean environment install, and absent Git repository/remote. No new model accuracy claim is made.

## Raw URL and regression follow-up — 2026-10-24

Source review of all three URL notebooks found no function/class definitions, parser-based feature extraction, or network feature acquisition code. The training cells load already numeric columns, select numeric fields, replace infinities with nulls, and use median imputation inside the saved model pipeline. The report notebook explicitly says its five example URLs are feature rows because its CSV contains engineered features. The fitted artifact's metadata and `feature_names_in_` both contain the same ordered 111 names; its pipeline is `SimpleImputer(strategy='median')` followed by a 111-input `RandomForestClassifier`. Thus feature-map inference and preprocessing are verified; raw URL transformations, source types/semantics and required external observations are absent. No guessed generator was added.

Added `test_raw_url_is_rejected_until_feature_generation_exists`. A call to `predict_url_features('https://example.test/path')` raises `ValueError: features must be a JSON object...`. This is a negative contract test, not raw URL-to-model inference. It does not assert a prediction.

Final reruns after that test was added:

| Suite | Command and environment | Result |
|---|---|---|
| Components | `py -3.11 -m unittest discover -s tests -p test_inference_components.py -v`; Python 3.11.1, existing installed libraries | **6 passed**, 0 failed; 7.768 s. Includes actual artifact inference and raw string rejection. |
| Email API/header | PowerShell: `$env:PYTHONPATH=(Resolve-Path '.venv\Lib\site-packages').Path; & $python312 -B -m pytest -p no:cacheprovider tests/test_api.py tests/test_header_forensics_api.py tests/test_header_forensics.py` from `git/Email Detection`, where `$python312` was the host bundled Python 3.12.14 executable | **26 passed, 0 failed, 0 skipped**, one Starlette/AnyIO BlockingPortal deprecation warning; 11.69 s. |
| Contract | PowerShell: `$env:PYTHONPATH=(Resolve-Path 'git/Email Detection/.venv/Lib/site-packages').Path; & $python312 -B -m unittest discover -s tests -p test_handoff_contract.py -v` from repository root, same host Python 3.12.14 | **3 passed**, 0 failed; 0.046 s. |

An initial rerun using plain `python` resolved to Python 3.11.1, then imported Python 3.12 native extensions from the stale Email `.venv`; collection failed on NumPy's `_multiarray_umath` and Pydantic Core's `ArgsKwargs`. The contract suite failed on the same Pydantic Core mismatch. No files/packages were changed in response. Re-running with the host bundled Python 3.12.14 and that venv's matching package directory passed. This reinforces that the stale venv launcher and bare `python` command are not portable setup instructions. The exact bundled executable path is host-specific and intentionally not embedded in public documentation.

Clean isolated dependency installation remains unverified: the earlier no-index pip install failed because no NumPy 2.4.6 wheel was available. The new wheelhouse instructions are not evidence of an actual clean install. No external requests were made.

Follow-up edits: root `README.md`, `BLUE_Engine_AI_Handoff/README.md`, `BLUE_Engine_AI_Handoff/requirements.txt`, this report, `audit/inference_readiness_report.md`, and `tests/test_inference_components.py`. The requirements comment was corrected to direct readers to the DGA/URL inference requirements and state the raw URL limitation. No original notebook, training logic, fitted artifact, or API route was changed. URL Phishing remains **not ready for raw URL inference** until its original feature generator/specification is recovered and validated.

## Local runnable API handoff — 2026-10-26

### Environment recovery

The Email Detection venv's `pyvenv.cfg` named a missing Python path from another machine. The available Python runtime is 3.12.14, matching the venv's recorded version; its existing site packages include FastAPI, Uvicorn, NumPy, pandas, scikit-learn, SciPy, and joblib. Updated only `git/Email Detection/.venv/pyvenv.cfg` to reference that available same-version runtime and the current venv location. The launcher then started successfully. `.venv\Scripts\python.exe -m pip check` returned **No broken requirements found**. No package was installed or upgraded. This is local-machine config repair, not portable environment provisioning.

Python 3.11.1 already has the inference pins and `tldextract==5.4.0`, but not FastAPI. The Email venv has FastAPI but not `tldextract`. To avoid mixing incompatible extension environments or installing packages, DGA and Typosquatting are exposed by a small standard-library HTTP adapter in `BLUE_Engine_AI_Handoff/domain_api.py`; model logic and thresholds remain in the existing inference modules.

### HTTP integration

- Email FastAPI unchanged: `GET /health`, `POST /detect`, and `POST /analyze-headers` on port 8000.
- New local domain API: `GET /api/v1/domain-health`, `POST /api/v1/dga/predict`, and `POST /api/v1/typosquatting/predict` on port 8001.
- Domain request body is exactly `{"domain":"<domain-like string>"}`. The adapter calls the original functions and returns their result dictionaries. Invalid values return 422; unknown routes return 404. The default bind is loopback only.
- Updated `docs/API_Integration_Contract.yaml` and the two domain request examples. Legacy URL Phishing remains a 111-feature map; v2 remains separate and is not routed here.

### Tests and live smoke results

- `py -3.11 -m unittest discover -s tests -p test_domain_api.py -v` — **4 passed**. Exercises both model artifacts through an HTTP server, health, invalid input, and unknown route.
- `py -3.11 -m unittest discover -s tests -p test_inference_components.py -v` — **6 passed**.
- From `git/Email Detection`: `.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider tests/test_api.py tests/test_header_forensics_api.py tests/test_header_forensics.py` — **26 passed, 0 failed, 0 skipped**, one Starlette/AnyIO deprecation warning.
- From `git/Email Detection`: `.\.venv\Scripts\python.exe -B -m unittest discover -s ..\..\tests -p test_handoff_contract.py -v` — **3 passed**.
- Live loopback smoke launched Email with `.venv\Scripts\python.exe -m uvicorn email_detection.api:app --app-dir src --host 127.0.0.1 --port 18765` and domain API with `py -3.11 BLUE_Engine_AI_Handoff/domain_api.py --host 127.0.0.1 --port 18766`. Both health checks and the four shipped Email, header, DGA and Typosquatting example requests returned HTTP 200. Email health reported `model_loaded=true`; domain health reported both artifact files present. `/detect` returned `benign`, margin `-1.2602952583451852`; header forensics returned score 0 / `Low`; DGA returned `legit`, score `0.02267200820485388`; TypoDS returned `NotTypo`, score `0.018660139627318585`, threshold `0.9223777972589455`. These example outputs establish execution only, not accuracy.

No model or artifact was changed or retrained. Remaining blockers: clean dependency installation on a fresh machine is not verified; the Email venv repair is machine-specific; artifact/data delivery rights remain unresolved; legacy 111-feature raw-URL extraction is unavailable; and DGA/URL held-out metrics have not been produced.
