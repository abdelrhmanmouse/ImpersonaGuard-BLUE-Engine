# Local validation record — 2026-10-26

No packages were installed, no model was trained, and no artifact was changed. Tests ran from this package copy using the pre-existing Python 3.12.14 Email environment and Python 3.11.1 Domain runtime. Runtime artifacts were read from the parent project workspace through temporary environment variables; they are not included in this package. The commands below reproduce the environment routing used from a PowerShell prompt in the parent project directory. On a clone, obtain authorized artifacts and put them in the package-relative paths listed in `ARTIFACT_DELIVERY.md`; no parent-workspace paths are needed then.

Observed runtimes: Email Python 3.12.14, FastAPI 0.143.2, Starlette 0.52.1, pytest 9.1.1, NumPy 2.5.4, pandas 2.3.3, scikit-learn 1.9.1, joblib 1.6.0; Domain Python 3.11.1, NumPy 2.4.6, pandas 3.0.6, scikit-learn 1.9.1, SciPy 1.17.1, joblib 1.6.0, tldextract 5.4.0. These are versions observed in existing environments, not evidence that the requirements can be installed cleanly on another machine.

## Commands run

```powershell
Set-Location BLUE_Engine_AI_Handoff
$env:BLUE_ENGINE_ARTIFACTS_DIR = (Resolve-Path ..\artifacts).Path
$env:BLUE_ENGINE_URL_V2_MODEL_PATH = (Resolve-Path ..\url_phishing_v2\artifacts\url_phishing_v2.joblib).Path
$env:BLUE_ENGINE_EMAIL_MODEL_PATH = (Resolve-Path '..\git\Email Detection\artifacts\best_baseline.joblib').Path
$env:BLUE_ENGINE_EMAIL_METADATA_PATH = (Resolve-Path '..\git\Email Detection\artifacts\best_model_metadata.json').Path
& '..\git\Email Detection\.venv\Scripts\python.exe' -B -m pytest -p no:cacheprovider services/email/tests
& '..\git\Email Detection\.venv\Scripts\python.exe' -B -m unittest discover -s tests -p test_handoff_contract.py -v
py -3.11 -m unittest discover -s tests -p test_domain_api.py -v
py -3.11 -m unittest discover -s tests -p test_inference_components.py -v
```

Results: Email/header **26 passed, 0 failed, 0 skipped**, with one Starlette/AnyIO deprecation warning; contract consistency **3 passed**; Domain HTTP/API **8 passed**; component inference **6 passed**. Total unit tests: **43 passed, 0 failed, 0 skipped**.

Services were launched in separate PowerShell processes from the package directory:

```powershell
$env:BLUE_ENGINE_EMAIL_MODEL_PATH = (Resolve-Path '..\git\Email Detection\artifacts\best_baseline.joblib').Path
$env:BLUE_ENGINE_EMAIL_METADATA_PATH = (Resolve-Path '..\git\Email Detection\artifacts\best_model_metadata.json').Path
& '..\git\Email Detection\.venv\Scripts\python.exe' -m uvicorn email_detection.api:app --app-dir services/email/src --host 127.0.0.1 --port 8000

$env:BLUE_ENGINE_ARTIFACTS_DIR = (Resolve-Path ..\artifacts).Path
$env:BLUE_ENGINE_URL_V2_MODEL_PATH = (Resolve-Path ..\url_phishing_v2\artifacts\url_phishing_v2.joblib).Path
py -3.11 domain_api.py --host 127.0.0.1 --port 8001
```

With both servers running, the exact smoke command was:

```powershell
py -3.11 scripts/smoke_test.py
```

It passed 11 checks: Email health, docs, detection and header analysis; Domain health, DGA, Typosquatting, V2 valid and invalid URL, legacy 111-field schema fixture, and aggregate analysis. All successful calls returned HTTP 200; the invalid `ftp://` URL returned HTTP 422. The two processes were stopped after the run.

## Representative observed outputs

- Email `/health`: HTTP 200, `model_loaded=true`.
- Domain health: HTTP 200, DGA and Typosquatting artifacts present.
- DGA input `quiet-cobalt-basin.example`: `legit`, score `0.016974382629992412`.
- Typosquatting input `paypa1.com`: `NotTypo`, score `0.49935726264526714`.
- V2 input `https://example.com/login`: `phishing`, score `1.0`.
- Legacy all-zero 111-feature **schema fixture**: `Phishing`, score `0.7333333333333333`; this is not a representation of a URL and must not be interpreted as one.
- Aggregator example returned `analysis_status=complete`, `risk_category=high`, including the V2 phishing output.

These are outputs for smoke inputs, not performance evidence. In particular, the V2 result aligns with its independently documented false-positive issue. No clean installation was performed, and artifact redistribution authorization remains unverified.
