# Project findings

## Scope and method
Initial source audit: inspected project notebooks, Python modules, Markdown, requirements, tests, reports, CSV metadata, model files and stored notebook outputs. Notebook source and output were reviewed separately. The initial audit did not retrain models or edit source. Login Anomaly Detection is excluded from these deliverables. See the 2026-10-24 implementation update at the end; it supersedes initial URL/DGA inference-status findings.

## Files associated with each model

### URL phishing
- `ImpersonaGuard_n.ipynb`, `ImpersonaGuard_URL_Train_Test_Accuracy_Comparison.ipynb`, `git/URL Phishing Detection/ImpersonaGuard_URL_Phishing_Report_EN.ipynb`: numeric feature exploration/training/evaluation code and stored outputs; duplicate experiment content.
- `git/URL Phishing Detection/dataset_full.csv`: raw dataset expected by notebook; notebook output schema 88,647 × 112.
- No URL-specific Python inference, endpoint or model artifact found.

### DGA
- `Domain Similarity/ImpersonaGuard_Domain_Similarity_Experiments.ipynb`: data cleaning, `legit`/`dga` mapping, rule/ML/hybrid experiment.
- `1_Raw_Domain_Dataset_labeled.csv` and duplicate under `Domain Similarity/Data/`: 133,926 labeled domain rows per notebook output.
- Root README and `typosquatting_domain_model.py` explicitly keep DGA experiment separate from typo classifier. No trained DGA artifact/API found.

### Typosquatting
- `typosquatting_domain_model.py`: normalization, joblib loading, inference schema.
- `typosquatting_detector.py`: independent deterministic brand similarity rules.
- `artifacts/typosquatting_experiment/typods_dataset_ts/`: model, metadata, threshold tuning, train/validation/test predictions and reports.
- `data/dataset_ts.csv`, notebook cell 20, experiment README and requirements file support model association.

### Email spam/phishing text
- `git/Email Detection/src/email_detection/{api.py,models.py,data.py,split.py,domains.py}` and scripts/tests: actual text baseline, preprocessing, routes and tests.
- `git/Email Detection/artifacts/best_baseline.joblib`, `best_model_metadata.json`; reports `baseline_comparison.csv/.md`, `validation_results.json`, `data_audit.md/.json`.
- README describes phishing-vs-safe email labels; product classification as generic spam needs confirmation.

### Email header forensics
- `git/Email Detection/src/email_detection/header_forensics.py` and `api.py`: parser, heuristic scoring and actual `/analyze-headers` route.
- `git/Email Detection/tests/test_header_forensics*.py`, `Email Header Forensics/README.md`, `examples.json`: functional evidence and synthetic examples. Not a trained model.

## Candidate ranking and evidence
1. **Email phishing text:** strongest service readiness evidence: source, serialized artifact, metadata, tests, reports. Still internal dataset and experimental threshold; fresh external holdout advised.
2. **Typosquatting ML:** strongest reproducible saved domain model: loader, final artifact, detailed metadata, prediction files, reload-verification claims. Internal balanced TypoDS data, approximate family split and no target brand/external benchmark.
3. **Header forensics:** actual deterministic service route and tests; no predictive validation needed for parser correctness, but heuristic calibration/trust limits remain.
4. **URL phishing:** notebook candidates only; highest stored test accuracy is Random Forest 97.0474%, but no artifact, complete metric table, feature construction serving path or leakage audit.
5. **DGA:** notebook candidates and saved metric/prediction CSVs exist, but no artifact, inference function or route. Reproducibility, anomaly review and task/data provenance require owner confirmation.

Ranks indicate review readiness, not comparative security performance.

## Metrics and conflicts
- URL: `ImpersonaGuard_n.ipynb`, stored cell 12 output: test accuracy RF .970474, ExtraTrees .969958, HistGradientBoosting .967492, LogisticRegression .933551. Train RF/ExtraTrees .999928. These are historical notebook outputs. Full metrics table was not rendered in saved output. RF/ExtraTrees train-test gap and dataset feature provenance warrant leakage/overfit review.
- DGA: detailed saved held-out values and confusion matrices are recorded in the Source verification update below and in `impersonaguard_domain_results/method_comparison.csv` plus `test_predictions.csv`; these are associated by notebook output paths but lack run identity/hash.
- Typosquatting: current frozen threshold test results in `threshold_tuning.json`: accuracy .7882, P .9977, R .5777, F1 .7317, FPR .00134; TN745 FP1 FN315 TP431. Earlier validation-F1 operating point in experiment README reports test F1 .9603, recall .9718 and FPR .0523. This is not an unexplained conflict: threshold was later retuned to optimize recall subject to validation FPR<=1%, causing the recall tradeoff. Current artifact is threshold-tuning policy.
- Email text: `baseline_comparison.csv`: LinearSVC test P .981873, R .993884, F1 .987842, PR-AUC .998726; TN1086 FP12 FN4 TP650. Project notes test evaluation was inspected during correction of a threshold bug and recommends fresh external holdout.
- Header forensics: no model metrics; tests validate deterministic behavior.

## API reality
Implemented email API routes are `GET /health`, `POST /detect`, `POST /analyze-headers`. Requested `/api/v1/...` routes do not exist. No URL/DGA/typo HTTP endpoint found. No authentication requirement or implementation found in inspected API source. Proposed schemas are placeholders in the OpenAPI document.

## Missing information and decisions
- URL: dataset provenance, feature meaning/generation, full 111-column schema and order, exact current reproducibility, metrics beyond accuracy, artifact and inference contract; audit feature leakage.
- DGA: intended task definition, dataset source/license/collection methodology, run identity for saved metrics, artifact, threshold and inference schema.
- Typosquatting: approve current threshold/recalibration policy, validate independent domain labels and family grouping, confirm package/artifact lifecycle and attribution requirements.
- Email: confirm generic spam vs phishing product semantics, production threshold/cost tradeoff, fresh external holdout, dataset license obligations, route auth policy.
- Header: confirm trusted upstream source for authentication results, whether heuristic scores/bands are suitable, and operational privacy policy.
- All models: establish access control, rate limits, monitoring, retention, release ownership and operational SLOs.

## Source modification check
Handoff files were created only under `BLUE_Engine_AI_Handoff/`. No original project source was intentionally modified. Output inventory was newly generated; a repository diff is not available because this directory is not a Git worktree.

## Source verification update — 2026-10-24

This section records a second-pass comparison of the handoff against the source, saved artifacts, saved experiment outputs, and generated FastAPI OpenAPI schema. It supersedes earlier statements below where noted.

### Direct checks performed

- **Implemented routes:** imported `email_detection.api.create_app` from `git/Email Detection/src` using the project's existing `.venv/Lib/site-packages` with the bundled Python runtime, then inspected `create_app(...).openapi()`. Exactly these application paths were present: `GET /health`, `POST /detect`, `POST /analyze-headers`. No `/api/v1/...` paths exist in the app. The requested API paths in the handoff are proposals. The check did not start a network server or call model inference.
- **Email artifact:** `git/Email Detection/artifacts/best_baseline.joblib` exists (1,888,446 bytes); `best_model_metadata.json` maps `Safe Email`→0 and `Phishing Email`→1, with `linear_svm` and threshold `-0.13062904379568877`. Source loader additionally checks classifier type, metadata and finite threshold. Actual runtime load was not performed in this pass.
- **Typosquatting artifact:** `artifacts/typosquatting_experiment/typods_dataset_ts/final_model.joblib` exists (762,011 bytes) and was loaded for inspection. It contains a `Pipeline(TfidfVectorizer, LogisticRegression)` named `CharTFIDF_LogisticRegression_C5`, threshold `0.9223777972589455`, labels `0: NotTypo`, `1: Typo`. This confirms the saved artifact's pipeline, but not predictive correctness.
- **URL artifact:** no URL `.pkl`, `.joblib`, `.pt`, `.pth`, `.onnx`, `.h5`, or `.keras` artifact was found in the identified URL project location; notebook code trains in memory only.
- **DGA evaluation update:** the earlier statement that no complete numeric comparison was found is superseded. `impersonaguard_domain_results/method_comparison.csv` has 3 method rows, and `test_predictions.csv` has 20,089 held-out rows. The notebook source writes these exact filenames. Metrics in the CSV are: Rule-Based accuracy .593708, precision 0, recall 0, F1 0, ROC-AUC .044421, PR-AUC .240547; ML accuracy .992981, precision .983066, recall .999367, F1 .991149, ROC-AUC .999799, PR-AUC .999673; Hybrid accuracy .993429, precision .984773, recall .998734, F1 .991704, ROC-AUC .999319, PR-AUC .998222. Recomputed from saved prediction rows, confusion matrices (TN,FP,FN,TP) are Rule (11927,262,7900,0), ML (12053,136,5,7895), Hybrid (12067,122,10,7890). The file is traceable to notebook output naming/schema, but contains no run timestamp, source hash, or notebook execution identifier; exact experiment revision and reproducibility remain **NEEDS CONFIRMATION**. Hybrid's slightly higher accuracy/F1 and ML's higher ROC-/PR-AUC do not alone establish an approved operating point.

### API contract and example discrepancies

- `POST /detect` request model is `DetectRequest`: required strict nonblank `email_text` length 1–100000; optional nullable `sender_address`, `claimed_domain`, `expected_domain`; `extra='forbid'`. `claimed_domain` and `expected_domain` are domain-normalized when non-null. A non-empty malformed `sender_address` yields 422; an empty string is falsy in the route and is treated as absent (not rejected). The prior requirements wording that broadly said invalid sender is 422 should be read with this qualification.
- `POST /analyze-headers` request model is `HeaderForensicsRequest`: required strict nonblank `raw_header` length 1–100000, optional nullable `expected_domain`, `extra='forbid'`. Malformed header text may be analyzed and returned with a finding; this is distinct from malformed JSON/request validation.
- The prior `examples/email_spam_request.json` and `email_header_request.json` included `_note` keys. These contradicted `extra='forbid'`, so those keys have been removed. The current examples contain only allowed fields and are synthetic; they assert no predictions.
- `url_phishing_request.json`, `dga_request.json`, and `typosquatting_request.json` remain explicitly illustrative. There is no HTTP schema for these endpoints. URL's empty `features` object is not sufficient to invoke the notebook model: the current notebook fits on 111 numeric columns. DGA's candidate is a domain string from the training notebook, without an inference function. The typo example expresses the Python helper's single domain-like argument as illustrative JSON; no HTTP endpoint accepts it.
- The OpenAPI file was refreshed from FastAPI-generated OpenAPI JSON, preserving the typed request/response components for actual email routes; proposed paths were added as explicit placeholders. The generated route/source schema was verified, but parser validation status below still applies.

### YAML/OpenAPI parser status at initial audit

At the initial audit no YAML parser or OpenAPI validator was used. This status is superseded below: PyYAML `safe_load` subsequently parsed the contract, but no formal OpenAPI semantic validator was available.

### Dependency and integration gaps confirmed

- Email service dependencies and ranges are declared in `git/Email Detection/requirements.txt`; its API additionally relies on `pydantic` via FastAPI, `rapidfuzz` through `domains.py`, plus pandas/numpy/scikit-learn/scipy/joblib for artifact/runtime workflows. Project lock file records a separate resolved environment.
- Typosquatting inference imports `numpy`, `tldextract`, `joblib`, `pandas`, and the sklearn artifact pipeline. `artifacts/typosquatting_experiment/requirements-typosquatting.txt` and root `requirements.txt` pin numpy 2.4.6, pandas 3.0.6, scikit-learn 1.9.1, joblib 1.6.0, tldextract 5.4.0.
- The earlier combined handoff `requirements.txt` mixed Email's `pandas<3.0` range with Typosquatting metadata's `pandas==3.0.6`. It was split into component-specific files; clean installation remains unverified.
- URL engineered-feature and DGA domain-string artifacts/functions now exist as described in the implementation update. Raw URL feature generation remains missing. Header forensics has a deterministic function/API and no predictive artifact by design.

### Prioritized Software Team integration tasks

1. **Header forensics (lowest model-build blocker):** approve trusted provenance for Authentication-Results/Received-SPF, score/risk policy, and retention/auth controls; validate exact response schema and operational privacy. The route/function exists; trained artifact is not applicable.
2. **Email phishing text:** decide whether product scope is phishing or generic spam; approve threshold/cost tradeoff; refresh external holdout; add access-control/retention policy; verify artifact and metadata together in target runtime; use source-generated response schemas. `/detect` is implemented, while `/api/v1/email-spam/predict` is not.
3. **Typosquatting:** approve operating threshold versus recall tradeoff; check TypoDS attribution/usage; validate on independently labeled target-brand/family-separated data; lock compatible runtime and artifact digest; create/approve HTTP schema and route if required. Python inference exists, HTTP endpoint does not.
4. **URL phishing:** implement/review raw URL-to-111-feature generation and external-field policy; establish source data rights and provenance; audit for target leakage; run appropriate held-out validation; decide if a route is needed. A feature-map baseline exists, but raw URL inference remains blocked.
5. **DGA:** confirm domain-string vs DNS-telemetry product intent; establish dataset provenance/license; review the saved experimental metrics and their run identity; validate on independent/time-based data; decide on the ML/rule/hybrid operating point and whether an HTTP route is needed. A local ML candidate and Python inference exist; no accuracy claim or API endpoint exists.

These priorities reflect implementation blockers, not threat severity or comparative model quality.

## 2026-10-24 implementation status update

The earlier URL/DGA “no artifact/function” and Typosquatting dependency statements describe the pre-implementation state and are superseded by `inference_readiness_report.md`, `full_functionality_audit.md`, and `implementation_and_test_results.md`.

- Added and locally tested Python inference for existing Domain Similarity rules, retained Typosquatting ML inference, rebuilt the notebook's DGA char-TF-IDF/Logistic Regression candidate from only its training split, and rebuilt the notebook's first URL Random Forest candidate from only its training split.
- URL inference accepts an engineered 111-field feature map; raw-URL feature generation is still missing. DGA inference classifies domain strings; it is not DNS telemetry. Neither has a new HTTP endpoint.
- No evaluation metrics were computed for the new DGA/URL artifacts. Their smoke outputs are software checks, not accuracy results.
- The new model artifacts and local training data are excluded by root `.gitignore`. DGA/URL data provenance, clean dependency installation, Git tracking, and artifact delivery remain unresolved. Overall handoff is not fully reproducible from a clean checkout.
