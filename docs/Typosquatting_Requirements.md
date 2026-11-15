# Typosquatting Detection — Requirements and Audit

Evidence labels: **CONFIRMED FROM SOURCE**, **INFERRED — NEEDS REVIEW**, **NEEDS CONFIRMATION**, **NOT FOUND**.

## A. Model Overview
Two separate implementations: saved ML classifier (`typosquatting_domain_model.py`) and deterministic trusted-brand similarity rules (`typosquatting_detector.py`). Trained candidate is best supported: source, persisted artifact, metadata, evaluation and reload verification. It predicts dataset label, not confirmed maliciousness or target brand.

## B. Data and Labels
`data/dataset_ts.csv`, metadata: 10,000 rows after cleaning, balanced 5,000 `NotTypo` / 5,000 `Typo`; mapping 0/1 respectively. Approximately grouped 70/15/15: train 7,002, validation 1,506, test 1,492. Groups join exact SLD and inferred one-edit typo/legit pairs; dataset lacks target-brand mappings; labels not independently reannotated. Described as TypoDS validation dataset.

## C. Preprocessing and Features
Inference normalizes domain-like string to lowercase IDNA ASCII hostname, strips scheme/path/port, validates DNS label lengths/chars. Persisted model receives normalized strings, then char TF-IDF. Artifact experiment: char ngrams 2–5, max 100,000, min_df 2, unicode accent strip, sublinear TF. Do not confuse helper's `FEATURE_NAMES` numeric lexical feature function with model pipeline. Rule detector separately extracts registered domain, skeletonizes confusables/leet, compares edit distance and SequenceMatcher against trusted-brand list.

## D. Model Configuration
`artifacts/typosquatting_experiment/typods_dataset_ts/final_model.joblib`; loaded with joblib by `TyposquattingDomainClassifier`; predicts probability and applies stored threshold. Selected `CharTFIDF_LogisticRegression_C5`: C=5, liblinear, balanced class weights, max_iter=2000, seed42. Current threshold 0.9223777972589455. Metadata versions: Python3.11.1, sklearn1.9.1, pandas3.0.6, numpy2.4.6, joblib1.6.0, tldextract5.4.0.

## E. Evaluation Results
`threshold_tuning.json` and experiment README: frozen threshold test n=1492, accuracy .7882, precision .9977, recall .5777, F1 .7317, FPR .00134, ROC-AUC .9904, PR-AUC .9886; TN745 FP1 FN315 TP431. Earlier validation-F1 threshold test F1 .9603, recall .9718, FPR .0523; threshold later retuned to prioritize <=1% validation FPR, with large recall reduction. Reload verification reports identical scores/predictions. Internal balanced data, approximate family grouping, no target brands/external set; no real-world guarantee.

## F. Inference Contract
Python helper accepts a domain-like value and returns `input`, `normalized_domain`, integer `prediction`, `label`, `score`, `threshold`, `model_name`, `interpretation`. `domain_api.py` exposes the same result at `POST /api/v1/typosquatting/predict` on port 8001. Score is positive-class `predict_proba`, compared to threshold. Invalid hostname input returns HTTP 422.

The brand-rule interface is separate: `TyposquattingDetector().detect(domain)` returns normalized host/registered domain, alert flag, closest trusted brand, similarity score, and a reason. Its current default uses `SequenceMatcher`, confusable/leet normalization, one-edit Damerau-Levenshtein checks, and suspicious-addition tokens at `similarity_threshold=0.86`; this is not the notebook's 0.72 DGA rule baseline. Public Suffix List extraction is configured to use the installed snapshot without network refresh.

## G. Software Integration Requirements
Pin artifact digest and runtime versions; load trusted artifact only; keep rule and ML outputs separate. Validate string and map ValueError safely. Avoid raw domain logging. Confirm threshold, artifact ownership and data attribution before release.

## H. Acceptance Tests
Artifact load/label mapping; parity with verified `test_predictions.csv`; score threshold boundary; URL/domain/IDN normalization and invalid strings; batch ordering and reload determinism. No fabricated predictions.

## I. Latest Runtime Checks
The new root `tests/test_inference_components.py` suite ran under Python 3.11.1 and passed 5 tests: brand similarity, saved TypoDS row parity and new inputs, invalid inputs, DGA artifact inference, and URL engineered-feature inference/schema errors. These are execution checks, not model-accuracy validation. See `audit/implementation_and_test_results.md` for commands and actual outputs.
