# Email Spam Detection — Requirements and Audit

Evidence labels: **CONFIRMED FROM SOURCE**, **INFERRED — NEEDS REVIEW**, **NEEDS CONFIRMATION**, **NOT FOUND**.

## A. Model Overview
Implemented email phishing text classifier via FastAPI `/detect`, with validation-selected LinearSVC artifact. This is phishing-vs-safe classification, not general unsolicited-spam detection; confirm product name.

## B. Data and Labels
Dataset `zefang-liu/phishing-email-dataset`, pinned revision documented in project README/data audit. Raw 18,650 rows; 11,322 Safe Email, 7,328 Phishing Email. Audit: 16 missing and 19 blank texts; normalized duplicates collapsed; conflicting normalized group excluded; 17,513 eligible unique rows (10,977 safe, 6,536 phishing). StratifiedGroupKFold 80/10/10; train 14,010, validation 1,751, test 1,752. Mapping exact trimmed Safe Email→0, Phishing Email→1. Declared license LGPL-3.0; legal clearance is outside this audit.

## C. Preprocessing and Features
Use only `Email Text`; drop `Unnamed: 0`; exclude missing/blank text and invalid labels. Normalize case/whitespace for dedupe only; preserve original text for model. Group shared normalized 200-char prefixes across splits; fit TF-IDF on train. Word unigrams/bigrams, min_df2, max 100,000, lowercase, Unicode accent stripping, sublinear TF; no stopwords/stemming.

## D. Model Configuration
Candidates LogisticRegression C1, LinearSVC C1, MultinomialNB alpha1. Selected LinearSVC max_iter10000, seed42, C1. TF-IDF config above. Artifact `git/Email Detection/artifacts/best_baseline.joblib`, metadata `best_model_metadata.json`, threshold -0.13062904379568877. Project declares runtime ranges in `requirements.txt`; metadata records run versions.

## E. Evaluation Results
`reports/baseline_comparison.csv`: validation-selected threshold held-out test SVM precision .981873, recall .993884, F1 .987842, PR-AUC .998726, FP12 FN4; TN1086 FP12 FN4 TP650. Validation precision .972810, recall .986217, F1 .979468. Test was inspected during correction of a threshold bug; project recommends a fresh external holdout. Experimental threshold, not production decision.

## F. Inference Contract
Implemented `POST /detect`. Required strict nonblank `email_text` string 1–100000 chars; optional nullable strings `sender_address`, `claimed_domain`, `expected_domain`; extra fields forbidden. Optional domains validated; invalid sender/domain is 422. Response includes verdict phishing|benign, raw uncalibrated LinearSVC decision-margin `score`, `score_kind`, model, optional domain similarity/reason, claimed domain and signals. Verdict uses metadata threshold; domain similarity does not change it. `/health` status. 503 if artifact unavailable, 500 inference failure. No auth found.

## G. Software Integration Requirements
Use project `src/email_detection/api.py` and matching artifact/metadata. Never interpret margin as probability. Avoid logging or retaining raw emails; no auth implementation found. Apply access and retention policy externally.

## H. Acceptance Tests
Existing `tests/test_api.py` exercises health, response behavior, validation, missing/invalid model. Add artifact parity, size boundaries, forbidden fields, privacy/logging and fresh holdout/threshold review. Existing synthetic test expectations are not general evaluation fixtures.
