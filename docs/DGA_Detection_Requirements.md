# DGA Detection — Source Findings and Runtime Interface

## What the source implements

`Domain Similarity/ImpersonaGuard_Domain_Similarity_Experiments.ipynb` is a **domain-string** `dga` vs `legit` experiment, not DNS-activity analysis. It compares three distinct methods: a brand-list SequenceMatcher rule (`RULE_THRESHOLD=0.72`), char TF-IDF + Logistic Regression, and a hybrid 0.65 ML probability + 0.35 rule score. The rule and hybrid are not interchangeable with the ML pipeline.

The notebook's ML preprocessing is domain normalization followed by a fitted `TfidfVectorizer(analyzer="char", ngram_range=(2,5), min_df=2, max_features=150000, sublinear_tf=True)` and `LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)`. The default ML threshold is 0.5. Existing saved evaluation CSVs are historical outputs, not fitted models or evidence of deployment performance.

## Implemented local inference

- `dga_domain_model.py`: `predict_dga_domain(domain)` loads a serialized model and preprocessing pipeline together and returns normalized domain, integer prediction, `legit`/`dga` label, class probability, threshold, and model identity. `domain_api.py` exposes the same result at `POST /api/v1/dga/predict` on port 8001.
- `scripts/train_dga_domain_model.py`: rebuilt the notebook ML candidate from the original root dataset. The input CSV was locally verified to have `Domain`/`class`, 133,926 rows, and labels `legit`/`dga`; its hash matched the duplicate under `Domain Similarity/Data/`. The existing split code yielded 93,748 training rows, 20,089 validation rows, and 20,089 held-out test rows. Only training rows fitted the model. Validation and test were not used for fitting, and this build computed no metrics.
- Saved artifact: `artifacts/dga_domain_inference/dga_domain_model.joblib` (2,454,362 bytes, compressed); it contains the fitted pipeline and source/version/split metadata.
- Required runtime pins are in `BLUE_Engine_AI_Handoff/requirements-domain-inference.txt`; they match the locally tested Python 3.11.1 package versions. A clean install was attempted offline and failed because wheels were unavailable.
- Runtime evidence: two new synthetic domain strings returned valid output objects in `audit/implementation_and_test_results.md`; malformed/empty input checks passed. Returned labels are software outputs, not expected labels or accuracy claims. HTTP smoke-test results are recorded in the README.

## Limitations and requirements

Data provenance/license was not found. The CSV and generated model are excluded by the root `.gitignore`; an authorized data supply and artifact build are required on another machine. The training script intentionally refuses to overwrite an existing model. Confirm whether product scope means domain-string classification or DNS telemetry before integration. Do not describe this interface as DNS telemetry detection.

The source notebook's normalizer preserves one source string containing an embedded newline. The trainer intentionally reproduces that cleaning behavior for parity; the inference function rejects malformed hostname inputs. Investigate source data quality before any accuracy or production claim.
