# URL Phishing — Source Findings and Feature Inference

## What the source contains

`ImpersonaGuard_n.ipynb`, `ImpersonaGuard_URL_Train_Test_Accuracy_Comparison.ipynb`, and `git/URL Phishing Detection/ImpersonaGuard_URL_Phishing_Report_EN.ipynb` contain the same numeric-feature training comparison. The local `dataset_full.csv` has 88,647 rows, 112 columns, 1,438 duplicate rows, target `phishing` (0 legitimate, 1 phishing), and 111 numeric input features after notebook preprocessing. The notebook drops exact duplicate rows and missing targets, converts the target to int, replaces infinite numeric values with NaN, makes a stratified 80/20 split with seed 42, and median-imputes within each candidate pipeline.

The CSV has **engineered feature values, not raw URLs**. No source function was found to compute all 111 inputs. Several fields describe outside observations such as response time, SPF, ASN, domain age, IP/name/MX/TTL counts, TLS certificate, redirects, and search indexing. No external data lookup is performed by the added inference function.

## Implemented local inference

- `url_phishing_inference.py`: `predict_url_features(feature_map)` accepts exactly the artifact's 111 named numeric fields; values may be JSON numbers or `null`. Missing/extra fields and nonnumeric values are rejected. Pipeline median imputation handles `null`/nonfinite values as in training. It returns 0/1 label, probability score, score kind, model identity, and an explicit engineered-feature input-kind.
- `scripts/train_url_phishing_feature_model.py`: fits the first notebook candidate, Random Forest (300 trees, seed 42), using the notebook's deduplicated rows and stratified 80% training split only. The held-out 20% is reserved and not used for fitting or model selection. This build computed no evaluation metrics.
- Saved local artifact: `artifacts/url_phishing_inference/url_phishing_model.joblib` (32,042,280 bytes, compressed), containing the fitted imputer/model and ordered feature names, label mapping, data digest, split details, and environment metadata.
- Required runtime pins are in `BLUE_Engine_AI_Handoff/requirements-domain-inference.txt`; they match the locally tested Python 3.11.1 package versions. A clean install was attempted offline and failed because wheels were unavailable.
- Runtime evidence: a synthetic 111-field fixture produced a valid structured output; missing-field and wrong-type cases raised `ValueError`. The synthetic result is not a prediction about a real URL. See `audit/implementation_and_test_results.md`.

## What remains before raw URL integration

There is no raw-URL parsing/feature-generation function, raw URL fixture, implemented HTTP route, artifact delivery channel, or verified dataset provenance/license in the inspected source. The generated baseline accepts an engineered feature record only. Before a URL endpoint or raw URL claim, provide and review the exact feature producer, external-feature availability/freshness/failure policy, URL privacy/logging policy, and a contract; then run parity and held-out evaluation with proper source data rights. The original notebooks were left unchanged. The locally generated model is excluded from Git by root ignore rules, and the script requires the source CSV, which is also excluded.
