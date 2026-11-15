# Legacy URL Phishing Extractor Recovery Decision

Date: 2026-10-26  
Scope: read-only source recovery and integration decision for the legacy 111-feature URL phishing model. No model inference, training, package installation, or source changes were performed. This report is the only file created by this phase.

## Decision

**GO only for Option A:** keep the legacy model contract as an already-engineered, ordered 111-feature map. **NO-GO for raw-URL integration** until the feature producer and external-value semantics are established. Keep `url_phishing_v2` separate; it is not a substitute for or reproduction of this model.

Option B (a new extractor) can be considered only after obtaining reference evidence sufficient to validate it. Option C (evaluate v2 for raw URLs) is a separate product/model evaluation and must not be presented as legacy compatibility.

## Recovery investigation and evidence

### Confirmed local facts

- The audit environment has no Git repository metadata at the workspace root, `BLUE_Engine_AI_Handoff/`, `git/URL Phishing Detection/`, or `compatibility_audit/`. `git rev-parse --show-toplevel` failed in each location; recursive directory inspection found no `.git` directory. No local Git revision/history can therefore be attributed to the dataset, notebooks, or extractor.
- No local `.bundle`, patch, diff, or history file was found. The archive `BLUE_Engine_AI_Handoff.zip` has 19 entries and no extractor/revision material. A larger local archive contains the duplicate URL report notebook and a dataset entry, but no URL feature-extraction source among its non-venv files. Archives were inspected by listing entries only; nothing was extracted.
- Reviewed the source and saved outputs in `ImpersonaGuard_n.ipynb`, `ImpersonaGuard_URL_Train_Test_Accuracy_Comparison.ipynb`, and `git/URL Phishing Detection/ImpersonaGuard_URL_Phishing_Report_EN.ipynb`. The notebooks load engineered numeric columns, clean/split them, and fit estimators. No URL parsing, lexical feature producer, DNS/HTTP/TLS/WHOIS lookup implementation, or original extraction version appears in their cells. Saved outputs report dataset summaries and engineered rows; the report notebook describes its demo examples as feature rows, not raw-URL/reference pairs.
- `git/URL Phishing Detection/dataset_full.csv` has the engineered columns and target, but no raw URL, source row ID, or join key. The saved artifact records the 111 names/order and feature-map task, not extraction code.
- Reviewed dependency declarations: `requirements.txt`, `BLUE_Engine_AI_Handoff/requirements.txt`, `BLUE_Engine_AI_Handoff/requirements-domain-inference.txt`, `git/Email Detection/requirements.txt`, `git/Email Detection/requirements-lock.txt`, `artifacts/typosquatting_experiment/requirements-typosquatting.txt`, and the v2 requirements files. These describe current/runtime or separate-component environments; none identifies the dependencies/environment used by the original 111-feature extractor.
- Local documentation, including `BLUE_Engine_AI_Handoff/docs/URL_Phishing_Requirements.md`, `audit/inference_readiness_report.md`, `audit/full_functionality_audit.md`, `audit/implementation_and_test_results.md`, and the compatibility-audit reports, consistently records raw-URL generation as absent. `url_feature_extractor.py` is explicitly a first-pass implementation, while the compatibility-audit harnesses are experiments; neither is evidence of the original producer.

### External provenance already recorded in the compatibility audit

The existing `compatibility_audit/reference_pair_decision.md` records that the original [GregaVrbancic/Phishing-Dataset repository](https://github.com/GregaVrbancic/Phishing-Dataset) publishes feature CSVs and documentation, and that the [2020 Data in Brief paper](https://doi.org/10.1016/j.dib.2020.106438) describes the process at a high level. Neither source, as previously inspected and documented there, supplied the original script or a row-linked raw-URL companion. The paper's generic pseudocode is not enough to reconstruct exact formulas, component splitting, external lookups, or failure values.

The candidate at [pasuman/url-sentinel-ai](https://github.com/pasuman/url-sentinel-ai) is not version/provenance evidence for this dataset producer. Its code and rules remain a candidate implementation, not the legacy extractor.

### Conclusion on recoverability

**The exact original extractor is not recoverable from the files, notebook outputs, dependency declarations, archives, or Git metadata available in this workspace.** This conclusion is limited to the inspected local evidence and sources already recorded in the audit; it does not prove that the original authors no longer possess the source.

Unknowns that remain include the original code/revision, dependency versions, URL normalization and component boundaries, `qty_tld_url` and `qty_params` implementation details, exact missing-component sentinel rules, and the derivation/time/source/failure semantics for the external fields. The prior compatibility findings remain in force; this report does not repeat that table.

## Minimum evidence needed to proceed safely

Obtain either of the following, with provenance and permission to use it:

1. **Reference-pair route:** raw URLs paired unambiguously (stable IDs or verified row order) with all 111 original feature values from the exact dataset version. Include the source revision/file hash and document excluded or ambiguous rows.
2. **Original-implementation route:** the exact original extraction source and revision used to create `dataset_full.csv`, plus its dependency/runtime specification and the external lookup sources/configuration.

In either route, obtain authoritative definitions for external fields 98–111 and their data timestamps, units, lookup failures, unavailable values, and sentinel/NaN behavior. Feature names/order alone, matching labels, current URL lists, or synthetic examples are insufficient.

## Smallest next implementation phase

**Phase 3: provenance intake and parity gate; do not build or connect an extractor before intake passes.** Preserve the existing legacy artifact and v2 system unchanged.

Acceptance criteria:

1. Record the source URL/provider, license/permission, dataset version, retrieval date, SHA-256, extractor revision, and dependency/runtime versions for the submitted evidence.
2. Verify the reference dataset contains unique, auditable joins from raw URLs to exactly 111 feature values in the saved artifact's exact `metadata.feature_names` order; record every excluded/ambiguous row and reason.
3. If original code is supplied, run it in an isolated environment and freeze its dependencies. If only pairs are supplied, create a separate extractor only for rules supported by those pairs; do not infer missing external values.
4. Require exact equality for deterministic integer/count fields on every accepted reference pair, and an agreed documented tolerance plus captured lookup provenance for any time-varying external fields. No unresolved feature may be silently defaulted.
5. Add tests that fail on missing/extra/reordered feature names, incorrect types, URL parsing edge cases represented in the references, and incorrect missing/failed-lookup behavior. Report coverage against all supplied reference pairs.
6. Only after the parity gate passes, perform a local feature-map-to-existing-artifact smoke test on reference-derived inputs. Keep it distinct from accuracy evaluation; any accuracy claim needs a valid held-out evaluation and authorized labels.

Until those criteria pass, preserve the current API input contract as a 111-feature map and reject claims of raw-URL capability. No extractor-to-model connection or changes to production components are authorized by this phase.
