# Runtime Artifact Delivery

The API source code and tests are included. Model files are deliberately excluded from Git because the package has no documented redistribution authorization for the underlying data/model artifacts. Each listed artifact existed in the parent project workspace during preparation; none is included in this handoff package.

The software team must obtain these files from the project owner through an approved internal delivery channel, then place them at the relative package paths below. Do not use datasets as a substitute; inference requires the fitted artifacts and, for Email, the matching metadata file.

| Component | Required package-relative path | Current source-workspace state | Bytes | SHA-256 |
|---|---|---|---:|---|
| Email text classifier | services/email/artifacts/best_baseline.joblib | Present outside package; excluded | 1,888,446 | 24eec7839f42080e56018dd9fd8d32ea62c26ac728a075a38125d16ebfc56c2d |
| Email metadata | services/email/artifacts/best_model_metadata.json | Present outside package; excluded | 273 | 50645e96ebeca54f86ad6f639cb5370a3cd7a287b6c1753677ff489cae126f05 |
| DGA | artifacts/dga_domain_inference/dga_domain_model.joblib | Present outside package; excluded | 2,454,362 | 455e95954df1a292a8dada06069e66c70e4c696a7c290c0b1a8a008f86ac8dc4 |
| Typosquatting | artifacts/typosquatting_experiment/typods_dataset_ts/final_model.joblib | Present outside package; excluded | 762,011 | 6ccb123496282c3a1830b0c811ec7fd495fd4c31d12d85d48df4ffa928f15f38 |
| Legacy URL Phishing (111 features) | artifacts/url_phishing_inference/url_phishing_model.joblib | Present outside package; excluded | 32,042,280 | b7a3af56ae75388186ebb19a48a673817d4da7619bf01d5af359e62b3976303d |
| URL Phishing V2 (34 features) | url_phishing_v2/artifacts/url_phishing_v2.joblib | Present outside package; excluded | 5,465,535 | 377e861fa1e398ca02f2185e49917688f0c7207646514e78ba2b21e43124ef58 |

Place each artifact at its listed path and verify its digest with PowerShell. Example:

    Get-FileHash -Algorithm SHA256 -LiteralPath .\artifacts\dga_domain_inference\dga_domain_model.joblib

The exact Email artifact digests are not evidence of license or redistribution permission. The project files inspected did not contain documented redistribution approvals for these fitted artifacts or their source datasets. Do not commit or publish them until the project owner confirms rights and an approved distribution method. The 32 MB legacy URL model may also require a large-file delivery decision if approved.

No raw URL feature extractor for the legacy 111-feature model is included or inferred. Its API still requires a complete feature map. V2 is a separate experimental raw-URL model.
