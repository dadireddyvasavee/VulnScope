# Architecture

## Data flow
1. **Hashing** – sample identity (MD5/SHA-1/SHA-256) used as the DB key and for leakage checks.
2. **Static analysis** – `pefile` parses headers, sections and imports. Anomalies flagged:
   high-entropy sections (> 7.2 bits/byte), RWX sections, virtual-only sections, entry point outside or in a non-executable section, no imports.
3. **Suspicious API categorization** – imports grouped into injection, anti-analysis, persistence, keylogging, networking, crypto, dynamic loading, execution. Presence is evidence, not proof.
4. **YARA** – rules in `rules/*.yar`. `yara-python` when available, otherwise a limited string-only fallback.
5. **Behavior** – parses sandbox JSON for LOLBin execution, encoded PowerShell, shadow-copy deletion, Run-key persistence, mass file modification, encrypted-extension writes, network activity. Combined with noisy-OR into a 0–1 score.
6. **Features** – 12 structural + 8 API-category + 7 behavior features (`features/vectorizer.py`). Deliberately interpretable so SHAP output is readable by analysts.
7. **Models** – Random Forest and XGBoost. Threshold chosen on the validation split to meet a target FPR (default 1%).
8. **Explainability** – TreeSHAP per-sample contributions.
9. **Risk scoring** – weighted average of available components (ML 0.5, YARA 0.25, behavior 0.25), with a floor so a single very strong signal is not diluted. Bands: clean / low / medium / high / critical.
10. **Reporting** – IOC extraction from printable strings and behavior data; JSON + Markdown reports; persisted via SQLAlchemy.

## Design decisions
- **Interpretable features over raw byte models**: lower ceiling than end-to-end deep models, but every verdict can be explained to an analyst.
- **Same feature space for live PEs and EMBER** (`ember_loader.py`) so a model trained on EMBER can score uploaded files.
- **Static-only by design**: dynamic behavior is imported from reports, keeping the service safe to run anywhere.
