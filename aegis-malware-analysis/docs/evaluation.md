# Evaluation Methodology

## Datasets
| Dataset | Use | Notes |
|---|---|---|
| EMBER 2018 v2 | Train / val / test | Feature JSON only; `appeared` month enables temporal split |
| BODMAS | Family classification, cross-dataset generalization | Different collection period and source |
| Clean Windows PEs | Real-world false-positive check | Never committed |

## Splits and leakage prevention
- **Temporal split**: train `< 2018-09`, validation `2018-09..2018-10`, test `>= 2018-11`. Mimics deployment, where models face samples newer than training data.
- **Hash de-duplication**: `dedupe_check` aborts training if any SHA-256 appears in more than one split.
- Threshold selection uses **validation only**; test is touched once.

## Metrics
Precision, recall, F1, ROC-AUC, FPR, FNR, per-sample inference latency (written to `artifacts/metrics.json`). Accuracy alone is not reported because class balance varies over time.

**Why both error types matter**
- *False negative* – malicious file passes; potential infection, data loss, lateral movement.
- *False positive* – legitimate software blocked or quarantined; analyst fatigue and loss of trust in alerts.
Production detectors operate at very low FPR, so we report recall **at a fixed FPR** (1%) rather than at 0.5.

## Ablation
`train.py` reports structure-only, imports-only and structure+imports models. Behavior features are evaluated separately on samples with sandbox reports, since EMBER has none.

## Robustness / generalization
- Train on EMBER, test on BODMAS (cross-dataset).
- Track metric decay per test month (concept drift).
- Packed vs. unpacked subsets (high-entropy sections) to check reliance on packing as a proxy.

## Results
Fill this section only from `artifacts/metrics.json` produced by your own run. Record dataset version, commit hash, seed and date.

| Model | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Latency (ms) |
|---|---|---|---|---|---|---|---|
| Random Forest | | | | | | | |
| XGBoost | | | | | | | |
