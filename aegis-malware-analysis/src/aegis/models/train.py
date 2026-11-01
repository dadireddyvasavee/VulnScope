"""Train + evaluate RF and XGBoost with a validation-chosen threshold. Results are written
to JSON; nothing is hard-coded. Usage:
  python -m aegis.models.train --data data/ember/train_features_*.jsonl data/ember/test_features.jsonl \
      --val-month 2018-09 --test-month 2018-11 --out artifacts/
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from aegis.features.vectorizer import FEATURE_NAMES
from aegis.models.metrics import security_metrics, threshold_at_fpr, latency_ms


def build_models(seed: int = 42) -> dict:
    return {
        "random_forest": RandomForestClassifier(n_estimators=300, n_jobs=-1, class_weight="balanced",
                                                random_state=seed),
        "xgboost": XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.8,
                                 colsample_bytree=0.8, eval_metric="logloss", random_state=seed, n_jobs=-1),
    }


def train_and_evaluate(X, y, train_idx, val_idx, test_idx, target_fpr=0.01, feature_mask=None, seed=42):
    cols = np.arange(X.shape[1]) if feature_mask is None else np.where(feature_mask)[0]
    Xs = X[:, cols]
    results, fitted = {}, {}
    for name, model in build_models(seed).items():
        model.fit(Xs[train_idx], y[train_idx])
        thr = threshold_at_fpr(y[val_idx], model.predict_proba(Xs[val_idx])[:, 1], target_fpr)
        test_scores = model.predict_proba(Xs[test_idx])[:, 1]
        m = security_metrics(y[test_idx], test_scores, thr)
        m["latency_ms_per_sample"] = latency_ms(model.predict_proba, Xs[test_idx][:2000])
        m["n_train"], m["n_val"], m["n_test"] = len(train_idx), len(val_idx), len(test_idx)
        results[name], fitted[name] = m, model
    return results, fitted


def ablation(X, y, tr, va, te, groups: dict[str, list[str]]):
    out = {}
    for gname, feats in groups.items():
        mask = np.array([f in feats for f in FEATURE_NAMES])
        out[gname], _ = train_and_evaluate(X, y, tr, va, te, feature_mask=mask)
    return out


def main():
    from aegis.features.ember_loader import load_jsonl, temporal_split, dedupe_check
    from aegis.features.vectorizer import STATIC_FEATURES, API_FEATURES
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="+", required=True)
    ap.add_argument("--val-month", required=True)
    ap.add_argument("--test-month", required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--out", default="artifacts")
    a = ap.parse_args()
    X, y, months, hashes = load_jsonl(a.data, a.limit)
    tr, va, te = temporal_split(months, a.val_month, a.test_month)
    leaks = dedupe_check(hashes, tr, va, te)
    if leaks:
        raise SystemExit(f"Leakage: {leaks} sha256 values occur in multiple splits")
    results, models = train_and_evaluate(X, y, tr, va, te)
    results["ablation"] = ablation(X, y, tr, va, te, {
        "structure_only": STATIC_FEATURES, "imports_only": API_FEATURES,
        "structure_plus_imports": STATIC_FEATURES + API_FEATURES})
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(results, indent=2))
    for n, m in models.items():
        joblib.dump(m, out / f"{n}.joblib")
    print(json.dumps({k: v for k, v in results.items() if k != "ablation"}, indent=2))


if __name__ == "__main__":
    main()
