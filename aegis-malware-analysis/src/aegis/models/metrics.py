from __future__ import annotations
import time
import numpy as np
from sklearn.metrics import (precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix)


def security_metrics(y_true, y_score, threshold: float = 0.5) -> dict:
    y_true = np.asarray(y_true)
    y_pred = (np.asarray(y_score) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)) if len(set(y_true)) > 1 else float("nan"),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "fnr": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def threshold_at_fpr(y_true, y_score, target_fpr: float = 0.01) -> float:
    """Pick the lowest threshold whose FPR on the VALIDATION set is <= target."""
    y_true, y_score = np.asarray(y_true), np.asarray(y_score)
    neg = np.sort(y_score[y_true == 0])
    if len(neg) == 0:
        return 0.5
    k = int(np.ceil((1 - target_fpr) * len(neg))) - 1
    return float(np.nextafter(neg[min(max(k, 0), len(neg) - 1)], 1.0))


def latency_ms(predict_fn, X, repeats: int = 3) -> float:
    best = float("inf")
    for _ in range(repeats):
        t = time.perf_counter()
        predict_fn(X)
        best = min(best, time.perf_counter() - t)
    return 1000 * best / max(len(X), 1)
