"""Per-sample SHAP explanations for tree models.
XGBoost: uses the booster's native TreeSHAP (pred_contribs) - same algorithm as shap.TreeExplainer and
robust to shap/xgboost version mismatches. Other tree models (e.g. RandomForest): shap.TreeExplainer."""
from __future__ import annotations
import numpy as np

from aegis.features.vectorizer import FEATURE_NAMES


def shap_values(model, x: np.ndarray) -> np.ndarray:
    x = x.reshape(1, -1)
    if hasattr(model, "get_booster"):
        import xgboost as xgb
        contribs = model.get_booster().predict(xgb.DMatrix(x), pred_contribs=True)
        return np.asarray(contribs).reshape(-1)[:-1]  # last column is the bias term
    import shap
    sv = shap.TreeExplainer(model).shap_values(x)
    if isinstance(sv, list):
        sv = sv[1]
    sv = np.asarray(sv)
    if sv.ndim == 3:
        sv = sv[..., 1]
    return sv.reshape(-1)


def explain(model, x: np.ndarray, top_k: int = 8, feature_names=FEATURE_NAMES) -> list[dict]:
    """Top-k contributions. Positive = pushes toward malicious (log-odds for XGBoost)."""
    sv = shap_values(model, x)
    order = np.argsort(-np.abs(sv))[:top_k]
    return [{"feature": feature_names[i], "value": float(x[i]), "contribution": round(float(sv[i]), 5)}
            for i in order]
