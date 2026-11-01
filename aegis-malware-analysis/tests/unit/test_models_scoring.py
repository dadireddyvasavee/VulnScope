import numpy as np
from aegis.models.metrics import security_metrics, threshold_at_fpr
from aegis.models.train import train_and_evaluate
from aegis.features.ember_loader import temporal_split, dedupe_check, ember_record_to_vector
from aegis.features.vectorizer import FEATURE_NAMES
from aegis.scoring.risk import risk_score
from aegis.yara_engine.engine import YaraMatch


def test_metrics_confusion():
    m = security_metrics([0, 0, 1, 1], [0.1, 0.9, 0.8, 0.2])
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 1, 1)
    assert m["fpr"] == 0.5 and m["fnr"] == 0.5


def test_threshold_respects_target_fpr():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(1000), np.ones(1000)]
    s = np.r_[rng.random(1000) * 0.7, 0.3 + rng.random(1000) * 0.7]
    t = threshold_at_fpr(y, s, 0.01)
    assert security_metrics(y, s, t)["fpr"] <= 0.01


def test_temporal_split_and_leak_check():
    months = np.array(["2018-01", "2018-05", "2018-09", "2018-11", "2018-12"])
    tr, va, te = temporal_split(months, "2018-09", "2018-11")
    assert list(tr) == [0, 1] and list(va) == [2] and list(te) == [3, 4]
    h = np.array(["a", "b", "c", "a", "d"])
    assert dedupe_check(h, tr, va, te) == 1


def test_ember_record_vector_shape():
    rec = {"general": {"size": 1000, "exports": 0}, "histogram": [1] * 256,
           "section": {"sections": [{"entropy": 7.5, "props": ["MEM_EXECUTE", "MEM_WRITE"]}]},
           "imports": {"kernel32.dll": ["VirtualAllocEx"]}, "header": {"coff": {"characteristics": []}}}
    v = ember_record_to_vector(rec)
    assert v.shape == (len(FEATURE_NAMES),) and v[5] == 1


def test_training_pipeline_runs_on_synthetic_data():
    rng = np.random.default_rng(1)
    n = 600
    y = rng.integers(0, 2, n)
    X = rng.normal(size=(n, len(FEATURE_NAMES))).astype(np.float32)
    X[:, 1] += y * 2.0
    res, models = train_and_evaluate(X, y, np.arange(400), np.arange(400, 500), np.arange(500, n))
    for name in ("random_forest", "xgboost"):
        assert 0 <= res[name]["roc_auc"] <= 1 and "latency_ms_per_sample" in res[name]


def test_risk_score_bands_and_strong_signal():
    yara = [YaraMatch("r", [], {"severity": "high"}, [])]
    r = risk_score(0.95, yara, None)
    assert r["verdict"] == "critical"
    assert risk_score(0.02, [], 0.0)["verdict"] == "clean"
    assert risk_score(None, [], None)["score"] == 0


def test_shap_rf_and_xgb():
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    from aegis.explain.shap_explainer import explain
    rng = np.random.default_rng(0)
    X = rng.random((200, len(FEATURE_NAMES)))
    y = (X[:, 3] > 0.5).astype(int)
    for m in (RandomForestClassifier(n_estimators=20, random_state=0), XGBClassifier(n_estimators=20)):
        e = explain(m.fit(X, y), X[0], top_k=3)
        assert e[0]["feature"] == FEATURE_NAMES[3]
