import json
from pathlib import Path
import numpy as np
from fastapi.testclient import TestClient
from xgboost import XGBClassifier

from aegis.api.main import create_app
from aegis.features.vectorizer import FEATURE_NAMES
from aegis.pipeline import Analyzer
from tests.fixtures.make_pe import build_pe, BENIGN_IMPORTS, INJECTOR_IMPORTS

FX = Path(__file__).parents[1] / "fixtures"


def _toy_model():
    rng = np.random.default_rng(0)
    X = rng.random((200, len(FEATURE_NAMES)))
    y = (X[:, 12] > 0.5).astype(int)
    return XGBClassifier(n_estimators=20, max_depth=3).fit(X, y)


def test_end_to_end_pipeline_with_shap():
    sample = build_pe(INJECTOR_IMPORTS, rwx=True, extra=b"\x00http://bad.example.org/x 198.51.100.7")
    sb = json.loads((FX / "sandbox_ransom_like.json").read_text())
    r = Analyzer(model=_toy_model()).analyze(sample, sb)
    assert r["static"]["is_pe"] and r["explanation"] and len(r["explanation"]) == 8
    assert r["verdict"] in {"high", "critical"}
    assert "update-check.example-c2.net" in r["iocs"]["domains"]
    assert r["iocs"]["ips"] == []  # documentation/private ranges are filtered by design


def test_api_flow(tmp_path):
    client = TestClient(create_app(f"sqlite:///{tmp_path}/t.db"))
    assert client.get("/health").json()["status"] == "ok"
    res = client.post("/analyze", files={"file": ("b.exe", build_pe(BENIGN_IMPORTS))})
    assert res.status_code == 200 and res.json()["verdict"] == "clean"
    aid = res.json()["id"]
    assert client.get("/analyses").json()[0]["id"] == aid
    assert "AEGIS Analysis Report" in client.get(f"/analyses/{aid}/report.md").text
    assert client.post("/analyze", files={"file": ("e", b"")}).status_code == 400
