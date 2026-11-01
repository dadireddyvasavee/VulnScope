import io
import zipfile
from pathlib import Path
from fastapi.testclient import TestClient

from vulnscope.benchmark.groundtruth import load_annotations, score
from vulnscope.scanner import scan_path
from vulnscope.api.main import create_app

APP = Path(__file__).parents[1] / "fixtures" / "vulnapp"


def test_annotated_corpus_scores():
    gt = load_annotations(APP)
    assert sum(gt.values()) == 14
    res = scan_path(APP)
    m = score(res["findings"], gt)
    # Regression guard on the fixture corpus (not a claim about real-world performance)
    assert m["micro"]["recall"] == 1.0, m
    assert m["micro"]["fp"] == 0, m
    assert res["severity_breakdown"]


def test_findings_sorted_by_priority_with_remediation():
    res = scan_path(APP)
    pr = [f["priority"] for f in res["findings"]]
    assert pr == sorted(pr, reverse=True)
    assert all(f["remediation"]["advice"] for f in res["findings"])


def test_api_scan_snippet_zip_and_history(tmp_path):
    c = TestClient(create_app(f"sqlite:///{tmp_path}/v.db"))
    r = c.post("/scan/code", json={"code": "import os\nos.system(input())\n", "filename": "a.py"}).json()
    assert r["findings"][0]["cwe"] == "CWE-78"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in APP.glob("*.py"):
            z.write(p, f"proj/{p.name}")
    r2 = c.post("/scan/zip", files={"file": ("proj.zip", buf.getvalue())})
    assert r2.status_code == 200 and len(r2.json()["findings"]) >= 14
    hist = c.get("/scans").json()
    assert len(hist) == 2
    sid = hist[0]["id"]
    fid = c.get(f"/scans/{sid}").json()["findings"][0]["id"]
    assert c.patch(f"/findings/{fid}", json={"status": "false_positive"}).json()["status"] == "false_positive"
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../escape.py", "x=1")
    assert c.post("/scan/zip", files={"file": ("e.zip", evil.getvalue())}).status_code == 400
