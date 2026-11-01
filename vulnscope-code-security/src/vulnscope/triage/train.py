"""Train + evaluate the triage model with REPOSITORY-LEVEL splits (no repo in two splits).
Input: several annotated corpora (one dir per repo). Each finding is labeled TP/FP against ground truth.
python -m vulnscope.triage.train corpora/repo1 corpora/repo2 ... --out artifacts/triage.json"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

from vulnscope.benchmark.groundtruth import load_annotations
from vulnscope.models import Finding, TraceStep
from vulnscope.scanner import scan_path
from vulnscope.triage.model import TriageModel


def labeled_findings(repo: Path):
    gt = load_annotations(repo)
    vulns = {k for k, v in gt.items() if v == 1}
    out = []
    for d in scan_path(repo)["findings"]:
        d = dict(d)
        d["trace"] = [TraceStep(**s) for s in d["trace"]]
        f = Finding(**d)
        out.append((f, int((f.file, f.line, f.cwe) in vulns)))
    return out


def evaluate(repos: list[Path], test_repos: list[Path], drop_threshold: float = 0.3):
    train = [x for r in repos for x in labeled_findings(r)]
    test = [x for r in test_repos for x in labeled_findings(r)]
    assert not ({str(r) for r in repos} & {str(r) for r in test_repos}), "repo leakage"
    if len({y for _, y in train}) < 2:
        raise ValueError("training corpora must contain both true and false positives")
    m = TriageModel().fit([f for f, _ in train], [y for _, y in train])
    fs, ys = [f for f, _ in test], np.array([y for _, y in test])
    p = np.array([f.triage_prob for f in m.score(fs)])
    keep = p >= drop_threshold
    base_fp, base_tp = int(((ys == 0)).sum()), int((ys == 1).sum())
    return {
        "n_train": len(train), "n_test": len(test),
        "baseline": {"tp": base_tp, "fp": base_fp, "precision": base_tp / max(len(ys), 1)},
        "after_triage": {"tp": int(((ys == 1) & keep).sum()), "fp": int(((ys == 0) & keep).sum()),
                         "precision": float(precision_score(ys, keep.astype(int), zero_division=0)),
                         "recall_retained": float(recall_score(ys, keep.astype(int), zero_division=0)),
                         "f1": float(f1_score(ys, keep.astype(int), zero_division=0))},
        "fp_reduction": 1 - ((ys == 0) & keep).sum() / base_fp if base_fp else 0.0,
        "roc_auc": float(roc_auc_score(ys, p)) if len(set(ys)) > 1 else None,
        "feature_importance": [(n, round(float(v), 4)) for n, v in m.importances()[:10]],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", nargs="+", required=True)
    ap.add_argument("--test", nargs="+", required=True)
    ap.add_argument("--out", default="artifacts/triage.json")
    a = ap.parse_args()
    res = evaluate([Path(x) for x in a.train], [Path(x) for x in a.test])
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
