"""Ground truth from inline annotations in labeled corpora:
    some_sink(x)   # VULN: CWE-89      -> a true vulnerability is on this line
    safe_call(x)   # SAFE: CWE-89      -> a tool reporting CWE-89 here is a false positive
Also loads JSONL ground truth for external corpora: {"file","line","cwe","label": 1|0}."""
from __future__ import annotations
import json
import re
from collections import defaultdict
from pathlib import Path

ANN = re.compile(r"#\s*(VULN|SAFE):\s*(CWE-\d+(?:\s*,\s*CWE-\d+)*)")


def load_annotations(root: str | Path) -> dict[tuple, int]:
    root = Path(root)
    gt = {}
    for p in root.rglob("*.py"):
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            m = ANN.search(line)
            if m:
                for cwe in re.split(r"\s*,\s*", m.group(2)):
                    gt[(str(p.relative_to(root)), i, cwe)] = 1 if m.group(1) == "VULN" else 0
    return gt


def load_jsonl(path) -> dict[tuple, int]:
    return {(r["file"], r["line"], r["cwe"]): int(r["label"])
            for r in (json.loads(l) for l in Path(path).read_text().splitlines() if l.strip())}


def score(findings: list[dict], gt: dict[tuple, int], line_tolerance: int = 0) -> dict:
    """Per-CWE precision/recall/F1. A finding matches a VULN label with the same file+CWE within tolerance.
    Findings on unlabeled lines count as FP (corpora must be fully annotated for their CWEs)."""
    vulns = {k for k, v in gt.items() if v == 1}
    by_cwe = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    matched = set()
    labeled_cwes = {k[2] for k in gt}
    for f in findings:
        if f["cwe"] not in labeled_cwes:
            continue
        hit = next((k for k in vulns if k[0] == f["file"] and k[2] == f["cwe"] and abs(k[1] - f["line"]) <= line_tolerance), None)
        if hit and hit not in matched:
            matched.add(hit)
            by_cwe[f["cwe"]]["tp"] += 1
        elif not hit:
            by_cwe[f["cwe"]]["fp"] += 1
    for k in vulns - matched:
        by_cwe[k[2]]["fn"] += 1
    out = {}
    for c, d in sorted(by_cwe.items()):
        p = d["tp"] / (d["tp"] + d["fp"]) if d["tp"] + d["fp"] else 0.0
        r = d["tp"] / (d["tp"] + d["fn"]) if d["tp"] + d["fn"] else 0.0
        out[c] = {**d, "precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}
    T = sum(d["tp"] for d in by_cwe.values()); P = sum(d["fp"] for d in by_cwe.values()); N = sum(d["fn"] for d in by_cwe.values())
    mp, mr = (T / (T + P) if T + P else 0.0), (T / (T + N) if T + N else 0.0)
    out["micro"] = {"tp": T, "fp": P, "fn": N, "precision": round(mp, 4), "recall": round(mr, 4),
                    "f1": round(2 * mp * mr / (mp + mr), 4) if mp + mr else 0.0}
    return out
