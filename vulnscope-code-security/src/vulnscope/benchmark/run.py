"""Benchmark VulnScope vs Bandit vs Semgrep on an annotated corpus.
python -m vulnscope.benchmark.run <corpus_dir> [--gt gt.jsonl] [--out artifacts/benchmark.json]"""
from __future__ import annotations
import argparse
import json
import time
from pathlib import Path

from vulnscope.benchmark.groundtruth import load_annotations, load_jsonl, score
from vulnscope.scanner import scan_path
from vulnscope.external import run_bandit, run_semgrep


def _rel(findings, root):
    out = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        try:
            d["file"] = str(Path(d["file"]).resolve().relative_to(Path(root).resolve()))
        except ValueError:
            pass
        out.append(d)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--gt")
    ap.add_argument("--out", default="artifacts/benchmark.json")
    ap.add_argument("--tolerance", type=int, default=0)
    a = ap.parse_args()
    gt = load_jsonl(a.gt) if a.gt else load_annotations(a.corpus)
    res = {}
    t = time.perf_counter(); vs = scan_path(a.corpus); res["vulnscope"] = {"metrics": score(vs["findings"], gt, a.tolerance), "seconds": time.perf_counter() - t}
    for name, fn in (("bandit", run_bandit), ("semgrep", run_semgrep)):
        t = time.perf_counter(); f = fn(a.corpus)
        res[name] = {"metrics": score(_rel(f, a.corpus), gt, a.tolerance), "seconds": time.perf_counter() - t,
                     "available": bool(f) or None}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    for k, v in res.items():
        print(k, v["metrics"].get("micro"))


if __name__ == "__main__":
    main()
