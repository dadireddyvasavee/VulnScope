"""Loads EMBER-format JSONL (raw features) into the AEGIS feature space and builds a
TEMPORAL split (train on older samples, test on newer) to avoid leakage.
Download EMBER 2018 via scripts/download_ember.sh; samples with label -1 (unlabeled) are dropped."""
from __future__ import annotations
import json
from pathlib import Path
import numpy as np

from aegis.static.suspicious_apis import SUSPICIOUS_APIS
from aegis.features.vectorizer import FEATURE_NAMES, BEHAVIOR_FEATURES


def ember_record_to_vector(rec: dict) -> np.ndarray:
    gen, sec, imp = rec.get("general", {}), rec.get("section", {}), rec.get("imports", {})
    sections = sec.get("sections", [])
    ents = [s.get("entropy", 0.0) for s in sections] or [0.0]
    hist = np.asarray(rec.get("histogram", [0] * 256), dtype=float)
    p = hist / hist.sum() if hist.sum() else hist
    overall = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
    flat = [f for fs in imp.values() for f in fs]
    names = set(flat)
    rwx = sum({"MEM_EXECUTE", "MEM_WRITE"} <= set(s.get("props", [])) for s in sections)
    v = [np.log1p(gen.get("size", 0)), overall, len(sections), max(ents), float(np.mean(ents)), rwx,
         sum(e > 7.2 for e in ents), len(imp), len(flat), gen.get("exports", 0),
         float("DLL" in rec.get("header", {}).get("coff", {}).get("characteristics", [])),
         float(gen.get("has_signature", 0) == 0) + float(not imp)]
    v += [len(names & apis) for apis in SUSPICIOUS_APIS.values()]
    v += [0.0] * len(BEHAVIOR_FEATURES)
    assert len(v) == len(FEATURE_NAMES)
    return np.asarray(v, dtype=np.float32)


def load_jsonl(paths: list[str | Path], limit: int | None = None):
    X, y, months, hashes = [], [], [], []
    for path in paths:
        with open(path) as f:
            for line in f:
                rec = json.loads(line)
                if rec.get("label", -1) == -1:
                    continue
                X.append(ember_record_to_vector(rec))
                y.append(int(rec["label"]))
                months.append(rec.get("appeared", "1970-01"))
                hashes.append(rec.get("sha256", ""))
                if limit and len(X) >= limit:
                    break
    return np.vstack(X), np.asarray(y), np.asarray(months), np.asarray(hashes)


def temporal_split(months: np.ndarray, val_month: str, test_month: str):
    """train: < val_month, val: [val_month, test_month), test: >= test_month."""
    train = months < val_month
    val = (months >= val_month) & (months < test_month)
    test = months >= test_month
    return np.where(train)[0], np.where(val)[0], np.where(test)[0]


def dedupe_check(hashes: np.ndarray, *index_sets) -> int:
    """Returns number of sha256 values that appear in more than one split (should be 0)."""
    seen = [set(hashes[i]) - {""} for i in index_sets]
    overlap = set()
    for a in range(len(seen)):
        for b in range(a + 1, len(seen)):
            overlap |= seen[a] & seen[b]
    return len(overlap)
