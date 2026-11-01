"""Evidence-backed risk score: combines ML probability, YARA severity and behavior score.
Every component contributing to the score is returned as evidence."""
from __future__ import annotations

YARA_SEVERITY = {"info": 0.0, "low": 0.3, "medium": 0.6, "high": 0.9, "critical": 1.0}
WEIGHTS = {"ml": 0.5, "yara": 0.25, "behavior": 0.25}
BANDS = [(0.8, "critical"), (0.6, "high"), (0.35, "medium"), (0.15, "low"), (0.0, "clean")]


def risk_score(ml_prob: float | None, yara_matches: list, behavior: float | None) -> dict:
    yara = max((YARA_SEVERITY.get(m.meta.get("severity", "low"), 0.3) for m in yara_matches), default=0.0)
    comps = {"ml": ml_prob, "yara": yara, "behavior": behavior}
    avail = {k: v for k, v in comps.items() if v is not None}
    total_w = sum(WEIGHTS[k] for k in avail)
    score = sum(WEIGHTS[k] * v for k, v in avail.items()) / total_w if total_w else 0.0
    # a single very strong signal should not be diluted away
    score = max(score, 0.9 * max(avail.values(), default=0.0)) if max(avail.values(), default=0) >= 0.9 else score
    band = next(b for t, b in BANDS if score >= t)
    return {"score": round(score, 4), "verdict": band, "components": avail,
            "evidence": {"yara_rules": [m.rule for m in yara_matches]}}
