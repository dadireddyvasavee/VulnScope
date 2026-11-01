"""CVSS v3.1-style severity *presentation*. Base vectors are typical for each CWE in a network-facing
web app; they are estimates for prioritization, not official CVSS scores for a specific CVE."""
from __future__ import annotations
import math

W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
     "PR": {"N": 0.85, "L": 0.62, "H": 0.27}, "UI": {"N": 0.85, "R": 0.62},
     "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0}, "A": {"H": 0.56, "L": 0.22, "N": 0}}

CWE_VECTORS = {
    "CWE-78": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-89": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-95": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-502": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-22": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-918": "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
    "CWE-798": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-295": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-327": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-489": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "CWE-377": "AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = dict(p.split(":") for p in vector.split("/"))
    changed = m["S"] == "C"
    pr = W["PR"][m["PR"]]
    if changed and m["PR"] in ("L", "H"):
        pr = {"L": 0.68, "H": 0.5}[m["PR"]]
    iss = 1 - (1 - W["C"][m["C"]]) * (1 - W["I"][m["I"]]) * (1 - W["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * pr * W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))


def rating(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"


def apply_severity(f) -> None:
    vec = CWE_VECTORS.get(f.cwe, "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N")
    s = base_score(vec)
    f.cvss = s
    f.severity = rating(s)
    # priority: severity x confidence (triage prob if available); reachability from real input boosts
    conf = f.triage_prob if f.triage_prob is not None else f.confidence
    f.priority = round((s / 10) * conf * (1.25 if f.tainted else 1.0), 4)
