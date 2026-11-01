from __future__ import annotations
from datetime import datetime, timezone


def build_report(hashes: dict, pe, yara_matches, behavior, risk: dict, explanation, iocs: dict) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample": hashes,
        "verdict": risk["verdict"], "risk_score": risk["score"], "risk_components": risk["components"],
        "static": pe.to_dict() if pe else None,
        "yara": [{"rule": m.rule, "tags": m.tags, "severity": m.meta.get("severity"),
                  "description": m.meta.get("description")} for m in yara_matches],
        "behavior": {"signals": behavior.signals} if behavior else None,
        "explanation": explanation,
        "iocs": iocs,
    }


def to_markdown(r: dict) -> str:
    s = r["sample"]
    lines = [f"# AEGIS Analysis Report", f"**SHA-256:** `{s['sha256']}`  ", f"**Size:** {s['size']} bytes  ",
             f"**Verdict:** {r['verdict'].upper()} (score {r['risk_score']})", "", "## Risk components"]
    lines += [f"- {k}: {v:.3f}" for k, v in r["risk_components"].items()]
    if r["yara"]:
        lines += ["", "## YARA matches"] + [f"- {y['rule']} ({y['severity']}): {y['description']}" for y in r["yara"]]
    if r["static"] and r["static"]["suspicious_apis"]:
        lines += ["", "## Suspicious imports"] + [f"- {c}: {', '.join(a)}" for c, a in r["static"]["suspicious_apis"].items()]
    if r["static"] and r["static"]["anomalies"]:
        lines += ["", "## Structural anomalies"] + [f"- {a}" for a in r["static"]["anomalies"]]
    if r["behavior"]:
        lines += ["", "## Behavior signals"] + [f"- {k}: {len(v)} event(s)" for k, v in r["behavior"]["signals"].items()]
    if r["explanation"]:
        lines += ["", "## Model explanation (SHAP)"] + [f"- {e['feature']} = {e['value']:.2f} -> {e['contribution']:+.4f}" for e in r["explanation"]]
    ioc_lines = [f"- {k}: {', '.join(v)}" for k, v in r["iocs"].items() if v]
    if ioc_lines:
        lines += ["", "## IOCs"] + ioc_lines
    return "\n".join(lines) + "\n"
