"""Adapters for Bandit and Semgrep (run as subprocesses with argument lists; no shell)."""
from __future__ import annotations
import json
import shutil
import subprocess

from vulnscope.models import Finding, TraceStep

BANDIT_CWE = {"B602": "CWE-78", "B605": "CWE-78", "B604": "CWE-78", "B607": "CWE-78", "B608": "CWE-89",
              "B301": "CWE-502", "B302": "CWE-502", "B506": "CWE-502", "B307": "CWE-95", "B102": "CWE-95",
              "B105": "CWE-798", "B106": "CWE-798", "B107": "CWE-798", "B501": "CWE-295", "B303": "CWE-327",
              "B324": "CWE-327", "B201": "CWE-489", "B306": "CWE-377"}


def run_bandit(path: str) -> list[Finding]:
    if not shutil.which("bandit"):
        return []
    p = subprocess.run(["bandit", "-r", path, "-f", "json", "-q"], capture_output=True, text=True)
    data = json.loads(p.stdout or "{}")
    out = []
    for r in data.get("results", []):
        cwe = f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else BANDIT_CWE.get(r["test_id"], "CWE-0")
        out.append(Finding(rule_id=r["test_id"], cwe=cwe, title=r["issue_text"], file=r["filename"],
                           line=r["line_number"], col=r.get("col_offset", 0), snippet=r.get("code", "").strip()[:200],
                           function=None, tainted=False, trace=[TraceStep(r["line_number"], "sink", r["test_name"])],
                           engine="bandit", confidence={"HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3}[r["issue_confidence"]]))
    return out


def run_semgrep(path: str, config: str = "p/python") -> list[Finding]:
    if not shutil.which("semgrep"):
        return []
    p = subprocess.run(["semgrep", "--config", config, "--json", "--quiet", path], capture_output=True, text=True)
    data = json.loads(p.stdout or "{}")
    out = []
    for r in data.get("results", []):
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe = (cwes[0] if isinstance(cwes, list) and cwes else str(cwes)).split(":")[0] or "CWE-0"
        ln = r["start"]["line"]
        out.append(Finding(rule_id=r["check_id"], cwe=cwe, title=r["extra"].get("message", "")[:160], file=r["path"],
                           line=ln, col=r["start"].get("col", 0), snippet=r["extra"].get("lines", "").strip()[:200],
                           function=None, tainted=False, trace=[TraceStep(ln, "sink", r["check_id"])],
                           engine="semgrep", confidence=0.6))
    return out
