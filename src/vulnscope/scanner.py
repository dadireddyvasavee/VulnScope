"""Scan orchestration: walk repo, run taint + pattern rules (+ optional Bandit/Semgrep), merge,
triage, score and attach remediation."""
from __future__ import annotations
import time
from pathlib import Path

from vulnscope.models import Finding
from vulnscope.taint.engine import analyze_source
from vulnscope.rules.pattern_rules import run_pattern_rules
from vulnscope.severity.cvss import apply_severity
from vulnscope.remediation.advisor import remediation_for

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages", ".tox", "build", "dist"}


def iter_py(root: Path):
    if root.is_file():
        yield root
        return
    for p in root.rglob("*.py"):
        if not (set(p.relative_to(root).parts) & SKIP_DIRS):
            yield p


def scan_source(source: str, filename: str) -> list[Finding]:
    try:
        f = analyze_source(source, filename)
    except SyntaxError:
        return []
    keys = {(x.line, x.cwe) for x in f}
    return f + [p for p in run_pattern_rules(source, filename) if (p.line, p.cwe) not in keys]


def scan_path(path: str | Path, external: bool = False, triage=None) -> dict:
    root = Path(path)
    t0 = time.perf_counter()
    findings, files, loc, errors = [], 0, 0, []
    for p in iter_py(root):
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            errors.append(str(e))
            continue
        files += 1
        loc += src.count("\n") + 1
        rel = str(p.relative_to(root)) if root.is_dir() else p.name
        findings += scan_source(src, rel)
    if external:
        from vulnscope.external import run_bandit, run_semgrep
        own = {(f.file, f.line, f.cwe) for f in findings}
        for ext in run_bandit(str(root)) + run_semgrep(str(root)):
            try:
                ext.file = str(Path(ext.file).resolve().relative_to(root.resolve()))
            except ValueError:
                pass
            if (ext.file, ext.line, ext.cwe) not in own:
                findings.append(ext)
    return finalize(findings, triage, files, loc, time.perf_counter() - t0, errors)


def finalize(findings, triage, files, loc, secs, errors=()):
    if triage is not None:
        triage.score(findings)
    for f in findings:
        apply_severity(f)
        f.remediation = remediation_for(f)
    findings.sort(key=lambda f: -(f.priority or 0))
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return {"files": files, "loc": loc, "seconds": round(secs, 3),
            "ms_per_kloc": round(1000 * secs / max(loc / 1000, 1e-9), 2),
            "severity_breakdown": sev, "findings": [f.to_dict() for f in findings], "errors": list(errors)}
