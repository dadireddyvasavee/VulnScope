"""End-to-end analysis of bytes already on disk. Never executes the sample."""
from __future__ import annotations
import re
from pathlib import Path

from aegis.ingest.hashing import hash_bytes
from aegis.static.pe_parser import parse_pe
from aegis.yara_engine.engine import YaraEngine
from aegis.behavior.sandbox_parser import parse_report, behavior_score
from aegis.features.vectorizer import vectorize
from aegis.scoring.risk import risk_score
from aegis.reporting.ioc import extract_iocs
from aegis.reporting.report import build_report

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
_ASCII = re.compile(rb"[\x20-\x7e]{6,}")


class Analyzer:
    def __init__(self, model=None, rules_dir=RULES_DIR):
        self.model = model
        self.yara = YaraEngine(rules_dir)

    def analyze(self, data: bytes, sandbox_report: dict | None = None, explain: bool = True) -> dict:
        hashes = hash_bytes(data)
        pe = parse_pe(data)
        matches = self.yara.scan(data)
        beh = parse_report(sandbox_report) if sandbox_report else None
        ml_prob, explanation = None, None
        if self.model is not None and pe.is_pe:
            x = vectorize(pe, len(data), beh)
            ml_prob = float(self.model.predict_proba(x.reshape(1, -1))[0, 1])
            if explain:
                from aegis.explain.shap_explainer import explain as shap_explain
                explanation = shap_explain(self.model, x)
        strings = b"\n".join(_ASCII.findall(data)).decode(errors="ignore")
        if beh:
            strings += "\n" + "\n".join(beh.domains + beh.ips + beh.http_urls + beh.commands)
        iocs = extract_iocs(strings)
        risk = risk_score(ml_prob, matches, behavior_score(beh) if beh else None)
        return build_report(hashes, pe, matches, beh, risk, explanation, iocs)
