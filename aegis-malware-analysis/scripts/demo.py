"""Generates sample output from harmless synthetic inputs (no real malware)."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from aegis.pipeline import Analyzer
from aegis.reporting.report import to_markdown
from tests.fixtures.make_pe import build_pe, INJECTOR_IMPORTS

sample = build_pe(INJECTOR_IMPORTS, rwx=True, high_entropy=True)
sb = json.loads((ROOT / "tests/fixtures/sandbox_ransom_like.json").read_text())
report = Analyzer().analyze(sample, sb)
out = ROOT / "docs/sample_output"
out.mkdir(parents=True, exist_ok=True)
(out / "report.json").write_text(json.dumps(report, indent=2))
(out / "report.md").write_text(to_markdown(report))
print(to_markdown(report))
