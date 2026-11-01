"""Scans the deliberately vulnerable fixture app and writes sample output + benchmark vs annotations."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vulnscope.scanner import scan_path
from vulnscope.benchmark.groundtruth import load_annotations, score

app = ROOT / "tests/fixtures/vulnapp"
res = scan_path(app)
out = ROOT / "docs/sample_output"
out.mkdir(parents=True, exist_ok=True)
(out / "scan_vulnapp.json").write_text(json.dumps(res, indent=2))
m = score(res["findings"], load_annotations(app))
(out / "fixture_scores.json").write_text(json.dumps(m, indent=2))
for f in res["findings"][:5]:
    print(f"[{f['severity']}] {f['cwe']} {f['file']}:{f['line']} {f['title']}")
    for s in f["trace"]:
        print(f"     {s['kind']:9} L{s['line']}: {s['detail']}")
print("\nFixture micro:", m["micro"], "\n(fixture regression check only - not a real-world benchmark)")
