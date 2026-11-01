"""vulnscope scan <path> [--external] [--json out.json] [--fail-on high]"""
import argparse
import json
import sys

from vulnscope.scanner import scan_path

ORDER = ["low", "medium", "high", "critical"]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vulnscope")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("path")
    s.add_argument("--external", action="store_true", help="also run Bandit/Semgrep if installed")
    s.add_argument("--json")
    s.add_argument("--fail-on", choices=ORDER)
    a = ap.parse_args(argv)
    res = scan_path(a.path, external=a.external)
    for f in res["findings"]:
        print(f"[{f['severity'].upper():8}] {f['cwe']:8} {f['file']}:{f['line']}  {f['title']}  (prio {f['priority']})")
    print(f"\n{len(res['findings'])} findings in {res['files']} files / {res['loc']} LOC ({res['seconds']}s)")
    if a.json:
        open(a.json, "w").write(json.dumps(res, indent=2))
    if a.fail_on and any(ORDER.index(f["severity"]) >= ORDER.index(a.fail_on) for f in res["findings"] if f["severity"] in ORDER):
        sys.exit(1)


if __name__ == "__main__":
    main()
