from vulnscope.rules.pattern_rules import run_pattern_rules
from vulnscope.severity.cvss import base_score, rating, apply_severity
from vulnscope.remediation.advisor import remediation_for
from vulnscope.taint.engine import analyze_source


def test_hardcoded_secret_rules():
    src = 'PASSWORD = "hunter22"\nTOKEN = "changeme"\nAPI_KEY = ""\ncfg = {"api_key": "abcd1234"}\nlogin(password="realpass1")\n'
    lines = {f.line for f in run_pattern_rules(src, "x.py") if f.cwe == "CWE-798"}
    assert lines == {1, 4, 5}


def test_tls_debug_hash_rules():
    src = 'import requests, hashlib\nrequests.get(u, verify=False)\napp.run(debug=True)\nhashlib.md5(b"")\n'
    assert {f.cwe for f in run_pattern_rules(src, "x.py")} == {"CWE-295", "CWE-489", "CWE-327"}


def test_cvss_reference_values():
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N") == 7.2
    assert rating(9.8) == "critical" and rating(5.0) == "medium"


def test_priority_and_remediation_explain_source_to_sink():
    f = analyze_source('import os\nx = input()\nos.system(x)\n')[0]
    apply_severity(f)
    r = remediation_for(f)
    assert f.severity == "critical" and f.priority > 0.8
    assert "line 2" in r["source_to_sink"] and "line 3" in r["source_to_sink"]
