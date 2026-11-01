from vulnscope.taint.engine import analyze_source


def cwes(src):
    return {(f.cwe, f.line, f.tainted) for f in analyze_source(src)}


def test_flask_sqli_fstring_with_trace():
    src = '''from flask import request
def h():
    n = request.args.get("n")
    q = f"select * from t where n='{n}'"
    db.execute(q)
'''
    f = [x for x in analyze_source(src) if x.cwe == "CWE-89"][0]
    assert f.tainted and f.line == 5
    kinds = [s.kind for s in f.trace]
    assert kinds[0] == "source" and kinds[-1] == "sink" and "propagate" in kinds


def test_parameterized_query_is_clean():
    src = '''from flask import request
def h():
    n = request.args.get("n")
    db.execute("select * from t where n=?", (n,))
'''
    assert not analyze_source(src)


def test_sanitizer_breaks_taint():
    src = '''import os, shlex
from flask import request
def h():
    x = shlex.quote(request.args["x"])
    os.system("ls " + x)
'''
    assert not analyze_source(src)


def test_import_alias_resolution():
    src = '''import subprocess as sp
from os import system as run_it
x = input()
sp.call(x, shell=True)
run_it(x)
'''
    got = cwes(src)
    assert ("CWE-78", 4, True) in got and ("CWE-78", 5, True) in got


def test_interprocedural_param_to_sink():
    src = '''import os
from flask import request
def helper(cmd):
    os.system(cmd)
def h():
    helper(request.args.get("c"))
def safe():
    helper("ls")
'''
    fs = analyze_source(src)
    assert len(fs) == 1 and fs[0].line == 4 and fs[0].tainted
    assert any(s.kind == "call" for s in fs[0].trace)


def test_return_passthrough_and_source_function():
    src = '''import os
def get_input():
    return input()
def wrap(v):
    return "echo " + v
def main():
    os.system(wrap(get_input()))
'''
    assert ("CWE-78", 7, True) in cwes(src)


def test_untainted_pickle_still_reported_low_confidence():
    fs = analyze_source("import pickle\ndef f(b):\n    return pickle.loads(b)\n")
    assert len(fs) == 1 and not fs[0].tainted and fs[0].confidence < 0.5


def test_route_param_is_source():
    src = '''from flask import Flask
app = Flask(__name__)
@app.route("/f/<name>")
def f(name):
    return open(name).read()
'''
    assert ("CWE-22", 5, True) in cwes(src)


def test_loop_and_container_propagation():
    src = '''import os
import sys
for arg in sys.argv[1:]:
    parts = [arg, "x"]
    os.system(" ".join(parts))
'''
    assert ("CWE-78", 5, True) in cwes(src)


def test_syntax_error_does_not_crash_scanner():
    from vulnscope.scanner import scan_source
    assert scan_source("def broken(:\n", "x.py") == []


def test_dynamic_sql_heuristic_respects_sanitizers():
    unsafe = analyze_source('def f(cur, x):\n    q = "select * from t where a=%s" % x\n    cur.execute(q)\n')
    assert unsafe == []  # x is a parameter: recorded in the summary, reported only when a tainted caller exists
    heur = analyze_source('def f(cur):\n    x = get_value()\n    cur.execute("select %s" % x)\n')
    assert len(heur) == 1 and not heur[0].tainted and heur[0].confidence < 0.5
    safe = analyze_source('def f(cur, x):\n    n = int(x)\n    cur.execute("select %d" % n)\n')
    assert safe == []
