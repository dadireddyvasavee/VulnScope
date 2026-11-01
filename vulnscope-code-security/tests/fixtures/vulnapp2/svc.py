"""Second DELIBERATELY VULNERABLE corpus (held-out repo for triage tests)."""
import os
import pickle
import subprocess
from flask import request


def handler():
    path = request.args.get("p")
    data = open(path).read()  # VULN: CWE-22
    os.popen("cat " + path)  # VULN: CWE-78
    return data


def cache_load(blob):
    return pickle.loads(blob)  # SAFE: CWE-502


def job(cur):
    tbl = os.environ.get("TABLE")
    cur.execute("SELECT * FROM " + tbl)  # SAFE: CWE-89
    subprocess.call("make " + tbl, shell=True)  # SAFE: CWE-78
