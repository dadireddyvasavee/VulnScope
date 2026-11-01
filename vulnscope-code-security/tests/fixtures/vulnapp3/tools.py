"""Third labeled corpus: internal tooling with look-alike (non-exploitable) patterns."""
import marshal
import os
import subprocess


def load_compiled(blob):
    return marshal.loads(blob)  # SAFE: CWE-502


def build(target, cur):
    name = os.getenv("BUILD_NAME")
    subprocess.run("make " + name, shell=True)  # SAFE: CWE-78
    cur.execute("DELETE FROM builds WHERE n = '%s'" % name)  # SAFE: CWE-89


def cli():
    arg = input()
    os.system("echo " + arg)  # VULN: CWE-78
