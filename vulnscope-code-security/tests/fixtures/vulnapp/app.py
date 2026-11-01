"""DELIBERATELY VULNERABLE test application. Never deploy. Annotated ground truth:
# VULN: CWE-x  marks a real vulnerability; # SAFE: CWE-x marks a look-alike that is safe."""
import os
import pickle
import sqlite3
import subprocess
import shlex
import yaml
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
DB_PASSWORD = "Sup3rS3cret!"  # VULN: CWE-798
API_KEY = os.environ.get("API_KEY")
PLACEHOLDER_TOKEN = "changeme"
BASE = "/srv/files"


def get_db():
    return sqlite3.connect("app.db")


@app.route("/user")
def user():
    name = request.args.get("name")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # VULN: CWE-89
    return "ok"


@app.route("/user_safe")
def user_safe():
    name = request.args.get("name")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # SAFE: CWE-89
    return "ok"


@app.route("/count")
def count():
    limit = int(request.args.get("limit", "10"))
    cur = get_db().cursor()
    cur.execute("SELECT * FROM t LIMIT %d" % limit)  # SAFE: CWE-89
    return "ok"


@app.route("/ping")
def ping():
    host = request.args["host"]
    os.system("ping -c 1 " + host)  # VULN: CWE-78
    return "ok"


@app.route("/ping_safe")
def ping_safe():
    host = request.args["host"]
    subprocess.run(["ping", "-c", "1", host], check=False)  # SAFE: CWE-78
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)  # SAFE: CWE-78
    return "ok"


@app.route("/run")
def run():
    cmd = request.form.get("cmd")
    out = subprocess.check_output(cmd, shell=True)  # VULN: CWE-78
    return out


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)  # VULN: CWE-502
    return str(obj)


@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.load(request.data)  # VULN: CWE-502
    safe = yaml.load(request.data, Loader=yaml.SafeLoader)  # SAFE: CWE-502
    return str(cfg) + str(safe)


@app.route("/calc")
def calc():
    expr = request.args.get("e")
    return str(eval(expr))  # VULN: CWE-95


@app.route("/download")
def download():
    fname = request.args.get("f")
    return send_file(os.path.join(BASE, fname))  # VULN: CWE-22


@app.route("/download_safe")
def download_safe():
    fname = secure_filename(request.args.get("f"))
    return send_file(os.path.join(BASE, fname))  # SAFE: CWE-22


@app.route("/files/<path:name>")
def files(name):
    with open(os.path.join(BASE, name)) as fh:  # VULN: CWE-22
        return fh.read()


def build_query(table, value):
    return "SELECT * FROM " + table + " WHERE v = '" + value + "'"


def run_query(q):
    get_db().execute(q)  # VULN: CWE-89


@app.route("/search")
def search():
    v = request.args.get("v")
    run_query(build_query("items", v))
    return "ok"


def internal_report():
    run_query("SELECT 1")
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)  # VULN: CWE-489
