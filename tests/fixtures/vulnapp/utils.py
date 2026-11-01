import hashlib
import requests


def fetch(url):
    return requests.get(url, verify=False)  # VULN: CWE-295


def checksum(data):
    return hashlib.md5(data).hexdigest()  # VULN: CWE-327


def connect():
    return {"user": "admin", "password": "P@ssw0rd123"}  # VULN: CWE-798


def connect_env(env):
    return {"user": "admin", "password": env["DB_PASS"]}  # SAFE: CWE-798
