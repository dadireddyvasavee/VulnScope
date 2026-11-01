GUIDE = {
    "CWE-89": ("Use parameterized queries; never build SQL with f-strings, % or +.",
               'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))'),
    "CWE-78": ("Avoid shell=True / os.system. Pass an argument list to subprocess.run and validate against an allow-list.",
               'subprocess.run(["ping", "-c", "1", host], check=True)  # host validated with ipaddress.ip_address()'),
    "CWE-95": ("Never eval/exec untrusted input. Use ast.literal_eval for literals or explicit parsing.",
               "value = ast.literal_eval(user_text)"),
    "CWE-502": ("Do not deserialize untrusted data with pickle/marshal; use JSON. For YAML use yaml.safe_load.",
                "data = json.loads(payload)  # or yaml.safe_load(stream)"),
    "CWE-22": ("Normalize the path and verify it stays inside an allowed base directory; use secure_filename.",
               "p = (BASE / secure_filename(name)).resolve()\nif not p.is_relative_to(BASE): abort(400)"),
    "CWE-918": ("Validate outbound URLs against an allow-list of hosts and block internal address ranges.",
                "if urlparse(url).hostname not in ALLOWED_HOSTS: abort(400)"),
    "CWE-798": ("Load secrets from environment variables or a secret manager (e.g. Azure Key Vault); rotate the exposed secret.",
                'password = os.environ["DB_PASSWORD"]'),
    "CWE-295": ("Keep TLS verification enabled; supply a CA bundle if needed.", 'requests.get(url, verify="/path/ca.pem")'),
    "CWE-327": ("Use SHA-256+ for integrity and bcrypt/argon2/scrypt for passwords.", "hashlib.sha256(data).hexdigest()"),
    "CWE-489": ("Disable debug mode in production; drive it from configuration.", 'app.run(debug=os.getenv("FLASK_DEBUG") == "1")'),
    "CWE-377": ("Use tempfile.NamedTemporaryFile or mkstemp.", "fd, path = tempfile.mkstemp()"),
}


def remediation_for(f) -> dict:
    advice, example = GUIDE.get(f.cwe, ("Review this code path and apply input validation.", ""))
    explanation = None
    if f.tainted and f.trace:
        src = next((s for s in f.trace if s.kind == "source"), f.trace[0])
        explanation = f"Untrusted data from line {src.line} ({src.detail}) reaches {f.title.lower()} at line {f.line} " \
                      f"through {sum(s.kind in ('propagate', 'call') for s in f.trace)} step(s) without sanitization."
    return {"advice": advice, "secure_example": example, "source_to_sink": explanation,
            "reference": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"}
