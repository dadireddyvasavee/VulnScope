"""Non-taint pattern rules (AST based)."""
from __future__ import annotations
import ast
import re

from vulnscope.models import Finding, TraceStep
from vulnscope.parser.ast_index import ImportMap, dotted

SECRET_NAME = re.compile(r"(pass(word|wd)?|pwd|secret|api_?key|access_?key|token|auth_?key|private_?key|client_secret)$", re.I)
PLACEHOLDER = re.compile(r"^(|x+|\*+|changeme|change_me|your[_-].*|<.*>|\$\{.*\}|placeholder|dummy|test|example|none|null)$", re.I)
WEAK_HASH = {"hashlib.md5", "hashlib.sha1"}


def _f(rule, cwe, title, file, node, lines, conf, func=None):
    ln = node.lineno
    return Finding(rule_id=rule, cwe=cwe, title=title, file=file, line=ln, col=node.col_offset,
                   snippet=lines[ln - 1].strip() if ln <= len(lines) else "", function=func, tainted=False,
                   trace=[TraceStep(ln, "sink", title)], confidence=conf)


def _secret_value(v) -> bool:
    return isinstance(v, ast.Constant) and isinstance(v.value, str) and len(v.value) >= 4 and \
        not PLACEHOLDER.match(v.value.strip())


def run_pattern_rules(source: str, filename: str) -> list[Finding]:
    tree = ast.parse(source)
    lines = source.splitlines()
    imp = ImportMap(tree)
    out = []
    for n in ast.walk(tree):
        # CWE-798 hardcoded credentials: NAME = "literal" / obj.NAME = "literal" / dict key / kwarg
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else \
                    (t.slice.value if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) else None)
                if isinstance(name, str) and SECRET_NAME.search(name) and _secret_value(n.value):
                    out.append(_f("VS-CWE-798", "CWE-798", f"Hardcoded credential in '{name}'", filename, n, lines, 0.7))
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and SECRET_NAME.search(k.value) and _secret_value(v):
                    out.append(_f("VS-CWE-798", "CWE-798", f"Hardcoded credential in key '{k.value}'", filename, v, lines, 0.6))
        elif isinstance(n, ast.Call):
            name = imp.resolve(dotted(n.func)) or ""
            for k in n.keywords:
                if k.arg and SECRET_NAME.search(k.arg) and _secret_value(k.value):
                    out.append(_f("VS-CWE-798", "CWE-798", f"Hardcoded credential passed as '{k.arg}'", filename, n, lines, 0.65))
                if k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False and name.startswith("requests."):
                    out.append(_f("VS-CWE-295", "CWE-295", "TLS certificate verification disabled", filename, n, lines, 0.8))
                if k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True and name.endswith(".run"):
                    out.append(_f("VS-CWE-489", "CWE-489", "Debug mode enabled in web application", filename, n, lines, 0.6))
            if name in WEAK_HASH:
                out.append(_f("VS-CWE-327", "CWE-327", f"Weak hash algorithm {name}", filename, n, lines, 0.4))
            if name == "tempfile.mktemp":
                out.append(_f("VS-CWE-377", "CWE-377", "Insecure temporary file (mktemp)", filename, n, lines, 0.7))
    # dedupe by (line, cwe)
    seen, uniq = set(), []
    for f in out:
        if (f.line, f.cwe) not in seen:
            seen.add((f.line, f.cwe))
            uniq.append(f)
    return uniq
