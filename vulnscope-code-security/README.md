# VULNSCOPE – AI-Assisted Vulnerability Discovery & Secure Code Analysis

VULNSCOPE is a static application security testing (SAST) engine for Python. It parses code into ASTs, tracks untrusted data from **sources to sinks** across functions, maps findings to CWE, presents CVSS-style severity, ranks findings with an ML triage model to cut false positives, and explains every finding with the full taint trace plus a secure alternative.

## Architecture

```mermaid
flowchart LR
  A[Python repo / snippet / zip] --> B[AST index<br/>imports, aliases, functions, call graph]
  B --> C[Taint engine<br/>sources → propagation → sanitizers → sinks<br/>inter-procedural summaries]
  B --> D[Pattern rules<br/>secrets, TLS, debug, weak hash]
  X[Bandit / Semgrep optional] --> E
  C & D --> E[Normalizer + de-dup<br/>CWE mapping]
  E --> F[ML triage<br/>P(true positive)]
  F --> G[CVSS v3.1 base score + priority]
  G --> H[Remediation + source-to-sink explanation]
  H --> I[(SQLite / PostgreSQL)] --> J[FastAPI] --> K[React + TypeScript dashboard]
```

### Detection coverage
| CWE | Detection |
|---|---|
| CWE-89 SQL injection | Tainted query into `execute/executemany/raw`; heuristic for formatted queries (sanitizer-aware) |
| CWE-78 OS command injection | `os.system/popen`, `subprocess.*` with `shell=True` or tainted executable |
| CWE-95 Code injection | `eval` / `exec` |
| CWE-502 Insecure deserialization | `pickle/marshal/dill`, `yaml.load` without SafeLoader |
| CWE-22 Path traversal | `open`, `send_file`, `os.remove`, `shutil.rmtree` |
| CWE-918 SSRF | `requests.*`, `urlopen` with tainted URL |
| CWE-798 Hardcoded credentials | Secret-like names / dict keys / kwargs assigned to literals (placeholders ignored) |
| CWE-295, 489, 327, 377 | `verify=False`, `debug=True`, MD5/SHA-1, `mktemp` |

### Taint engine
- Sources: Flask/Django request objects, `input()`, `sys.argv`, **route parameters**.
- Sanitizers: `int`, `float`, `shlex.quote`, `secure_filename`, `os.path.basename`, `html.escape`, …
- Propagation through assignments, f-strings, `%`/`+`/`.format`, containers, loops, `with`, attribute/subscript stores, unknown calls (conservative).
- **Inter-procedural**: per-function summaries (param→sink, param→return, source→return) iterated to a fixed point, so `run_query(build_query(request.args["v"]))` is caught at the sink inside `run_query`.
- Import aliases resolved (`import subprocess as sp`, `from os import system as run`).

## Quick start
```bash
pip install -r requirements.txt
pytest -q
python scripts/demo.py                                   # scans the vulnerable fixture app
PYTHONPATH=src python -m vulnscope.cli scan path/to/repo --external --fail-on high
uvicorn vulnscope.api.main:app --app-dir src --reload
cd frontend && npm install && npm run dev
```

## Benchmark & triage
```bash
bash scripts/get_corpora.sh
PYTHONPATH=src python -m vulnscope.benchmark.run data/corpora/pygoat --gt data/gt/pygoat.jsonl
PYTHONPATH=src python -m vulnscope.triage.train --train <repoA> <repoB> --test <repoC>
```
See [docs/evaluation.md](docs/evaluation.md). The built-in fixture app is a regression test, **not** a performance claim.

## Docs
[Architecture](docs/architecture.md) · [Evaluation](docs/evaluation.md) · [Limitations](docs/limitations.md) · [Ethics](docs/ethics.md)
