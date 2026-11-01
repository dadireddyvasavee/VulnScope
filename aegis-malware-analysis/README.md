# AEGIS – AI-Powered Malware Analysis & Behavioral Detection Engine

AEGIS is a **defensive** malware research platform. It statically analyzes Windows PE files, scans them with YARA, ingests behavioral reports produced by an isolated sandbox, classifies samples with Random Forest / XGBoost, and explains every verdict with SHAP and evidence-backed risk scoring.

> **Safety:** AEGIS never executes samples. Uploaded bytes are parsed in memory only. Behavioral data comes exclusively from sandbox reports generated in an isolated, authorized environment.

## Architecture

```mermaid
flowchart LR
  A[Sample bytes] --> B[Hashing]
  A --> C[PE static parser<br/>headers, sections, entropy, imports]
  A --> D[YARA engine]
  S[Sandbox JSON report] --> E[Behavior parser]
  C --> F[Feature vectorizer]
  E --> F
  F --> G[RF / XGBoost]
  G --> H[SHAP explainer]
  G & D & E --> I[Risk scorer]
  I --> J[IOC extraction + report]
  J --> K[(SQLite / PostgreSQL)] --> L[FastAPI] --> M[React dashboard]
```

| Module | Path | Purpose |
|---|---|---|
| Ingest | `src/aegis/ingest` | MD5 / SHA-1 / SHA-256, streaming file hashing |
| Static | `src/aegis/static` | PE parsing (pefile), section entropy, RWX/entry-point anomalies, suspicious API categories |
| YARA | `src/aegis/yara_engine`, `rules/` | yara-python scanning with a string-rule fallback for CI |
| Behavior | `src/aegis/behavior` | Process, file, registry, network signals from CAPE/Cuckoo-style reports |
| Features | `src/aegis/features` | 27-dim interpretable feature vector; EMBER loader with temporal split + leakage check |
| Models | `src/aegis/models` | RF + XGBoost training, validation-chosen threshold at target FPR, metrics, ablation |
| Explain | `src/aegis/explain` | Per-sample TreeSHAP contributions |
| Scoring | `src/aegis/scoring` | Weighted ML + YARA + behavior score with verdict bands |
| Reporting | `src/aegis/reporting` | IOC extraction (refanging, private-IP filtering), JSON + Markdown reports |
| API | `src/aegis/api` | FastAPI + SQLAlchemy persistence |
| Dashboard | `frontend/` | React (Vite) upload, report, history views |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt sqlalchemy python-multipart
pytest -q                                              # unit + integration tests
python scripts/demo.py                                 # writes docs/sample_output/
uvicorn aegis.api.main:app --app-dir src --reload      # API on :8000
cd frontend && npm install && npm run dev              # dashboard on :5173
```

Train on EMBER 2018:
```bash
bash scripts/download_ember.sh
PYTHONPATH=src python -m aegis.models.train \
  --data data/ember/train_features_*.jsonl data/ember/test_features.jsonl \
  --val-month 2018-09 --test-month 2018-11 --out artifacts/
AEGIS_MODEL=artifacts/xgboost.joblib uvicorn aegis.api.main:app --app-dir src
```
Use PostgreSQL by setting `AEGIS_DB_URL=postgresql+psycopg2://user:pass@host/aegis`.

## Sample input / output
`python scripts/demo.py` analyzes a harmless synthetic PE (built in `tests/fixtures/make_pe.py`) together with a synthetic sandbox report. Output: [`docs/sample_output/report.md`](docs/sample_output/report.md).

## Evaluation
See [`docs/evaluation.md`](docs/evaluation.md). Metrics are produced by `aegis.models.train` into `artifacts/metrics.json`. **No results are reported in this README until they are produced by that script.**

## Documentation
- [Architecture](docs/architecture.md) · [Evaluation methodology](docs/evaluation.md) · [Limitations](docs/limitations.md) · [Ethics & safety](docs/ethics.md)

## License
MIT
