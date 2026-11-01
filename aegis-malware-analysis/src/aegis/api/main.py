"""FastAPI service. Run: uvicorn aegis.api.main:app --reload
Uploaded bytes are analyzed in memory and never written to disk or executed."""
from __future__ import annotations
import json
import os
from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy import select

from aegis.pipeline import Analyzer
from aegis.reporting.report import to_markdown
from aegis.api.db import make_session, save, Analysis

MAX_BYTES = 50 * 1024 * 1024


def create_app(db_url: str | None = None, model=None) -> FastAPI:
    if model is None and os.getenv("AEGIS_MODEL"):
        import joblib
        model = joblib.load(os.environ["AEGIS_MODEL"])
    app = FastAPI(title="AEGIS", version="0.1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
    analyzer, Session = Analyzer(model=model), make_session(db_url)

    @app.get("/health")
    def health():
        return {"status": "ok", "model_loaded": analyzer.model is not None, "yara_backend": analyzer.yara.backend}

    @app.post("/analyze")
    async def analyze(file: UploadFile = File(...), sandbox_report: str | None = Form(None)):
        data = await file.read()
        if not data or len(data) > MAX_BYTES:
            raise HTTPException(400, "empty or oversized file")
        sb = json.loads(sandbox_report) if sandbox_report else None
        report = analyzer.analyze(data, sb)
        report["id"] = save(Session, report)
        return report

    @app.get("/analyses")
    def list_analyses(limit: int = 50):
        with Session() as s:
            rows = s.scalars(select(Analysis).order_by(Analysis.id.desc()).limit(limit)).all()
            return [{"id": r.id, "sha256": r.sha256, "verdict": r.verdict, "score": r.score,
                     "created_at": r.created_at.isoformat()} for r in rows]

    @app.get("/analyses/{aid}")
    def get_analysis(aid: int):
        with Session() as s:
            r = s.get(Analysis, aid)
            if not r:
                raise HTTPException(404)
            return json.loads(r.report_json)

    @app.get("/analyses/{aid}/report.md", response_class=PlainTextResponse)
    def get_md(aid: int):
        return to_markdown(get_analysis(aid))

    return app


app = create_app()
