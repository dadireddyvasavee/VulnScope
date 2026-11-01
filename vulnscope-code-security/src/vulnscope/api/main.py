"""FastAPI service. Run: uvicorn vulnscope.api.main:app --app-dir src --reload
Uploaded archives are extracted to a temp dir with zip-slip protection; code is parsed, never executed."""
from __future__ import annotations
import json
import os
import tempfile
import zipfile
from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select

from vulnscope.api.db import make_session, save_scan, Scan, FindingRow
from vulnscope.scanner import scan_path, scan_source, finalize

MAX_ZIP = 50 * 1024 * 1024
STATUSES = {"open", "confirmed", "false_positive", "fixed"}


class CodeIn(BaseModel):
    code: str
    filename: str = "snippet.py"


class StatusIn(BaseModel):
    status: str


def safe_extract(zf: zipfile.ZipFile, dest: Path):
    total = 0
    for m in zf.infolist():
        target = (dest / m.filename).resolve()
        if not str(target).startswith(str(dest.resolve()) + os.sep) and target != dest.resolve():
            raise HTTPException(400, f"unsafe path in archive: {m.filename}")
        total += m.file_size
        if total > 5 * MAX_ZIP:
            raise HTTPException(400, "archive too large when extracted")
    zf.extractall(dest)


def create_app(db_url=None, triage=None) -> FastAPI:
    if triage is None and os.getenv("VULNSCOPE_TRIAGE"):
        import joblib
        triage = joblib.load(os.environ["VULNSCOPE_TRIAGE"])
    app = FastAPI(title="VULNSCOPE", version="0.1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
    Session = make_session(db_url)

    @app.get("/health")
    def health():
        return {"status": "ok", "triage_model": triage is not None}

    @app.post("/scan/code")
    def scan_code(body: CodeIn):
        res = finalize(scan_source(body.code, body.filename), triage, 1, body.code.count("\n") + 1, 0.0)
        res["id"] = save_scan(Session, body.filename, res)
        return res

    @app.post("/scan/zip")
    async def scan_zip(file: UploadFile = File(...)):
        data = await file.read()
        if len(data) > MAX_ZIP:
            raise HTTPException(400, "archive too large")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.zip"
            p.write_bytes(data)
            try:
                with zipfile.ZipFile(p) as zf:
                    safe_extract(zf, Path(td) / "src")
            except zipfile.BadZipFile:
                raise HTTPException(400, "not a zip archive")
            res = scan_path(Path(td) / "src", triage=triage)
        res["id"] = save_scan(Session, file.filename, res)
        return res

    @app.get("/scans")
    def scans():
        with Session() as s:
            return [{"id": x.id, "name": x.name, "files": x.files, "loc": x.loc, "seconds": x.seconds,
                     "severity": json.loads(x.severity_json), "created_at": x.created_at.isoformat()}
                    for x in s.scalars(select(Scan).order_by(Scan.id.desc())).all()]

    @app.get("/scans/{sid}")
    def scan(sid: int):
        with Session() as s:
            sc = s.get(Scan, sid)
            if not sc:
                raise HTTPException(404)
            return {"id": sc.id, "name": sc.name, "severity": json.loads(sc.severity_json),
                    "findings": [{**json.loads(f.data_json), "id": f.id, "status": f.status} for f in sc.findings]}

    @app.patch("/findings/{fid}")
    def update(fid: int, body: StatusIn):
        if body.status not in STATUSES:
            raise HTTPException(400, f"status must be one of {sorted(STATUSES)}")
        with Session() as s:
            f = s.get(FindingRow, fid)
            if not f:
                raise HTTPException(404)
            f.status = body.status
            s.commit()
            return {"id": fid, "status": f.status}

    @app.get("/scans/{sid}/report.md")
    def report_md(sid: int):
        from fastapi.responses import PlainTextResponse
        d = scan(sid)
        lines = [f"# VULNSCOPE report: {d['name']}", "", "| Severity | Count |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in d["severity"].items()]
        for f in d["findings"]:
            lines += ["", f"## [{f['severity'].upper()}] {f['cwe']} {f['title']}",
                      f"`{f['file']}:{f['line']}` — status: {f['status']}, CVSS {f['cvss']}", "", f"```python\n{f['snippet']}\n```"]
            if f["remediation"]["source_to_sink"]:
                lines.append(f["remediation"]["source_to_sink"])
            lines.append(f"**Fix:** {f['remediation']['advice']}")
        return PlainTextResponse("\n".join(lines))

    return app


app = create_app()
