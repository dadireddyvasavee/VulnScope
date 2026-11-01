import { useEffect, useState } from "react";
import type { Finding, ScanResult, ScanSummary } from "./types";

const API: string = import.meta.env.VITE_API_URL || "http://localhost:8000";
const SEV: Record<string, string> = { critical: "#b00020", high: "#e65100", medium: "#f9a825", low: "#558b2f" };
const ORDER = ["critical", "high", "medium", "low"];

function Badge({ v }: { v: string }) {
  return <span className="badge" style={{ background: SEV[v] || "#666" }}>{v}</span>;
}

function Breakdown({ s }: { s: Record<string, number> }) {
  const total = Object.values(s).reduce((a, b) => a + b, 0) || 1;
  return (
    <div style={{ display: "flex", height: 18, borderRadius: 4, overflow: "hidden", margin: "8px 0" }}>
      {ORDER.filter(k => s[k]).map(k => (
        <div key={k} title={`${k}: ${s[k]}`} style={{ width: `${(100 * s[k]) / total}%`, background: SEV[k], color: "#fff", fontSize: 11, textAlign: "center" }}>{s[k]}</div>
      ))}
    </div>
  );
}

function FindingCard({ f, onStatus }: { f: Finding; onStatus: (id: number, s: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="card" style={{ margin: "8px 0" }}>
      <div onClick={() => setOpen(!open)} style={{ cursor: "pointer" }}>
        <Badge v={f.severity} /> <b>{f.cwe}</b> {f.title} — <span className="mono">{f.file}:{f.line}</span>
        <small> · CVSS {f.cvss} · priority {f.priority}{f.tainted ? " · reachable from user input" : ""}</small>
        {f.status && <small> · <i>{f.status}</i></small>}
      </div>
      {open && (
        <div>
          <pre className="mono">{f.snippet}</pre>
          {f.trace.length > 1 && (<><h4>Source → sink</h4>
            <ol>{f.trace.map((t, i) => <li key={i}><b>{t.kind}</b> (line {t.line}) {t.detail}</li>)}</ol></>)}
          {f.remediation.source_to_sink && <p>{f.remediation.source_to_sink}</p>}
          <p><b>Fix:</b> {f.remediation.advice}</p>
          {f.remediation.secure_example && <pre className="mono">{f.remediation.secure_example}</pre>}
          <a href={f.remediation.reference} target="_blank" rel="noreferrer">{f.cwe} reference</a>
          {f.id !== undefined && (
            <div>{["confirmed", "false_positive", "fixed", "open"].map(s =>
              <button key={s} style={{ marginRight: 6 }} onClick={() => onStatus(f.id!, s)}>{s}</button>)}</div>)}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [code, setCode] = useState("");
  const [zip, setZip] = useState<File | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [filter, setFilter] = useState("all");

  const loadHistory = () => fetch(`${API}/scans`).then(r => r.json()).then(setHistory);
  const openScan = (id: number) => fetch(`${API}/scans/${id}`).then(r => r.json()).then(setResult);
  useEffect(() => { loadHistory(); }, []);

  async function scanCode() {
    const r: ScanResult = await fetch(`${API}/scan/code`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, filename: "snippet.py" }) }).then(r => r.json());
    await loadHistory(); openScan(r.id);
  }
  async function scanZip() {
    if (!zip) return;
    const fd = new FormData(); fd.append("file", zip);
    const r: ScanResult = await fetch(`${API}/scan/zip`, { method: "POST", body: fd }).then(r => r.json());
    await loadHistory(); openScan(r.id);
  }
  async function setStatus(id: number, status: string) {
    await fetch(`${API}/findings/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) });
    if (result) openScan(result.id);
  }

  const findings = (result?.findings || []).filter(f => filter === "all" || f.severity === filter);
  const breakdown = result?.severity || result?.severity_breakdown || {};

  return (
    <main>
      <h1>VULNSCOPE <small>Secure Code Analysis</small></h1>
      <section className="card">
        <h2>Scan</h2>
        <textarea rows={8} style={{ width: "100%" }} className="mono" placeholder="Paste Python code…" value={code} onChange={e => setCode(e.target.value)} />
        <button disabled={!code.trim()} onClick={scanCode}>Scan snippet</button>{" "}
        <input type="file" accept=".zip" onChange={e => setZip(e.target.files?.[0] || null)} />
        <button disabled={!zip} onClick={scanZip}>Scan repository (.zip)</button>
      </section>

      {result && (
        <section className="card">
          <h2>Findings ({result.findings.length})</h2>
          <Breakdown s={breakdown} />
          <select value={filter} onChange={e => setFilter(e.target.value)}>
            <option value="all">All severities</option>{ORDER.map(s => <option key={s}>{s}</option>)}
          </select>{" "}
          <a href={`${API}/scans/${result.id}/report.md`} target="_blank" rel="noreferrer">Download report</a>
          {findings.map((f, i) => <FindingCard key={f.id ?? i} f={f} onStatus={setStatus} />)}
        </section>
      )}

      <section className="card">
        <h2>Scan history</h2>
        <table><thead><tr><th>ID</th><th>Name</th><th>Files</th><th>LOC</th><th>Severity</th><th>Date</th></tr></thead>
          <tbody>{history.map(h => <tr key={h.id} onClick={() => openScan(h.id)}><td>{h.id}</td><td>{h.name}</td><td>{h.files}</td>
            <td>{h.loc}</td><td><Breakdown s={h.severity} /></td><td>{h.created_at.slice(0, 19)}</td></tr>)}</tbody></table>
      </section>
    </main>
  );
}
