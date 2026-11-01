import { useEffect, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const COLORS = { critical: "#b00020", high: "#e65100", medium: "#f9a825", low: "#558b2f", clean: "#2e7d32" };

function Badge({ v }) {
  return <span className="badge" style={{ background: COLORS[v] || "#666" }}>{v}</span>;
}

function Report({ r }) {
  if (!r) return null;
  return (
    <section className="card">
      <h2>Report <Badge v={r.verdict} /> <small>score {r.risk_score}</small></h2>
      <p className="mono">{r.sample.sha256}</p>
      <h3>Risk components</h3>
      <ul>{Object.entries(r.risk_components).map(([k, v]) => <li key={k}>{k}: {v.toFixed(3)}</li>)}</ul>
      {r.yara.length > 0 && (<><h3>YARA</h3><ul>{r.yara.map(y => <li key={y.rule}>{y.rule} ({y.severity})</li>)}</ul></>)}
      {r.static?.is_pe && (<>
        <h3>Sections</h3>
        <table><thead><tr><th>Name</th><th>Entropy</th><th>RWX</th></tr></thead>
          <tbody>{r.static.sections.map(s => <tr key={s.name}><td>{s.name}</td><td>{s.entropy}</td>
            <td>{s.executable && s.writable ? "yes" : ""}</td></tr>)}</tbody></table>
        <h3>Suspicious imports</h3>
        <ul>{Object.entries(r.static.suspicious_apis).map(([c, a]) => <li key={c}><b>{c}</b>: {a.join(", ")}</li>)}</ul>
      </>)}
      {r.behavior && (<><h3>Behavior signals</h3>
        <ul>{Object.entries(r.behavior.signals).map(([k, v]) => <li key={k}>{k} ({v.length})</li>)}</ul></>)}
      {r.explanation && (<><h3>Why (SHAP)</h3>
        <ul>{r.explanation.map(e => <li key={e.feature}>{e.feature} = {e.value.toFixed(2)} →
          <span style={{ color: e.contribution > 0 ? "#b00020" : "#2e7d32" }}> {e.contribution > 0 ? "+" : ""}{e.contribution}</span></li>)}</ul></>)}
      <h3>IOCs</h3>
      <ul>{Object.entries(r.iocs).filter(([, v]) => v.length).map(([k, v]) => <li key={k}><b>{k}</b>: {v.join(", ")}</li>)}</ul>
      <a href={`${API}/analyses/${r.id}/report.md`} target="_blank">Download Markdown report</a>
    </section>
  );
}

export default function App() {
  const [file, setFile] = useState(null);
  const [sandbox, setSandbox] = useState(null);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [err, setErr] = useState("");

  const loadHistory = () => fetch(`${API}/analyses`).then(r => r.json()).then(setHistory).catch(() => {});
  useEffect(() => { loadHistory(); }, []);

  async function submit(e) {
    e.preventDefault(); setErr("");
    const fd = new FormData();
    fd.append("file", file);
    if (sandbox) fd.append("sandbox_report", await sandbox.text());
    const res = await fetch(`${API}/analyze`, { method: "POST", body: fd });
    if (!res.ok) { setErr(await res.text()); return; }
    setReport(await res.json()); loadHistory();
  }

  return (
    <main>
      <h1>AEGIS <small>Malware Analysis Dashboard</small></h1>
      <p className="warn">Files are parsed statically and never executed.</p>
      <form className="card" onSubmit={submit}>
        <label>Sample <input type="file" onChange={e => setFile(e.target.files[0])} required /></label>
        <label>Sandbox report (JSON, optional) <input type="file" accept=".json" onChange={e => setSandbox(e.target.files[0])} /></label>
        <button disabled={!file}>Analyze</button>
        {err && <p className="err">{err}</p>}
      </form>
      <Report r={report} />
      <section className="card">
        <h2>History</h2>
        <table><thead><tr><th>ID</th><th>SHA-256</th><th>Verdict</th><th>Score</th></tr></thead>
          <tbody>{history.map(h => <tr key={h.id} onClick={() => fetch(`${API}/analyses/${h.id}`).then(r => r.json()).then(d => setReport({ ...d, id: h.id }))}>
            <td>{h.id}</td><td className="mono">{h.sha256.slice(0, 16)}…</td><td><Badge v={h.verdict} /></td><td>{h.score}</td></tr>)}</tbody></table>
      </section>
    </main>
  );
}
