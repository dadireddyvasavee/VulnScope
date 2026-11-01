# Architecture
1. **AST index** (`parser/ast_index.py`) – import alias map, dotted call names, function index (incl. class methods, decorators), call graph.
2. **Taint engine** (`taint/engine.py`) – statement-ordered analysis per function. Branches are analyzed sequentially (may-taint union), which favors recall. Every taint value carries a trace of `TraceStep(line, kind, detail)`.
3. **Summaries** – for each function: `sink_params`, `ret_params`, `ret_source`. Re-computed for 3 rounds (enough for typical call depth in web handlers); findings are collected in the final round only.
4. **Pattern rules** (`rules/pattern_rules.py`) – AST rules that do not need data flow.
5. **External engines** (`external.py`) – Bandit and Semgrep JSON normalized to the same `Finding` model; de-duplicated by (file, line, CWE).
6. **Severity** (`severity/cvss.py`) – CVSS v3.1 base-score formula over a typical vector per CWE. Presented as *estimated* severity. Priority = (CVSS/10) × confidence (or triage probability) × 1.25 if reachable from user input.
7. **Triage** (`triage/`) – gradient boosting on 23 features (taint, trace length, propagation/call steps, test-path location, route reachability, engine agreement, CWE one-hot).
8. **Remediation** (`remediation/advisor.py`) – per-CWE secure alternative and natural-language source-to-sink explanation.
9. **API** – snippet and zip scanning (zip-slip and size checks), scan history, finding status workflow (open / confirmed / false_positive / fixed), Markdown reports.
