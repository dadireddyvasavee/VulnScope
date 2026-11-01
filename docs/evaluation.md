# Evaluation Methodology

## Ground truth
- Inline annotations `# VULN: CWE-x` / `# SAFE: CWE-x` (look-alikes) or JSONL `{file,line,cwe,label}` for external corpora.
- Corpora: PyGoat, DVPWA (deliberately vulnerable apps), CVEfixes Python subset (vulnerable vs. fixed functions), plus the built-in fixtures.

## Metrics
Per-CWE and micro precision, recall, F1 (`benchmark/run.py`), scan time per KLOC. Same corpus and same matching rule (file + line ± tolerance + CWE) for VulnScope, Bandit and Semgrep.

**Why errors matter**: a false negative ships an exploitable bug; false positives waste reviewer time and train developers to ignore the tool — the main reason SAST tools get switched off.

## Leakage prevention
- Triage is trained and tested on **different repositories** (`triage/train.py` asserts this). Function- or line-level random splits leak project-specific code style.
- Rules and sanitizer lists are frozen before looking at test corpora.

## Triage evaluation
Report on the held-out repos: FP reduction, recall retained, precision before/after, ROC-AUC and feature importance. A triage model that removes FPs by also removing real vulnerabilities is reported as such.

## Ablation
1. Pattern rules only  2. + intra-procedural taint  3. + inter-procedural summaries  4. + ML triage  5. + Bandit/Semgrep merge.

## Results
Fill only from `artifacts/benchmark.json` / `artifacts/triage.json` produced by your runs (record commit, corpus versions, date).

| Engine | Precision | Recall | F1 | ms/KLOC |
|---|---|---|---|---|
| VulnScope | | | | |
| Bandit | | | | |
| Semgrep (p/python) | | | | |
