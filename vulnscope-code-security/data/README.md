# Data (not committed)
- `scripts/get_corpora.sh` → PyGoat, DVPWA into `data/corpora/`
- Ground truth for external corpora: `data/gt/<repo>.jsonl` lines `{"file": "...", "line": 42, "cwe": "CWE-89", "label": 1}` (label 0 = known safe look-alike)
- CVEfixes Python subset: vulnerable (label 1) and fixed (label 0) function pairs; split **by repository**.
