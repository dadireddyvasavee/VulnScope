#!/usr/bin/env bash
# Clones deliberately vulnerable Python apps for benchmarking. Scan only code you are authorized to scan.
set -euo pipefail
mkdir -p data/corpora && cd data/corpora
git clone --depth 1 https://github.com/adeyosemanputra/pygoat.git || true
git clone --depth 1 https://github.com/anxolerd/dvpwa.git || true
echo "Now create ground truth: data/gt/<repo>.jsonl with {file,line,cwe,label} for each known vuln/look-alike."
echo "CVEfixes (Python subset): https://github.com/secureIT-project/CVEfixes - use vulnerable/fixed function pairs."
