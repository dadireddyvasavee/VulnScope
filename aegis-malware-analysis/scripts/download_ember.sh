#!/usr/bin/env bash
# Downloads EMBER 2018 (v2) pre-extracted features (~1.6 GB). Contains feature JSON only - no binaries.
set -euo pipefail
mkdir -p data/ember && cd data/ember
curl -L -o ember_dataset_2018_2.tar.bz2 https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xjf ember_dataset_2018_2.tar.bz2 --strip-components=1
echo "Done. Train with:"
echo "python -m aegis.models.train --data data/ember/train_features_*.jsonl data/ember/test_features.jsonl --val-month 2018-09 --test-month 2018-11 --out artifacts/"
