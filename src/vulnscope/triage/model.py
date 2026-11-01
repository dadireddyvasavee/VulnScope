"""ML triage: predicts P(true positive) for a finding from engineered features, to rank and filter
false positives. Trained on findings labeled TP/FP against ground truth (see benchmark/)."""
from __future__ import annotations
import re
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier

CWES = ["CWE-89", "CWE-78", "CWE-95", "CWE-502", "CWE-22", "CWE-918", "CWE-798", "CWE-295", "CWE-327", "CWE-489", "CWE-377"]
TEST_PATH = re.compile(r"(^|/)(tests?|test_[^/]*|[^/]*_test\.py|conftest\.py|examples?|docs?)(/|$)", re.I)
FEATURE_NAMES = ["tainted", "trace_len", "n_propagate", "n_calls", "confidence", "in_test_path", "from_route",
                 "snippet_has_constant_only", "engine_vulnscope", "engine_bandit", "engine_semgrep", "n_engines"] + \
                [f"cwe_{c}" for c in CWES]


def features(f, n_engines: int = 1) -> np.ndarray:
    steps = f.trace or []
    v = [float(f.tainted), len(steps), sum(s.kind == "propagate" for s in steps), sum(s.kind == "call" for s in steps),
         f.confidence, float(bool(TEST_PATH.search(f.file.replace("\\", "/")))),
         float(any("route parameter" in s.detail for s in steps)),
         float(bool(re.fullmatch(r"[^()]*\(\s*(['\"]).*\1\s*\)\s*", f.snippet or ""))),
         float(f.engine == "vulnscope"), float(f.engine == "bandit"), float(f.engine == "semgrep"), float(n_engines)]
    v += [float(f.cwe == c) for c in CWES]
    return np.asarray(v, dtype=np.float32)


class TriageModel:
    def __init__(self, seed: int = 42):
        self.clf = GradientBoostingClassifier(random_state=seed, n_estimators=150, max_depth=3)
        self.fitted = False

    def fit(self, findings, labels):
        self.clf.fit(np.vstack([features(f) for f in findings]), np.asarray(labels))
        self.fitted = True
        return self

    def score(self, findings):
        if not self.fitted or not findings:
            return findings
        P = self.clf.predict_proba(np.vstack([features(f) for f in findings]))[:, 1]
        for f, p in zip(findings, P):
            f.triage_prob = round(float(p), 4)
        return findings

    def importances(self):
        return sorted(zip(FEATURE_NAMES, self.clf.feature_importances_), key=lambda x: -x[1])
