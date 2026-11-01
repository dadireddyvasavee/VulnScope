"""Turns a PEReport (+ optional behavior profile) into a fixed-length numeric vector.
Feature names are kept so SHAP output is human-readable."""
from __future__ import annotations
import numpy as np

from aegis.static.suspicious_apis import SUSPICIOUS_APIS

STATIC_FEATURES = ["size_log", "overall_entropy", "num_sections", "max_section_entropy",
                   "mean_section_entropy", "num_rwx_sections", "num_high_entropy_sections",
                   "num_imported_dlls", "num_imports", "num_exports", "is_dll", "num_anomalies"]
API_FEATURES = [f"api_{c}" for c in SUSPICIOUS_APIS]
BEHAVIOR_FEATURES = ["beh_shadow_copy_deletion", "beh_encrypted_extension_writes", "beh_mass_file_modification",
                     "beh_registry_persistence", "beh_encoded_powershell", "beh_lolbin_execution",
                     "beh_network_activity"]
FEATURE_NAMES = STATIC_FEATURES + API_FEATURES + BEHAVIOR_FEATURES


def vectorize(pe_report, size: int, behavior=None) -> np.ndarray:
    ents = [s.entropy for s in pe_report.sections] or [0.0]
    v = [np.log1p(size), pe_report.overall_entropy, pe_report.num_sections, max(ents), float(np.mean(ents)),
         sum(s.executable and s.writable for s in pe_report.sections),
         sum(s.entropy > 7.2 for s in pe_report.sections), len(pe_report.imports),
         len(pe_report.flat_imports), len(pe_report.exports), float(pe_report.is_dll), len(pe_report.anomalies)]
    v += [len(pe_report.suspicious_apis.get(c, [])) for c in SUSPICIOUS_APIS]
    sig = behavior.signals if behavior else {}
    v += [float(f.removeprefix("beh_") in sig) for f in BEHAVIOR_FEATURES]
    return np.asarray(v, dtype=np.float32)
