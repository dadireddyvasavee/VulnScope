# Limitations
- PE (Windows) only; ELF, Mach-O, scripts and documents are not parsed.
- Feature set is compact and interpretable; it will underperform byte-level deep models on raw detection rate.
- Behavior features require sandbox reports; most EMBER samples have none, so behavior impact is measured on a smaller subset.
- YARA fallback supports plain-string rules only; install `yara-python` for full syntax.
- Adversaries can manipulate imports and section entropy; static features alone are evadable.
- Risk-score weights are hand-set; they should be calibrated on labeled data.
- IOC extraction from strings produces candidates, not confirmed indicators.
