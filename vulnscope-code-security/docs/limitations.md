# Limitations
- Python only; dynamic features (`getattr`, `**kwargs` forwarding, monkey-patching, decorators that wrap arguments) are not modeled.
- Branch-insensitive: sanitization in one branch is not tracked per path; may produce FPs.
- Method resolution is name-based (no type inference), so `obj.execute` is treated as a DB call.
- Inter-procedural analysis is per-file; cross-module flows are not followed.
- CVSS values are typical-vector estimates, not CVE-specific scores.
- Triage quality depends on labeled corpora size and diversity.
