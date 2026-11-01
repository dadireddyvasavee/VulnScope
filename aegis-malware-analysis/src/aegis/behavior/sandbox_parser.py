"""Parses sandbox JSON reports (CAPE/Cuckoo-style) produced in an ISOLATED environment.
AEGIS never runs samples itself; it only consumes reports."""
from __future__ import annotations
from dataclasses import dataclass, field

PERSISTENCE_KEYS = ("\\currentversion\\run", "\\currentversion\\runonce", "\\services\\", "\\winlogon")
SUSPICIOUS_PROCS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
                    "regsvr32.exe", "mshta.exe", "schtasks.exe", "vssadmin.exe", "bcdedit.exe"}
SHADOW_DELETE = ("delete shadows", "shadowcopy delete", "resize shadowstorage")


@dataclass
class BehaviorProfile:
    processes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)
    registry_set: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    http_urls: list[str] = field(default_factory=list)
    signals: dict[str, list[str]] = field(default_factory=dict)

    def add(self, signal: str, evidence: str):
        self.signals.setdefault(signal, []).append(evidence)


def parse_report(report: dict) -> BehaviorProfile:
    b = BehaviorProfile()
    beh = report.get("behavior", {})
    for p in beh.get("processes", []):
        name = p.get("process_name", "").lower()
        b.processes.append(name)
        cmd = p.get("command_line", "")
        if cmd:
            b.commands.append(cmd)
        if name in SUSPICIOUS_PROCS:
            b.add("lolbin_execution", name)
        low = cmd.lower()
        if "-enc" in low or "frombase64string" in low:
            b.add("encoded_powershell", cmd[:200])
        if any(s in low for s in SHADOW_DELETE):
            b.add("shadow_copy_deletion", cmd[:200])

    s = beh.get("summary", {})
    b.files_written = s.get("write_files", s.get("file_written", []))
    b.files_deleted = s.get("delete_files", s.get("file_deleted", []))
    b.registry_set = s.get("write_keys", s.get("regkey_written", []))
    for k in b.registry_set:
        if any(x in k.lower() for x in PERSISTENCE_KEYS):
            b.add("registry_persistence", k)
    if len(b.files_written) > 50 and len(b.files_deleted) > 50:
        b.add("mass_file_modification", f"{len(b.files_written)} written / {len(b.files_deleted)} deleted")
    for f in b.files_written:
        if f.lower().endswith((".locked", ".encrypted", ".crypt")):
            b.add("encrypted_extension_writes", f)
            break

    net = report.get("network", {})
    b.domains = sorted({d.get("domain", d) if isinstance(d, dict) else d for d in net.get("domains", [])})
    b.ips = sorted({h.get("ip", h) if isinstance(h, dict) else h for h in net.get("hosts", [])})
    b.http_urls = [h.get("uri", "") for h in net.get("http", []) if isinstance(h, dict)]
    if b.domains or b.ips:
        b.add("network_activity", f"{len(b.domains)} domains, {len(b.ips)} hosts")
    return b


SIGNAL_WEIGHTS = {"shadow_copy_deletion": 0.9, "encrypted_extension_writes": 0.8, "mass_file_modification": 0.6,
                  "registry_persistence": 0.6, "encoded_powershell": 0.7, "lolbin_execution": 0.3,
                  "network_activity": 0.2}


def behavior_score(b: BehaviorProfile) -> float:
    """Noisy-OR combination of signal weights -> 0..1."""
    p = 1.0
    for sig in b.signals:
        p *= 1 - SIGNAL_WEIGHTS.get(sig, 0.1)
    return round(1 - p, 4)
