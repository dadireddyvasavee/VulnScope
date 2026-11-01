"""Static PE analysis with pefile. Parses structure only; never executes the sample."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict

from .entropy import shannon_entropy
from .suspicious_apis import classify_imports

HIGH_ENTROPY = 7.2


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    executable: bool
    writable: bool


@dataclass
class PEReport:
    is_pe: bool
    error: str | None = None
    machine: str | None = None
    timestamp: int | None = None
    is_dll: bool = False
    num_sections: int = 0
    entry_point: int = 0
    sections: list[SectionInfo] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    suspicious_apis: dict[str, list[str]] = field(default_factory=dict)
    anomalies: list[str] = field(default_factory=list)
    overall_entropy: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def flat_imports(self) -> list[str]:
        return [f for fs in self.imports.values() for f in fs]


def parse_pe(data: bytes) -> PEReport:
    try:
        import pefile
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pefile is required: pip install pefile") from e

    if data[:2] != b"MZ":
        return PEReport(is_pe=False, error="missing MZ header", overall_entropy=shannon_entropy(data))
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as e:
        return PEReport(is_pe=False, error=str(e), overall_entropy=shannon_entropy(data))

    r = PEReport(is_pe=True, overall_entropy=shannon_entropy(data))
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    r.machine = pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine))
    r.timestamp = fh.TimeDateStamp
    r.is_dll = bool(fh.Characteristics & 0x2000)
    r.num_sections = fh.NumberOfSections
    r.entry_point = oh.AddressOfEntryPoint

    ep_section = None
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        info = SectionInfo(name, s.Misc_VirtualSize, s.SizeOfRawData, round(s.get_entropy(), 4),
                           bool(s.Characteristics & 0x20000000), bool(s.Characteristics & 0x80000000))
        r.sections.append(info)
        if s.contains_rva(oh.AddressOfEntryPoint):
            ep_section = info
        if info.entropy > HIGH_ENTROPY:
            r.anomalies.append(f"high_entropy_section:{name}")
        if info.executable and info.writable:
            r.anomalies.append(f"rwx_section:{name}")
        if info.raw_size == 0 and info.virtual_size > 0:
            r.anomalies.append(f"virtual_only_section:{name}")

    if ep_section is None:
        r.anomalies.append("entry_point_outside_sections")
    elif not ep_section.executable:
        r.anomalies.append("entry_point_in_non_executable_section")

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="replace").lower()
        r.imports[dll] = [i.name.decode(errors="replace") for i in entry.imports if i.name]
    for exp in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        if exp.name:
            r.exports.append(exp.name.decode(errors="replace"))

    if not r.imports:
        r.anomalies.append("no_imports")
    r.suspicious_apis = classify_imports(r.flat_imports)
    pe.close()
    return r
