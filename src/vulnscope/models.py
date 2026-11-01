from __future__ import annotations
from dataclasses import dataclass, field, asdict


@dataclass
class TraceStep:
    line: int
    kind: str          # source | propagate | call | sink | param
    detail: str


@dataclass
class Finding:
    rule_id: str
    cwe: str
    title: str
    file: str
    line: int
    col: int
    snippet: str
    function: str | None
    tainted: bool
    trace: list[TraceStep] = field(default_factory=list)
    engine: str = "vulnscope"
    confidence: float = 0.5
    severity: str | None = None
    cvss: float | None = None
    priority: float | None = None
    remediation: dict | None = None
    triage_prob: float | None = None

    @property
    def key(self):
        return (self.file, self.line, self.cwe)

    def to_dict(self):
        return asdict(self)
