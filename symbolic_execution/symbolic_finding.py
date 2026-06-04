from __future__ import annotations
from dataclasses import dataclass, field
from .symbolic_value import TaintSource


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class SymbolicFinding:
    vuln_type:   str
    severity:    str
    title:       str
    description: str
    block_offset: int
    taint_source: TaintSource
    path_summary: list[str]      = field(default_factory=list)
    confirmed:    bool           = False

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def escalate(self, new_severity: str, reason: str) -> SymbolicFinding:
        return SymbolicFinding(
            vuln_type    = self.vuln_type,
            severity     = new_severity,
            title        = f"{self.title} [escalated: {reason}]",
            description  = self.description,
            block_offset = self.block_offset,
            taint_source = self.taint_source,
            path_summary = self.path_summary,
            confirmed    = self.confirmed,
        )

    def __repr__(self) -> str:
        return (
            f"[{self.severity}] {self.title} "
            f"@ 0x{self.block_offset:04x} "
            f"(taint={self.taint_source.value})"
        )
