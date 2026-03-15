from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List


@dataclass
class Finding:
    """Represents a discovered potential vulnerability.

    Backward-compat:
        Older versions/tests sometimes instantiated ``Finding`` with additional
        keyword arguments (e.g. ``Finding(**payload)``). To keep compatibility,
        the constructor accepts and ignores unknown kwargs.
    """

    rule_id: str
    description: str
    file_path: str
    line_number: int
    sink_context: str
    severity: str = "CRITICAL"
    source_var: str = ""
    sink_name: str = ""

    def __init__(
        self,
        rule_id: str,
        description: str,
        file_path: str,
        line_number: int,
        sink_context: str,
        severity: str = "CRITICAL",
        source_var: str = "",
        sink_name: str = "",
        **_ignored: Any,
    ) -> None:
        self.rule_id = rule_id
        self.description = description
        self.file_path = file_path
        self.line_number = int(line_number or 0)
        self.sink_context = sink_context
        self.severity = severity
        self.source_var = source_var
        self.sink_name = sink_name


@dataclass
class ScanResult:
    """Represents the complete result of a scan."""

    total_files: int
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
