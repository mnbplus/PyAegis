from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    """Represents a discovered potential vulnerability."""

    rule_id: str
    description: str
    file_path: str
    line_number: int
    sink_context: str
    severity: str = "CRITICAL"
    source_var: str = ""


@dataclass
class ScanResult:
    """Represents the complete result of a scan."""

    total_files: int
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
