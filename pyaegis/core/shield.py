"""
pyaegis/core/shield.py  -- stub implementation

Shield provides deduplication / fingerprinting for findings.
This stub exposes the minimal API referenced by __init__.py.
"""
from dataclasses import dataclass, field
from typing import List, Optional
import hashlib

from pyaegis.models import Finding


@dataclass
class ShieldEntry:
    """A deduplicated finding record."""
    fingerprint: str
    finding: Finding
    suppressed: bool = False


@dataclass
class Shield:
    """Deduplication and suppression layer over raw findings."""
    _entries: List[ShieldEntry] = field(default_factory=list)

    def add(self, finding: Finding) -> Optional[ShieldEntry]:
        """Add a finding; return None if duplicate, else the new ShieldEntry."""
        fp = fingerprint_finding(finding)
        for e in self._entries:
            if e.fingerprint == fp:
                return None
        entry = ShieldEntry(fingerprint=fp, finding=finding)
        self._entries.append(entry)
        return entry

    def entries(self) -> List[ShieldEntry]:
        return [e for e in self._entries if not e.suppressed]

    def suppress(self, fingerprint: str) -> bool:
        for e in self._entries:
            if e.fingerprint == fingerprint:
                e.suppressed = True
                return True
        return False


def fingerprint_finding(finding: Finding) -> str:
    """Return a stable fingerprint for a Finding based on key fields."""
    key = f"{finding.rule_id}:{finding.file_path}:{finding.line_number}:{finding.sink_name}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]
