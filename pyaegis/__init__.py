"""PyAegis — Python Static Application Security Testing.

Public API::

    from pyaegis import scan_code_string, scan_file, scan_directory
    from pyaegis import TaintTracker, ParallelProjectParser, Finding
"""
from __future__ import annotations

from .api import scan_code_string, scan_file, scan_directory
from .core.taint import TaintTracker
from .core.parser import ParallelProjectParser
from .models import Finding, ScanResult

__all__ = [
    "scan_code_string",
    "scan_file",
    "scan_directory",
    "TaintTracker",
    "ParallelProjectParser",
    "Finding",
    "ScanResult",
]
