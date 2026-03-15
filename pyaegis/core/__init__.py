"""Core analysis primitives for PyAegis.

This package intentionally keeps imports light to avoid import-time side effects.
"""

from .parser import PyASTParser
from .taint import TaintTracker
from .shield import Shield, ShieldEntry, fingerprint_finding

# Optional P0 inter-procedural support
from .call_graph import GlobalSymbolTable, InterproceduralTaintTracker

# Optional: pattern-based detectors (best-effort, lightweight)
from .detectors import (
    BaseDetector,
    HardcodedSecretsDetector,
    WeakCryptoDetector,
    InsecureDeserializationDetector,
    InsecureRandomDetector,
)

__all__ = [
    "PyASTParser",
    "TaintTracker",
    "GlobalSymbolTable",
    "InterproceduralTaintTracker",
    "Shield",
    "ShieldEntry",
    "fingerprint_finding",
    "BaseDetector",
    "HardcodedSecretsDetector",
    "WeakCryptoDetector",
    "InsecureDeserializationDetector",
    "InsecureRandomDetector",
]
