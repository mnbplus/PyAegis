"""
pyaegis/core/detectors.py  -- stub implementation

Pattern-based detectors for common vulnerability classes.
This stub exposes the minimal API referenced by __init__.py.
"""
from abc import ABC, abstractmethod
from typing import List
import ast
import re

from pyaegis.models import Finding


class BaseDetector(ABC):
    """Abstract base for all pattern-based detectors."""

    @abstractmethod
    def analyze(self, tree: ast.AST, filepath: str) -> List[Finding]:
        """Run detection on an AST; return a list of findings."""
        ...


class HardcodedSecretsDetector(BaseDetector):
    """Detect hardcoded secrets / credentials in source code."""

    _PATTERNS = [
        re.compile(r'(?i)(password|passwd|secret|api_key|token|auth)\s*=\s*["\'][^"\']{4,}["\']'),
    ]

    def analyze(self, tree: ast.AST, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        if any(kw in name_lower for kw in
                               ("password", "passwd", "secret", "api_key", "token", "auth")):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                if len(node.value.value) >= 4:
                                    findings.append(Finding(
                                        rule_id="PYA-010",
                                        description=f"Possible hardcoded secret in variable '{target.id}'",
                                        file_path=filepath,
                                        line_number=getattr(node, "lineno", 0),
                                        sink_context="",
                                        severity="HIGH",
                                        sink_name=target.id,
                                    ))
        return findings


class WeakCryptoDetector(BaseDetector):
    """Detect use of weak cryptographic algorithms (MD5, SHA1, DES, etc.)."""

    _WEAK = {"md5", "sha1", "des", "rc4", "rc2", "blowfish"}

    def analyze(self, tree: ast.AST, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = ""
                if isinstance(node.func, ast.Attribute):
                    fn = node.func.attr.lower()
                elif isinstance(node.func, ast.Name):
                    fn = node.func.id.lower()
                if fn in self._WEAK:
                    findings.append(Finding(
                        rule_id="PYA-007",
                        description=f"Use of weak cryptographic function: {fn}",
                        file_path=filepath,
                        line_number=getattr(node, "lineno", 0),
                        sink_context="",
                        severity="MEDIUM",
                        sink_name=fn,
                    ))
        return findings


class InsecureDeserializationDetector(BaseDetector):
    """Detect insecure deserialization calls."""

    _SINKS = {"pickle.loads", "pickle.load", "marshal.loads",
              "yaml.load", "jsonpickle.decode", "dill.loads"}

    def analyze(self, tree: ast.AST, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                parts = []
                n = node.func
                while isinstance(n, ast.Attribute):
                    parts.append(n.attr)
                    n = n.value
                if isinstance(n, ast.Name):
                    parts.append(n.id)
                full = ".".join(reversed(parts))
                if full in self._SINKS:
                    findings.append(Finding(
                        rule_id="PYA-004",
                        description=f"Insecure deserialization: {full}",
                        file_path=filepath,
                        line_number=getattr(node, "lineno", 0),
                        sink_context="",
                        severity="CRITICAL",
                        sink_name=full,
                    ))
        return findings


class InsecureRandomDetector(BaseDetector):
    """Detect use of non-cryptographic random for security-sensitive contexts."""

    _SINKS = {"random.random", "random.randint", "random.choice",
              "random.randrange", "random.shuffle", "random.sample"}

    def analyze(self, tree: ast.AST, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                parts = []
                n = node.func
                while isinstance(n, ast.Attribute):
                    parts.append(n.attr)
                    n = n.value
                if isinstance(n, ast.Name):
                    parts.append(n.id)
                full = ".".join(reversed(parts))
                if full in self._SINKS:
                    findings.append(Finding(
                        rule_id="PYA-008",
                        description=f"Use of insecure random function: {full}",
                        file_path=filepath,
                        line_number=getattr(node, "lineno", 0),
                        sink_context="",
                        severity="MEDIUM",
                        sink_name=full,
                    ))
        return findings
