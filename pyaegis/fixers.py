"""PyAegis built-in remediation suggestions (P3)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .models import Finding


@dataclass(frozen=True)
class Remediation:
    vuln_type: str
    title: str
    snippet: str


class RemediationEngine:

    _REMEDIATIONS = {
        "command_injection": Remediation(
            vuln_type="command_injection",
            title="Avoid shell=True; use subprocess list form",
            snippet="import subprocess\nsubprocess.run(['echo', user_input], check=True)",
        ),
        "sql_injection": Remediation(
            vuln_type="sql_injection",
            title="Use parameterized queries",
            snippet='query = "SELECT * FROM users WHERE name = %s"\ncursor.execute(query, (name,))',
        ),
        "code_injection": Remediation(
            vuln_type="code_injection",
            title="Replace eval with ast.literal_eval",
            snippet="import ast\nresult = ast.literal_eval(user_input)",
        ),
        "hardcoded_secret": Remediation(
            vuln_type="hardcoded_secret",
            title="Load secrets from environment variables",
            snippet='import os\nAPI_KEY = os.environ.get("API_KEY", "")',
        ),
        "deserialization": Remediation(
            vuln_type="deserialization",
            title="Avoid pickle on untrusted data; prefer JSON",
            snippet="import json\nobj = json.loads(untrusted_text)",
        ),
        "path_traversal": Remediation(
            vuln_type="path_traversal",
            title="Normalize paths with pathlib.Path.resolve()",
            snippet="from pathlib import Path\nuser_path = Path(base_dir, user_input).resolve()\nif not str(user_path).startswith(str(base_dir)):\n    raise ValueError('path traversal')",
        ),
    }

    _GENERIC = Remediation(
        vuln_type="generic",
        title="Validate and sanitize untrusted input",
        snippet="ALLOWED = {'a', 'b'}\nif value not in ALLOWED:\n    raise ValueError",
    )

    def get_remediation(self, vuln_type: str) -> Remediation:
        key = (vuln_type or "").strip().lower()
        return self._REMEDIATIONS.get(key, self._GENERIC)


def _infer_vuln_type_from_finding(finding):
    rule_id = (getattr(finding, "rule_id", "") or "").strip().upper()
    rule_map = {
        "PYA-001": "command_injection",
        "PYA-002": "sql_injection",
        "PYA-003": "code_injection",
        "PYA-004": "deserialization",
        "PYA-006": "path_traversal",
    }
    if rule_id in rule_map:
        return rule_map[rule_id]

    haystack = " ".join([
        getattr(finding, "sink_name", "") or "",
        getattr(finding, "sink_context", "") or "",
        getattr(finding, "description", "") or "",
    ]).lower()

    if re.search(r"subprocess|os\.system|shell", haystack):
        return "command_injection"
    if re.search(r"sql|cursor|execute|query", haystack):
        return "sql_injection"
    if re.search(r"\beval\b|\bexec\b", haystack):
        return "code_injection"
    if re.search(r"pickle|yaml\.load", haystack):
        return "deserialization"
    if re.search(r"path|open\(|unlink", haystack):
        return "path_traversal"
    if re.search(r"secret|token|password", haystack):
        return "hardcoded_secret"
    return "generic"


def format_remediation_hint(finding, fmt="text", engine=None):
    engine = engine or RemediationEngine()
    vuln_type = _infer_vuln_type_from_finding(finding)
    rem = engine.get_remediation(vuln_type)

    if fmt == "md":
        lines = [
            "### Remediation",
            "**" + rem.title + "**",
            "vuln_type: `" + rem.vuln_type + "`",
            "",
            "```python",
            rem.snippet,
            "```",
            ""
        ]
        return "\n".join(lines)

    indented = "\n".join("    " + ln for ln in rem.snippet.splitlines())
    return "  Remediation:\n  - Type: " + rem.vuln_type + "\n  - Title: " + rem.title + "\n  - Snippet:\n" + indented + "\n"
