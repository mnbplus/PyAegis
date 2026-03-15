"""PyAegis rule catalog.

This module defines stable rule IDs (e.g. PYA-001) and provides metadata used by:
- `pyaegis explain <RULE_ID>`
- SARIF rule metadata

Rule IDs are intended to be stable across versions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class RuleInfo:
    id: str
    name: str
    short_description: str
    full_description: str
    severity: str
    cwe: str
    cwe_uri: str
    owasp: str
    help_uri: str
    remediation: str


RULES: Dict[str, RuleInfo] = {
    "PYA-001": RuleInfo(
        id="PYA-001",
        name="CommandInjection",
        short_description="OS command injection via tainted data",
        full_description=(
            "Untrusted input flows into an OS command execution sink such as "
            "os.system/os.popen/subprocess.* with inadequate validation or "
            "sanitization, enabling arbitrary command execution."
        ),
        severity="CRITICAL",
        cwe="CWE-78",
        cwe_uri="https://cwe.mitre.org/data/definitions/78.html",
        owasp="A03:2021",
        help_uri="https://owasp.org/www-community/attacks/Command_Injection",
        remediation=(
            "Prefer subprocess.run([...], shell=False). Avoid shell=True. "
            "Use allowlists for commands/arguments; validate inputs strictly."
        ),
    ),
    "PYA-002": RuleInfo(
        id="PYA-002",
        name="SqlInjection",
        short_description="SQL injection via tainted data",
        full_description=(
            "Untrusted input is used to build SQL queries without proper "
            "parameterization, allowing attackers to alter query semantics."
        ),
        severity="CRITICAL",
        cwe="CWE-89",
        cwe_uri="https://cwe.mitre.org/data/definitions/89.html",
        owasp="A03:2021",
        help_uri="https://owasp.org/www-community/attacks/SQL_Injection",
        remediation=(
            "Use parameterized queries or a safe ORM API. Never concatenate "
            "user input into SQL strings."
        ),
    ),
    "PYA-003": RuleInfo(
        id="PYA-003",
        name="CodeInjection",
        short_description="Code injection via eval/exec with tainted data",
        full_description=(
            "Untrusted input reaches dynamic code execution primitives like "
            "eval(), exec(), or compile(), enabling arbitrary code execution."
        ),
        severity="CRITICAL",
        cwe="CWE-94",
        cwe_uri="https://cwe.mitre.org/data/definitions/94.html",
        owasp="A03:2021",
        help_uri="https://owasp.org/www-community/attacks/Code_Injection",
        remediation=(
            "Avoid eval/exec. If you need to parse literals, use ast.literal_eval. "
            "Prefer safe parsers and explicit mappings."
        ),
    ),
    "PYA-004": RuleInfo(
        id="PYA-004",
        name="InsecureDeserialization",
        short_description="Insecure deserialization of untrusted data",
        full_description=(
            "Untrusted data is deserialized using unsafe mechanisms (pickle, yaml.load, "
            "dill, marshal, jsonpickle), which may instantiate attacker-controlled objects "
            "or execute code."
        ),
        severity="CRITICAL",
        cwe="CWE-502",
        cwe_uri="https://cwe.mitre.org/data/definitions/502.html",
        owasp="A08:2021",
        help_uri="https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
        remediation=(
            "Do not deserialize untrusted bytes with pickle/dill/marshal. Use safe formats "
            "(JSON) and strict schemas. For YAML, use yaml.safe_load."
        ),
    ),
    "PYA-005": RuleInfo(
        id="PYA-005",
        name="SSRF",
        short_description="Server-Side Request Forgery via tainted URL",
        full_description=(
            "Untrusted input is used as a URL/host in outbound requests, allowing attackers "
            "to reach internal services or metadata endpoints."
        ),
        severity="HIGH",
        cwe="CWE-918",
        cwe_uri="https://cwe.mitre.org/data/definitions/918.html",
        owasp="A10:2021",
        help_uri="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        remediation=(
            "Allowlist schemes/hosts, block private IP ranges, disable redirects, and "
            "use dedicated egress proxies where possible."
        ),
    ),
    "PYA-006": RuleInfo(
        id="PYA-006",
        name="PathTraversal",
        short_description="Path traversal / unsafe file operation via tainted path",
        full_description=(
            "Untrusted input influences file paths used in open/remove/copy/etc, enabling "
            "directory traversal or arbitrary file read/write/delete."
        ),
        severity="HIGH",
        cwe="CWE-22",
        cwe_uri="https://cwe.mitre.org/data/definitions/22.html",
        owasp="A01:2021",
        help_uri="https://owasp.org/www-community/attacks/Path_Traversal",
        remediation=(
            "Resolve paths against a trusted base directory and verify the resolved path stays "
            "within that base. Avoid using user input as a filename directly."
        ),
    ),
}


def get_rule(rule_id: str) -> Optional[RuleInfo]:
    return RULES.get(rule_id.upper().strip())


def as_reporter_meta(rule_id: str) -> dict:
    """Convert RuleInfo into the metadata shape used by reporters."""
    r = get_rule(rule_id)
    if not r:
        return {}
    return {
        "name": r.name,
        "shortDescription": r.short_description,
        "fullDescription": r.full_description,
        "helpText": r.remediation,
        "helpUri": r.help_uri,
        "cwe": r.cwe,
        "cweUri": r.cwe_uri,
        "owasp": r.owasp,
        "severity": r.severity,
        "fix": r.remediation,
    }


def format_explain(rule_id: str) -> str:
    r = get_rule(rule_id)
    if not r:
        return (
            f"Unknown rule id: {rule_id}\n"
            "Tip: run `pyaegis explain PYA-001` to see an example.\n"
        )
    lines = [
        f"{r.id} — {r.short_description}",
        "",
        f"Severity : {r.severity}",
        f"CWE      : {r.cwe} ({r.cwe_uri})",
        f"OWASP    : {r.owasp}",
        f"Reference: {r.help_uri}",
        "",
        "What it means:",
        f"  {r.full_description}",
        "",
        "How to fix:",
        f"  {r.remediation}",
        "",
    ]
    return "\n".join(lines)
