"""
PyAegis Reporters - Output formatters for scan results.
SARIF 2.1.0 with full rule metadata, CWE tags, help URIs, and fix suggestions.
"""

import datetime
import json
from typing import Any, Dict, List

from .models import Finding, ScanResult


# ---------------------------------------------------------------------------
# Rule metadata registry
# ---------------------------------------------------------------------------

RULE_METADATA: Dict[str, Dict[str, str]] = {
    "taint-command-injection": {
        "name": "CommandInjection",
        "shortDescription": "OS command injection via tainted data",
        "fullDescription": (
            "User-controlled data flows into a shell execution sink "
            "(os.system, subprocess.*, eval, exec) without sanitization, "
            "enabling arbitrary command execution."
        ),
        "helpText": (
            "Use subprocess.run() with a list of arguments and shell=False. "
            "Never pass unsanitized user input to shell commands. "
            "Consider using shlex.quote() if shell strings are unavoidable."
        ),
        "helpUri": "https://owasp.org/www-community/attacks/Command_Injection",
        "cwe": "CWE-78",
        "cweUri": "https://cwe.mitre.org/data/definitions/78.html",
        "owasp": "A03:2021",
        "fix": "Replace shell=True with a list-form subprocess call; validate/whitelist inputs before use.",
    },
    "taint-sql-injection": {
        "name": "SqlInjection",
        "shortDescription": "SQL injection via tainted data",
        "fullDescription": (
            "User-controlled data is concatenated into a SQL query without "
            "parameterization, allowing an attacker to manipulate database queries."
        ),
        "helpText": (
            "Use parameterized queries or an ORM. "
            "Example: cursor.execute('SELECT * FROM t WHERE id=%s', (uid,))"
        ),
        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
        "cwe": "CWE-89",
        "cweUri": "https://cwe.mitre.org/data/definitions/89.html",
        "owasp": "A03:2021",
        "fix": "Use parameterized queries; never build SQL strings with user data.",
    },
    "taint-eval-injection": {
        "name": "EvalInjection",
        "shortDescription": "Code injection via eval/exec with tainted data",
        "fullDescription": (
            "Tainted user input reaches eval() or exec(), allowing arbitrary "
            "Python code execution."
        ),
        "helpText": (
            "Avoid eval/exec entirely. If dynamic evaluation is required, "
            "use ast.literal_eval for safe literal parsing."
        ),
        "helpUri": "https://owasp.org/www-community/attacks/Code_Injection",
        "cwe": "CWE-94",
        "cweUri": "https://cwe.mitre.org/data/definitions/94.html",
        "owasp": "A03:2021",
        "fix": "Replace eval/exec with ast.literal_eval or a safe data-parsing alternative.",
    },
    "taint-path-traversal": {
        "name": "PathTraversal",
        "shortDescription": "Path traversal via tainted filename",
        "fullDescription": (
            "User-controlled data is used in a file-system path operation "
            "without normalization, allowing directory traversal attacks."
        ),
        "helpText": (
            "Use pathlib.Path.resolve() and validate that the resolved path "
            "starts with the intended base directory."
        ),
        "helpUri": "https://owasp.org/www-community/attacks/Path_Traversal",
        "cwe": "CWE-22",
        "cweUri": "https://cwe.mitre.org/data/definitions/22.html",
        "owasp": "A01:2021",
        "fix": "Validate resolved paths against a trusted base directory before opening files.",
    },
    "taint-ssrf": {
        "name": "SSRF",
        "shortDescription": "Server-Side Request Forgery via tainted URL",
        "fullDescription": (
            "User-controlled data is used as a URL in an outbound HTTP request, "
            "allowing the server to be used as a proxy to internal services."
        ),
        "helpText": (
            "Validate and whitelist allowed URL schemes and hosts. "
            "Use an allowlist of known-safe endpoints."
        ),
        "helpUri": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "cwe": "CWE-918",
        "cweUri": "https://cwe.mitre.org/data/definitions/918.html",
        "owasp": "A10:2021",
        "fix": "Allowlist permitted hosts/schemes; reject or sanitize user-supplied URLs.",
    },
    # Generic fallback populated dynamically for unknown rule IDs
}

_GENERIC_META: Dict[str, str] = {
    "name": "SecurityFinding",
    "shortDescription": "Potential security vulnerability detected",
    "fullDescription": "A taint-tracking analysis identified a potentially dangerous data flow.",
    "helpText": "Review the flagged code path and ensure untrusted input is properly validated.",
    "helpUri": "https://owasp.org/www-project-top-ten/",
    "cwe": "CWE-20",
    "cweUri": "https://cwe.mitre.org/data/definitions/20.html",
    "owasp": "A03:2021",
    "fix": "Validate and sanitize all user-controlled input before use in sensitive operations.",
}


def _get_meta(rule_id: str) -> Dict[str, str]:
    """Return rule metadata, falling back to generic entry."""
    return RULE_METADATA.get(rule_id, _GENERIC_META)


def _severity_to_sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
    }.get(severity.upper(), "warning")


# ---------------------------------------------------------------------------
# Text reporter
# ---------------------------------------------------------------------------


class TextReporter:
    """Human-readable console output."""

    def __init__(self, stream):
        self.stream = stream

    def report(self, result: ScanResult) -> None:
        w = self.stream.write
        w("=" * 64 + "\n")
        w("  PyAegis Security Scan Report\n")
        w("=" * 64 + "\n")

        if not result.findings:
            # Keep the phrasing stable for tests and external integrations.
            w("\nNo vulnerabilities found.\n")
        else:
            w(f"\nFound {len(result.findings)} issue(s):\n\n")
            for f in result.findings:
                meta = _get_meta(f.rule_id)
                w(f"[{f.severity}] {f.rule_id} — {meta['shortDescription']}\n")
                w(f"  File   : {f.file_path}:{f.line_number}\n")
                w(f"  Source : {f.source_var}\n")
                w(f"  Sink   : {f.sink_context}\n")
                w(f"  CWE    : {meta['cwe']}\n")
                w(f"  Fix    : {meta['fix']}\n")
                w("\n")

        w("-" * 64 + "\n")
        w(f"Files scanned : {result.total_files}\n")
        w(f"Total findings: {len(result.findings)}\n")
        w(f"Duration      : {result.duration_seconds:.3f}s\n")


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------


class JSONReporter:
    """Machine-readable JSON output."""

    def __init__(self, stream):
        self.stream = stream

    def report(self, result: ScanResult) -> None:
        # Test suite expects a stable top-level shape.
        data = {
            "meta": {
                "scan_time": datetime.datetime.utcnow().isoformat() + "Z",
                "total_files_scanned": result.total_files,
                "duration_seconds": result.duration_seconds,
                "total_findings": len(result.findings),
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "source_var": f.source_var,
                    "sink_context": f.sink_context,
                    "cwe": _get_meta(f.rule_id)["cwe"],
                    "fix": _get_meta(f.rule_id)["fix"],
                }
                for f in result.findings
            ],
        }
        self.stream.write(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# SARIF 2.1.0 reporter
# ---------------------------------------------------------------------------


class SARIFReporter:
    """Produces a SARIF 2.1.0 document."""

    SCHEMA_URI = (
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
    )
    TOOL_NAME = "PyAegis"
    TOOL_VERSION = "0.2.0"
    TOOL_INFO_URI = "https://github.com/mnbplus/PyAegis"

    def __init__(self, stream):
        self.stream = stream

    def report(self, result: ScanResult) -> None:
        sarif_doc = self._build(result)
        self.stream.write(json.dumps(sarif_doc, indent=2))

    def _build(self, result: ScanResult) -> Dict[str, Any]:
        rules_map: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        for finding in result.findings:
            rule_id = finding.rule_id
            meta = _get_meta(rule_id)

            if rule_id not in rules_map:
                rules_map[rule_id] = self._build_rule(rule_id, meta)

            sarif_results.append(self._build_result(finding, meta))

        return {
            "$schema": self.SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "semanticVersion": self.TOOL_VERSION,
                            "informationUri": self.TOOL_INFO_URI,
                            "organization": "PyAegis Project",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "commandLine": "pyaegis scan",
                            "endTimeUtc": datetime.datetime.utcnow().strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                        }
                    ],
                    "results": sarif_results,
                    "properties": {
                        "totalFiles": result.total_files,
                        "durationSeconds": result.duration_seconds,
                    },
                }
            ],
        }

    @staticmethod
    def _build_rule(rule_id: str, meta: Dict[str, str]) -> Dict[str, Any]:
        return {
            "id": rule_id,
            "name": meta["name"],
            "shortDescription": {"text": meta["shortDescription"]},
            "fullDescription": {"text": meta["fullDescription"]},
            "help": {
                "text": meta["helpText"],
                "markdown": (
                    f"**{meta['shortDescription']}**\n\n"
                    f"{meta['fullDescription']}\n\n"
                    f"### Remediation\n{meta['helpText']}\n\n"
                    f"### References\n"
                    f"- [{meta['cwe']}]({meta['cweUri']})\n"
                    f"- [OWASP {meta['owasp']}](https://owasp.org/Top10/)\n"
                    f"- [Details]({meta['helpUri']})\n"
                ),
            },
            "helpUri": meta["helpUri"],
            "defaultConfiguration": {
                "level": _severity_to_sarif_level(meta.get("severity", "HIGH"))
            },
            "properties": {
                "tags": [
                    meta["cwe"],
                    f"owasp:{meta['owasp']}",
                    "security",
                    "python",
                ],
                "precision": "medium",
                "problem.severity": meta.get("severity", "HIGH").lower(),
            },
        }

    @staticmethod
    def _build_result(finding: Finding, meta: Dict[str, str]) -> Dict[str, Any]:
        uri = finding.file_path.replace("\\", "/")
        level = _severity_to_sarif_level(finding.severity)

        fix_obj = {
            "description": {"text": meta["fix"]},
            "artifactChanges": [],
        }

        result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level,
            "rank": {
                "CRITICAL": 95.0,
                "HIGH": 80.0,
                "MEDIUM": 50.0,
                "LOW": 25.0,
                "INFO": 5.0,
            }.get(finding.severity.upper(), 50.0),
            "message": {
                "text": (
                    f"{finding.description} "
                    f"(source: `{finding.source_var}`, sink: `{finding.sink_context}`)"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": 1,
                        },
                    },
                    "logicalLocations": [
                        {
                            "kind": "module",
                            "name": uri.replace("/", ".").rstrip(".py"),
                        }
                    ],
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": (
                    f"{finding.rule_id}:{uri}:{finding.line_number}"
                )
            },
            "fixes": [fix_obj],
            "properties": {
                "severity": finding.severity,
                "sourceVariable": finding.source_var,
                "sinkContext": finding.sink_context,
                "cwe": meta["cwe"],
            },
        }
        return result


# ---------------------------------------------------------------------------
# Legacy functional API (backwards-compatible)
# ---------------------------------------------------------------------------


def generate_text_report(result: ScanResult) -> str:
    import io

    buf = io.StringIO()
    TextReporter(buf).report(result)
    return buf.getvalue()


def generate_json_report(result: ScanResult) -> str:
    import io

    buf = io.StringIO()
    JSONReporter(buf).report(result)
    return buf.getvalue()


def generate_sarif_report(result: ScanResult) -> str:
    import io

    buf = io.StringIO()
    SARIFReporter(buf).report(result)
    return buf.getvalue()
