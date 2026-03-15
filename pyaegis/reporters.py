"""PyAegis Reporters - Output formatters for scan results.

SARIF 2.1.0 with full rule metadata, CWE tags, help URIs, and fix suggestions.

Text reporter UX improvements:
- Optional colored severity labels
- Code context (2 lines before/after)
- Summary statistics
"""

from __future__ import annotations

import csv
import datetime
import html as html_lib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .models import Finding, ScanResult
from .rules_catalog import as_reporter_meta
from .fixers import RemediationEngine

_remediation_engine = RemediationEngine()


# ---------------------------------------------------------------------------
# Rule metadata registry
# ---------------------------------------------------------------------------

# NOTE: Reporter metadata is backed by the stable rule catalog.
# To add/update rule descriptions, edit pyaegis/rules_catalog.py.

RULE_METADATA: Dict[str, Dict[str, str]] = {
    rid: as_reporter_meta(rid)
    for rid in [
        "PYA-001",
        "PYA-002",
        "PYA-003",
        "PYA-004",
        "PYA-005",
        "PYA-006",
    ]
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
    "severity": "HIGH",
}


def _get_meta(rule_id: str) -> Dict[str, str]:
    """Return rule metadata, falling back to generic entry."""
    meta = RULE_METADATA.get(rule_id)
    return meta if meta else _GENERIC_META


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


@dataclass(frozen=True)
class _Counts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


def _count_findings(findings: List[Finding]) -> _Counts:
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.severity or "").upper()
        if sev in c:
            c[sev] += 1
        else:
            c["HIGH"] += 1
    return _Counts(
        critical=c["CRITICAL"],
        high=c["HIGH"],
        medium=c["MEDIUM"],
        low=c["LOW"],
        info=c["INFO"],
    )


def _supports_color(stream) -> bool:
    if os.getenv("NO_COLOR") is not None:
        return False
    if os.getenv("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _ansi(color_code: str, text: str) -> str:
    return f"\x1b[{color_code}m{text}\x1b[0m"


def _colorize_severity(sev: str, *, enabled: bool) -> str:
    sev_u = (sev or "").upper()
    if not enabled:
        return sev_u

    # CRITICAL red, HIGH orange-ish, MEDIUM yellow, LOW blue
    colors = {
        "CRITICAL": "31",  # red
        "HIGH": "38;5;208",  # orange
        "MEDIUM": "33",  # yellow
        "LOW": "34",  # blue
        "INFO": "90",  # gray
    }
    code = colors.get(sev_u, "0")
    return _ansi(code, sev_u)


def _read_context(file_path: str, line_number: int, radius: int = 2) -> Optional[str]:
    """Read code context around a 1-based line_number.

    Returns a formatted block or None if unreadable.
    """
    if not file_path or line_number <= 0:
        return None

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None

    idx = line_number - 1
    start = max(idx - radius, 0)
    end = min(idx + radius, len(lines) - 1)

    out: list[str] = []
    for i in range(start, end + 1):
        prefix = ">" if i == idx else " "
        out.append(f"{prefix} {i+1:>5} | {lines[i].rstrip()}\n")
    return "".join(out)


class TextReporter:
    """Human-readable console output."""

    def __init__(self, stream, *, color: Optional[bool] = None, context_lines: int = 2):
        self.stream = stream
        self.context_lines = context_lines
        if color is None:
            self.color = _supports_color(stream)
        else:
            self.color = bool(color)

    def report(self, result: ScanResult) -> None:
        w = self.stream.write
        counts = _count_findings(result.findings)

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
                title = meta.get("shortDescription", "Security finding")
                sev_label = _colorize_severity(f.severity, enabled=self.color)

                w(f"[{sev_label}] {f.rule_id} — {title}\n")
                w(f"  File   : {f.file_path}:{f.line_number}\n")

                if getattr(f, "sink_name", ""):
                    w(f"  Sink   : {f.sink_name}\n")
                w(f"  Context: {f.sink_context}\n")

                if getattr(f, "source_var", ""):
                    w(f"  Source : {f.source_var}\n")

                if meta.get("cwe"):
                    w(f"  CWE    : {meta.get('cwe')}\n")
                if meta.get("fix"):
                    w(f"  Fix    : {meta.get('fix')}\n")

                ctx = _read_context(f.file_path, f.line_number, radius=self.context_lines)
                if ctx:
                    w("\n  Code:\n")
                    # keep indentation consistent
                    for line in ctx.splitlines(True):
                        w("  " + line)

                # --- AI remediation snippet (P3) ---
                try:
                    rem = _remediation_engine.get_remediation(f)
                    w(f"\n  Suggested Fix : {rem.title}\n")
                    w(f"  Hint          : {rem.explanation}\n")
                    w("  Example (after):\n")
                    for ex_line in rem.example_after.splitlines():
                        w(f"    {ex_line}\n")
                except Exception:
                    pass

                w("\n")

        w("-" * 64 + "\n")
        w(f"Files scanned : {result.total_files}\n")
        w(f"Total findings: {len(result.findings)}\n")
        w(
            "Severity     : "
            f"CRITICAL={counts.critical} HIGH={counts.high} "
            f"MEDIUM={counts.medium} LOW={counts.low} INFO={counts.info}\n"
        )
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
# CSV reporter
# ---------------------------------------------------------------------------


class CSVReporter:
    """CSV output (one finding per row)."""

    FIELDNAMES = [
        "rule_id",
        "severity",
        "description",
        "file_path",
        "line_number",
        "source_var",
        "sink_context",
        "sink_name",
        "cwe",
        "fix",
    ]

    def __init__(self, stream):
        self.stream = stream

    def report(self, result: ScanResult) -> None:
        writer = csv.DictWriter(self.stream, fieldnames=self.FIELDNAMES)
        writer.writeheader()
        for f in result.findings:
            meta = _get_meta(f.rule_id)
            writer.writerow(
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "source_var": f.source_var,
                    "sink_context": f.sink_context,
                    "sink_name": getattr(f, "sink_name", ""),
                    "cwe": meta.get("cwe", ""),
                    "fix": meta.get("fix", ""),
                }
            )


# ---------------------------------------------------------------------------
# HTML reporter
# ---------------------------------------------------------------------------


class HTMLReporter:
    """Standalone HTML report for easy sharing."""

    def __init__(self, stream):
        self.stream = stream

    def report(self, result: ScanResult) -> None:
        total = len(result.findings)
        duration = f"{result.duration_seconds:.3f}s"
        rows = []
        for f in result.findings:
            meta = _get_meta(f.rule_id)
            rows.append(
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": meta.get("shortDescription", "Security finding"),
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "source_var": f.source_var,
                    "sink_context": f.sink_context,
                    "sink_name": getattr(f, "sink_name", ""),
                    "cwe": meta.get("cwe", ""),
                    "fix": meta.get("fix", ""),
                }
            )

        html = self._build_html(
            total_files=result.total_files,
            duration=duration,
            total_findings=total,
            rows=rows,
        )
        self.stream.write(html)

    def _build_html(
        self,
        *,
        total_files: int,
        duration: str,
        total_findings: int,
        rows: List[Dict[str, Any]],
    ) -> str:
        def esc(val: Any) -> str:
            return html_lib.escape(str(val))

        if total_findings == 0:
            rows_html = (
                "<tr><td colspan='9' class='empty'>"
                "No vulnerabilities found." "</td></tr>"
            )
        else:
            rows_html = "\n".join(
                "<tr>"
                f"<td><code>{esc(r['rule_id'])}</code></td>"
                f"<td class='sev sev-{esc(r['severity']).lower()}'>{esc(r['severity'])}</td>"
                f"<td>{esc(r['title'])}</td>"
                f"<td><code>{esc(r['file_path'])}:{esc(r['line_number'])}</code></td>"
                f"<td>{esc(r['sink_context'])}</td>"
                f"<td>{esc(r['sink_name'])}</td>"
                f"<td>{esc(r['source_var'])}</td>"
                f"<td>{esc(r['cwe'])}</td>"
                f"<td>{esc(r['description'])}</td>"
                "</tr>"
                for r in rows
            )

        return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>PyAegis Report</title>
  <style>
    :root {{
      --bg: #0b0e14;
      --card: #111622;
      --text: #e6edf3;
      --muted: #9aa4b2;
      --accent: #6cb6ff;
      --border: #1c2333;
      --sev-critical: #ff6b6b;
      --sev-high: #ff922b;
      --sev-medium: #f9c74f;
      --sev-low: #63e6be;
      --sev-info: #74c0fc;
    }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 32px 40px 16px;
      background: linear-gradient(120deg, #111827, #0b0e14);
      border-bottom: 1px solid var(--border);
    }}
    header h1 {{
      margin: 0 0 8px;
      font-size: 24px;
      letter-spacing: 0.5px;
    }}
    header p {{
      margin: 0;
      color: var(--muted);
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      padding: 16px 40px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 16px;
    }}
    .card h3 {{
      margin: 0 0 6px;
      font-size: 13px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .card p {{
      margin: 0;
      font-size: 20px;
      font-weight: 600;
    }}
    .table-wrap {{
      padding: 8px 40px 40px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }}
    th, td {{
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      font-size: 13px;
    }}
    th {{
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      background: #0f1524;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    code {{
      color: var(--accent);
    }}
    .sev {{
      font-weight: 600;
    }}
    .sev-critical {{ color: var(--sev-critical); }}
    .sev-high {{ color: var(--sev-high); }}
    .sev-medium {{ color: var(--sev-medium); }}
    .sev-low {{ color: var(--sev-low); }}
    .sev-info {{ color: var(--sev-info); }}
    .empty {{
      color: var(--muted);
      text-align: center;
      padding: 24px;
    }}
    footer {{
      padding: 0 40px 32px;
      color: var(--muted);
      font-size: 12px;
    }}
  </style>
</head>
<body>
  <header>
    <h1>PyAegis Security Scan Report</h1>
    <p>Generated at {esc(datetime.datetime.utcnow().isoformat())}Z</p>
  </header>
  <section class=\"stats\">
    <div class=\"card\">
      <h3>Files scanned</h3>
      <p>{esc(total_files)}</p>
    </div>
    <div class=\"card\">
      <h3>Total findings</h3>
      <p>{esc(total_findings)}</p>
    </div>
    <div class=\"card\">
      <h3>Duration</h3>
      <p>{esc(duration)}</p>
    </div>
  </section>
  <section class=\"table-wrap\">
    <table>
      <thead>
        <tr>
          <th>Rule</th>
          <th>Severity</th>
          <th>Title</th>
          <th>Location</th>
          <th>Context</th>
          <th>Sink</th>
          <th>Source</th>
          <th>CWE</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </section>
  <footer>
    Report generated by PyAegis.
  </footer>
</body>
</html>"""


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
            }.get((finding.severity or "").upper(), 50.0),
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
                "primaryLocationLineHash": f"{finding.rule_id}:{uri}:{finding.line_number}"
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


def generate_csv_report(result: ScanResult) -> str:
    import io

    buf = io.StringIO()
    CSVReporter(buf).report(result)
    return buf.getvalue()


def generate_html_report(result: ScanResult) -> str:
    import io

    buf = io.StringIO()
    HTMLReporter(buf).report(result)
    return buf.getvalue()


def generate_sarif_report(result: ScanResult) -> str:
    import io

    buf = io.StringIO()
    SARIFReporter(buf).report(result)
    return buf.getvalue()
