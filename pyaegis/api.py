"""pyaegis.api — Headless / programmatic API for PyAegis.

Designed for use by AI coding assistants, IDE plugins, CI pipelines, and
other tools that need to scan Python code without spawning a subprocess.

Quick start::

    from pyaegis.api import scan_code_string, scan_file, scan_directory

    findings = scan_code_string(source_code, severity_filter=["HIGH", "CRITICAL"])
"""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml

# ---------------------------------------------------------------------------
# Severity ranking
# ---------------------------------------------------------------------------

_SEVERITY_RANK: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _default_rules_path() -> str:
    return str(Path(__file__).resolve().parent / "rules" / "default.yml")


def _resolve_rules_path(ruleset: str) -> str:
    """Resolve a ruleset name or file path to an absolute YAML path."""
    if not ruleset or ruleset == "default":
        return _default_rules_path()
    # Explicit file path
    if os.path.isfile(ruleset):
        return os.path.abspath(ruleset)
    # Bundled ruleset name e.g. "ssrf", "xxe", "deserialization"
    rules_dir = Path(__file__).resolve().parent / "rules"
    for ext in (".yml", ".yaml"):
        candidate = rules_dir / (ruleset.lower() + ext)
        if candidate.exists():
            return str(candidate)
    # Fall back to default
    return _default_rules_path()


def _load_rules(rules_path: str) -> dict:
    try:
        with open(rules_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def _severity_passes_filter(
    severity: str, severity_filter: Optional[List[str]]
) -> bool:
    """Return True when *severity* is at or above the minimum in filter.

    e.g. filter=["HIGH", "CRITICAL"] keeps HIGH and CRITICAL;
         filter=["MEDIUM"] keeps MEDIUM, HIGH, and CRITICAL.
    """
    if not severity_filter:
        return True
    normalised = [s.upper() for s in severity_filter]
    min_rank = min(_SEVERITY_RANK.get(s, 0) for s in normalised)
    return _SEVERITY_RANK.get(severity.upper(), 0) >= min_rank


def _finding_to_dict(f: Any) -> Dict[str, Any]:
    """Convert a Finding dataclass to a plain dict for API consumers."""
    return {
        "filename": getattr(f, "file_path", ""),
        "line": getattr(f, "line_number", 0),
        "col": 0,
        "severity": getattr(f, "severity", ""),
        "rule_id": getattr(f, "rule_id", ""),
        "sink_name": getattr(f, "sink_name", ""),
        "source_var": getattr(f, "source_var", ""),
        "message": getattr(f, "description", ""),
        "sink_context": getattr(f, "sink_context", ""),
    }


def _findings_to_csv(findings: List[Any]) -> str:
    """Convert findings to a CSV string (header + rows)."""
    import csv
    import io

    output = io.StringIO()
    fieldnames = [
        "rule_id",
        "severity",
        "message",
        "filename",
        "line",
        "sink_name",
        "source_var",
        "sink_context",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        row = _finding_to_dict(f)
        writer.writerow(
            {
                "rule_id": row.get("rule_id", ""),
                "severity": row.get("severity", ""),
                "message": row.get("message", ""),
                "filename": row.get("filename", ""),
                "line": row.get("line", 0),
                "sink_name": row.get("sink_name", ""),
                "source_var": row.get("source_var", ""),
                "sink_context": row.get("sink_context", ""),
            }
        )
    return output.getvalue()


def _findings_to_json_payload(
    findings: List[Any],
    *,
    total_files: int,
    duration_seconds: float,
) -> Dict[str, Any]:
    """Return a JSON-serializable payload with scan metadata + findings."""
    return {
        "meta": {
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_files_scanned": total_files,
            "duration_seconds": float(f"{duration_seconds:.3f}"),
            "total_findings": len(findings),
        },
        "findings": [_finding_to_dict(f) for f in findings],
    }


def _sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
    }.get(severity.upper(), "warning")


def _findings_to_sarif(
    findings: List[Any],
    tool_version: str = "0.2.0",
) -> Dict[str, Any]:
    """Convert a list of Finding objects to a SARIF 2.1.0 dict."""
    from pyaegis.rules_catalog import get_rule

    rules_seen: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = getattr(f, "rule_id", "PYA-999")
        if rule_id not in rules_seen:
            rule_info = get_rule(rule_id)
            if rule_info:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "name": rule_info.name,
                    "shortDescription": {"text": rule_info.short_description},
                    "fullDescription": {"text": rule_info.full_description},
                    "helpUri": rule_info.help_uri,
                    "defaultConfiguration": {"level": _sarif_level(rule_info.severity)},
                }
            else:
                sink = getattr(f, "sink_name", rule_id)
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": f"Taint flow into {sink}"},
                    "defaultConfiguration": {
                        "level": _sarif_level(getattr(f, "severity", "HIGH"))
                    },
                }

        filename = getattr(f, "file_path", "<unknown>")
        line = getattr(f, "line_number", 1) or 1
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(getattr(f, "severity", "HIGH")),
                "message": {"text": getattr(f, "description", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": filename},
                            "region": {
                                "startLine": line,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PyAegis",
                        "version": tool_version,
                        "informationUri": "https://github.com/pyaegis/pyaegis",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _findings_to_text(findings: List[Any]) -> str:
    if not findings:
        return "No security issues found."
    lines = [f"PyAegis found {len(findings)} issue(s):\n"]
    for i, f in enumerate(findings, 1):
        filename = getattr(f, "file_path", "<unknown>")
        line_no = getattr(f, "line_number", 0)
        severity = getattr(f, "severity", "UNKNOWN")
        rule_id = getattr(f, "rule_id", "")
        sink_name = getattr(f, "sink_name", "")
        source_var = getattr(f, "source_var", "")
        description = getattr(f, "description", "")
        sink_context = getattr(f, "sink_context", "")
        entry = (
            f"  [{i}] {severity} | {rule_id} | {filename}:{line_no}\n"
            f"      Sink    : {sink_name}\n"
            f"      Source  : {source_var}\n"
            f"      Message : {description}\n"
        )
        if sink_context:
            entry += f"      Context : {sink_context}\n"
        lines.append(entry)
    return "\n".join(lines)


def _format_findings(findings: List[Any], return_format: str) -> Any:
    """Convert findings to the requested output format."""
    if return_format == "dict":
        return [_finding_to_dict(f) for f in findings]
    if return_format == "sarif":
        return _findings_to_sarif(findings)
    if return_format == "text":
        return _findings_to_text(findings)
    if return_format in {"json", "csv"}:
        return [_finding_to_dict(f) for f in findings]
    raise ValueError(
        f"Unknown return_format {return_format!r}. "
        "Choose 'dict', 'sarif', 'text', 'json', or 'csv'."
    )


def _run_scan_on_files(
    py_files: List[str],
    rules_path: str,
    workers: int = 1,
) -> List[Any]:
    """Core engine: parse *py_files* and run taint analysis.

    Returns a list of raw Finding objects.
    """
    from pyaegis.core.parser import ParallelProjectParser
    from pyaegis.core.taint import TaintTracker

    rules = _load_rules(rules_path)
    if not rules:
        rules = {
            "inputs": ["input", "request", "sys.argv", "os.getenv"],
            "sinks": ["eval", "exec", "os.system", "subprocess.*"],
            "sanitizers": ["html.escape", "bleach.clean"],
        }

    effective_workers = workers if workers > 0 else max(os.cpu_count() or 1, 1)

    proj_parser = ParallelProjectParser(
        pool_size=effective_workers,
        timeout=None,
    )
    cfgs = proj_parser.parse_all(py_files, show_progress=False)

    raw_depth = rules.get("max_call_depth")
    try:
        max_call_depth = int(raw_depth) if raw_depth is not None else 3
    except (TypeError, ValueError):
        max_call_depth = 3

    tracker = TaintTracker(
        sources=rules.get("inputs", []),
        sinks=rules.get("sinks", []),
        sanitizers=rules.get("sanitizers", []),
        conditional_sinks=rules.get("conditional_sinks", []),
        source_decorators=rules.get("source_decorators", []),
        symbol_table=proj_parser.symbol_table,
        max_call_depth=max_call_depth,
    )
    for filepath, cfg in cfgs.items():
        if cfg:
            tracker.analyze_cfg(cfg, filepath)

    return tracker.get_findings()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_code_string(
    source_code: str,
    *,
    filename: str = "<string>",
    ruleset: str = "default",
    return_format: Literal["dict", "sarif", "text", "json", "csv"] = "dict",
    severity_filter: Optional[List[str]] = None,
) -> Any:
    """Scan a Python source code string for security vulnerabilities.

    This is the primary API for integrating PyAegis into AI coding assistants,
    IDE plugins, and other tools that work with in-memory code.

    Args:
        source_code: Python source code as a string.
        filename: Virtual filename used in finding output (default: "<string>").
        ruleset: Rules to use.  ``"default"`` uses the bundled rules.  Can also
                 be a path to a custom YAML file, or a bundled ruleset name
                 such as ``"ssrf"``, ``"xxe"``, ``"deserialization"``.
        return_format: Output format:

            - ``"dict"``: List of finding dicts with keys:
                          ``filename``, ``line``, ``col``, ``severity``,
                          ``rule_id``, ``sink_name``, ``source_var``,
                          ``message``, ``sink_context``.
            - ``"json"``: JSON-serializable payload with scan metadata + findings.
            - ``"csv"``: CSV string with one finding per row.
            - ``"sarif"``: SARIF 2.1.0 dict (for IDE diagnostic integration).
            - ``"text"``: Human-readable string.

        severity_filter: Only return findings at or above these severities.
                         e.g. ``["HIGH", "CRITICAL"]``.

    Returns:
        Findings in the requested format.  Empty list / minimal SARIF /
        success string if no findings match.

    Example (AI agent usage)::

        from pyaegis.api import scan_code_string

        code = '''
        import os
        from flask import request
        def view():
            cmd = request.args.get("cmd")
            os.system(cmd)  # SINK
        '''
        result = scan_code_string(code, severity_filter=["HIGH", "CRITICAL"])
        # result: [{"line": 5, "severity": "CRITICAL", "sink_name": "os.system", ...}]
    """
    rules_path = _resolve_rules_path(ruleset)

    # PyASTParser reads from disk, so write to a named temp file.
    suffix = Path(filename).suffix or ".py"
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    start_time = time.time()
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(source_code)

        try:
            findings = _run_scan_on_files([tmp_path], rules_path, workers=1)
        except Exception:
            # e.g. ParserError on syntax errors — return empty, don't crash caller
            findings = []
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # Patch file_path to the virtual filename for cleaner output
    for f in findings:
        f.file_path = filename

    if severity_filter:
        findings = [
            f for f in findings if _severity_passes_filter(f.severity, severity_filter)
        ]

    duration_seconds = time.time() - start_time
    if return_format == "json":
        return _findings_to_json_payload(
            findings,
            total_files=1,
            duration_seconds=duration_seconds,
        )
    if return_format == "csv":
        return _findings_to_csv(findings)

    return _format_findings(findings, return_format)


def scan_file(
    file_path: str,
    *,
    ruleset: str = "default",
    return_format: Literal["dict", "sarif", "text", "json", "csv"] = "dict",
    severity_filter: Optional[List[str]] = None,
) -> Any:
    """Scan a single Python file for security vulnerabilities.

    Convenience wrapper around :func:`scan_code_string` that reads the file
    from disk.

    Args:
        file_path: Absolute or relative path to a ``.py`` file.
        ruleset: Rules to use (same as :func:`scan_code_string`).
        return_format: Output format (same as :func:`scan_code_string`).
        severity_filter: Severity allowlist (same as :func:`scan_code_string`).

    Returns:
        Findings in the requested format.
    """
    abs_path = os.path.abspath(file_path)
    rules_path = _resolve_rules_path(ruleset)

    start_time = time.time()
    findings = _run_scan_on_files([abs_path], rules_path, workers=1)

    if severity_filter:
        findings = [
            f for f in findings if _severity_passes_filter(f.severity, severity_filter)
        ]

    duration_seconds = time.time() - start_time
    if return_format == "json":
        return _findings_to_json_payload(
            findings,
            total_files=1,
            duration_seconds=duration_seconds,
        )
    if return_format == "csv":
        return _findings_to_csv(findings)

    return _format_findings(findings, return_format)


def scan_directory(
    path: str,
    *,
    ruleset: str = "default",
    return_format: Literal["dict", "sarif", "text", "json", "csv"] = "dict",
    severity_filter: Optional[List[str]] = None,
    workers: int = 0,
) -> Any:
    """Scan a directory of Python files for security vulnerabilities.

    Args:
        path: Directory to scan (all ``.py`` files are discovered recursively).
        ruleset: Rules to use (same as :func:`scan_code_string`).
        return_format: Output format (same as :func:`scan_code_string`).
        severity_filter: Severity allowlist (same as :func:`scan_code_string`).
        workers: Number of parallel worker processes.  ``0`` (default) uses
                 ``os.cpu_count()``.

    Returns:
        Findings in the requested format.
    """
    rules_path = _resolve_rules_path(ruleset)

    py_files: List[str] = []
    for root, _dirs, files in os.walk(path):
        for fname in files:
            if fname.endswith(".py"):
                py_files.append(os.path.join(root, fname))

    if not py_files:
        if return_format == "json":
            return _findings_to_json_payload([], total_files=0, duration_seconds=0.0)
        if return_format == "csv":
            return _findings_to_csv([])
        return _format_findings([], return_format)

    start_time = time.time()
    findings = _run_scan_on_files(py_files, rules_path, workers=workers)

    if severity_filter:
        findings = [
            f for f in findings if _severity_passes_filter(f.severity, severity_filter)
        ]

    duration_seconds = time.time() - start_time
    if return_format == "json":
        return _findings_to_json_payload(
            findings,
            total_files=len(py_files),
            duration_seconds=duration_seconds,
        )
    if return_format == "csv":
        return _findings_to_csv(findings)

    return _format_findings(findings, return_format)
