"""
PyAegis MCP Server
==================
Exposes PyAegis security-scanning capabilities as MCP tools so that
AI agents (Claude Desktop, Cursor, etc.) can call them directly.

Tools
-----
- scan_code       : scan a Python code string for security issues
- scan_file       : scan a file on disk
- explain_finding : explain a rule_id and give remediation advice
- list_rules      : list all built-in detection rules

Usage
-----
    python -m pyaegis.mcp_server          # stdio transport (default)
    pip install pyaegis[mcp]              # install with MCP extras

Logging note
------------
For stdio transport never write to stdout; use stderr or a log file.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

# Configure logging to stderr so it never corrupts the stdio JSON-RPC stream
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [pyaegis-mcp] %(levelname)s %(message)s",
)
log = logging.getLogger("pyaegis.mcp_server")

try:
    from mcp.server import Server
    import mcp.types as types
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "MCP extras are required. Install with: pip install pyaegis[mcp]"
    ) from exc

# ---------------------------------------------------------------------------
# PyAegis public API imports
# ---------------------------------------------------------------------------
try:
    from pyaegis.api import scan_code_string, scan_file as _scan_file

    _API_AVAILABLE = True
except ImportError:  # pragma: no cover
    _API_AVAILABLE = False
    scan_code_string = None  # type: ignore
    _scan_file = None  # type: ignore

try:
    from pyaegis.debt import DebtAnalyser

    _DEBT_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DEBT_AVAILABLE = False
    DebtAnalyser = None  # type: ignore

try:
    from pyaegis.rules_catalog import RULES, format_explain

    _CATALOG_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CATALOG_AVAILABLE = False
    RULES = {}  # type: ignore
    format_explain = None  # type: ignore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_api() -> None:
    if not _API_AVAILABLE:
        raise RuntimeError(
            "PyAegis core is not installed properly. Run `pip install pyaegis`."
        )


def _findings_to_text(findings: list[dict[str, Any]]) -> str:
    """Render a list of finding dicts as a readable string."""
    if not findings:
        return "No security issues found."
    lines = [f"Found {len(findings)} issue(s):\n"]
    for i, f in enumerate(findings, 1):
        lines.append(
            f"  [{i}] {f.get('severity', '?')} | {f.get('rule_id', '?')} | "
            f"line {f.get('line', '?')} | {f.get('sink_name', '')}\n"
            f"       {f.get('message', '')}\n"
            f"       Context: {f.get('sink_context', '').strip()}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

server = Server("pyaegis")


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """Advertise the tools this server provides."""
    return [
        types.Tool(
            name="scan_code",
            description=(
                "Scan a Python code snippet for security vulnerabilities using "
                "PyAegis taint-analysis. Returns a JSON report with findings "
                "including rule_id, severity, line number, sink name, and message."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Python source code to scan.",
                    },
                    "filename": {
                        "type": "string",
                        "description": (
                            "Optional virtual filename shown in findings "
                            "(e.g. 'app.py'). Defaults to '<string>'."
                        ),
                    },
                    "severity_filter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Only return findings at or above these severity levels. "
                            "E.g. ['HIGH', 'CRITICAL']. Omit to return all."
                        ),
                    },
                },
                "required": ["code"],
            },
        ),
        types.Tool(
            name="scan_file",
            description=(
                "Scan a Python file on disk for security vulnerabilities using "
                "PyAegis taint-analysis. Returns a JSON report with findings."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to the .py file to scan.",
                    },
                    "severity_filter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Only return findings at or above these severity levels. "
                            "E.g. ['HIGH', 'CRITICAL']. Omit to return all."
                        ),
                    },
                },
                "required": ["path"],
            },
        ),
        types.Tool(
            name="explain_finding",
            description=(
                "Explain what a PyAegis rule detects and provide actionable "
                "remediation advice. Pass a rule_id like 'PYA-001' or 'PYA-002'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": (
                            "Rule identifier from a scan finding, e.g. 'PYA-001', "
                            "'PYA-002'. Use list_rules to see all available IDs."
                        ),
                    }
                },
                "required": ["rule_id"],
            },
        ),
        types.Tool(
            name="list_rules",
            description=(
                "List all built-in PyAegis security detection rules with their "
                "IDs, names, severity levels, and CWE references."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        types.Tool(
            name="scan_directory",
            description=(
                "Scan all Python files in a directory recursively for security "
                "vulnerabilities. Returns aggregated JSON findings across all files."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to the directory to scan.",
                    },
                    "severity_filter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Only return findings at or above these severity levels.",
                    },
                },
                "required": ["path"],
            },
        ),
        types.Tool(
            name="debt_analysis",
            description=(
                "Analyse technical debt hotspots in a Python git repository. "
                "Combines Git commit churn frequency, bug-fix density, and "
                "cyclomatic complexity (radon) to rank files by risk score. "
                "Returns top hotspots and an LLM-ready refactoring prompt."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Path to the git repository root. Defaults to current directory.",
                    },
                    "top": {
                        "type": "integer",
                        "description": "Number of top hotspots to return (default 10).",
                    },
                    "include_llm_prompt": {
                        "type": "boolean",
                        "description": "If true, include a ready-made LLM refactoring prompt in the response.",
                    },
                },
                "required": [],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict[str, Any] | None
) -> list[types.TextContent]:
    """Dispatch tool calls to PyAegis."""
    args = arguments or {}

    def text(content: str) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=content)]

    # ------------------------------------------------------------------
    # scan_code
    # ------------------------------------------------------------------
    if name == "scan_code":
        _require_api()
        code: str = args.get("code", "")
        filename: str = args.get("filename", "<string>")
        severity_filter = args.get("severity_filter") or None

        if not code.strip():
            return text(json.dumps({"status": "clean", "findings": []}, indent=2))

        log.info("scan_code: filename=%s severity_filter=%s", filename, severity_filter)
        try:
            findings: list[dict[str, Any]] = scan_code_string(
                code,
                filename=filename,
                return_format="dict",
                severity_filter=severity_filter,
            )
        except Exception as exc:
            log.exception("scan_code failed")
            return text(json.dumps({"error": str(exc)}, indent=2))

        result = {
            "status": "issues_found" if findings else "clean",
            "count": len(findings),
            "findings": findings,
        }
        return text(json.dumps(result, indent=2, default=str))

    # ------------------------------------------------------------------
    # scan_file
    # ------------------------------------------------------------------
    elif name == "scan_file":
        _require_api()
        file_path: str = args.get("path", "")
        severity_filter = args.get("severity_filter") or None

        if not file_path:
            return text(json.dumps({"error": "'path' argument is required"}, indent=2))

        log.info("scan_file: path=%s severity_filter=%s", file_path, severity_filter)
        try:
            findings = _scan_file(
                file_path,
                return_format="dict",
                severity_filter=severity_filter,
            )
        except FileNotFoundError:
            return text(json.dumps({"error": f"File not found: {file_path}"}, indent=2))
        except Exception as exc:
            log.exception("scan_file failed")
            return text(json.dumps({"error": str(exc)}, indent=2))

        result = {
            "status": "issues_found" if findings else "clean",
            "count": len(findings),
            "findings": findings,
        }
        return text(json.dumps(result, indent=2, default=str))

    # ------------------------------------------------------------------
    # explain_finding
    # ------------------------------------------------------------------
    elif name == "explain_finding":
        rule_id: str = args.get("rule_id", "").strip().upper()
        if not rule_id:
            return text("Error: 'rule_id' argument is required.")

        if _CATALOG_AVAILABLE:
            explanation = format_explain(rule_id)
        else:
            explanation = f"Rule catalog unavailable. rule_id={rule_id}"

        return text(explanation)

    # ------------------------------------------------------------------
    # list_rules
    # ------------------------------------------------------------------
    elif name == "list_rules":
        if not _CATALOG_AVAILABLE or not RULES:
            return text(json.dumps({"error": "Rule catalog unavailable."}, indent=2))

        rules_list = [
            {
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity,
                "short_description": rule.short_description,
                "cwe": rule.cwe,
                "owasp": rule.owasp,
            }
            for rule in RULES.values()
        ]
        return text(
            json.dumps(
                {"total": len(rules_list), "rules": rules_list},
                indent=2,
            )
        )

    # ------------------------------------------------------------------
    # scan_directory
    # ------------------------------------------------------------------
    elif name == "scan_directory":
        _require_api()
        import os

        dir_path: str = args.get("path", "")
        severity_filter = args.get("severity_filter") or None

        if not dir_path or not os.path.isdir(dir_path):
            return text(
                json.dumps({"error": f"Directory not found: {dir_path}"}, indent=2)
            )

        py_files = [
            os.path.join(root, f)
            for root, _, files in os.walk(dir_path)
            for f in files
            if f.endswith(".py")
        ]
        if not py_files:
            return text(
                json.dumps(
                    {"status": "clean", "findings": [], "files_scanned": 0}, indent=2
                )
            )

        log.info("scan_directory: path=%s files=%d", dir_path, len(py_files))
        all_findings: list[dict[str, Any]] = []
        for fp in py_files:
            try:
                findings = _scan_file(
                    fp, return_format="dict", severity_filter=severity_filter
                )
                all_findings.extend(findings)
            except Exception as exc:
                log.warning("scan_directory: skipping %s: %s", fp, exc)

        result = {
            "status": "issues_found" if all_findings else "clean",
            "files_scanned": len(py_files),
            "count": len(all_findings),
            "findings": all_findings,
        }
        return text(json.dumps(result, indent=2, default=str))

    # ------------------------------------------------------------------
    # debt_analysis
    # ------------------------------------------------------------------
    elif name == "debt_analysis":
        if not _DEBT_AVAILABLE:
            return text(
                json.dumps(
                    {
                        "error": "debt extras not installed. Run: pip install pyaegis[debt]"
                    },
                    indent=2,
                )
            )
        import os

        repo_path: str = args.get("repo_path", os.getcwd())
        top: int = int(args.get("top", 10))
        include_prompt: bool = bool(args.get("include_llm_prompt", False))

        log.info("debt_analysis: repo=%s top=%d", repo_path, top)
        try:
            analyser = DebtAnalyser(repo_root=repo_path)
            report = analyser.analyse(top=top)
        except Exception as exc:
            log.exception("debt_analysis failed")
            return text(json.dumps({"error": str(exc)}, indent=2))

        result = report.to_dict()
        if include_prompt:
            result["llm_prompt"] = report.to_llm_prompt(top=top)
        return text(json.dumps(result, indent=2, default=str))

    else:
        return text(f"Unknown tool: {name}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from mcp.server.stdio import stdio_server
    import asyncio

    asyncio.run(stdio_server(server))
