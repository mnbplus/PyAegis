"""PyAegis CLI.

UX goals:
- Provide discoverable subcommands: scan / explain / list-rules / init / version
- Keep backwards compatibility: `pyaegis <path>` still performs a scan.
- Friendly first-run behavior: no-arg invocation prints help.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import logging
from pathlib import Path
from typing import Iterable, Optional, Sequence

import yaml

from pyaegis.core.parser import ParallelProjectParser
from pyaegis.core.taint import TaintTracker
from pyaegis.exceptions import ParserError
from pyaegis.models import ScanResult
from pyaegis.reporters import (
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    SARIFReporter,
    TextReporter,
)
from pyaegis.rules_catalog import RULES, format_explain


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pyaegis")


__version__ = "0.2.0"


BANNER = r"""
    ____        ___                _
   / __ \__  __/   |  ___  ____ _(_)____
  / /_/ / / / / /| | / _ \/ __ `/ / ___/
 / ____/ /_/ / ___ |/  __/ /_/ / (__  )
/_/    \__, /_/  |_|\___/\__, /_/_/____/
      /____/            /____/

 [ Advanced Python Static Application Security Testing Engine ]
"""


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _default_rules_path() -> str:
    return str(Path(__file__).resolve().parent / "rules" / "default.yml")


def _load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _find_python_files(directory: str) -> list[str]:
    py_files: list[str] = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


def _parse_severity_csv(value: Optional[str]) -> Optional[set[str]]:
    if not value:
        return None
    items = [x.strip().upper() for x in value.split(",") if x.strip()]
    unknown = [x for x in items if x not in SEVERITIES]
    if unknown:
        raise ValueError(
            "Unknown severity level(s): "
            + ", ".join(unknown)
            + f". Valid: {', '.join(SEVERITIES)}"
        )
    return set(items)


def _merge_config(
    args: argparse.Namespace, config: dict, *, keys: Iterable[str]
) -> argparse.Namespace:
    """Merge config values into args only when args has None.

    This keeps CLI flags authoritative.
    """

    for k in keys:
        if getattr(args, k, None) is None and k in config:
            setattr(args, k, config[k])
    return args


def _build_parser() -> argparse.ArgumentParser:
    examples = (
        "Examples:\n"
        "  pyaegis scan .\n"
        "  pyaegis scan src --severity HIGH,CRITICAL\n"
        "  pyaegis explain PYA-001\n"
        "  pyaegis list-rules\n"
        "  pyaegis init\n"
    )

    parser = argparse.ArgumentParser(
        prog="pyaegis",
        description="PyAegis - a Python-first SAST tool (AST + taint tracking)",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")

    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser(
        "scan",
        help="Scan a file or directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_scan.add_argument("target", nargs="?", default=".", help="Target path to scan")
    p_scan.add_argument(
        "--rules",
        default=None,
        help="Path to rules YAML file (defaults to bundled default rules).",
    )
    p_scan.add_argument(
        "--format",
        choices=["text", "json", "sarif", "csv", "html"],
        default=None,
        help="Output format.",
    )
    p_scan.add_argument("--output", default=None, help="Output file path.")

    p_scan.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel worker processes for parsing.",
    )
    p_scan.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Per-file parsing timeout in seconds (best-effort).",
    )

    p_scan.add_argument(
        "--quiet",
        action="store_true",
        help="Only output findings (suppress scan progress logs).",
    )
    p_scan.add_argument(
        "--severity",
        default=None,
        help="Comma-separated severity allowlist, e.g. HIGH,CRITICAL",
    )
    p_scan.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (Text format only).",
    )

    # explain
    p_explain = sub.add_parser("explain", help="Explain a rule id")
    p_explain.add_argument("rule_id", help="Rule id, e.g. PYA-001")

    # list-rules
    sub.add_parser("list-rules", help="List all built-in rules")

    # init
    p_init = sub.add_parser(
        "init",
        help="Create a .pyaegis.yml config file in the current directory",
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .pyaegis.yml if it already exists.",
    )

    # version
    sub.add_parser("version", help="Show version")

    return parser


def _cmd_version() -> int:
    sys.stdout.write(f"PyAegis v{__version__}\n")
    return 0


def _cmd_list_rules() -> int:
    w = sys.stdout.write
    w("Built-in rules:\n\n")
    for rid in sorted(RULES.keys()):
        r = RULES[rid]
        w(f"{r.id:<7}  {r.severity:<8}  {r.short_description}\n")
    w("\nTip: run `pyaegis explain PYA-001` for details.\n")
    return 0


def _cmd_explain(rule_id: str) -> int:
    sys.stdout.write(format_explain(rule_id))
    return 0 if rule_id.upper().strip() in RULES else 1


def _cmd_init(force: bool) -> int:
    path = Path.cwd() / ".pyaegis.yml"
    if path.exists() and not force:
        sys.stderr.write(".pyaegis.yml already exists. Use --force to overwrite.\n")
        return 1

    content = {
        "rules": _default_rules_path().replace("\\", "/"),
        "format": "text",
        # allowlist; set to null to disable filtering
        "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "workers": max(os.cpu_count() or 4, 1),
        "timeout": None,
        "quiet": False,
        "no_color": False,
    }

    # Keep it human-friendly and editable.
    yaml_text = (
        "# PyAegis configuration\n"
        "#\n"
        "# Common keys:\n"
        "#   rules: path to a YAML rules file\n"
        "#   format: text | json | sarif | csv | html\n"
        "#   severity: list of severities to report (allowlist)\n"
        "#   workers: parsing worker processes\n"
        "#   timeout: per-file parse timeout seconds (null = no limit)\n"
        "#\n"
        + yaml.safe_dump(content, sort_keys=False)
    )

    path.write_text(yaml_text, encoding="utf-8")
    sys.stdout.write(f"Created {path}\n")
    return 0


def _scan(args: argparse.Namespace) -> int:
    if args.quiet:
        logger.setLevel(logging.WARNING)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Optional project config: .pyaegis.yml in current directory
    cfg_path = Path.cwd() / ".pyaegis.yml"
    config = {}
    if cfg_path.exists():
        try:
            config = _load_yaml(str(cfg_path))
        except Exception as e:  # pragma: no cover
            logger.warning(f"Failed to read {cfg_path}: {e}")

    # merge config defaults
    args = _merge_config(
        args,
        config,
        keys=["rules", "format", "workers", "timeout", "severity"],
    )

    # finalize defaults
    rules_path = args.rules or _default_rules_path()
    out_format = args.format or "text"
    workers = int(args.workers) if args.workers is not None else max(os.cpu_count() or 4, 1)
    timeout = args.timeout

    # severity filter from config can be list
    sev_allow: Optional[set[str]]
    if isinstance(args.severity, list):
        sev_allow = {str(x).strip().upper() for x in args.severity}
    else:
        try:
            sev_allow = _parse_severity_csv(args.severity)
        except ValueError as e:
            sys.stderr.write(str(e) + "\n")
            return 2

    if not args.quiet:
        sys.stdout.write(BANNER + "\n")

    target = args.target
    if not target:
        sys.stderr.write("No target provided.\n")
        return 2

    if not os.path.exists(target):
        logger.error(f"Target {target} not found.")
        return 1

    start_time = time.time()

    py_files = [target] if os.path.isfile(target) else _find_python_files(target)
    if not py_files:
        logger.warning("No Python files found.")

    if not args.quiet:
        logger.info(f"Parsing {len(py_files)} Python files using Multiprocessing AST...")

    proj_parser = ParallelProjectParser(pool_size=workers, timeout=timeout)

    try:
        cfgs = proj_parser.parse_all(py_files, show_progress=not args.quiet)
    except ParserError as e:
        logger.critical(str(e))
        return 1

    rules = {}
    if os.path.exists(rules_path):
        rules = _load_yaml(rules_path)

    # default fallback
    if not rules:
        rules = {
            "inputs": ["input", "request", "sys.argv", "os.getenv"],
            "sinks": ["eval", "exec", "os.system", "subprocess.*"],
            "sanitizers": ["html.escape", "bleach.clean"],
        }

    if not args.quiet:
        logger.info("Performing Taint Tracking against Context Sinks...")

    tracker = TaintTracker(
        sources=rules.get("inputs", []),
        sinks=rules.get("sinks", []),
        sanitizers=rules.get("sanitizers", []),
        conditional_sinks=rules.get("conditional_sinks", []),
        source_decorators=rules.get("source_decorators", []),
    )

    for filepath, cfg in cfgs.items():
        if cfg:
            tracker.analyze_cfg(cfg, filepath)

    duration = time.time() - start_time
    findings = tracker.get_findings()

    if sev_allow is not None:
        findings = [f for f in findings if (f.severity or "").upper() in sev_allow]

    scan_result = ScanResult(
        total_files=len(py_files),
        findings=findings,
        duration_seconds=float(f"{duration:.3f}"),
    )

    output_stream = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    try:
        if out_format == "json":
            reporter = JSONReporter(output_stream)
        elif out_format == "sarif":
            reporter = SARIFReporter(output_stream)
        elif out_format == "csv":
            reporter = CSVReporter(output_stream)
        elif out_format == "html":
            reporter = HTMLReporter(output_stream)
        else:
            reporter = TextReporter(output_stream, color=not args.no_color)

        reporter.report(scan_result)
    finally:
        if args.output:
            output_stream.close()

    return 1 if findings else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]

    parser = _build_parser()

    # Friendly first-run: show help when invoked with no args.
    if not argv:
        parser.print_help(sys.stdout)
        return 2

    # Backwards-compatibility:
    #   pyaegis <path>  -> pyaegis scan <path>
    # but keep flags working: pyaegis --version / -h
    known_cmds = {"scan", "explain", "list-rules", "init", "version"}
    if argv and not argv[0].startswith("-") and argv[0] not in known_cmds:
        argv = ["scan", *argv]

    args = parser.parse_args(argv)

    # global shortcuts
    if args.version:
        return _cmd_version()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    cmd = getattr(args, "command", None)
    if cmd == "version":
        return _cmd_version()
    if cmd == "list-rules":
        return _cmd_list_rules()
    if cmd == "explain":
        return _cmd_explain(args.rule_id)
    if cmd == "init":
        return _cmd_init(args.force)
    if cmd == "scan":
        return _scan(args)

    # If we get here, user passed something like `pyaegis -h` which argparse handles,
    # or an incomplete command.
    parser.print_help(sys.stdout)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
