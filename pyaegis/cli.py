"""PyAegis CLI - Command-line interface."""
import argparse
import sys
import os
import time
import yaml
import logging
from pathlib import Path

from pyaegis.core.parser import ParallelProjectParser
from pyaegis.core.taint import TaintTracker
from pyaegis.exceptions import ParserError
from pyaegis.models import ScanResult
from pyaegis.reporters import JSONReporter, SARIFReporter, TextReporter

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_rules(rule_path: str) -> dict:
    """Load YAML rules from disk."""
    with open(rule_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def find_python_files(directory: str) -> list:
    """Recursively find *.py files under a directory."""
    py_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


# ---------------------------------------------------------------------------
# scan sub-command
# ---------------------------------------------------------------------------

def cmd_scan(args) -> int:
    """Run a SAST scan."""
    print(BANNER)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if not os.path.exists(args.target):
        logger.error(f"Target {args.target} not found.")
        return 1

    start_time = time.time()

    py_files = (
        [args.target] if os.path.isfile(args.target) else find_python_files(args.target)
    )

    logger.info(f"Parsing {len(py_files)} Python files using Multiprocessing AST...")
    proj_parser = ParallelProjectParser()
    try:
        cfgs = proj_parser.parse_all(py_files)
    except ParserError as e:
        logger.critical(str(e))
        return 1

    rules = {
        "inputs": ["input", "request", "sys.argv", "os.getenv"],
        "sinks": ["eval", "exec", "os.system", "subprocess.*"],
        "sanitizers": ["html.escape", "bleach.clean"],
    }
    if os.path.exists(args.rules):
        rules = load_rules(args.rules)

    logger.info("Performing Taint Tracking against Context Sinks...")
    tracker = TaintTracker(
        sources=rules.get("inputs", []),
        sinks=rules.get("sinks", []),
        sanitizers=rules.get("sanitizers", []),
    )

    for filepath, cfg in cfgs.items():
        if cfg:
            tracker.analyze_cfg(cfg, filepath)

    duration = time.time() - start_time
    findings = tracker.get_findings()

    scan_result = ScanResult(
        total_files=len(py_files),
        findings=findings,
        duration_seconds=float(f"{duration:.3f}"),
    )

    output_stream = (
        open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    )

    try:
        if args.format == "json":
            reporter = JSONReporter(output_stream)
        elif args.format == "sarif":
            reporter = SARIFReporter(output_stream)
        else:
            reporter = TextReporter(output_stream)

        reporter.report(scan_result)
    finally:
        if args.output:
            output_stream.close()
            logger.info(f"Report written to {args.output}")

    return 1 if findings else 0


# ---------------------------------------------------------------------------
# init sub-command
# ---------------------------------------------------------------------------

_CI_CHOICES = ("github", "gitlab", "precommit")


def cmd_init(args) -> int:
    """Generate CI configuration files."""
    ci = args.ci

    if ci == "github":
        from pyaegis.integrations.github_actions import generate_github_actions_workflow
        content = generate_github_actions_workflow()
        out_path = Path(".github") / "workflows" / "pyaegis.yml"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        print(f"[pyaegis] Created {out_path}")
        print("  → Push to GitHub and enable Code Scanning in repo Settings > Security.")

    elif ci == "gitlab":
        from pyaegis.integrations.gitlab_ci import generate_gitlab_ci_snippet
        content = generate_gitlab_ci_snippet()
        out_path = Path("pyaegis-gitlab-ci.yml")
        out_path.write_text(content, encoding="utf-8")
        print(f"[pyaegis] Created {out_path}")
        print("  → Merge this snippet into your .gitlab-ci.yml file.")

    elif ci == "precommit":
        from pyaegis.integrations.pre_commit import generate_pre_commit_config
        # Check if .pre-commit-config.yaml already exists
        existing = Path(".pre-commit-config.yaml")
        if existing.exists():
            # Append a comment + snippet rather than overwriting
            snippet = generate_pre_commit_config(use_local=True)
            out_path = Path("pyaegis-pre-commit-snippet.yaml")
            out_path.write_text(snippet, encoding="utf-8")
            print(f"[pyaegis] .pre-commit-config.yaml already exists.")
            print(f"  → Snippet written to {out_path} — merge it manually.")
        else:
            content = generate_pre_commit_config(use_local=True)
            existing.write_text(content, encoding="utf-8")
            print(f"[pyaegis] Created .pre-commit-config.yaml")
            print("  → Run: pre-commit install")
    else:
        print(f"[pyaegis] Unknown CI target '{ci}'. Choose from: {', '.join(_CI_CHOICES)}",
              file=sys.stderr)
        return 2

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyaegis",
        description="PyAegis — Python SAST engine with taint tracking.",
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version and exit."
    )

    subparsers = parser.add_subparsers(dest="command")

    # ---- scan ----
    scan_p = subparsers.add_parser("scan", help="Scan a file or directory.")
    scan_p.add_argument("target", nargs="?", default=".",
                        help="Target file or directory (default: current directory).")
    scan_p.add_argument("--rules", default="pyaegis/rules/default.yml",
                        help="Path to rules YAML file.")
    scan_p.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                        help="Output format.")
    scan_p.add_argument("--output", default=None,
                        help="Output file path (default: stdout).")
    scan_p.add_argument("--debug", action="store_true",
                        help="Enable debug logging.")

    # ---- positional shortcut: pyaegis <target> (no subcommand) ----
    # Handled in main() for backwards compatibility.

    # ---- init ----
    init_p = subparsers.add_parser(
        "init",
        help="Generate CI/CD configuration files.",
    )
    init_p.add_argument(
        "--ci",
        required=True,
        choices=list(_CI_CHOICES),
        metavar="CI",
        help=(
            "CI platform to generate config for. "
            "Choices: github, gitlab, precommit."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()

    # Version shortcut
    if argv and argv[0] == "--version":
        sys.stdout.write(f"PyAegis v{__version__}\n")
        return 0

    # Backwards-compat: `pyaegis <target>` without explicit `scan` subcommand
    if argv and not argv[0].startswith("-") and argv[0] not in ("scan", "init"):
        argv = ["scan"] + argv

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "init":
        return cmd_init(args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
