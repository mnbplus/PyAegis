import argparse
import sys
import os
import time
import yaml
import logging
from pyaegis.core.parser import ParallelProjectParser
from pyaegis.core.taint import TaintTracker
from pyaegis.exceptions import ParserError
from pyaegis.models import ScanResult
from pyaegis.reporters import JSONReporter, SARIFReporter, TextReporter

# Setup Global Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pyaegis")


def load_rules(rule_path: str):
    with open(rule_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def find_python_files(directory: str):
    py_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


def main():
    print(
        r"""
    ____        ___                _
   / __ \__  __/   |  ___  ____ _(_)____
  / /_/ / / / / /| | / _ \/ __ `/ / ___/
 / ____/ /_/ / ___ |/  __/ /_/ / (__  )
/_/    \__, /_/  |_|\___/\__, /_/_/____/
      /____/            /____/

 [ Advanced Python Static Application Security Testing Engine ]
    """
    )

    parser = argparse.ArgumentParser(description="PyAegis SAST Tool")
    parser.add_argument("target", help="Target file or directory to scan.")
    parser.add_argument(
        "--rules", default="pyaegis/rules/default.yml", help="Path to rules YAML file."
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format.",
    )
    parser.add_argument("--output", default=None, help="Output file path.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if not os.path.exists(args.target):
        logger.error(f"Target {args.target} not found.")
        sys.exit(1)

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
        sys.exit(1)

    rules = {
        "inputs": ["input", "request", "os.environ"],
        "sinks": ["eval", "exec", "os.system", "subprocess.call"],
    }
    if os.path.exists(args.rules):
        rules = load_rules(args.rules)

    logger.info("Performing Taint Tracking against Context Sinks...")
    tracker = TaintTracker(
        sources=rules.get("inputs", []), sinks=rules.get("sinks", [])
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

    # Configure reporter
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

    if findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
