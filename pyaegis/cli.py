import argparse
import sys
import os
import yaml
from pyaegis.core.parser import ParallelProjectParser
from pyaegis.core.taint import TaintTracker

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
    print(r"""
    ____        ___                _     
   / __ \__  __/   |  ___  ____ _(_)____
  / /_/ / / / / /| | / _ \/ __ `/ / ___/
 / ____/ /_/ / ___ |/  __/ /_/ / (__  ) 
/_/    \__, /_/  |_|\___/\__, /_/_/____/  
      /____/            /____/           

 [ Advanced Python Static Application Security Testing Engine ]
    """)

    parser = argparse.ArgumentParser(description="PyAegis SAST Tool")
    parser.add_argument("target", help="Target file or directory to scan.")
    parser.add_argument("--rules", default="pyaegis/rules/default.yml", help="Path to rules YAML file.")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target {args.target} not found.")
        sys.exit(1)

    py_files = [args.target] if os.path.isfile(args.target) else find_python_files(args.target)
    
    print(f"[*] Parsing {len(py_files)} Python files using Multiprocessing AST...")
    proj_parser = ParallelProjectParser()
    cfgs = proj_parser.parse_all(py_files)

    rules = {"inputs": ["input", "request", "os.environ"], "sinks": ["eval", "exec", "os.system", "subprocess.call"]}
    if os.path.exists(args.rules):
        rules = load_rules(args.rules)

    print("[*] Performing Taint Tracking against Context Sinks...")
    tracker = TaintTracker(sources=rules.get("inputs", []), sinks=rules.get("sinks", []))
    
    for filepath, cfg in cfgs.items():
        tracker.analyze_cfg(cfg, filepath)

    findings = tracker.get_findings()
    if not findings:
        print("[+] No vulnerabilities detected. Subsystems secure.")
    else:
        print(f"[-] Detected {len(findings)} Potential Vulnerabilities:")
        for vuln in findings:
            print(f"    -> [CRITICAL] {vuln['type']} via `{vuln['sink']}` | File: {vuln['file']}:{vuln['line']} | Context: {vuln['function']}")
        sys.exit(1)

if __name__ == "__main__":
    main()
