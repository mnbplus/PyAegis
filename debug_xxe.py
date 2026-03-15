from pyaegis.core.parser import PyASTParser
from pyaegis.core.taint import TaintTracker
from pyaegis.cli import _resolve_ruleset, _load_yaml
import tempfile
import os

# Create a test file
code = '''
import xml.etree.ElementTree as ET

def parse_xml(request):
    data = request.data
    return ET.fromstring(data)
'''

with tempfile.TemporaryDirectory() as tmpdir:
    test_file = os.path.join(tmpdir, "app.py")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(code)
    
    # Get the rules
    rules_path = _resolve_ruleset("xxe")
    print(f"Rules path: {rules_path}")
    
    rules = _load_yaml(rules_path)
    print(f"Rules: {rules}")
    
    # Parse
    parser = PyASTParser(test_file)
    parser.parse()
    cfg = parser.extract_cfg()
    print(f"CFG: {cfg}")
    
    # Track
    tracker = TaintTracker(
        sources=rules.get("inputs", []),
        sinks=rules.get("sinks", []),
        sanitizers=rules.get("sanitizers", []),
    )
    tracker.analyze_cfg(cfg, filepath=test_file)
    findings = tracker.get_findings()
    
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f}")
