import textwrap
from pathlib import Path

import yaml

from pyaegis.core.parser import PyASTParser
from pyaegis.core.taint import TaintTracker


def _run_with_rules(tmp_path, code: str, rules_file_name: str):
    p = tmp_path / "app.py"
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")

    repo_root = Path(__file__).resolve().parents[1]
    rules_path = repo_root / "pyaegis" / "rules" / rules_file_name

    # Load rules from repository path to ensure the new files exist.
    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=rules.get("inputs", []),
        sinks=rules.get("sinks", []),
        sanitizers=rules.get("sanitizers", []),
        conditional_sinks=rules.get("conditional_sinks", []),
        source_decorators=rules.get("source_decorators", []),
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    return tracker.get_findings()


def test_rules_xxe_elementtree_fromstring(tmp_path):
    findings = _run_with_rules(
        tmp_path,
        """
        from xml.etree import ElementTree as ET

        def f(request):
            data = request.get_data()
            ET.fromstring(data)
        """,
        "xxe.yml",
    )
    assert len(findings) == 1
    assert findings[0].sink_name.endswith("fromstring")


def test_rules_ssrf_requests_get(tmp_path):
    findings = _run_with_rules(
        tmp_path,
        """
        import requests

        def f(request):
            url = request.args.get('url')
            requests.get(url)
        """,
        "ssrf.yml",
    )
    assert len(findings) == 1
    assert findings[0].sink_name == "requests.get"


def test_rules_deserialization_pickle_loads(tmp_path):
    findings = _run_with_rules(
        tmp_path,
        """
        import pickle

        def f(request):
            blob = request.data
            pickle.loads(blob)
        """,
        "deserialization.yml",
    )
    assert len(findings) == 1
    assert findings[0].sink_name == "pickle.loads"


def test_rules_deserialization_yaml_load_without_loader(tmp_path):
    findings = _run_with_rules(
        tmp_path,
        """
        import yaml

        def f(request):
            s = request.data
            yaml.load(s)
        """,
        "deserialization.yml",
    )
    assert len(findings) == 1
    assert findings[0].sink_name == "yaml.load"


def test_rules_path_traversal_open(tmp_path):
    findings = _run_with_rules(
        tmp_path,
        """
        def f(request):
            fn = request.GET.get('p')
            open(fn, 'w').write('x')
        """,
        "path_traversal.yml",
    )
    assert len(findings) == 1
    assert findings[0].sink_name in ("open", "builtins.open")
