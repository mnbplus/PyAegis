from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser
import os


def test_ast_parser_valid_file(tmp_path):
    # Setup temporary python file
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "test_file.py"
    p.write_text("def hello():\n    return 'Hello World'", encoding="utf-8")

    parser = PyASTParser(str(p))
    tree = parser.parse()
    assert tree is not None

    cfg = parser.extract_cfg()
    assert "hello" in cfg


def test_taint_tracker_detects_sink():
    # Simulate a vulnerable block of code
    code_body = """
import os
def insecure_endpoint(request):
    user_input = request.GET.get('cmd')
    os.system(user_input)
    """
    tmp_path = "dummy_test_file.py"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(code_body)

    parser = PyASTParser(tmp_path)
    parser.parse()
    cfg = parser.extract_cfg()

    # Rule definition
    tracker = TaintTracker(sources=["request"], sinks=["os.system"])
    tracker.analyze_cfg(cfg, filepath=tmp_path)

    findings = tracker.get_findings()
    assert len(findings) == 1
    assert findings[0].sink_context == "insecure_endpoint"
    assert "insecure_endpoint" in findings[0].sink_context

    os.remove(tmp_path)
