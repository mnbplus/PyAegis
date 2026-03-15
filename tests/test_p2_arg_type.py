import subprocess


def test_conditional_sink_arg_type_string_passes_for_string(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(
        """
import subprocess

def f(request):
    cmd = request.args.get('cmd')
    subprocess.run(cmd, shell=True)
""".lstrip(),
        encoding="utf-8",
    )

    from pyaegis.core.parser import PyASTParser
    from pyaegis.core.taint import TaintTracker

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["subprocess.*"],
        conditional_sinks=[
            {
                "name": "subprocess.run",
                "severity": "CRITICAL",
                "rule_id": "PYA-001",
                "conditions": [
                    {"has_kwarg": {"shell": True}},
                    {"arg_type": "string"},
                ],
            }
        ],
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    findings = tracker.get_findings()
    assert len(findings) == 1
    assert findings[0].sink_name == "subprocess.run"


def test_conditional_sink_arg_type_string_blocks_for_list(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(
        """
import subprocess

def f(request):
    arg = request.args.get('x')
    # primary arg is a list => arg_type:string should fail
    subprocess.run(['ls', arg], shell=True)
""".lstrip(),
        encoding="utf-8",
    )

    from pyaegis.core.parser import PyASTParser
    from pyaegis.core.taint import TaintTracker

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["subprocess.*"],
        conditional_sinks=[
            {
                "name": "subprocess.run",
                "severity": "CRITICAL",
                "rule_id": "PYA-001",
                "conditions": [
                    {"has_kwarg": {"shell": True}},
                    {"arg_type": "string"},
                ],
            }
        ],
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    findings = tracker.get_findings()
    assert len(findings) == 0
