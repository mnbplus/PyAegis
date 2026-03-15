"""Tests for conditional sink logic.

Covers:
- subprocess.run WITHOUT shell=True  → no finding
- subprocess.run WITH shell=True     → finding reported
- pickle.loads in a test file        → suppressed (not_in_test_file condition)
"""
import textwrap
from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser


# Conditional sink definitions reused across tests
_SUBPROCESS_CONDITIONAL = [
    {
        "name": "subprocess.run",
        "severity": "HIGH",
        "rule_id": "PYA-001",
        "conditions": [
            {"has_kwarg": {"shell": True}}
        ],
    }
]

_PICKLE_CONDITIONAL = [
    {
        "name": "pickle.loads",
        "severity": "CRITICAL",
        "rule_id": "PYA-004",
        "conditions": [
            {"not_in_test_file": True}
        ],
    }
]


def _parse(tmp_path, name, code):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()
    return cfg, str(p)


# ---------------------------------------------------------------------------
# subprocess.run  —  shell kwarg gating
# ---------------------------------------------------------------------------

def test_subprocess_run_no_shell_no_finding(tmp_path):
    """subprocess.run with tainted arg but NO shell=True must NOT fire."""
    code = """
    import subprocess

    def f(request):
        cmd = request.args.get('cmd')
        subprocess.run(cmd)
    """
    cfg, filepath = _parse(tmp_path, "sub_no_shell.py", code)
    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["subprocess.run"],
        conditional_sinks=_SUBPROCESS_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=filepath)
    assert len(tracker.get_findings()) == 0, (
        "subprocess.run without shell=True should not be flagged"
    )


def test_subprocess_run_with_shell_true_finds(tmp_path):
    """subprocess.run with tainted arg AND shell=True MUST fire."""
    code = """
    import subprocess

    def f(request):
        cmd = request.args.get('cmd')
        subprocess.run(cmd, shell=True)
    """
    cfg, filepath = _parse(tmp_path, "sub_shell_true.py", code)
    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["subprocess.run"],
        conditional_sinks=_SUBPROCESS_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=filepath)
    assert len(tracker.get_findings()) >= 1, (
        "subprocess.run with shell=True should be flagged"
    )


def test_subprocess_run_shell_false_no_finding(tmp_path):
    """subprocess.run with explicit shell=False must NOT fire."""
    code = """
    import subprocess

    def f(request):
        cmd = request.args.get('cmd')
        subprocess.run(cmd, shell=False)
    """
    cfg, filepath = _parse(tmp_path, "sub_shell_false.py", code)
    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["subprocess.run"],
        conditional_sinks=_SUBPROCESS_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=filepath)
    assert len(tracker.get_findings()) == 0, (
        "subprocess.run with shell=False should not be flagged"
    )


def test_subprocess_run_clean_arg_no_finding(tmp_path):
    """subprocess.run with clean (non-tainted) arg and shell=True must NOT fire."""
    code = """
    import subprocess

    def f():
        subprocess.run('ls -l', shell=True)
    """
    cfg, filepath = _parse(tmp_path, "sub_clean_arg.py", code)
    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["subprocess.run"],
        conditional_sinks=_SUBPROCESS_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=filepath)
    assert len(tracker.get_findings()) == 0, (
        "Clean arg with shell=True should not be flagged (no taint)"
    )


def test_subprocess_run_via_glob_pattern(tmp_path):
    """Glob-based conditional sink entry also works for subprocess.run."""
    code = """
    import subprocess

    def f(request):
        cmd = request.args.get('cmd')
        subprocess.run(cmd, shell=True)
    """
    cfg, filepath = _parse(tmp_path, "sub_glob.py", code)
    glob_conditional = [
        {
            "name": "subprocess.*",
            "severity": "HIGH",
            "rule_id": "PYA-001",
            "conditions": [
                {"has_kwarg": {"shell": True}}
            ],
        }
    ]
    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["subprocess.*"],
        conditional_sinks=glob_conditional,
    )
    tracker.analyze_cfg(cfg, filepath=filepath)
    assert len(tracker.get_findings()) >= 1


# ---------------------------------------------------------------------------
# pickle.loads  —  not_in_test_file suppression
# ---------------------------------------------------------------------------

def test_pickle_loads_in_test_file_suppressed(tmp_path):
    """pickle.loads in a test_*.py file should be suppressed."""
    code = """
    import pickle

    def f(request):
        blob = request.data
        pickle.loads(blob)
    """
    # Write to a test_* named file so _is_test_filepath returns True
    p = tmp_path / "test_pickle_usage.py"
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.data"],
        sinks=["pickle.loads"],
        conditional_sinks=_PICKLE_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 0, (
        "pickle.loads in a test file should be suppressed by not_in_test_file condition"
    )


def test_pickle_loads_in_production_file_fires(tmp_path):
    """pickle.loads with tainted data in a production file MUST fire."""
    code = """
    import pickle

    def f(request):
        blob = request.data
        pickle.loads(blob)
    """
    # Use a non-test filename
    p = tmp_path / "views.py"
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.data"],
        sinks=["pickle.loads"],
        conditional_sinks=_PICKLE_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) >= 1, (
        "pickle.loads with tainted data in production code should fire"
    )


def test_pickle_loads_in_tests_subdir_suppressed(tmp_path):
    """pickle.loads in a file under a 'tests/' directory is also suppressed."""
    code = """
    import pickle

    def f(request):
        blob = request.data
        pickle.loads(blob)
    """
    # Simulate a path that includes 'tests' as a directory component
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    p = tests_dir / "helper.py"
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.data"],
        sinks=["pickle.loads"],
        conditional_sinks=_PICKLE_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 0, (
        "pickle.loads under tests/ directory should be suppressed"
    )


# ---------------------------------------------------------------------------
# Multiple conditional sinks in one config
# ---------------------------------------------------------------------------

def test_multiple_conditional_sinks_combined(tmp_path):
    """Both subprocess and pickle conditional sinks can coexist in one tracker."""
    code = """
    import subprocess
    import pickle

    def dangerous(request):
        cmd = request.args.get('cmd')
        blob = request.data
        subprocess.run(cmd, shell=True)
        pickle.loads(blob)
    """
    p = tmp_path / "combined.py"
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.args", "request.data"],
        sinks=["subprocess.run", "pickle.loads"],
        conditional_sinks=_SUBPROCESS_CONDITIONAL + _PICKLE_CONDITIONAL,
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    # Both sinks should fire: subprocess.run has shell=True, pickle in production file
    assert len(tracker.get_findings()) >= 2
