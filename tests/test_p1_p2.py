"""
Tests for P1 (framework-aware source detection) and P2 (conditional sink rules).
"""
import os
import textwrap
import tempfile

import pytest

from pyaegis.core.parser import PyASTParser
from pyaegis.core.taint import TaintTracker, _is_test_filepath, _check_conditional_sink
import ast


# ── helpers ──────────────────────────────────────────────────────────────────

def _run(code: str, filepath: str = "app.py",
         sources=None, sinks=None, sanitizers=None,
         conditional_sinks=None, source_decorators=None):
    """Write code to a temp file, parse, run taint analysis, return findings."""
    sources = sources or ["request", "request.args", "request.form",
                          "request.json", "request.data", "request.GET",
                          "request.POST", "input", "sys.argv"]
    sinks = sinks or ["os.system", "eval", "exec", "subprocess.*"]
    sanitizers = sanitizers or []
    conditional_sinks = conditional_sinks or []
    source_decorators = source_decorators or []

    # Write to a temp file whose name matches the requested filepath pattern
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, os.path.basename(filepath))
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(code).lstrip("\n"))

    parser = PyASTParser(tmp_path)
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
        conditional_sinks=conditional_sinks,
        source_decorators=source_decorators,
    )
    tracker.analyze_cfg(cfg, filepath=tmp_path)
    return tracker.get_findings()


# ── P2: _is_test_filepath ─────────────────────────────────────────────────────

class TestIsTestFilepath:
    def test_tests_directory(self):
        assert _is_test_filepath("/project/tests/test_foo.py")

    def test_test_prefix_file(self):
        assert _is_test_filepath("/project/src/test_views.py")

    def test_test_suffix_file(self):
        assert _is_test_filepath("/project/src/views_test.py")

    def test_non_test_file(self):
        assert not _is_test_filepath("/project/src/views.py")

    def test_windows_path(self):
        assert _is_test_filepath("D:\\project\\tests\\test_core.py")

    def test_testing_directory(self):
        assert _is_test_filepath("/project/testing/helpers.py")


# ── P2: conditional sink — has_kwarg ─────────────────────────────────────────

class TestConditionalSinkHasKwarg:
    """subprocess.run should only fire when shell=True."""

    _COND_SINKS = [
        {
            "name": "subprocess.run",
            "severity": "CRITICAL",
            "rule_id": "PYA-001",
            "conditions": [{"has_kwarg": {"shell": True}}],
        },
        {
            "name": "subprocess.call",
            "severity": "CRITICAL",
            "rule_id": "PYA-001",
            "conditions": [{"has_kwarg": {"shell": True}}],
        },
    ]

    def test_subprocess_run_shell_true_fires(self):
        """subprocess.run(tainted, shell=True) → should report."""
        findings = _run(
            """
            import subprocess
            def f(request):
                cmd = request.args.get('x')
                subprocess.run(cmd, shell=True)
            """,
            sinks=["subprocess.*"],
            conditional_sinks=self._COND_SINKS,
        )
        assert len(findings) == 1
        assert findings[0].sink_name == "subprocess.run"

    def test_subprocess_run_shell_false_suppressed(self):
        """subprocess.run(tainted, shell=False) → should NOT report."""
        findings = _run(
            """
            import subprocess
            def f(request):
                cmd = request.args.get('x')
                subprocess.run(cmd, shell=False)
            """,
            sinks=["subprocess.*"],
            conditional_sinks=self._COND_SINKS,
        )
        assert len(findings) == 0, "shell=False should not be flagged"

    def test_subprocess_run_no_shell_kwarg_suppressed(self):
        """subprocess.run(tainted) without shell kwarg → should NOT report."""
        findings = _run(
            """
            import subprocess
            def f(request):
                cmd = request.args.get('x')
                subprocess.run(cmd)
            """,
            sinks=["subprocess.*"],
            conditional_sinks=self._COND_SINKS,
        )
        assert len(findings) == 0, "missing shell kwarg should not be flagged"

    def test_subprocess_call_shell_true_fires(self):
        """subprocess.call(tainted, shell=True) → should report."""
        findings = _run(
            """
            import subprocess
            def f(request):
                cmd = request.args.get('x')
                subprocess.call(cmd, shell=True)
            """,
            sinks=["subprocess.*"],
            conditional_sinks=self._COND_SINKS,
        )
        assert len(findings) == 1

    def test_subprocess_call_shell_false_suppressed(self):
        findings = _run(
            """
            import subprocess
            def f(request):
                cmd = request.args.get('x')
                subprocess.call(cmd, shell=False)
            """,
            sinks=["subprocess.*"],
            conditional_sinks=self._COND_SINKS,
        )
        assert len(findings) == 0

    def test_eval_unconditional_always_fires(self):
        """eval has no conditions — always reports."""
        findings = _run(
            """
            def f(request):
                x = request.args.get('x')
                eval(x)
            """,
            sinks=["eval"],
            conditional_sinks=[],  # eval has no conditional sink entry
        )
        assert len(findings) == 1


# ── P2: not_in_test_file condition ───────────────────────────────────────────

class TestNotInTestFile:
    _COND_SINKS = [
        {
            "name": "pickle.loads",
            "severity": "HIGH",
            "rule_id": "PYA-004",
            "conditions": [{"not_in_test_file": True}],
        }
    ]

    def test_pickle_in_production_code_fires(self, tmp_path):
        """pickle.loads in a non-test file should be reported."""
        p = tmp_path / "app.py"
        p.write_text(textwrap.dedent("""
            import pickle
            def f(request):
                data = request.data
                pickle.loads(data)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request", "request.data"],
            sinks=["pickle.loads"],
            conditional_sinks=self._COND_SINKS,
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 1

    def test_pickle_in_test_file_suppressed(self, tmp_path):
        """pickle.loads in a test file should be suppressed."""
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        p = test_dir / "test_serialization.py"
        p.write_text(textwrap.dedent("""
            import pickle
            def f(request):
                data = request.data
                pickle.loads(data)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request", "request.data"],
            sinks=["pickle.loads"],
            conditional_sinks=self._COND_SINKS,
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0, "pickle in test file should be suppressed"


# ── P1: framework-aware source detection ─────────────────────────────────────

class TestFrameworkAwareSource:
    """Route-decorated functions should have their args auto-tainted."""

    def test_flask_route_arg_tainted(self, tmp_path):
        """Flask @app.route — function args are auto-tainted."""
        p = tmp_path / "flask_app.py"
        p.write_text(textwrap.dedent("""
            from flask import Flask
            app = Flask(__name__)

            @app.route('/run')
            def run_cmd(cmd):
                import os
                os.system(cmd)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request"],
            sinks=["os.system"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 1

    def test_fastapi_get_arg_tainted(self, tmp_path):
        """FastAPI @app.get — function args are auto-tainted."""
        p = tmp_path / "fastapi_app.py"
        p.write_text(textwrap.dedent("""
            from fastapi import FastAPI
            app = FastAPI()

            @app.get('/items')
            def get_items(query: str):
                import os
                os.system(query)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request"],
            sinks=["os.system"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 1

    def test_non_route_function_not_auto_tainted(self, tmp_path):
        """Regular function without route decorator — args NOT auto-tainted."""
        p = tmp_path / "app.py"
        p.write_text(textwrap.dedent("""
            def run_cmd(cmd):
                import os
                os.system(cmd)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request"],
            sinks=["os.system"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0

    def test_fastapi_post_tainted_to_eval(self, tmp_path):
        """FastAPI @app.post — arg flows to eval → should report."""
        p = tmp_path / "fastapi_post.py"
        p.write_text(textwrap.dedent("""
            from fastapi import FastAPI
            app = FastAPI()

            @app.post('/exec')
            def execute(code: str):
                eval(code)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request"],
            sinks=["eval"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 1

    def test_flask_route_shell_true_fires(self, tmp_path):
        """Flask route arg → subprocess.run(shell=True) → should report."""
        p = tmp_path / "flask_sub.py"
        p.write_text(textwrap.dedent("""
            from flask import Flask
            import subprocess
            app = Flask(__name__)

            @app.route('/run')
            def run_cmd(cmd):
                subprocess.run(cmd, shell=True)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request"],
            sinks=["subprocess.*"],
            conditional_sinks=[
                {
                    "name": "subprocess.run",
                    "severity": "CRITICAL",
                    "rule_id": "PYA-001",
                    "conditions": [{"has_kwarg": {"shell": True}}],
                }
            ],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 1

    def test_flask_route_shell_false_suppressed(self, tmp_path):
        """Flask route arg → subprocess.run(shell=False) → should NOT report."""
        p = tmp_path / "flask_safe.py"
        p.write_text(textwrap.dedent("""
            from flask import Flask
            import subprocess
            app = Flask(__name__)

            @app.route('/run')
            def run_cmd(cmd):
                subprocess.run(cmd, shell=False)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request"],
            sinks=["subprocess.*"],
            conditional_sinks=[
                {
                    "name": "subprocess.run",
                    "severity": "CRITICAL",
                    "rule_id": "PYA-001",
                    "conditions": [{"has_kwarg": {"shell": True}}],
                }
            ],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0

    def test_router_post_arg_tainted(self, tmp_path):
        """APIRouter @router.post — args auto-tainted."""
        p = tmp_path / "router_app.py"
        p.write_text(textwrap.dedent("""
            from fastapi import APIRouter
            router = APIRouter()

            @router.post('/submit')
            def submit(data: str):
                eval(data)
        """), encoding="utf-8")

        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request"],
            sinks=["eval"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 1
