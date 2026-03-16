"""
Tests for self.method() instance call taint propagation.

Scenario: a class method receives tainted input and passes it to a sink
via self.other_method(). TaintTracker should follow the call through the
GlobalSymbolTable and report the finding.
"""
import ast
import textwrap
from pyaegis.core.call_graph import GlobalSymbolTable
from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return str(p)


def _make_tracker(symbol_table=None):
    return TaintTracker(
        sources=["request", "input", "user_input"],
        sinks=["os.system", "subprocess.*", "eval", "exec"],
        sanitizers=["shlex.quote", "html.escape"],
        symbol_table=symbol_table,
        max_call_depth=4,
    )


def _analyze(tmp_path, name, src):
    fpath = _write(tmp_path, name, src)
    tree = ast.parse(textwrap.dedent(src), filename=fpath)
    st = GlobalSymbolTable(root_dir=str(tmp_path))
    st.register_file(fpath, tree)
    parser = PyASTParser(fpath)
    parser.parse()
    cfg = parser.extract_cfg()
    tracker = _make_tracker(symbol_table=st)
    tracker.analyze_cfg(cfg, fpath)
    return tracker.get_findings()


# ---------------------------------------------------------------------------
# Test 1: self.method() taint propagation — direct sink in called method
# ---------------------------------------------------------------------------


def test_self_method_taint_reaches_sink(tmp_path):
    """self.run_cmd(user_input) -> inside run_cmd: os.system(cmd) => finding."""
    src = """\
        import os

        class Handler:
            def handle(self, user_input):
                self.run_cmd(user_input)

            def run_cmd(self, cmd):
                os.system(cmd)
        """
    findings = _analyze(tmp_path, "handler.py", src)
    assert len(findings) >= 1, f"Expected finding via self.run_cmd(), got: {findings}"
    assert "os.system" in {f.sink_name for f in findings}


# ---------------------------------------------------------------------------
# Test 2: self.method() sanitized — no finding
# ---------------------------------------------------------------------------


def test_self_method_sanitized_no_finding(tmp_path):
    """self.run_cmd(shlex.quote(user_input)) — sanitized, no finding."""
    src = """\
        import os
        import shlex

        class Handler:
            def handle(self, user_input):
                safe = shlex.quote(user_input)
                self.run_cmd(safe)

            def run_cmd(self, cmd):
                os.system(cmd)
        """
    findings = _analyze(tmp_path, "handler_safe.py", src)
    assert len(findings) == 0, f"Expected no findings after sanitizer, got: {findings}"


# ---------------------------------------------------------------------------
# Test 3: self.attr taint flows into direct sink in another method
# ---------------------------------------------------------------------------


def test_self_attr_to_sink(tmp_path):
    """Taint stored in self.data, execute() uses self.data as sink arg."""
    src = """\
        import os

        class Processor:
            def load(self, user_input):
                self.data = user_input

            def execute(self):
                os.system(self.data)
        """
    findings = _analyze(tmp_path, "processor.py", src)
    assert len(findings) >= 1, f"Expected finding via self.data, got: {findings}"
    assert "os.system" in {f.sink_name for f in findings}


# ---------------------------------------------------------------------------
# Test 4: chained self.method() — two hops before sink
# ---------------------------------------------------------------------------


def test_self_method_chain_two_hops(tmp_path):
    """handle -> self.prepare(x) -> self.dispatch(x) -> os.system(x)."""
    src = """\
        import os

        class Pipeline:
            def handle(self, user_input):
                self.prepare(user_input)

            def prepare(self, x):
                self.dispatch(x)

            def dispatch(self, x):
                os.system(x)
        """
    findings = _analyze(tmp_path, "pipeline.py", src)
    assert (
        len(findings) >= 1
    ), f"Expected finding via chained self.method(), got: {findings}"
    assert "os.system" in {f.sink_name for f in findings}
