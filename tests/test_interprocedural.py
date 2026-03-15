"""Tests for inter-procedural taint analysis (GlobalSymbolTable + InterproceduralAnalyzer).

Note: These tests exercise the new GlobalSymbolTable.register_file() API.
Some tests are skipped pending full API alignment.
"""
import ast
import os
import textwrap

from pyaegis.core.call_graph import GlobalSymbolTable, InterproceduralAnalyzer
from pyaegis.core.parser import PyASTParser
from pyaegis.core.taint import TaintTracker


def _write(tmp_path, rel: str, code: str):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


def _first_call(tree: ast.AST) -> ast.Call:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            return node
    raise AssertionError("No ast.Call found")


# --- existing symbol table tests ---


def test_global_symbol_table_build_empty():
    """build() with empty list should return a valid table."""
    st = GlobalSymbolTable.build([])
    assert st is not None


def test_global_symbol_table_register_file():
    """register_file() should not raise for valid Python source."""
    code = "def foo(x): pass"
    tree = ast.parse(code)
    st = GlobalSymbolTable()
    st.register_file("mod.py", tree)  # should not raise


def test_interprocedural_alias_exists():
    """InterproceduralAnalyzer should be importable as an alias."""
    assert InterproceduralAnalyzer is not None


def test_symbol_table_registers_functions():
    code = "def foo(x, y): pass\ndef bar(z): pass"
    tree = ast.parse(code)
    st = GlobalSymbolTable()
    st.register_file("mod.py", tree)
    assert "mod.foo" in st.functions
    assert "mod.bar" in st.functions


def test_symbol_table_registers_imports():
    code = "from mymod import helper"
    tree = ast.parse(code)
    st = GlobalSymbolTable()
    st.register_file("app.py", tree)
    assert "helper" in st.imports["app.py"]


# --- inter-procedural taint tests ---


def test_interprocedural_basic(tmp_path):
    """Taint should flow across modules into a sink inside the callee."""
    utils = _write(
        tmp_path,
        "utils.py",
        """
        def run_cmd(cmd):
            import os
            os.system(cmd)
        """,
    )
    app = _write(
        tmp_path,
        "app.py",
        """
        from utils import run_cmd

        def handler(request):
            cmd = request.args.get("cmd")
            run_cmd(cmd)
        """,
    )

    gst = GlobalSymbolTable.build([str(utils), str(app)], root_dir=str(tmp_path))
    parser = PyASTParser(str(app))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.args", "input"],
        sinks=["os.system", "eval"],
        sanitizers=[],
        symbol_table=gst,
    )
    tracker.analyze_cfg(cfg, filepath=str(app))

    findings = tracker.get_findings()
    assert any(
        f.sink_name == "os.system"
        and os.path.abspath(f.file_path) == os.path.abspath(str(utils))
        for f in findings
    )


def test_interprocedural_propagates_internal_source_return(tmp_path):
    """Taint should propagate when the callee sources data internally."""
    utils = _write(
        tmp_path,
        "utils.py",
        """
        def get_cmd():
            return input("cmd")
        """,
    )
    app = _write(
        tmp_path,
        "app.py",
        """
        from utils import get_cmd

        def handler():
            cmd = get_cmd()
            eval(cmd)
        """,
    )

    gst = GlobalSymbolTable.build([str(utils), str(app)], root_dir=str(tmp_path))
    parser = PyASTParser(str(app))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["input", "request"],
        sinks=["eval", "os.system"],
        sanitizers=[],
        symbol_table=gst,
    )
    tracker.analyze_cfg(cfg, filepath=str(app))

    findings = tracker.get_findings()
    assert any(
        f.sink_name == "eval"
        and os.path.abspath(f.file_path) == os.path.abspath(str(app))
        for f in findings
    )
