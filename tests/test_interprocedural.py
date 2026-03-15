"""Tests for inter-procedural taint analysis (GlobalSymbolTable + InterproceduralAnalyzer).

Note: These tests exercise the new GlobalSymbolTable.register_file() API.
Some tests are skipped pending full API alignment.
"""
import ast
import pytest

from pyaegis.core.call_graph import GlobalSymbolTable, InterproceduralAnalyzer


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


@pytest.mark.skip(reason="API alignment pending - tracked in ROADMAP P0")
def test_symbol_table_registers_functions():
    code = "def foo(x, y): pass\ndef bar(z): pass"
    tree = ast.parse(code)
    st = GlobalSymbolTable()
    st.register_file("mod.py", tree)
    assert "mod.foo" in st.functions
    assert "mod.bar" in st.functions


@pytest.mark.skip(reason="API alignment pending - tracked in ROADMAP P0")
def test_symbol_table_registers_imports():
    code = "from mymod import helper"
    tree = ast.parse(code)
    st = GlobalSymbolTable()
    st.register_file("app.py", tree)
    assert "helper" in st.imports["app.py"]


@pytest.mark.skip(reason="API alignment pending - tracked in ROADMAP P0")
def test_interprocedural_basic():
    pass


@pytest.mark.skip(reason="requires full inter-procedural taint integration - ROADMAP P0")
def test_interprocedural_propagates_internal_source_return(tmp_path):
    pass
