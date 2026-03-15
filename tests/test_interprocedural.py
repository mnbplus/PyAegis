import ast
from pyaegis.core.call_graph import GlobalSymbolTable, InterproceduralAnalyzer


def test_symbol_table_registers_functions():
    code = 'def foo(x, y): pass\ndef bar(z): pass'
    tree = ast.parse(code)
    st = GlobalSymbolTable()
    st.register_file('test_module.py', tree)
    assert 'test_module.foo' in st.functions
    assert 'test_module.bar' in st.functions


def test_symbol_table_registers_imports():
    code = 'from mymodule import helper'
    tree = ast.parse(code)
    st = GlobalSymbolTable()
    st.register_file('app.py', tree)
    assert 'helper' in st.imports['app.py']


def test_interprocedural_basic():
    code_a = 'import os\ndef process(user_data):\n    os.system(user_data)'
    code_b = 'from a import process\ndef handler(req):\n    process(req)'
    st = GlobalSymbolTable()
    st.register_file('a.py', ast.parse(code_a))
    st.register_file('b.py', ast.parse(code_b))
    analyzer = InterproceduralAnalyzer(st)
    # process() called with tainted arg at index 0
    result = analyzer.has_tainted_sink('b.py', 'process', [0])
    assert result  # should detect taint reaching os.system
