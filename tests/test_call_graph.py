import ast
import textwrap

from pyaegis.core.call_graph import GlobalSymbolTable, InterproceduralTaintTracker


def _write(tmp_path, name: str, code: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


def _first_call(tree: ast.AST) -> ast.Call:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            return node
    raise AssertionError("No ast.Call found")


def test_call_graph_symbol_table_and_alias_resolution(tmp_path):
    # Build a small 2-module project under tmp_path.
    mod_a = _write(
        tmp_path,
        "mod_a.py",
        """
        def get_cmd(request):
            return request.args.get('cmd')
        """,
    )
    mod_b = _write(
        tmp_path,
        "mod_b.py",
        """
        import mod_a as ma

        def endpoint(request):
            return ma.get_cmd(request)
        """,
    )

    gst = GlobalSymbolTable.build([str(mod_a), str(mod_b)], root_dir=str(tmp_path))

    # Register: top-level functions should be indexed by qualname.
    assert gst.get("mod_a.get_cmd") is not None
    assert gst.get("mod_b.endpoint") is not None

    ip = InterproceduralTaintTracker(gst)
    tree_b = ast.parse(mod_b.read_text(encoding="utf-8"), filename=str(mod_b))
    call = _first_call(tree_b)

    assert ip.resolve_call_qualname(call, caller_file=str(mod_b)) == "mod_a.get_cmd"
    sym = ip.resolve_symbol(call, caller_file=str(mod_b))
    assert sym is not None
    assert sym.qualname == "mod_a.get_cmd"


def test_call_graph_ambiguous_bare_name_returns_none(tmp_path):
    a = _write(
        tmp_path,
        "a.py",
        """\
    def dup():
        return 1
    """,
    )
    b = _write(
        tmp_path,
        "b.py",
        """\
    def dup():
        return 2
    """,
    )
    c = _write(
        tmp_path,
        "c.py",
        """\
    def caller():
        return dup()
    """,
    )

    gst = GlobalSymbolTable.build([str(a), str(b), str(c)], root_dir=str(tmp_path))
    ip = InterproceduralTaintTracker(gst)

    tree = ast.parse(c.read_text(encoding="utf-8"), filename=str(c))
    call = _first_call(tree)

    assert ip.resolve_call_qualname(call, caller_file=str(c)) == "dup"
    assert ip.resolve_symbol(call, caller_file=str(c)) is None
