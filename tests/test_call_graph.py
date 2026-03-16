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


def test_class_method_indexed_by_qualname(tmp_path):
    """Methods inside a class should be indexed as module.ClassName.method_name."""
    mod = _write(
        tmp_path,
        "service.py",
        """
        class UserService:
            def get_user(self, user_id):
                return user_id

            def delete_user(self, user_id):
                pass

        def standalone(x):
            return x
        """,
    )

    gst = GlobalSymbolTable.build([str(mod)], root_dir=str(tmp_path))

    # Class methods should be indexed under module.Class.method
    assert gst.get("service.UserService.get_user") is not None
    assert gst.get("service.UserService.delete_user") is not None
    # Top-level function should still work
    assert gst.get("service.standalone") is not None
    # Non-existent should return None
    assert gst.get("service.UserService.nonexistent") is None


def test_class_method_args_include_self(tmp_path):
    """Method FunctionSymbol.args should include self."""
    mod = _write(
        tmp_path,
        "svc.py",
        """
        class Handler:
            def process(self, request, data):
                pass
        """,
    )

    gst = GlobalSymbolTable.build([str(mod)], root_dir=str(tmp_path))
    sym = gst.get("svc.Handler.process")
    assert sym is not None
    assert sym.args == ["self", "request", "data"]


def test_class_method_get_by_name(tmp_path):
    """get_by_name() should return class methods by bare method name."""
    mod = _write(
        tmp_path,
        "repo.py",
        """
        class UserRepo:
            def find(self, uid):
                return uid
        """,
    )

    gst = GlobalSymbolTable.build([str(mod)], root_dir=str(tmp_path))
    results = gst.get_by_name("find")
    assert len(results) == 1
    assert results[0].qualname == "repo.UserRepo.find"


def test_class_method_taint_across_modules(tmp_path):
    """Taint should propagate into a class method sink in another module."""
    _write(
        tmp_path,
        "dao.py",
        """
        import os

        class QueryRunner:
            def run(self, query):
                os.system(query)
        """,
    )
    _write(
        tmp_path,
        "view.py",
        """
        from dao import QueryRunner

        def handle(request):
            q = request.args.get("q")
            runner = QueryRunner()
            runner.run(q)
        """,
    )

    fps = [str(tmp_path / "dao.py"), str(tmp_path / "view.py")]
    gst = GlobalSymbolTable.build(fps, root_dir=str(tmp_path))

    # dao.QueryRunner.run should be indexed
    assert gst.get("dao.QueryRunner.run") is not None
