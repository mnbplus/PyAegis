import textwrap

import ast

from pyaegis.core.call_graph import GlobalSymbolTable, InterproceduralTaintTracker
from pyaegis.core.parser import PyASTParser


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


def test_call_graph_resolves_relative_import_from_package(tmp_path):
    """pkg/app.py uses `from .utils import get_cmd as gc`.

    We expect InterproceduralTaintTracker to resolve gc() -> pkg.utils.get_cmd.
    """

    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        # package marker
        """,
    )
    utils = _write(
        tmp_path,
        "pkg/utils.py",
        """
        def get_cmd(request):
            return request.args.get('cmd')
        """,
    )
    app = _write(
        tmp_path,
        "pkg/app.py",
        """
        from .utils import get_cmd as gc

        def handler(request):
            return gc(request)
        """,
    )

    gst = GlobalSymbolTable.build([str(utils), str(app)], root_dir=str(tmp_path))

    ip = InterproceduralTaintTracker(gst)
    tree_app = ast.parse(app.read_text(encoding="utf-8"), filename=str(app))
    call = _first_call(tree_app)

    assert ip.resolve_call_qualname(call, caller_file=str(app)) == "pkg.utils.get_cmd"
    sym = ip.resolve_symbol(call, caller_file=str(app))
    assert sym is not None
    assert sym.qualname == "pkg.utils.get_cmd"


def test_call_graph_resolves_relative_import_module_alias(tmp_path):
    """pkg/app.py uses `from . import utils as u`; u.get_cmd() should resolve."""

    _write(tmp_path, "pkg/__init__.py", "# package\n")
    utils = _write(
        tmp_path,
        "pkg/utils.py",
        """
        def get_cmd(request):
            return request.args.get('cmd')
        """,
    )
    app = _write(
        tmp_path,
        "pkg/app.py",
        """
        from . import utils as u

        def handler(request):
            return u.get_cmd(request)
        """,
    )

    # Build GST via PyASTParser register_file to mirror production behaviour
    gst = GlobalSymbolTable(root_dir=str(tmp_path))
    for p in (utils, app):
        parser = PyASTParser(str(p))
        tree = parser.parse()
        gst.register_file(str(p), tree)

    ip = InterproceduralTaintTracker(gst)
    parser = PyASTParser(str(app))
    tree = parser.parse()
    call = _first_call(tree)

    assert ip.resolve_call_qualname(call, caller_file=str(app)) == "pkg.utils.get_cmd"
