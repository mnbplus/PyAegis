import ast
import logging
import multiprocessing
from typing import Any, Dict, List, Optional, Tuple

from pyaegis.exceptions import ParserError

logger = logging.getLogger(__name__)


class PyASTParser:
    """AST parser + lightweight metadata extractor for taint analysis.

    PyAegis is intentionally lightweight (AST-based, not full SSA). This parser
    extracts *just enough* structure to enable:

    - Function bodies for intra-procedural taint tracking.
    - Decorator-based route discovery for common Python web frameworks
      (Flask/FastAPI style: @app.route, @app.get, ...).
    - A minimal call list per function for simple inter-procedural propagation.

    The returned data structure is still called a "CFG" for historical reasons.
    It is a function map with metadata.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.tree: Optional[ast.Module] = None

    def parse(self) -> ast.Module:
        """Parse the target file into an ``ast.Module``."""
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                code = f.read()
            self.tree = ast.parse(code, filename=self.filepath)
            return self.tree
        except SyntaxError as e:
            logger.error(f"Syntax error in '{self.filepath}': {e}")
            raise ParserError(f"Cannot parse file {self.filepath}") from e
        except Exception as e:
            logger.error(f"Failed opening/parsing '{self.filepath}': {e}")
            raise ParserError(f"Unexpected error: {e}") from e

    def extract_cfg(self) -> Dict[str, Any]:
        """Extract function metadata.

        Returns:
            Dict[str, Any]:
                ``{ function_name: {body, args, decorators, routes, calls} }``

        Backward compatibility:
            Older versions returned ``{function_name: node.body}``.
            The taint engine tolerates both forms.
        """
        if self.tree is None:
            self.parse()

        functions: Dict[str, Any] = {}

        for node in ast.walk(self.tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            decorators, routes = self._extract_decorators(node.decorator_list)
            calls = sorted(self._extract_calls(node))
            args = [a.arg for a in node.args.args]

            functions[node.name] = {
                "body": node.body,
                "args": args,
                "decorators": decorators,
                "routes": routes,
                "calls": calls,
            }

        return functions

    def _extract_calls(self, func_node: ast.FunctionDef) -> List[str]:
        """Collect dotted call names from within a function."""
        out = set()
        for n in ast.walk(func_node):
            if isinstance(n, ast.Call):
                name = self._get_full_name(n.func)
                if name:
                    out.add(name)
        return list(out)

    def _extract_decorators(
        self, decorator_list: List[ast.expr]
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Extract decorator names and route decorator metadata.

        Route detection targets:
            - Flask: ``@app.route('/path', methods=['GET'])``
            - FastAPI: ``@app.get('/path')``, ``@router.post('/path')``

        Returns:
            (decorator_names, routes)
        """
        decorator_names: List[str] = []
        routes: List[Dict[str, Any]] = []

        route_suffixes = {
            "route",
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "options",
            "head",
            "trace",
        }

        for dec in decorator_list:
            dec_name = (
                self._get_full_name(dec.func)
                if isinstance(dec, ast.Call)
                else self._get_full_name(dec)
            )
            if not dec_name:
                continue

            decorator_names.append(dec_name)

            suffix = dec_name.split(".")[-1]
            if suffix not in route_suffixes:
                continue

            info: Dict[str, Any] = {
                "decorator": dec_name,
                "path": None,
                "methods": [],
            }

            if isinstance(dec, ast.Call) and dec.args:
                first = dec.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    info["path"] = first.value

            if isinstance(dec, ast.Call) and dec.keywords:
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(
                        kw.value, (ast.List, ast.Tuple)
                    ):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant):
                                info["methods"].append(str(elt.value))

            # FastAPI-style decorators encode HTTP verb in the decorator name
            if suffix in {
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "options",
                "head",
                "trace",
            }:
                if not info["methods"]:
                    info["methods"].append(suffix.upper())

            routes.append(info)

        return decorator_names, routes

    def _get_full_name(self, node: ast.AST) -> str:
        """Resolve a node into a dotted name when possible."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_full_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Subscript):
            # request.GET['x'] -> request.GET
            return self._get_full_name(node.value)
        if isinstance(node, ast.Call):
            return self._get_full_name(node.func)
        return ""


def _worker_parse(filepath: str) -> Dict[str, Any]:
    parser = PyASTParser(filepath)
    parser.parse()
    return parser.extract_cfg()


class ParallelProjectParser:
    """Parse multiple files concurrently."""

    def __init__(self, pool_size: int = 4):
        self.pool_size = pool_size

    def parse_all(self, filepaths: List[str]) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        with multiprocessing.Pool(self.pool_size) as pool:
            cfgs = pool.map(_worker_parse, filepaths)
            for path, cfg in zip(filepaths, cfgs):
                results[path] = cfg
        return results
