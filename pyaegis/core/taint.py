import ast
import fnmatch
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from pyaegis.models import Finding
from pyaegis.rules_catalog import get_rule

try:
    # Optional dependency for P0 inter-procedural taint
    from pyaegis.core.call_graph import (
        GlobalSymbolTable,
        FunctionSymbol,
        InterproceduralTaintTracker,
    )
except Exception:  # pragma: no cover
    GlobalSymbolTable = None  # type: ignore
    FunctionSymbol = None  # type: ignore
    InterproceduralTaintTracker = None  # type: ignore


# Mapping from sink patterns to stable rule IDs.
# Keep this simple and conservative: if a sink matches multiple groups,
# the first match in order wins.
_RULE_GROUPS: List[Tuple[str, List[str]]] = [
    (
        "PYA-003",
        ["eval", "exec", "compile", "builtins.eval", "builtins.exec", "runpy.*"],
    ),
    (
        "PYA-001",
        ["os.system", "os.popen", "os.spawn*", "subprocess.*", "commands.getoutput"],
    ),
    (
        "PYA-004",
        [
            "pickle.load",
            "pickle.loads",
            "cPickle.loads",
            "dill.loads",
            "marshal.loads",
            "yaml.load",
            "yaml.unsafe_load",
            "ruamel.yaml.load",
            "jsonpickle.decode",
        ],
    ),
    (
        "PYA-005",
        [
            "urllib.request.urlopen",
            "urllib3.PoolManager.request",
            "urllib3.request",
            "requests.get",
            "requests.post",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.request",
            "aiohttp.ClientSession.*",
            "socket.create_connection",
        ],
    ),
    (
        "PYA-006",
        [
            "open",
            "builtins.open",
            "os.open",
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "os.rename",
            "os.replace",
            "os.mkdir",
            "os.makedirs",
            "shutil.*",
            "pathlib.Path*",
            "tempfile.NamedTemporaryFile",
        ],
    ),
    (
        "PYA-002",
        [
            "sqlite3.Connection.execute",
            "sqlite3.Cursor.execute",
            "sqlite3.Cursor.executemany",
            "psycopg2.connect",
            "psycopg2.cursor.execute",
            "MySQLdb.connect",
            "pymysql.connect",
            "sqlalchemy.text",
            "*.objects.raw",
            "*.raw",
        ],
    ),
]


def _rule_id_for_sink(sink_name: str) -> str:
    """Pick a stable rule id for the sink name."""
    for rid, pats in _RULE_GROUPS:
        for p in pats:
            if p == sink_name:
                return rid
            if any(ch in p for ch in "*?[]") and fnmatch.fnmatch(sink_name, p):
                return rid
    return "PYA-999"


def _is_test_filepath(filepath: str) -> bool:
    """Return True if the filepath looks like a test file."""
    # Normalize separators
    normalized = filepath.replace("\\", "/")
    # Check directory components
    parts = normalized.split("/")
    for part in parts[:-1]:
        if part in ("tests", "testing", "test"):
            return True
    # Check filename
    filename = parts[-1]
    if filename.startswith("test_") or filename.endswith("_test.py"):
        return True
    return False


def _primary_arg_for_type(call_node: ast.Call) -> Optional[ast.AST]:
    """Best-effort: pick the primary argument that represents user-controlled payload.

    For most sinks (e.g. eval(x), subprocess.run(cmd), open(path)), this is the
    first positional arg. Some APIs also accept keyword forms.
    """
    if call_node.args:
        return call_node.args[0]

    for kw in call_node.keywords:
        if kw.arg in {"args", "command", "cmd", "path", "filename"}:
            return kw.value

    return None


def _expr_is_string(expr: ast.AST) -> bool:
    """Heuristic string-typed expression check.

    We intentionally only *exclude* obvious non-string container literals.
    For unknown expressions (e.g. Name), we return True to avoid introducing
    false negatives when type information is unavailable.
    """
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, str)

    # f-string
    if isinstance(expr, ast.JoinedStr):
        return True

    # string concat / old-style formatting
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return _expr_is_string(expr.left) or _expr_is_string(expr.right)

    # Obvious containers / comprehensions are not strings
    if isinstance(
        expr,
        (
            ast.List,
            ast.Tuple,
            ast.Set,
            ast.Dict,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.GeneratorExp,
        ),
    ):
        return False

    # Unknown: assume string-ish (avoid suppressing true positives)
    return True


def _check_conditional_sink(
    sink_name: str,
    call_node: ast.Call,
    conditional_sinks: List[Dict[str, Any]],
    filepath: str,
) -> Optional[Dict[str, Any]]:
    """Check whether a conditional sink entry matches and its conditions are satisfied.

    Returns the matching conditional sink dict if all conditions pass, else None.
    """
    for cs in conditional_sinks:
        cs_name = cs.get("name", "")
        # Match by exact name or glob
        if cs_name != sink_name and not (
            any(ch in cs_name for ch in "*?[]") and fnmatch.fnmatch(sink_name, cs_name)
        ):
            continue
        # All conditions must pass
        conditions = cs.get("conditions", [])
        all_pass = True
        for cond in conditions:
            if "has_kwarg" in cond:
                for kw_name, kw_val in cond["has_kwarg"].items():
                    found = False
                    for kw in call_node.keywords:
                        if kw.arg == kw_name:
                            # Check value matches
                            if (
                                isinstance(kw.value, ast.Constant)
                                and kw.value.value == kw_val
                            ):
                                found = True
                            break
                    if not found:
                        all_pass = False
                        break
            if "not_in_test_file" in cond:
                if cond["not_in_test_file"] and _is_test_filepath(filepath):
                    all_pass = False
            if "arg_type" in cond:
                want = str(cond.get("arg_type", "")).strip().lower()
                if want == "string":
                    primary = _primary_arg_for_type(call_node)
                    if primary is None or not _expr_is_string(primary):
                        all_pass = False
                else:
                    # Unknown arg_type values are treated as non-match
                    all_pass = False
            if not all_pass:
                break
        if all_pass:
            return cs
    return None


@dataclass(frozen=True)
class _FnContext:
    """Internal helper container for a function's extracted metadata."""

    name: str
    body: List[ast.stmt]
    args: List[str]
    meta: Dict[str, Any]


class TaintTracker:
    """Simple taint analysis engine.

    Enhancements vs the baseline implementation:
    - Inter-procedural propagation (cross-function calls) within a parsed file.
    - Inter-procedural propagation across modules when a symbol table is provided.
    - String operations propagation: concatenation and f-string tainting.
    - Sanitizer detection: variables assigned from sanitizers are treated clean.
    - Tuple/starred unpacking: taint propagates to all unpacked targets.
    - Class instance attribute tracking: self.attr taint across methods.

    Notes:
    This is still a lightweight AST taint engine (best-effort), not a full dataflow
    solver. It aims to catch common patterns with low complexity.
    """

    def __init__(
        self,
        sources: List[str],
        sinks: List[str],
        sanitizers: Optional[List[str]] = None,
        conditional_sinks: Optional[List[Dict[str, Any]]] = None,
        source_decorators: Optional[List[str]] = None,
        symbol_table: Optional["GlobalSymbolTable"] = None,
        max_call_depth: int = 3,
    ):
        """
        Args:
            sources: Root objects / function names considered untrusted, and/or
                     attribute patterns (e.g. request.args, request.GET, input).
            sinks: Sensitive call targets. Supports glob patterns (e.g. subprocess.*).
            sanitizers: Calls that sanitize input (e.g. html.escape, bleach.clean).
            conditional_sinks: List of conditional sink definitions. Each entry is a dict
                with keys: name, severity, rule_id, conditions.
            source_decorators: List of decorator patterns that mark a function's args
                as tainted (e.g. route decorators like 'app.route', 'app.get').
            symbol_table: Optional global symbol table for inter-procedural taint across
                modules/files.
            max_call_depth: Max inter-procedural call depth when using symbol_table.
        """
        self.sources: Set[str] = set(sources)
        self.sinks: Set[str] = set(sinks)
        self.sanitizers: Set[str] = set(sanitizers or [])
        self.conditional_sinks: List[Dict[str, Any]] = conditional_sinks or []
        self.source_decorators: List[str] = source_decorators or []
        self.vulnerabilities: List[Finding] = []

        # Cache for inter-procedural return taint computation:
        # key: (file_path, func_name, frozenset(tainted_param_names)) -> bool
        self._return_taint_cache: Dict[Tuple[str, str, frozenset], bool] = {}

        # Cache for inter-procedural analyses to avoid duplicate findings.
        # key: (file_path, func_name, frozenset(tainted_param_names))
        self._analysis_cache: Set[Tuple[str, str, frozenset]] = set()

        # Instance attribute taint tracking:
        # key: instance_name (e.g. 'self'), value: set of tainted attribute names
        self._instance_taints: Dict[str, Set[str]] = {}

        # current context
        self._current_file: str = ""

        # import_map for the file currently being analysed:
        # { local_name -> absolute_qualname }  e.g. {"get_cmd": "utils.get_cmd"}
        # Built fresh in analyze_cfg() so it always matches the caller file.
        self._import_map: Dict[str, str] = {}

        self.symbol_table = symbol_table
        self._ip: Optional["InterproceduralTaintTracker"] = None
        if symbol_table is not None and InterproceduralTaintTracker is not None:
            self._ip = InterproceduralTaintTracker(
                symbol_table, max_depth=max_call_depth
            )

    def _call_id(self, file_path: str, fn_name: str) -> str:
        return f"{os.path.abspath(file_path)}::{fn_name}"

    def _build_import_map(self, filepath: str) -> Dict[str, str]:
        """Parse import statements in *filepath* and return a mapping
        ``{local_name -> absolute_qualname}``.

        Examples::

            from utils import get_cmd        -> {"get_cmd": "utils.get_cmd"}
            from utils import get_cmd as gc  -> {"gc":      "utils.get_cmd"}
            import utils                     -> {"utils":   "utils"}          (module alias)
            import utils as u                -> {"u":       "utils"}
            import pkg.mod as m              -> {"m":       "pkg.mod"}

        The result is used to resolve calls that are not in the local fnmap so
        that we can look them up in the GlobalSymbolTable and propagate taint
        across file boundaries.
        """
        # Delegate to _ip's cached parser when available to avoid double I/O.
        if self._ip is not None:
            _mod_aliases, _name_aliases = self._ip._parse_imports(filepath)
            result: Dict[str, str] = {}
            result.update(_name_aliases)  # local -> full qualname  (from x import y)
            result.update(_mod_aliases)  # local -> module name    (import x as y)
            return result

        # Fallback: parse ourselves (no symbol_table configured).
        result = {}
        try:
            with open(os.path.abspath(filepath), "r", encoding="utf-8") as fh:
                src = fh.read()
            tree = ast.parse(src, filename=filepath)
        except Exception:
            return result
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[-1]
                    result[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if (
                    node.level
                    and self.symbol_table is not None
                    and GlobalSymbolTable is not None
                ):
                    mod = GlobalSymbolTable._resolve_relative_module(
                        os.path.abspath(filepath),
                        mod,
                        node.level,
                        root_dir=self.symbol_table.root_dir,
                    )
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    full = f"{mod}.{alias.name}" if mod else alias.name
                    result[local] = full
        return result

    def analyze_cfg(self, cfg: Dict[str, Any], filepath: str):
        """Perform taint tracking for a single file's extracted CFG.

        The parser may return either:
            - legacy form: {func: [stmts...]}
            - metadata form: {func: {body,args,decorators,routes,calls}}
        """
        self._current_file = filepath

        fnmap: Dict[str, _FnContext] = {}

        for fn_name, meta in cfg.items():
            if isinstance(meta, list):
                fnmap[fn_name] = _FnContext(name=fn_name, body=meta, args=[], meta={})
            elif isinstance(meta, dict):
                fnmap[fn_name] = _FnContext(
                    name=fn_name,
                    body=meta.get("body", []) or [],
                    args=meta.get("args", []) or [],
                    meta=meta,
                )

        # Reset instance taints for this CFG analysis
        self._instance_taints = {}

        # Build import_map for this file so that calls to imported functions
        # (not present in local fnmap) can be resolved to their absolute
        # qualnames and looked up in the GlobalSymbolTable.
        self._import_map = self._build_import_map(filepath)

        # Build method->class_name map from GlobalSymbolTable for this file.
        # CFG keys are bare method names (e.g. 'handle'), but ST keys are
        # 'module.ClassName.method'. We need this to resolve self.method() calls.
        # _method_class_map: { bare_method_name -> class_name }
        self._method_class_map: Dict[str, str] = {}
        if self.symbol_table is not None:
            abs_filepath = os.path.abspath(filepath)
            for qualname, sym in self.symbol_table.functions.items():
                if os.path.abspath(sym.file_path) != abs_filepath:
                    continue
                parts = qualname.split(".")
                # qualname format: module.ClassName.method  (len >= 3)
                # or ClassName.method  (len == 2)
                if len(parts) >= 2:
                    self._method_class_map[parts[-1]] = parts[-2]

        for fn_name, fnctx in fnmap.items():
            # Seed taint: if the function has a parameter named like a source root
            # (e.g. request), consider it tainted.
            tainted_vars: Set[str] = set()
            for arg in fnctx.args:
                if arg in self.sources:
                    tainted_vars.add(arg)

            # Framework-aware: if function is decorated with a route decorator,
            # use the framework modeler to determine exactly which params are tainted.
            # Falls back to all non-self args when no modeler returns a specific list.
            if self._fn_has_route_decorator(fnctx, fnctx.meta):
                from pyaegis.frameworks.registry import (
                    get_tainted_params as _get_tainted_params,
                )

                func_meta = fnctx.meta if isinstance(fnctx.meta, dict) else {}
                precise = _get_tainted_params(func_meta)
                if precise:
                    tainted_vars.update(precise)
                else:
                    # No framework override — taint all non-self args (safe fallback)
                    for arg in fnctx.args:
                        if arg != "self":
                            tainted_vars.add(arg)

            # FastAPI Depends() injection: treat Depends parameters as tainted sources
            # (already handled by FastAPIModeler.get_tainted_params; kept here as an
            # explicit belt-and-suspenders pass for any non-FastAPI Depends patterns).
            if isinstance(fnctx.meta, dict):
                for dep in fnctx.meta.get("source_params", []) or []:
                    if dep != "self":
                        tainted_vars.add(dep)

            self._analyze_function(
                fnctx=fnctx,
                fnmap=fnmap,
                filepath=filepath,
                tainted_vars=tainted_vars,
                tainted_params=set(),
                callstack=[self._call_id(filepath, fn_name)],
            )

    def _fn_has_route_decorator(self, fnctx: _FnContext, meta: Any) -> bool:
        """Return True if the function has a web route decorator.

        Delegates to the framework plugin registry for built-in framework
        patterns (Flask, FastAPI, ...).  Falls back to matching
        ``self.source_decorators`` for any user-supplied extra patterns.
        """
        from pyaegis.frameworks.registry import is_route_function as _registry_check

        func_meta: Dict[str, Any] = meta if isinstance(meta, dict) else {}

        # Check via plugin registry (covers Flask, FastAPI, etc.)
        if _registry_check(func_meta):
            return True

        # Fallback: user-supplied source_decorators
        if self.source_decorators:
            decorators = func_meta.get("decorators", []) or []
            for dec in decorators:
                dec_str = str(dec)
                for pat in self.source_decorators:
                    if fnmatch.fnmatch(dec_str, pat) or dec_str == pat:
                        return True

        return False

    def _matches_any(self, name: str, patterns: Set[str]) -> bool:
        for p in patterns:
            if p == name:
                return True
            if any(ch in p for ch in "*?[]") and fnmatch.fnmatch(name, p):
                return True
        return False

    def _get_full_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_full_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._get_full_name(node.func)
        if isinstance(node, ast.Subscript):
            return self._get_full_name(node.value)
        return ""

    def _is_source_expr(self, expr: ast.AST) -> bool:
        """Determine whether an expression should be considered tainted."""
        full = self._get_full_name(expr)
        if full and self._matches_any(full, self.sources):
            return True

        if isinstance(expr, ast.Call):
            fn = self._get_full_name(expr.func)
            if fn and self._matches_any(fn, self.sources):
                return True
            root = expr.func
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in self.sources:
                return True

        return False

    def _is_sanitizer_call(self, expr: ast.AST) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        fn = self._get_full_name(expr.func)
        return bool(fn) and self._matches_any(fn, self.sanitizers)

    def _map_call_tainted_params(
        self,
        call: ast.Call,
        callee_args: List[str],
        tainted_vars: Set[str],
        fnmap: Dict[str, _FnContext],
        callstack: List[str],
        tainted_params: Set[str],
    ) -> Set[str]:
        callee_tainted_params: Set[str] = set()
        for i, a in enumerate(call.args):
            if i < len(callee_args) and self._is_tainted_expr(
                a, tainted_vars, fnmap, callstack, tainted_params
            ):
                callee_tainted_params.add(callee_args[i])
        for kw in call.keywords:
            if kw.arg and kw.arg in callee_args:
                if self._is_tainted_expr(
                    kw.value, tainted_vars, fnmap, callstack, tainted_params
                ):
                    callee_tainted_params.add(kw.arg)
        return callee_tainted_params

    def _build_fnmap_for_file(self, file_path: str) -> Dict[str, _FnContext]:
        if self.symbol_table is None:
            return {}
        out: Dict[str, _FnContext] = {}
        for name, sym in self.symbol_table.functions_in_file(file_path).items():
            try:
                body = list(getattr(sym.node, "body", []) or [])
                args = list(sym.args)
            except Exception:
                continue
            out[name] = _FnContext(name=name, body=body, args=args, meta={})
        return out

    def _analyze_symbol_if_needed(
        self,
        sym: "FunctionSymbol",
        tainted_params: Set[str],
        callstack: List[str],
    ) -> None:
        if not tainted_params:
            return
        key = (os.path.abspath(sym.file_path), sym.name, frozenset(tainted_params))
        if key in self._analysis_cache:
            return

        # depth guard
        if self._ip is not None and len(callstack) >= self._ip.max_depth:
            return

        self._analysis_cache.add(key)

        prev_file = self._current_file
        try:
            self._current_file = sym.file_path
            fnmap = self._build_fnmap_for_file(sym.file_path)
            fnctx = fnmap.get(sym.name)
            if fnctx is None:
                fnctx = _FnContext(
                    name=sym.name,
                    body=list(getattr(sym.node, "body", []) or []),
                    args=list(sym.args),
                    meta={},
                )
                fnmap[sym.name] = fnctx

            seeded: Set[str] = set(tainted_params)
            # If the callee uses a known source-root param name (e.g. request), keep behavior.
            for arg in fnctx.args:
                if arg in self.sources:
                    seeded.add(arg)

            self._analyze_function(
                fnctx=fnctx,
                fnmap=fnmap,
                filepath=sym.file_path,
                tainted_vars=seeded,
                tainted_params=set(tainted_params),
                callstack=callstack + [self._call_id(sym.file_path, sym.name)],
            )
        finally:
            self._current_file = prev_file

    def _resolve_self_method_symbol(
        self,
        inst_name: str,
        method_name: str,
        fnctx: _FnContext,
    ) -> "Optional[FunctionSymbol]":
        """Try to resolve ``inst_name.method_name()`` to a FunctionSymbol.

        Strategy:
        1. If ``inst_name == 'self'``, infer the class name from the current
           function's qualname stored in ``fnctx.name``.
           qualname formats produced by GlobalSymbolTable:
             - ``module.ClassName.method``  (full)
             - ``ClassName.method``         (short key)
           We take the second-to-last component as the class name.
        2. Look up ``ClassName.method_name`` and
           ``module.ClassName.method_name`` in the GlobalSymbolTable.
        3. For non-self instance variables we skip (class unknown at static
           analysis time without type inference).
        """
        if self.symbol_table is None:
            return None

        # Only handle 'self' for now; other instance vars need type inference.
        if inst_name != "self":
            return None

        # Infer class name from fnctx.name, e.g.:
        #   "mymod.MyClass.handle"  -> class_name = "MyClass"
        #   "MyClass.handle"        -> class_name = "MyClass"
        #   "handle"                -> fall back to _method_class_map
        parts = fnctx.name.split(".")
        if len(parts) >= 2:
            class_name = parts[-2]  # second-to-last component
        else:
            # CFG keys are bare method names; use the map built in analyze_cfg
            class_name = getattr(self, "_method_class_map", {}).get(method_name, "")
            if not class_name:
                # Also try looking up the caller's own name in the map
                class_name = getattr(self, "_method_class_map", {}).get(fnctx.name, "")
            if not class_name:
                return None

        # Try short key first: ClassName.method_name
        short_key = f"{class_name}.{method_name}"
        sym = self.symbol_table.get(short_key)
        if sym is not None:
            return sym

        # Try full qualname: derive module prefix from fnctx.name
        if len(parts) >= 3:
            module_prefix = ".".join(parts[:-2])
            full_key = f"{module_prefix}.{class_name}.{method_name}"
            sym = self.symbol_table.get(full_key)
            if sym is not None:
                return sym

        # Last resort: search by bare method name (unique only)
        cands = self.symbol_table.get_by_name(method_name)
        # Filter to same class if possible
        class_cands = [s for s in cands if class_name in s.qualname]
        if len(class_cands) == 1:
            return class_cands[0]
        if len(cands) == 1:
            return cands[0]

        return None

    def _is_tainted_expr(
        self,
        expr: ast.AST,
        tainted_vars: Set[str],
        fnmap: Dict[str, _FnContext],
        callstack: List[str],
        tainted_params: Set[str],
    ) -> bool:
        """Compute if an expression is tainted."""
        if expr is None:
            return False

        if isinstance(expr, ast.Name):
            return expr.id in tainted_vars

        if isinstance(expr, ast.Constant):
            return False

        if isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    if self._is_tainted_expr(
                        v.value, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        return True
            return False

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            return self._is_tainted_expr(
                expr.left, tainted_vars, fnmap, callstack, tainted_params
            ) or self._is_tainted_expr(
                expr.right, tainted_vars, fnmap, callstack, tainted_params
            )

        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(
                self._is_tainted_expr(e, tainted_vars, fnmap, callstack, tainted_params)
                for e in expr.elts
            )

        if isinstance(expr, ast.Dict):
            return any(
                self._is_tainted_expr(k, tainted_vars, fnmap, callstack, tainted_params)
                or self._is_tainted_expr(
                    v, tainted_vars, fnmap, callstack, tainted_params
                )
                for k, v in zip(expr.keys, expr.values)
                if k is not None and v is not None
            )

        if isinstance(expr, ast.IfExp):
            return self._is_tainted_expr(
                expr.body, tainted_vars, fnmap, callstack, tainted_params
            ) or self._is_tainted_expr(
                expr.orelse, tainted_vars, fnmap, callstack, tainted_params
            )

        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if self._is_tainted_expr(
                expr.elt, tainted_vars, fnmap, callstack, tainted_params
            ):
                return True
            for gen in expr.generators:
                if self._is_tainted_expr(
                    gen.iter, tainted_vars, fnmap, callstack, tainted_params
                ):
                    return True
                for if_expr in gen.ifs:
                    if self._is_tainted_expr(
                        if_expr, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        return True
            return False

        if isinstance(expr, ast.DictComp):
            if self._is_tainted_expr(
                expr.key, tainted_vars, fnmap, callstack, tainted_params
            ) or self._is_tainted_expr(
                expr.value, tainted_vars, fnmap, callstack, tainted_params
            ):
                return True
            for gen in expr.generators:
                if self._is_tainted_expr(
                    gen.iter, tainted_vars, fnmap, callstack, tainted_params
                ):
                    return True
                for if_expr in gen.ifs:
                    if self._is_tainted_expr(
                        if_expr, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        return True
            return False

        if isinstance(expr, ast.Attribute):
            # Attribute expressions can themselves be configured as sources
            # (e.g. "request.data"). We must check this *before* recursing into
            # the base Name; otherwise global framework objects imported into the
            # module scope ("from flask import request") won't be recognized.
            if self._is_source_expr(expr):
                return True

            base = expr.value
            if isinstance(base, ast.Name):
                inst_name = base.id
                attr_name = expr.attr
                if (
                    inst_name in self._instance_taints
                    and attr_name in self._instance_taints[inst_name]
                ):
                    return True
            return self._is_tainted_expr(
                base, tainted_vars, fnmap, callstack, tainted_params
            )

        if isinstance(expr, ast.Subscript):
            return self._is_tainted_expr(
                expr.value, tainted_vars, fnmap, callstack, tainted_params
            )

        if self._is_sanitizer_call(expr):
            return False

        if self._is_source_expr(expr):
            return True

        if isinstance(expr, ast.Call):
            fn = self._get_full_name(expr.func)
            if fn and self._matches_any(fn, self.sanitizers):
                return False

            # Inter-procedural: self.method() instance call resolution.
            # Pattern: self.process(tainted_arg) inside a class method.
            # We infer the class from the current fnctx qualname and look up
            # ClassName.method in the GlobalSymbolTable.
            if fn and "." in fn and self.symbol_table is not None and fn not in fnmap:
                inst_part, _, meth_part = fn.partition(".")
                # Only handle single-level attribute calls (self.foo, not a.b.c)
                if "." not in meth_part:
                    # We need the current fnctx to infer class name; pass a dummy
                    # that carries the current function's qualname. We retrieve it
                    # from _analyze_function via a thread-local-style attribute set
                    # below in _analyze_function. Here we fall back to fnmap keys
                    # to find a context that contains the right class segment.
                    _sym = None
                    # Try all fnctx entries that look like ClassName.meth
                    for _fn_key, _fnc in fnmap.items():
                        candidate = self._resolve_self_method_symbol(
                            inst_part, meth_part, _fnc
                        )
                        if candidate is not None:
                            _sym = candidate
                            break
                    if _sym is not None:
                        callee_tainted_params = self._map_call_tainted_params(
                            expr,
                            list(_sym.args),
                            tainted_vars,
                            fnmap,
                            callstack,
                            tainted_params,
                        )
                        max_d = self._ip.max_depth if self._ip is not None else 3
                        if len(callstack) < max_d:
                            if callee_tainted_params:
                                self._analyze_symbol_if_needed(
                                    _sym, callee_tainted_params, callstack
                                )
                            ext_fnmap = self._build_fnmap_for_file(_sym.file_path)
                            return self._function_returns_tainted(
                                fn=_sym.name,
                                fnmap=ext_fnmap
                                or {
                                    _sym.name: _FnContext(
                                        _sym.name,
                                        list(getattr(_sym.node, "body", []) or []),
                                        list(_sym.args),
                                        meta={},
                                    )
                                },
                                filepath=_sym.file_path,
                                tainted_params=callee_tainted_params,
                                callstack=callstack,
                            )

            # Inter-procedural: local function
            if fn in fnmap:
                callee = fnmap[fn]
                callee_tainted_params = self._map_call_tainted_params(
                    expr, callee.args, tainted_vars, fnmap, callstack, tainted_params
                )
                return self._function_returns_tainted(
                    fn=fn,
                    fnmap=fnmap,
                    filepath=self._current_file,
                    tainted_params=callee_tainted_params,
                    callstack=callstack,
                )

            # Inter-procedural: import_map resolution.
            # When the local fnmap has no entry for `fn`, check if it was
            # imported into this file.  The import_map was built by
            # _build_import_map() in analyze_cfg() and maps
            #   local_name -> absolute_qualname  (e.g. "get_cmd" -> "utils.get_cmd")
            # We resolve it against the GlobalSymbolTable directly, bypassing
            # the need for an ast.Call walk inside InterproceduralTaintTracker.
            if fn and self._import_map and self.symbol_table is not None:
                qualname = self._import_map.get(fn)
                # Also handle dotted calls like  u.get_data  where  u -> utils
                if qualname is None and "." in fn:
                    head, rest = fn.split(".", 1)
                    mod_qualname = self._import_map.get(head)
                    if mod_qualname is not None:
                        qualname = f"{mod_qualname}.{rest}"
                if qualname is not None:
                    sym = self.symbol_table.get(qualname)
                    if sym is None:
                        # Try by bare function name if unique
                        bare = qualname.split(".")[-1]
                        cands = self.symbol_table.get_by_name(bare)
                        if len(cands) == 1:
                            sym = cands[0]
                    if sym is not None:
                        callee_tainted_params = self._map_call_tainted_params(
                            expr,
                            list(sym.args),
                            tainted_vars,
                            fnmap,
                            callstack,
                            tainted_params,
                        )
                        max_d = self._ip.max_depth if self._ip is not None else 3
                        if len(callstack) < max_d:
                            if callee_tainted_params:
                                self._analyze_symbol_if_needed(
                                    sym, callee_tainted_params, callstack
                                )
                            ext_fnmap = self._build_fnmap_for_file(sym.file_path)
                            if not ext_fnmap:
                                ext_fnmap = {
                                    sym.name: _FnContext(
                                        sym.name,
                                        list(getattr(sym.node, "body", []) or []),
                                        list(sym.args),
                                        meta={},
                                    )
                                }
                            return self._function_returns_tainted(
                                fn=sym.name,
                                fnmap=ext_fnmap,
                                filepath=sym.file_path,
                                tainted_params=callee_tainted_params,
                                callstack=callstack,
                            )

            # Inter-procedural: cross-module via global symbol table
            if self._ip is not None:
                sym = self._ip.resolve_symbol(expr, caller_file=self._current_file)
                if sym is not None:
                    callee_tainted_params = self._map_call_tainted_params(
                        expr,
                        list(sym.args),
                        tainted_vars,
                        fnmap,
                        callstack,
                        tainted_params,
                    )

                    # When we can resolve the callee symbol, try to compute its return taint
                    # even if no arguments are tainted. This enables propagation for helpers
                    # that fetch taint sources internally (e.g. input(), os.getenv()).
                    if len(callstack) < self._ip.max_depth:
                        if callee_tainted_params:
                            self._analyze_symbol_if_needed(
                                sym, callee_tainted_params, callstack
                            )

                        ext_fnmap = self._build_fnmap_for_file(sym.file_path)
                        return self._function_returns_tainted(
                            fn=sym.name,
                            fnmap=ext_fnmap
                            or {
                                sym.name: _FnContext(
                                    sym.name,
                                    list(getattr(sym.node, "body", []) or []),
                                    list(sym.args),
                                    meta={},
                                )
                            },
                            filepath=sym.file_path,
                            tainted_params=callee_tainted_params,
                            callstack=callstack,
                        )

                    # If depth exceeded, fall back to heuristic.
                    if any(
                        self._is_tainted_expr(
                            a, tainted_vars, fnmap, callstack, tainted_params
                        )
                        for a in expr.args
                    ):
                        return True
                    for kw in expr.keywords:
                        if kw.value and self._is_tainted_expr(
                            kw.value, tainted_vars, fnmap, callstack, tainted_params
                        ):
                            return True
                    return False

            # Unknown calls: heuristic — tainted args taint the return value
            if any(
                self._is_tainted_expr(a, tainted_vars, fnmap, callstack, tainted_params)
                for a in expr.args
            ):
                return True
            for kw in expr.keywords:
                if kw.value and self._is_tainted_expr(
                    kw.value, tainted_vars, fnmap, callstack, tainted_params
                ):
                    return True

        return False

    def _taint_unpack_target(
        self,
        target: ast.AST,
        tainted_vars: Set[str],
        is_tainted: bool,
        is_clean: bool,
    ) -> None:
        """Recursively taint or clean all names in an unpack target (Tuple/List/Starred)."""
        if isinstance(target, ast.Name):
            if is_clean:
                tainted_vars.discard(target.id)
            elif is_tainted:
                tainted_vars.add(target.id)
        elif isinstance(target, ast.Starred):
            self._taint_unpack_target(target.value, tainted_vars, is_tainted, is_clean)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._taint_unpack_target(elt, tainted_vars, is_tainted, is_clean)

    def _record_instance_attr_taint(
        self,
        target: ast.AST,
        is_tainted: bool,
        is_clean: bool,
    ) -> None:
        """If target is `self.attr` (or any instance.attr), update _instance_taints."""
        if not isinstance(target, ast.Attribute):
            return
        if not isinstance(target.value, ast.Name):
            return
        inst_name = target.value.id
        attr_name = target.attr
        if is_clean:
            if inst_name in self._instance_taints:
                self._instance_taints[inst_name].discard(attr_name)
        elif is_tainted:
            if inst_name not in self._instance_taints:
                self._instance_taints[inst_name] = set()
            self._instance_taints[inst_name].add(attr_name)

    def _analyze_function(
        self,
        fnctx: _FnContext,
        fnmap: Dict[str, _FnContext],
        filepath: str,
        tainted_vars: Set[str],
        tainted_params: Set[str],
        callstack: List[str],
    ) -> None:
        """Analyze a single function body, updating vulnerabilities."""
        prev_file = self._current_file
        self._current_file = filepath
        try:
            mod = ast.Module(body=fnctx.body, type_ignores=[])
            for node in ast.walk(mod):
                if isinstance(node, ast.Assign):
                    value = node.value
                    is_clean = self._is_sanitizer_call(value)
                    is_tainted = self._is_tainted_expr(
                        value, tainted_vars, fnmap, callstack, tainted_params
                    )

                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if is_clean:
                                tainted_vars.discard(target.id)
                            elif is_tainted:
                                tainted_vars.add(target.id)
                        elif isinstance(target, (ast.Tuple, ast.List)):
                            self._taint_unpack_target(
                                target, tainted_vars, is_tainted, is_clean
                            )
                        elif isinstance(target, ast.Attribute):
                            self._record_instance_attr_taint(
                                target, is_tainted, is_clean
                            )

                if isinstance(node, ast.AnnAssign) and isinstance(
                    node.target, ast.Name
                ):
                    value = node.value
                    if value is None:
                        continue
                    if self._is_sanitizer_call(value):
                        tainted_vars.discard(node.target.id)
                    elif self._is_tainted_expr(
                        value, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        tainted_vars.add(node.target.id)

                if isinstance(node, ast.AugAssign) and isinstance(
                    node.target, ast.Name
                ):
                    if self._is_tainted_expr(
                        node.value, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        tainted_vars.add(node.target.id)

                if isinstance(node, ast.Call):
                    sink_name = self._get_full_name(node.func)

                    # --- Inter-procedural sink propagation ---
                    # For non-sink calls, if any arg is tainted and we can resolve
                    # the callee cross-module, analyze it for sinks (e.g. execute(cmd)).
                    if (
                        sink_name
                        and not self._matches_any(sink_name, self.sinks)
                        and len(callstack)
                        < (self._ip.max_depth if self._ip is not None else 3)
                    ):
                        # Only bother if at least one arg is tainted
                        if self._call_has_tainted_arg(
                            node, tainted_vars, fnmap, callstack, tainted_params
                        ):
                            # Local fnmap first
                            if sink_name not in fnmap:
                                sym = None
                                # Primary: resolve via _ip (handles import aliases)
                                if self._ip is not None:
                                    sym = self._ip.resolve_symbol(
                                        node, caller_file=self._current_file
                                    )
                                # self.method() instance call resolution
                                _self_method_sym = (
                                    False  # flag: skip self arg in mapping
                                )
                                if (
                                    sym is None
                                    and sink_name
                                    and "." in sink_name
                                    and self.symbol_table is not None
                                ):
                                    _inst, _, _meth = sink_name.partition(".")
                                    if "." not in _meth:
                                        for _fnc in fnmap.values():
                                            _candidate = (
                                                self._resolve_self_method_symbol(
                                                    _inst, _meth, _fnc
                                                )
                                            )
                                            if _candidate is not None:
                                                sym = _candidate
                                                _self_method_sym = True
                                                break
                                # Fallback: resolve via import_map directly
                                if (
                                    sym is None
                                    and self._import_map
                                    and self.symbol_table is not None
                                ):
                                    qualname = self._import_map.get(sink_name)
                                    if qualname is None and "." in sink_name:
                                        head, rest = sink_name.split(".", 1)
                                        mod_q = self._import_map.get(head)
                                        if mod_q is not None:
                                            qualname = f"{mod_q}.{rest}"
                                    if qualname is not None:
                                        sym = self.symbol_table.get(qualname)
                                        if sym is None:
                                            bare = qualname.split(".")[-1]
                                            cands = self.symbol_table.get_by_name(bare)
                                            if len(cands) == 1:
                                                sym = cands[0]
                                if sym is not None:
                                    # For self.method() calls, skip the implicit
                                    # 'self' parameter when mapping positional args.
                                    _callee_args = list(sym.args)
                                    if (
                                        _self_method_sym
                                        and _callee_args
                                        and _callee_args[0] == "self"
                                    ):
                                        _callee_args = _callee_args[1:]
                                    callee_tp = self._map_call_tainted_params(
                                        node,
                                        _callee_args,
                                        tainted_vars,
                                        fnmap,
                                        callstack,
                                        tainted_params,
                                    )
                                    self._analyze_symbol_if_needed(
                                        sym, callee_tp, callstack
                                    )
                            else:
                                # Local callee: recurse analyze for intra-procedural sinks
                                callee = fnmap[sink_name]
                                callee_tp = self._map_call_tainted_params(
                                    node,
                                    callee.args,
                                    tainted_vars,
                                    fnmap,
                                    callstack,
                                    tainted_params,
                                )
                                if callee_tp:
                                    call_id = self._call_id(filepath, sink_name)
                                    if call_id not in callstack:
                                        self._analyze_function(
                                            fnctx=callee,
                                            fnmap=fnmap,
                                            filepath=filepath,
                                            tainted_vars=set(callee_tp),
                                            tainted_params=callee_tp,
                                            callstack=callstack + [call_id],
                                        )

                    if sink_name and self._matches_any(sink_name, self.sinks):
                        if self._call_has_tainted_arg(
                            node, tainted_vars, fnmap, callstack, tainted_params
                        ):
                            cs_match = (
                                _check_conditional_sink(
                                    sink_name, node, self.conditional_sinks, filepath
                                )
                                if self.conditional_sinks
                                else None
                            )

                            has_cond_entry = any(
                                cs.get("name", "") == sink_name
                                or (
                                    any(ch in cs.get("name", "") for ch in "*?[]")
                                    and fnmatch.fnmatch(sink_name, cs.get("name", ""))
                                )
                                for cs in self.conditional_sinks
                            )

                            if has_cond_entry and cs_match is None:
                                pass
                            else:
                                rule_id = _rule_id_for_sink(sink_name)
                                sev = "CRITICAL"
                                if cs_match:
                                    rule_id = cs_match.get("rule_id", rule_id)
                                    sev = cs_match.get("severity", sev)
                                else:
                                    r = get_rule(rule_id)
                                    if r is not None:
                                        sev = r.severity
                                self.vulnerabilities.append(
                                    Finding(
                                        rule_id=rule_id,
                                        description=f"Tainted data reaches sink: {sink_name}",
                                        file_path=filepath,
                                        line_number=getattr(node, "lineno", 0),
                                        sink_context=fnctx.name,
                                        severity=sev,
                                        sink_name=sink_name,
                                    )
                                )
        finally:
            self._current_file = prev_file

    def _call_has_tainted_arg(
        self,
        call: ast.Call,
        tainted_vars: Set[str],
        fnmap: Dict[str, _FnContext],
        callstack: List[str],
        tainted_params: Set[str],
    ) -> bool:
        for a in call.args:
            if self._is_tainted_expr(a, tainted_vars, fnmap, callstack, tainted_params):
                return True
        for kw in call.keywords:
            if kw.value and self._is_tainted_expr(
                kw.value, tainted_vars, fnmap, callstack, tainted_params
            ):
                return True
        return False

    def _function_returns_tainted(
        self,
        fn: str,
        fnmap: Dict[str, _FnContext],
        filepath: str,
        tainted_params: Set[str],
        callstack: List[str],
    ) -> bool:
        """Determine whether function returns tainted, given tainted params."""
        abspath = os.path.abspath(filepath or self._current_file or "")
        key = (abspath, fn, frozenset(tainted_params))
        if key in self._return_taint_cache:
            return self._return_taint_cache[key]

        call_id = self._call_id(abspath or "<unknown>", fn)
        if call_id in callstack:
            return False

        fnctx = fnmap.get(fn)
        if fnctx is None:
            return False

        local_tainted: Set[str] = set(tainted_params)

        returns_tainted = False
        mod = ast.Module(body=fnctx.body, type_ignores=[])
        for node in ast.walk(mod):
            if isinstance(node, ast.Assign):
                value = node.value
                if self._is_sanitizer_call(value):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            local_tainted.discard(t.id)
                elif self._is_tainted_expr(
                    value, local_tainted, fnmap, callstack + [call_id], tainted_params
                ):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            local_tainted.add(t.id)
                        elif isinstance(t, (ast.Tuple, ast.List)):
                            self._taint_unpack_target(t, local_tainted, True, False)
            elif isinstance(node, ast.Return):
                if node.value is not None and self._is_tainted_expr(
                    node.value,
                    local_tainted,
                    fnmap,
                    callstack + [call_id],
                    tainted_params,
                ):
                    returns_tainted = True

        self._return_taint_cache[key] = returns_tainted
        return returns_tainted

    def get_findings(self) -> List[Finding]:
        return self.vulnerabilities
