import ast
import fnmatch
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from pyaegis.models import Finding
from pyaegis.rules_catalog import get_rule


# Mapping from sink patterns to stable rule IDs.
# Keep this simple and conservative: if a sink matches multiple groups,
# the first match in order wins.
_RULE_GROUPS: List[Tuple[str, List[str]]] = [
    ("PYA-003", ["eval", "exec", "compile", "builtins.eval", "builtins.exec", "runpy.*"]),
    ("PYA-001", ["os.system", "os.popen", "os.spawn*", "subprocess.*", "commands.getoutput"]),
    ("PYA-004", [
        "pickle.load",
        "pickle.loads",
        "cPickle.loads",
        "dill.loads",
        "marshal.loads",
        "yaml.load",
        "yaml.unsafe_load",
        "ruamel.yaml.load",
        "jsonpickle.decode",
    ]),
    ("PYA-005", [
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
    ]),
    ("PYA-006", [
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
    ]),
    ("PYA-002", [
        "sqlite3.Connection.execute",
        "sqlite3.Cursor.execute",
        "sqlite3.Cursor.executemany",
        "psycopg2.connect",
        "psycopg2.cursor.execute",
        "MySQLdb.connect",
        "pymysql.connect",
        "sqlalchemy.text",
    ]),
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
    import re
    # Normalize separators
    normalized = filepath.replace("\\", "/")
    # Check directory components
    parts = normalized.split("/")
    for part in parts[:-1]:  # directory parts
        if part in ("tests", "testing", "test"):
            return True
    # Check filename
    filename = parts[-1]
    if filename.startswith("test_") or filename.endswith("_test.py"):
        return True
    return False


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
                            if isinstance(kw.value, ast.Constant) and kw.value.value == kw_val:
                                found = True
                            break
                    if not found:
                        all_pass = False
                        break
            if "not_in_test_file" in cond:
                if cond["not_in_test_file"] and _is_test_filepath(filepath):
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


class TaintTracker:
    """Simple taint analysis engine.

    Enhancements vs the baseline implementation:
    - Inter-procedural propagation (cross-function calls) within a parsed file.
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
        """
        self.sources: Set[str] = set(sources)
        self.sinks: Set[str] = set(sinks)
        self.sanitizers: Set[str] = set(sanitizers or [])
        self.conditional_sinks: List[Dict[str, Any]] = conditional_sinks or []
        self.source_decorators: List[str] = source_decorators or []
        self.vulnerabilities: List[Finding] = []

        # Cache for inter-procedural return taint computation:
        # key: (func_name, frozenset(tainted_param_names)) -> bool(return_tainted)
        self._return_taint_cache: Dict[Tuple[str, frozenset], bool] = {}

        # Cache for inter-procedural analysis to avoid repeat walks
        self._analysis_cache: Set[Tuple[str, frozenset]] = set()

        # Instance attribute taint tracking:
        # key: instance_name (e.g. 'self'), value: set of tainted attribute names
        self._instance_taints: Dict[str, Set[str]] = {}

    def analyze_cfg(self, cfg: Dict[str, Any], filepath: str):
        """Perform taint tracking for a single file's extracted CFG.

        The parser may return either:
            - legacy form: {func: [stmts...]}
            - metadata form: {func: {body,args,decorators,routes,calls}}
        """
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
        self._analysis_cache = set()

        for fn_name, fnctx in fnmap.items():
            # Seed taint: if the function has a parameter named like a source root
            # (e.g. request), consider it tainted.
            tainted_vars: Set[str] = set()
            for arg in fnctx.args:
                if arg in self.sources:
                    tainted_vars.add(arg)

            # Framework-aware: if function is decorated with a route decorator,
            # all its args are considered tainted (they come from HTTP requests).
            if self._fn_has_route_decorator(fnctx, fnctx.meta):
                for arg in fnctx.args:
                    if arg != "self":
                        tainted_vars.add(arg)

            self._analyze_function(
                fnctx=fnctx,
                fnmap=fnmap,
                filepath=filepath,
                tainted_vars=tainted_vars,
                tainted_params=set(),
                callstack=[fn_name],
            )

    def _fn_has_route_decorator(self, fnctx: _FnContext, meta: Any) -> bool:
        """Return True if the function has a web route decorator."""
        # Built-in route decorator patterns to always check
        _ROUTE_PATTERNS = [
            "*.route", "*.get", "*.post", "*.put", "*.delete",
            "*.patch", "*.head", "*.options",
        ]
        routes = []
        if isinstance(meta, dict):
            routes = meta.get("routes", []) or []
        if routes:
            return True
        # Also check source_decorators passed by user
        decorators = []
        if isinstance(meta, dict):
            decorators = meta.get("decorators", []) or []
        all_patterns = _ROUTE_PATTERNS + self.source_decorators
        for dec in decorators:
            dec_str = str(dec)
            for pat in all_patterns:
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
        # request.args / request.GET / request.form ...
        full = self._get_full_name(expr)
        if full and self._matches_any(full, self.sources):
            return True

        # Calls: input(), request.get_json(), request.args.get(), etc.
        if isinstance(expr, ast.Call):
            fn = self._get_full_name(expr.func)
            if fn and self._matches_any(fn, self.sources):
                return True
            # if the root object of the call is a known source root (request)
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

        # Direct name lookup
        if isinstance(expr, ast.Name):
            return expr.id in tainted_vars

        # Constants are not tainted
        if isinstance(expr, ast.Constant):
            return False

        # f"{x}" / JoinedStr
        if isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    if self._is_tainted_expr(
                        v.value, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        return True
            return False

        # String concatenation / binary ops
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            return self._is_tainted_expr(
                expr.left, tainted_vars, fnmap, callstack, tainted_params
            ) or self._is_tainted_expr(
                expr.right, tainted_vars, fnmap, callstack, tainted_params
            )

        # Containers: if any element tainted
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

        # Instance attribute read: self.attr - check _instance_taints
        if isinstance(expr, ast.Attribute):
            base = expr.value
            # Check instance attribute taint tracking (e.g. self.data)
            if isinstance(base, ast.Name):
                inst_name = base.id
                attr_name = expr.attr
                if inst_name in self._instance_taints and attr_name in self._instance_taints[inst_name]:
                    return True
            return self._is_tainted_expr(
                base, tainted_vars, fnmap, callstack, tainted_params
            )

        if isinstance(expr, ast.Subscript):
            return self._is_tainted_expr(
                expr.value, tainted_vars, fnmap, callstack, tainted_params
            )

        # Sanitizer: explicitly clean
        if self._is_sanitizer_call(expr):
            return False

        # Source expressions
        if self._is_source_expr(expr):
            return True

        # Calls: tainted if any arg tainted, OR if called function returns tainted based on tainted args
        if isinstance(expr, ast.Call):
            fn = self._get_full_name(expr.func)
            # If the call target is a sanitizer, it's clean
            if fn and self._matches_any(fn, self.sanitizers):
                return False

            # If any argument tainted, the result often becomes tainted (heuristic)
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

            # Inter-procedural: if calling a local function, see whether it returns tainted
            if fn in fnmap:
                callee = fnmap[fn]
                callee_tainted_params = set()

                # map positional args
                for i, a in enumerate(expr.args):
                    if i < len(callee.args) and self._is_tainted_expr(
                        a, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        callee_tainted_params.add(callee.args[i])

                # map kwargs
                for kw in expr.keywords:
                    if kw.arg and kw.arg in callee.args:
                        if self._is_tainted_expr(
                            kw.value, tainted_vars, fnmap, callstack, tainted_params
                        ):
                            callee_tainted_params.add(kw.arg)

                return self._function_returns_tainted(
                    fn=fn,
                    fnmap=fnmap,
                    filepath="",
                    tainted_params=callee_tainted_params,
                    callstack=callstack,
                )

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
            # *rest — taint the inner name
            self._taint_unpack_target(target.value, tainted_vars, is_tainted, is_clean)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._taint_unpack_target(elt, tainted_vars, is_tainted, is_clean)

    def _call_arg_tainted_params(
        self,
        call: ast.Call,
        callee: _FnContext,
        tainted_vars: Set[str],
        fnmap: Dict[str, _FnContext],
        callstack: List[str],
        tainted_params: Set[str],
    ) -> Set[str]:
        """Map tainted call arguments onto callee parameter names."""
        callee_tainted_params: Set[str] = set()
        for i, a in enumerate(call.args):
            if i < len(callee.args) and self._is_tainted_expr(
                a, tainted_vars, fnmap, callstack, tainted_params
            ):
                callee_tainted_params.add(callee.args[i])
        for kw in call.keywords:
            if kw.arg and kw.arg in callee.args:
                if self._is_tainted_expr(
                    kw.value, tainted_vars, fnmap, callstack, tainted_params
                ):
                    callee_tainted_params.add(kw.arg)
        return callee_tainted_params

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
        # Normalize taint state and avoid repeated analyses
        tainted_vars = set(tainted_vars) | set(tainted_params)
        key = (fnctx.name, frozenset(tainted_vars))
        if key in self._analysis_cache:
            return
        self._analysis_cache.add(key)

        mod = ast.Module(body=fnctx.body, type_ignores=[])
        for node in ast.walk(mod):
            # Inter-procedural: propagate taint into local callees with tainted args
            if isinstance(node, ast.Call):
                callee_name = self._get_full_name(node.func)
                if callee_name in fnmap and callee_name not in callstack:
                    callee = fnmap[callee_name]
                    callee_tainted_params = self._call_arg_tainted_params(
                        node, callee, tainted_vars, fnmap, callstack, tainted_params
                    )
                    if callee_tainted_params:
                        self._analyze_function(
                            fnctx=callee,
                            fnmap=fnmap,
                            filepath=filepath,
                            tainted_vars=set(callee_tainted_params),
                            tainted_params=callee_tainted_params,
                            callstack=callstack + [callee_name],
                        )

            # Assignments
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
                        # Tuple/list unpacking: a, b = ...
                        self._taint_unpack_target(target, tainted_vars, is_tainted, is_clean)
                    elif isinstance(target, ast.Attribute):
                        # Instance attribute assignment: self.data = ...
                        self._record_instance_attr_taint(target, is_tainted, is_clean)

            # AnnAssign
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                value = node.value
                if value is None:
                    continue
                if self._is_sanitizer_call(value):
                    tainted_vars.discard(node.target.id)
                elif self._is_tainted_expr(
                    value, tainted_vars, fnmap, callstack, tainted_params
                ):
                    tainted_vars.add(node.target.id)

            # AugAssign (x += y)
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                if self._is_tainted_expr(
                    node.value, tainted_vars, fnmap, callstack, tainted_params
                ):
                    tainted_vars.add(node.target.id)

            # Sinks
            if isinstance(node, ast.Call):
                sink_name = self._get_full_name(node.func)
                if sink_name and self._matches_any(sink_name, self.sinks):
                    if self._call_has_tainted_arg(
                        node, tainted_vars, fnmap, callstack, tainted_params
                    ):
                        # Check conditional sinks first
                        cs_match = _check_conditional_sink(
                            sink_name, node, self.conditional_sinks, filepath
                        ) if self.conditional_sinks else None

                        # If there are conditional sink entries for this sink name,
                        # only report if conditions are satisfied
                        has_cond_entry = any(
                            cs.get("name", "") == sink_name or (
                                any(ch in cs.get("name", "") for ch in "*?[]")
                                and fnmatch.fnmatch(sink_name, cs.get("name", ""))
                            )
                            for cs in self.conditional_sinks
                        )

                        if has_cond_entry and cs_match is None:
                            # Conditions not met — suppress
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
        key = (fn, frozenset(tainted_params))
        if key in self._return_taint_cache:
            return self._return_taint_cache[key]

        # recursion guard
        if fn in callstack:
            return False

        fnctx = fnmap.get(fn)
        if fnctx is None:
            return False

        local_tainted: Set[str] = set(tainted_params)

        # analyze statements in a single pass, and mark return expressions
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
                    value, local_tainted, fnmap, callstack + [fn], tainted_params
                ):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            local_tainted.add(t.id)
                        elif isinstance(t, (ast.Tuple, ast.List)):
                            self._taint_unpack_target(t, local_tainted, True, False)
            elif isinstance(node, ast.Return):
                if node.value is not None and self._is_tainted_expr(
                    node.value, local_tainted, fnmap, callstack + [fn], tainted_params
                ):
                    returns_tainted = True

        self._return_taint_cache[key] = returns_tainted
        return returns_tainted

    def get_findings(self) -> List[Finding]:
        return self.vulnerabilities
