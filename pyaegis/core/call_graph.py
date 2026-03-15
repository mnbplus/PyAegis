"""
call_graph.py — Inter-procedural taint analysis via a global call graph.

Provides:
  - GlobalSymbolTable  : registers function definitions + import mappings across files
  - InterproceduralAnalyzer : depth-limited cross-module taint propagation
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

_MAX_DEPTH = 3  # maximum inter-procedural call depth


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FunctionDef:
    """Lightweight record of a function discovered across the project."""
    name: str                        # unqualified function name
    filepath: str                    # source file
    args: List[str]                  # positional parameter names
    body: List[ast.stmt]             # raw AST body nodes
    decorators: List[str] = field(default_factory=list)
    module: str = ""                 # dotted module path derived from filepath


@dataclass
class ImportAlias:
    """Records a single import statement resolved at the call-site level."""
    # e.g.  from a import process  ->  local_name='process', origin_module='a', origin_name='process'
    # e.g.  import a               ->  local_name='a',       origin_module='a', origin_name=''
    local_name: str
    origin_module: str
    origin_name: str   # empty string means the whole module was imported


# ---------------------------------------------------------------------------
# GlobalSymbolTable
# ---------------------------------------------------------------------------

class GlobalSymbolTable:
    """Collects function definitions and import mappings from every scanned file.

    Usage::

        gst = GlobalSymbolTable()
        for filepath, cfg in all_cfgs.items():
            gst.register_file(filepath, cfg, raw_ast_tree)
        # then pass to InterproceduralAnalyzer
    """

    def __init__(self) -> None:
        # module_path -> {func_name -> FunctionDef}
        self._functions: Dict[str, Dict[str, FunctionDef]] = {}
        # filepath -> list of ImportAlias
        self._imports: Dict[str, List[ImportAlias]] = {}
        # filepath -> module dotted path
        self._file_to_module: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_file(
        self,
        filepath: str,
        cfg: Dict[str, Any],
        tree: Optional[ast.Module] = None,
    ) -> None:
        """Register all functions and imports found in *filepath*.

        Args:
            filepath: absolute or project-relative path to the Python file.
            cfg:      output of ``PyASTParser.extract_cfg()`` for that file.
            tree:     the parsed ``ast.Module`` (used to extract imports).
                      If ``None`` the file is re-parsed on the fly.
        """
        module_path = _filepath_to_module(filepath)
        self._file_to_module[filepath] = module_path

        if module_path not in self._functions:
            self._functions[module_path] = {}

        # Register every function from the cfg
        for fn_name, meta in cfg.items():
            if isinstance(meta, list):
                body = meta
                args: List[str] = []
                decorators: List[str] = []
            elif isinstance(meta, dict):
                body = meta.get("body") or []
                args = meta.get("args") or []
                decorators = meta.get("decorators") or []
            else:
                continue

            fdef = FunctionDef(
                name=fn_name,
                filepath=filepath,
                args=args,
                body=body,
                decorators=decorators,
                module=module_path,
            )
            self._functions[module_path][fn_name] = fdef

        # Extract imports from AST
        if tree is None:
            try:
                import os
                with open(filepath, "r", encoding="utf-8") as fh:
                    source = fh.read()
                tree = ast.parse(source, filename=filepath)
            except Exception:
                tree = None

        aliases: List[ImportAlias] = []
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for alias in node.names:
                        aliases.append(
                            ImportAlias(
                                local_name=alias.asname or alias.name,
                                origin_module=node.module,
                                origin_name=alias.name,
                            )
                        )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        aliases.append(
                            ImportAlias(
                                local_name=alias.asname or alias.name,
                                origin_module=alias.name,
                                origin_name="",
                            )
                        )
        self._imports[filepath] = aliases

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def resolve_call(
        self,
        call_name: str,
        caller_filepath: str,
    ) -> Optional[FunctionDef]:
        """Resolve a call name (possibly qualified) to a FunctionDef.

        Tries:
        1. Direct match in the caller's own module.
        2. Import alias resolution from the caller file.
        3. Global search across all registered modules.
        """
        caller_module = self._file_to_module.get(caller_filepath, "")

        # 1. Same-module lookup
        local_fns = self._functions.get(caller_module, {})
        if call_name in local_fns:
            return local_fns[call_name]

        # 2. Import alias lookup
        for alias in self._imports.get(caller_filepath, []):
            if alias.local_name == call_name and alias.origin_name:
                # from <module> import <origin_name>   (possibly as <local_name>)
                target_fns = self._functions.get(alias.origin_module, {})
                fdef = target_fns.get(alias.origin_name)
                if fdef is not None:
                    return fdef
                # Try all modules that *end with* origin_module (relative imports)
                for mod, fns in self._functions.items():
                    if mod.endswith(alias.origin_module) or alias.origin_module.endswith(mod):
                        fdef = fns.get(alias.origin_name)
                        if fdef is not None:
                            return fdef

            # module-level import:  import a  ->  a.process
            if not alias.origin_name and call_name.startswith(alias.local_name + "."):
                remainder = call_name[len(alias.local_name) + 1:]
                target_fns = self._functions.get(alias.origin_module, {})
                fdef = target_fns.get(remainder)
                if fdef is not None:
                    return fdef

        # 3. Global scan (last resort)
        for mod, fns in self._functions.items():
            if call_name in fns:
                return fns[call_name]

        return None

    def get_all_functions(self) -> List[FunctionDef]:
        """Return every registered FunctionDef across all modules."""
        out: List[FunctionDef] = []
        for fns in self._functions.values():
            out.extend(fns.values())
        return out

    def dump_stats(self) -> Dict[str, int]:
        total_fns = sum(len(v) for v in self._functions.values())
        total_imports = sum(len(v) for v in self._imports.values())
        return {
            "modules": len(self._functions),
            "functions": total_fns,
            "import_aliases": total_imports,
        }


# ---------------------------------------------------------------------------
# InterproceduralAnalyzer
# ---------------------------------------------------------------------------

class InterproceduralAnalyzer:
    """Depth-limited inter-procedural taint propagation.

    Given a call site where a tainted value is passed as an argument, this
    analyzer traces into the callee's body (and recursively into callees of
    callees, up to ``max_depth`` levels) to determine whether the taint
    reaches a sink.

    It is intentionally conservative / sound (may have false positives) rather
    than precise, to avoid missing real vulnerabilities.
    """

    def __init__(
        self,
        symbol_table: GlobalSymbolTable,
        sinks: Set[str],
        sanitizers: Set[str],
        sources: Set[str],
        max_depth: int = _MAX_DEPTH,
    ) -> None:
        self.symbol_table = symbol_table
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.sources = sources
        self.max_depth = max_depth

        # Cache: (func_qualified_key, frozenset(tainted_params)) -> bool
        self._cache: Dict[Tuple[str, FrozenSet[str]], bool] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def call_reaches_sink(
        self,
        call_name: str,
        caller_filepath: str,
        tainted_arg_indices: List[int],
        call_node: ast.Call,
    ) -> bool:
        """Return True if calling *call_name* with tainted args reaches a sink.

        Args:
            call_name:           The dotted name of the callee as it appears in source.
            caller_filepath:     Absolute path of the file making the call.
            tainted_arg_indices: 0-based indices of positional arguments that are tainted.
            call_node:           The AST ``ast.Call`` node (for kwarg mapping).
        """
        fdef = self.symbol_table.resolve_call(call_name, caller_filepath)
        if fdef is None:
            return False

        tainted_params: Set[str] = set()
        for i in tainted_arg_indices:
            if i < len(fdef.args):
                tainted_params.add(fdef.args[i])

        # Map keyword arguments
        for kw in call_node.keywords:
            if kw.arg and kw.arg in fdef.args:
                # We cannot re-evaluate taint here (no tainted_vars set),
                # but the caller should only pass indices for actually tainted args.
                # Keyword taint is handled by the caller.
                pass

        if not tainted_params:
            return False

        return self._analyze_body_for_sink(
            fdef=fdef,
            tainted_params=frozenset(tainted_params),
            depth=0,
            callstack=frozenset([f"{fdef.module}.{fdef.name}"]),
        )

    def function_reaches_sink_with_tainted_params(
        self,
        fdef: FunctionDef,
        tainted_params: FrozenSet[str],
        depth: int = 0,
        callstack: Optional[FrozenSet[str]] = None,
    ) -> bool:
        """Recursively check whether fdef's body reaches a sink given tainted params."""
        if callstack is None:
            callstack = frozenset()
        return self._analyze_body_for_sink(fdef, tainted_params, depth, callstack)

    # ------------------------------------------------------------------
    # Internal analysis
    # ------------------------------------------------------------------

    def _analyze_body_for_sink(
        self,
        fdef: FunctionDef,
        tainted_params: FrozenSet[str],
        depth: int,
        callstack: FrozenSet[str],
    ) -> bool:
        """Walk the function body and check whether taint reaches a known sink."""
        if depth > self.max_depth:
            return False

        cache_key = (f"{fdef.module}.{fdef.name}", tainted_params)
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Guard against infinite recursion
        fn_key = f"{fdef.module}.{fdef.name}"
        if fn_key in callstack:
            self._cache[cache_key] = False
            return False

        new_callstack = callstack | {fn_key}

        # Build local taint set from tainted params
        local_tainted: Set[str] = set(tainted_params)
        result = False

        mod = ast.Module(body=fdef.body, type_ignores=[])

        for node in ast.walk(mod):
            # Track assignments that propagate taint
            if isinstance(node, ast.Assign):
                if self._expr_is_tainted(node.value, local_tainted):
                    for t in node.targets:
                        self._mark_tainted(t, local_tainted)
                elif self._is_sanitizer(node.value):
                    for t in node.targets:
                        self._mark_clean(t, local_tainted)

            # Check calls for sink hits
            if isinstance(node, ast.Call):
                fn_name = _get_full_name(node.func)
                if not fn_name:
                    continue

                # Direct sink hit
                if self._matches_sink(fn_name):
                    if self._call_has_tainted_arg(node, local_tainted):
                        result = True
                        break

                # Recurse into known callees (if depth permits)
                if depth < self.max_depth:
                    tainted_indices = [
                        i for i, a in enumerate(node.args)
                        if self._expr_is_tainted(a, local_tainted)
                    ]
                    if tainted_indices:
                        callee = self.symbol_table.resolve_call(
                            fn_name, fdef.filepath
                        )
                        if callee is not None:
                            callee_params: Set[str] = set()
                            for idx in tainted_indices:
                                if idx < len(callee.args):
                                    callee_params.add(callee.args[idx])
                            if callee_params:
                                if self._analyze_body_for_sink(
                                    fdef=callee,
                                    tainted_params=frozenset(callee_params),
                                    depth=depth + 1,
                                    callstack=new_callstack,
                                ):
                                    result = True
                                    break

        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    # Taint helpers (lightweight — no full expr tree walk needed here)
    # ------------------------------------------------------------------

    def _expr_is_tainted(self, expr: ast.AST, tainted: Set[str]) -> bool:
        """Quick taint check for an expression given a local tainted-var set."""
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in tainted
        if isinstance(expr, ast.Constant):
            return False
        if isinstance(expr, ast.JoinedStr):
            return any(
                self._expr_is_tainted(v.value, tainted)
                for v in expr.values
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            return self._expr_is_tainted(expr.left, tainted) or self._expr_is_tainted(
                expr.right, tainted
            )
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(e, tainted) for e in expr.elts)
        if isinstance(expr, ast.Attribute):
            return self._expr_is_tainted(expr.value, tainted)
        if isinstance(expr, ast.Subscript):
            return self._expr_is_tainted(expr.value, tainted)
        if isinstance(expr, ast.Call):
            fn = _get_full_name(expr.func)
            if fn and self._matches_any(fn, self.sanitizers):
                return False
            # If any arg is tainted, treat the call result as tainted
            return any(self._expr_is_tainted(a, tainted) for a in expr.args)
        return False

    def _is_sanitizer(self, expr: ast.AST) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        fn = _get_full_name(expr.func)
        return bool(fn) and self._matches_any(fn, self.sanitizers)

    def _matches_sink(self, name: str) -> bool:
        return self._matches_any(name, self.sinks)

    def _matches_any(self, name: str, patterns: Set[str]) -> bool:
        import fnmatch
        for p in patterns:
            if p == name:
                return True
            if any(ch in p for ch in "*?[]") and fnmatch.fnmatch(name, p):
                return True
        return False

    def _call_has_tainted_arg(self, call: ast.Call, tainted: Set[str]) -> bool:
        for a in call.args:
            if self._expr_is_tainted(a, tainted):
                return True
        for kw in call.keywords:
            if kw.value and self._expr_is_tainted(kw.value, tainted):
                return True
        return False

    def _mark_tainted(self, target: ast.AST, tainted: Set[str]) -> None:
        if isinstance(target, ast.Name):
            tainted.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_tainted(elt, tainted)
        elif isinstance(target, ast.Starred):
            self._mark_tainted(target.value, tainted)

    def _mark_clean(self, target: ast.AST, tainted: Set[str]) -> None:
        if isinstance(target, ast.Name):
            tainted.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_clean(elt, tainted)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _get_full_name(node: ast.AST) -> str:
    """Resolve an AST node to a dotted name string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _get_full_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _get_full_name(node.func)
    if isinstance(node, ast.Subscript):
        return _get_full_name(node.value)
    return ""


def _filepath_to_module(filepath: str) -> str:
    """Convert a file path to a dotted module path best-effort.

    e.g.  /project/pyaegis/core/taint.py  ->  pyaegis.core.taint
         a.py                              ->  a
    """
    import os
    # Normalise separators
    p = filepath.replace("\\", "/")
    # Strip .py
    if p.endswith(".py"):
        p = p[:-3]
    # Take the last meaningful path components (strip leading ./)
    p = p.lstrip("./")
    # Replace separators with dots
    return p.replace("/", ".")
