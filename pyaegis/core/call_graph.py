"""pyaegis.core.call_graph

Lightweight global symbol table + import alias resolver used for P0
inter-procedural (cross-module) taint propagation.

Design goals:
- Best-effort, fast, conservative.
- Index only *top-level* functions (and async functions).
- Resolve simple import aliases:
  - import pkg.mod as m -> m.f() => pkg.mod.f
  - from pkg.mod import f as g -> g() => pkg.mod.f
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class FunctionSymbol:
    """A globally discoverable top-level function."""

    name: str
    qualname: str
    file_path: str
    node: ast.AST  # ast.FunctionDef | ast.AsyncFunctionDef
    args: List[str]


class GlobalSymbolTable:
    """Global function symbol table across scanned files."""

    def __init__(self, root_dir: Optional[str] = None) -> None:
        self.root_dir = os.path.abspath(root_dir) if root_dir else os.getcwd()
        self._by_qualname: Dict[str, FunctionSymbol] = {}
        self._by_name: Dict[str, List[FunctionSymbol]] = {}
        self._by_file: Dict[str, Dict[str, FunctionSymbol]] = {}
        self._module_by_file: Dict[str, str] = {}
        # Backward-compat: import alias index by file (string path -> {local: qualname}).
        # Stored for both the raw path passed to register_file() and its abspath.
        self._imports_by_file: Dict[str, Dict[str, str]] = {}

    @property
    def functions(self) -> Dict[str, FunctionSymbol]:
        """Backward-compatible view: mapping qualname -> FunctionSymbol."""
        return self._by_qualname

    @property
    def imports(self) -> Dict[str, Dict[str, str]]:
        """Backward-compatible view: mapping file_path -> {local_name -> qualname}."""
        return self._imports_by_file

    @staticmethod
    def _module_name_for_file(file_path: str, *, root_dir: str) -> str:
        abspath = os.path.abspath(file_path)
        root = os.path.abspath(root_dir)
        try:
            rel = os.path.relpath(abspath, root)
        except Exception:
            rel = os.path.basename(abspath)
        # Normalize path separators to forward slashes
        rel = rel.replace("\\", "/")
        if rel.endswith(".py"):
            rel = rel[:-3]
        parts = [p for p in rel.split("/") if p and p not in (".", "..")]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        mod = (
            ".".join(parts) if parts else os.path.splitext(os.path.basename(abspath))[0]
        )
        return mod.strip(".")

    @staticmethod
    def _package_parts_for_file(file_path: str, module_name: str) -> List[str]:
        if not module_name:
            return []
        is_init = os.path.basename(file_path) == "__init__.py"
        parts = module_name.split(".") if module_name else []
        if not is_init and parts:
            return parts[:-1]
        return parts

    @staticmethod
    def _resolve_relative_module(
        file_path: str, module: str, level: int, *, root_dir: str
    ) -> str:
        if level <= 0:
            return module or ""
        module_name = GlobalSymbolTable._module_name_for_file(
            file_path, root_dir=root_dir
        )
        if not module_name:
            return module or ""
        package_parts = GlobalSymbolTable._package_parts_for_file(
            file_path, module_name
        )
        if level - 1 > len(package_parts):
            base_parts: List[str] = []
        else:
            base_parts = package_parts[: len(package_parts) - (level - 1)]
        if module:
            base_parts.extend([p for p in module.split(".") if p])
        return ".".join([p for p in base_parts if p])

    @classmethod
    def build(
        cls, filepaths: Iterable[str], *, root_dir: Optional[str] = None
    ) -> "GlobalSymbolTable":
        fps = list(filepaths)
        if root_dir is None:
            root_dir = cls._compute_root(fps)
        tab = cls(root_dir=root_dir)
        for fp in fps:
            abspath = os.path.abspath(fp)
            try:
                with open(abspath, "r", encoding="utf-8") as f:
                    src = f.read()
                tree = ast.parse(src, filename=abspath)
            except Exception:
                continue
            tab.register_file(abspath, tree)
        return tab

    @staticmethod
    def _compute_root(filepaths: Iterable[str]) -> str:
        fps = [os.path.abspath(p) for p in filepaths]
        if not fps:
            return os.getcwd()
        if len(fps) == 1:
            return os.path.dirname(fps[0])
        return os.path.commonpath(fps)

    def dump_stats(self) -> Dict[str, int]:
        modules = len({m for m in self._module_by_file.values() if m})
        functions = len(self._by_qualname)
        return {"modules": modules, "functions": functions, "import_aliases": 0}

    def register_file(self, filepath: str, tree: ast.AST) -> None:
        """Register a parsed AST Module into the symbol table."""
        if not isinstance(tree, ast.AST):
            return
        # Keep both the original filepath key and its abspath for backward compat.
        raw_fp = filepath
        abspath = os.path.abspath(filepath)
        mod = self._module_name_for_file(abspath, root_dir=self.root_dir)
        self._module_by_file[abspath] = mod
        self._by_file.setdefault(abspath, {})

        # Record import aliases for this file (for legacy tests / debug).
        imports_map: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[-1]
                    imports_map[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                modname = node.module or ""
                if node.level:
                    modname = self._resolve_relative_module(
                        abspath,
                        modname,
                        node.level,
                        root_dir=self.root_dir,
                    )
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    full = f"{modname}.{alias.name}" if modname else alias.name
                    imports_map[local] = full
        self._imports_by_file[raw_fp] = dict(imports_map)
        self._imports_by_file[abspath] = dict(imports_map)

        # Register only top-level function defs.
        body = getattr(tree, "body", None) or []
        for node in body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = [a.arg for a in node.args.args]
            qual = f"{mod}.{node.name}" if mod else node.name
            sym = FunctionSymbol(
                name=node.name,
                qualname=qual,
                file_path=abspath,
                node=node,
                args=args,
            )
            self._by_qualname[qual] = sym
            self._by_name.setdefault(node.name, []).append(sym)
            self._by_file[abspath][node.name] = sym

    def get(self, qualname: str) -> Optional[FunctionSymbol]:
        return self._by_qualname.get(qualname)

    def get_by_name(self, name: str) -> List[FunctionSymbol]:
        return list(self._by_name.get(name, []))

    def functions_in_file(self, file_path: str) -> Dict[str, FunctionSymbol]:
        return dict(self._by_file.get(os.path.abspath(file_path), {}))

    def module_for_file(self, file_path: str) -> str:
        return self._module_by_file.get(os.path.abspath(file_path), "")


class InterproceduralTaintTracker:
    """Resolve cross-module call targets from a call node."""

    def __init__(self, symbol_table: GlobalSymbolTable, *, max_depth: int = 3) -> None:
        self.symbol_table = symbol_table
        self.max_depth = int(max_depth or 0)
        self._import_cache: Dict[str, Tuple[Dict[str, str], Dict[str, str]]] = {}

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

    def _parse_imports(self, file_path: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        abspath = os.path.abspath(file_path)
        if abspath in self._import_cache:
            return self._import_cache[abspath]
        module_aliases: Dict[str, str] = {}
        name_aliases: Dict[str, str] = {}
        try:
            with open(abspath, "r", encoding="utf-8") as f:
                src = f.read()
            tree = ast.parse(src, filename=abspath)
        except Exception:
            self._import_cache[abspath] = (module_aliases, name_aliases)
            return module_aliases, name_aliases

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[-1]
                    module_aliases[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level:
                    mod = GlobalSymbolTable._resolve_relative_module(
                        abspath,
                        mod,
                        node.level,
                        root_dir=self.symbol_table.root_dir,
                    )
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    full = f"{mod}.{alias.name}" if mod else alias.name
                    name_aliases[local] = full
        self._import_cache[abspath] = (module_aliases, name_aliases)
        return module_aliases, name_aliases

    def resolve_call_qualname(self, call: ast.Call, *, caller_file: str) -> str:
        raw = self._get_full_name(call.func)
        if not raw:
            return ""
        module_aliases, name_aliases = self._parse_imports(caller_file)

        # from x import y as z -> z()
        if "." not in raw and raw in name_aliases:
            return name_aliases[raw]

        # import x as y -> y.f()
        if "." in raw:
            head, rest = raw.split(".", 1)
            if head in module_aliases:
                return f"{module_aliases[head]}.{rest}"
            # from x import mod as m -> m.f()  (module imported via ImportFrom)
            if head in name_aliases:
                return f"{name_aliases[head]}.{rest}"
        return raw

    def resolve_symbol(
        self, call: ast.Call, *, caller_file: str
    ) -> Optional[FunctionSymbol]:
        qn = self.resolve_call_qualname(call, caller_file=caller_file)
        if not qn:
            return None
        sym = self.symbol_table.get(qn)
        if sym is not None:
            return sym
        # unqualified name, try by-name if unique
        if "." not in qn:
            cands = self.symbol_table.get_by_name(qn)
            if len(cands) == 1:
                return cands[0]
        return None


# Alias for backward compat
InterproceduralAnalyzer = InterproceduralTaintTracker
