from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


@dataclass
class FunctionInfo:
    filepath: str
    node: ast.FunctionDef
    params: List[str]


class InterproceduralAnalyzer:
    def __init__(self, symbol_table: 'GlobalSymbolTable', max_depth: int = 3):
        self.st = symbol_table
        self.max_depth = max_depth
        self._visited: Set[str] = set()

    def has_tainted_sink(self, caller_file: str, call_name: str, tainted_arg_indices: List[int], depth: int = 0) -> bool:
        if depth >= self.max_depth:
            return False
        cache_key = f'{caller_file}:{call_name}:{tainted_arg_indices}:{depth}'
        if cache_key in self._visited:
            return False
        self._visited.add(cache_key)
        func_info = self.st.resolve(caller_file, call_name)
        if not func_info:
            return False
        tainted_params = {func_info.params[i] for i in tainted_arg_indices if i < len(func_info.params)}
        for node in ast.walk(func_info.node):
            if isinstance(node, ast.Call):
                for _i, arg in enumerate(node.args):
                    if isinstance(arg, ast.Name) and arg.id in tainted_params:
                        return True
        return False


@dataclass(frozen=True)
class FunctionSymbol:
    name: str
    qualname: str
    file_path: str
    node: ast.AST
    args: List[str]


class GlobalSymbolTable:
    def __init__(self, root_dir: Optional[str] = None):
        self.root_dir = os.path.abspath(root_dir) if root_dir else os.getcwd()
        self.functions: Dict[str, FunctionInfo] = {}
        self.imports: Dict[str, Dict[str, str]] = {}
        self._by_qualname: Dict[str, FunctionSymbol] = {}
        self._by_name: Dict[str, List[FunctionSymbol]] = {}
        self._by_file: Dict[str, Dict[str, FunctionSymbol]] = {}
        self._module_by_file: Dict[str, str] = {}

    @staticmethod
    def _compute_root(filepaths: Iterable[str]) -> str:
        fps = [os.path.abspath(p) for p in filepaths]
        if not fps:
            return os.getcwd()
        if len(fps) == 1:
            return os.path.dirname(fps[0])
        return os.path.commonpath(fps)

    @staticmethod
    def _module_name_for_file(file_path: str, *, root_dir: str) -> str:
        abspath = os.path.abspath(file_path)
        root = os.path.abspath(root_dir)
        try:
            rel = os.path.relpath(abspath, root)
        except Exception:
            rel = os.path.basename(abspath)
        rel = rel.replace('\\\\', '/')
        if rel.endswith('.py'):
            rel = rel[:-3]
        parts = [p for p in rel.split('/') if p and p not in ('.', '..')]
        if parts and parts[-1] == '__init__':
            parts = parts[:-1]
        mod = '.'.join(parts) if parts else os.path.splitext(os.path.basename(abspath))[0]
        return mod.strip('.')

    @classmethod
    def build(cls, filepaths: Iterable[str], *, root_dir: Optional[str] = None) -> 'GlobalSymbolTable':
        fps = list(filepaths)
        if root_dir is None:
            root_dir = cls._compute_root(fps)
        tab = cls(root_dir=root_dir)
        for fp in fps:
            abspath = os.path.abspath(fp)
            try:
                with open(abspath, 'r', encoding='utf-8') as f:
                    src = f.read()
                tree = ast.parse(src, filename=abspath)
            except Exception:
                continue
            tab.register_file(abspath, tree)
        return tab

    def dump_stats(self) -> Dict[str, int]:
        modules = len({m for m in self._module_by_file.values() if m})
        functions = len(self._by_qualname)
        import_aliases = sum(len(v) for v in self.imports.values())
        return {'modules': modules, 'functions': functions, 'import_aliases': import_aliases}

    @classmethod
    def build(cls, filepaths, root_dir=None) -> "GlobalSymbolTable":
        """Build a GlobalSymbolTable from an iterable of file paths."""
        st = cls()
        for fp in filepaths:
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                tree = ast.parse(source, filename=str(fp))
                st.register_file(str(fp), tree)
            except Exception:  # pragma: no cover
                pass
        return st

    def register_file(self, filepath: str, tree: ast.AST) -> None:
        if isinstance(tree, dict):
            self._register_cfg_dict(filepath, tree)
            return
        if not isinstance(tree, ast.AST):
            return
        module_name = Path(filepath).stem
        abspath = os.path.abspath(filepath)
        self.imports.setdefault(filepath, {})
        self.imports.setdefault(abspath, self.imports[filepath])
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    self.imports[filepath][local_name] = f'{node.module}.{alias.name}'
            elif isinstance(node, ast.FunctionDef):
                key = f'{module_name}.{node.name}'
                params = [a.arg for a in node.args.args if a.arg != 'self']
                self.functions[key] = FunctionInfo(filepath, node, params)
        mod = self._module_name_for_file(abspath, root_dir=self.root_dir)
        self._module_by_file[abspath] = mod
        self._by_file.setdefault(abspath, {})
        body_nodes = getattr(tree, 'body', None) or []
        for node in body_nodes:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = [a.arg for a in node.args.args]
            qual = f'{mod}.{node.name}' if mod else node.name
            sym = FunctionSymbol(name=node.name, qualname=qual, file_path=abspath, node=node, args=args)
            self._by_qualname[qual] = sym
            self._by_name.setdefault(node.name, []).append(sym)
            self._by_file[abspath][node.name] = sym

    def _register_cfg_dict(self, filepath: str, cfg: Dict[str, Any]) -> None:
        abspath = os.path.abspath(filepath)
        mod = self._module_name_for_file(abspath, root_dir=self.root_dir)
        self._module_by_file[abspath] = mod
        self._by_file.setdefault(abspath, {})
        self.imports.setdefault(filepath, {})
        self.imports.setdefault(abspath, self.imports[filepath])
        for fn_name, meta in cfg.items():
            if not isinstance(fn_name, str):
                continue
            if isinstance(meta, list):
                args: List[str] = []
                body_stmts = meta
            elif isinstance(meta, dict):
                args = list(meta.get('args') or [])
                body_stmts = list(meta.get('body') or [])
            else:
                continue
            fake_node = ast.FunctionDef(
                name=fn_name,
                args=ast.arguments(
                    posonlyargs=[],
                    args=[ast.arg(arg=a, annotation=None) for a in args],
                    vararg=None,
                    kwonlyargs=[],
                    kw_defaults=[],
                    kwarg=None,
                    defaults=[],
                ),
                body=body_stmts or [ast.Pass()],
                decorator_list=[],
                returns=None,
                lineno=0,
                col_offset=0,
            )
            stem = Path(filepath).stem
            self.functions[f'{stem}.{fn_name}'] = FunctionInfo(filepath, fake_node, [a for a in args if a != 'self'])
            qual = f'{mod}.{fn_name}' if mod else fn_name
            sym = FunctionSymbol(name=fn_name, qualname=qual, file_path=abspath, node=fake_node, args=args)
            self._by_qualname[qual] = sym
            self._by_name.setdefault(fn_name, []).append(sym)
            self._by_file[abspath][fn_name] = sym

    def resolve(self, caller_file: str, call_name: str) -> Optional[FunctionInfo]:
        imports = self.imports.get(caller_file, {})
        if call_name in imports:
            full_name = imports[call_name]
            if full_name in self.functions:
                return self.functions[full_name]
        module_name = Path(caller_file).stem
        local_key = f'{module_name}.{call_name}'
        return self.functions.get(local_key)

    def get(self, qualname: str) -> Optional[FunctionSymbol]:
        return self._by_qualname.get(qualname)

    def get_by_name(self, name: str) -> List[FunctionSymbol]:
        return list(self._by_name.get(name, []))

    def functions_in_file(self, file_path: str) -> Dict[str, FunctionSymbol]:
        return dict(self._by_file.get(os.path.abspath(file_path), {}))

    def module_for_file(self, file_path: str) -> str:
        return self._module_by_file.get(os.path.abspath(file_path), '')


class InterproceduralTaintTracker:
    def __init__(self, symbol_table: GlobalSymbolTable, *, max_depth: int = 3) -> None:
        self.symbol_table = symbol_table
        self.max_depth = int(max_depth or 0)
        self._import_cache: Dict[str, Tuple[Dict[str, str], Dict[str, str]]] = {}

    def _get_full_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_full_name(node.value)
            return f'{base}.{node.attr}' if base else node.attr
        if isinstance(node, ast.Call):
            return self._get_full_name(node.func)
        if isinstance(node, ast.Subscript):
            return self._get_full_name(node.value)
        return ''

    def _parse_imports(self, file_path: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        abspath = os.path.abspath(file_path)
        if abspath in self._import_cache:
            return self._import_cache[abspath]
        module_aliases: Dict[str, str] = {}
        name_aliases: Dict[str, str] = {}
        try:
            with open(abspath, 'r', encoding='utf-8') as f:
                src = f.read()
            tree = ast.parse(src, filename=abspath)
        except Exception:
            self._import_cache[abspath] = (module_aliases, name_aliases)
            return module_aliases, name_aliases
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split('.')[-1]
                    module_aliases[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ''
                for alias in node.names:
                    if alias.name == '*':
                        continue
                    local = alias.asname or alias.name
                    full = f'{mod}.{alias.name}' if mod else alias.name
                    name_aliases[local] = full
        self._import_cache[abspath] = (module_aliases, name_aliases)
        return module_aliases, name_aliases

    def resolve_call_qualname(self, call: ast.Call, *, caller_file: str) -> str:
        raw = self._get_full_name(call.func)
        if not raw:
            return ''
        module_aliases, name_aliases = self._parse_imports(caller_file)
        if '.' not in raw and raw in name_aliases:
            return name_aliases[raw]
        if '.' in raw:
            head, rest = raw.split('.', 1)
            if head in module_aliases:
                return f'{module_aliases[head]}.{rest}'
        return raw

    def resolve_symbol(self, call: ast.Call, *, caller_file: str) -> Optional[FunctionSymbol]:
        qn = self.resolve_call_qualname(call, caller_file=caller_file)
        if not qn:
            return None
        sym = self.symbol_table.get(qn)
        if sym is not None:
            return sym
        if '.' not in qn:
            cands = self.symbol_table.get_by_name(qn)
            if len(cands) == 1:
                return cands[0]
        return None
