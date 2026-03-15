import ast
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class FunctionSymbol:
    """Represents a globally discoverable function definition."""

    name: str
    qualname: str
    file_path: str
    node: ast.AST  # ast.FunctionDef | ast.AsyncFunctionDef
    args: List[str]


class GlobalSymbolTable:
    """Global function symbol table across a scanned project.

    This is intentionally lightweight and best-effort: it indexes *top-level*
    function definitions per module (plus a derived module name), so the taint
    engine can jump across modules when it sees a call with tainted arguments.

    Keys:
      - qualname: "pkg.mod.func"
      - name: "func" (may be ambiguous)
    """

    def __init__(self) -> None:
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

        rel = rel.replace("\\", "/")
        if rel.endswith(".py"):
            rel = rel[:-3]

        parts = [p for p in rel.split("/") if p and p not in (".", "..")]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]

        mod = ".".join(parts) if parts else os.path.splitext(os.path.basename(abspath))[0]
        # make it a valid-ish dotted path (best-effort)
        mod = mod.strip(".")
        return mod

    @classmethod
    def build(cls, filepaths: Iterable[str], *, root_dir: Optional[str] = None) -> "GlobalSymbolTable":
        fps = list(filepaths)
        tab = cls()
        if root_dir is None:
            root_dir = cls._compute_root(fps)

        for fp in fps:
            abspath = os.path.abspath(fp)
            try:
                with open(abspath, "r", encoding="utf-8") as f:
                    src = f.read()
                tree = ast.parse(src, filename=abspath)
            except Exception:
                # best-effort: skip unreadable/unparseable files
                continue

            mod = cls._module_name_for_file(abspath, root_dir=root_dir)
            tab._module_by_file[abspath] = mod
            if abspath not in tab._by_file:
                tab._by_file[abspath] = {}

            for node in tree.body:
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

                tab._by_qualname[qual] = sym
                tab._by_name.setdefault(node.name, []).append(sym)
                tab._by_file[abspath][node.name] = sym

        return tab

    def get(self, qualname: str) -> Optional[FunctionSymbol]:
        return self._by_qualname.get(qualname)

    def get_by_name(self, name: str) -> List[FunctionSymbol]:
        return list(self._by_name.get(name, []))

    def functions_in_file(self, file_path: str) -> Dict[str, FunctionSymbol]:
        return dict(self._by_file.get(os.path.abspath(file_path), {}))

    def module_for_file(self, file_path: str) -> str:
        return self._module_by_file.get(os.path.abspath(file_path), "")


class InterproceduralTaintTracker:
    """Resolve cross-module call targets and provide a bounded recursion guard."""

    def __init__(self, symbol_table: GlobalSymbolTable, *, max_depth: int = 3) -> None:
        self.symbol_table = symbol_table
        self.max_depth = int(max_depth or 0)

        # file_path -> (module_aliases, name_aliases)
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
                for alias in node.names:
                    local = alias.asname or alias.name
                    full = f"{mod}.{alias.name}" if mod else alias.name
                    name_aliases[local] = full

        self._import_cache[abspath] = (module_aliases, name_aliases)
        return module_aliases, name_aliases

    def resolve_call_qualname(self, call: ast.Call, *, caller_file: str) -> str:
        """Resolve a call target into a best-effort qualname."""
        raw = self._get_full_name(call.func)
        if not raw:
            return ""

        module_aliases, name_aliases = self._parse_imports(caller_file)

        # from x import y as z  -> z()
        if "." not in raw and raw in name_aliases:
            return name_aliases[raw]

        # import x as y -> y.f()
        if "." in raw:
            head, rest = raw.split(".", 1)
            if head in module_aliases:
                return f"{module_aliases[head]}.{rest}"

        return raw

    def resolve_symbol(self, call: ast.Call, *, caller_file: str) -> Optional[FunctionSymbol]:
        """Resolve a call node into a known function symbol."""
        qn = self.resolve_call_qualname(call, caller_file=caller_file)
        if not qn:
            return None

        # exact qualname
        sym = self.symbol_table.get(qn)
        if sym is not None:
            return sym

        # If it's an unqualified name, try by-name lookup.
        if "." not in qn:
            cands = self.symbol_table.get_by_name(qn)
            if len(cands) == 1:
                return cands[0]

        return None
