import ast
import hashlib
import logging
import multiprocessing
import os
import pickle
import time
from dataclasses import dataclass
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

        # Note: bandit uses an ast.NodeVisitor with node-specific hooks.
        # Here we keep things minimal, but avoid repeated ast.walk() where possible.
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
        """Extract decorator names and route decorator metadata."""
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
    """Worker entrypoint for multiprocessing."""
    parser = PyASTParser(filepath)
    parser.parse()
    return parser.extract_cfg()


def _file_signature(filepath: str) -> str:
    """Compute a stable signature based on mtime+size.

    Requirement: file caching mechanism based on "mtime hash".
    We hash mtime_ns and size to reduce collisions and keep the key compact.
    """
    st = os.stat(filepath)
    base = f"{st.st_mtime_ns}:{st.st_size}".encode("utf-8")
    return hashlib.sha1(base).hexdigest()


@dataclass
class _CacheEntry:
    sig: str
    cfg: Any


class _FileCache:
    """Persistent cache of parsed CFGs, keyed by absolute file path."""

    def __init__(self, cache_path: str):
        self.cache_path = cache_path
        self._entries: Dict[str, _CacheEntry] = {}

    def load(self) -> None:
        try:
            if not os.path.exists(self.cache_path):
                return
            with open(self.cache_path, "rb") as f:
                payload = pickle.load(f)
            # payload: {"version": int, "entries": {path: (sig, cfg)}}
            if not isinstance(payload, dict):
                return
            entries = payload.get("entries", {})
            if not isinstance(entries, dict):
                return
            out: Dict[str, _CacheEntry] = {}
            for path, v in entries.items():
                if (
                    isinstance(path, str)
                    and isinstance(v, tuple)
                    and len(v) == 2
                    and isinstance(v[0], str)
                ):
                    out[path] = _CacheEntry(sig=v[0], cfg=v[1])
            self._entries = out
        except Exception:
            # Corrupt cache should never break scanning.
            self._entries = {}

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            tmp = self.cache_path + ".tmp"
            payload = {
                "version": 1,
                "entries": {k: (v.sig, v.cfg) for k, v in self._entries.items()},
            }
            with open(tmp, "wb") as f:
                pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(tmp, self.cache_path)
        except Exception:
            # Best-effort.
            return

    def get_if_fresh(self, filepath: str) -> Optional[Any]:
        abspath = os.path.abspath(filepath)
        ent = self._entries.get(abspath)
        if ent is None:
            return None
        try:
            sig = _file_signature(abspath)
        except OSError:
            return None
        return ent.cfg if sig == ent.sig else None

    def put(self, filepath: str, cfg: Any) -> None:
        abspath = os.path.abspath(filepath)
        try:
            sig = _file_signature(abspath)
        except OSError:
            return
        self._entries[abspath] = _CacheEntry(sig=sig, cfg=cfg)


class ParallelProjectParser:
    """Parse multiple files concurrently.

    Features:
    - True multiprocessing with ``multiprocessing.Pool``.
    - Persistent file cache based on mtime hash (mtime_ns + size).
    - Progress bar (rich.progress) in the parent process.
    - Optional per-file timeout.
    """

    def __init__(
        self, pool_size: Optional[int] = None, timeout: Optional[float] = None
    ):
        self.pool_size = int(pool_size or (os.cpu_count() or 4))
        self.timeout = timeout
        # Built after parse_all completes; available for inter-procedural analysis.
        self.symbol_table: Optional[Any] = None

    def parse_all(
        self,
        filepaths: List[str],
        *,
        cache_path: Optional[str] = None,
        show_progress: bool = True,
    ) -> Dict[str, Any]:
        """Parse all given python files.

        Args:
            filepaths: paths to parse.
            cache_path: optional explicit cache file path.
            show_progress: enable rich progress bar.

        Returns:
            {filepath: cfg}
        """
        if not filepaths:
            return {}

        # Cache location: beside the target root.
        if cache_path is None:
            root_dir = (
                os.path.dirname(os.path.abspath(filepaths[0]))
                if len(filepaths) == 1
                else os.path.commonpath([os.path.abspath(p) for p in filepaths])
            )
            cache_path = os.path.join(root_dir, ".pyaegis_cache.pkl")

        cache = _FileCache(cache_path)
        cache.load()

        results: Dict[str, Any] = {}
        to_parse: List[str] = []

        for p in filepaths:
            cached = cache.get_if_fresh(p)
            if cached is not None:
                results[p] = cached
            else:
                to_parse.append(p)

        total = len(filepaths)

        progress_cm = _progress_ctx(enabled=show_progress)
        with progress_cm as progress:
            task_id = progress.add_task("Scanning", total=total)
            # Advance for cached files immediately
            if results:
                progress.advance(task_id, advance=len(results))

            if not to_parse:
                return results

            # Submit tasks gradually so we can enforce per-file runtime.
            ctx = multiprocessing.get_context("spawn")
            pool = ctx.Pool(processes=self.pool_size, maxtasksperchild=50)

            try:
                pending: List[str] = list(to_parse)
                active: Dict[str, Tuple[multiprocessing.pool.AsyncResult, float]] = {}

                while pending or active:
                    # Fill up to pool size
                    while pending and len(active) < self.pool_size:
                        fp = pending.pop()
                        ar = pool.apply_async(_worker_parse, (fp,))
                        active[fp] = (ar, time.monotonic())

                    # Collect finished
                    finished: List[str] = []
                    for fp, (ar, started) in list(active.items()):
                        if ar.ready():
                            try:
                                cfg = ar.get(timeout=0)
                            except ParserError:
                                pool.terminate()
                                pool.join()
                                raise
                            except Exception as e:
                                pool.terminate()
                                pool.join()
                                raise ParserError(f"Unexpected error: {e}") from e

                            results[fp] = cfg
                            cache.put(fp, cfg)
                            finished.append(fp)
                            progress.advance(task_id, advance=1)

                    for fp in finished:
                        active.pop(fp, None)

                    # Enforce timeout (wall time since submission)
                    if self.timeout is not None and self.timeout > 0:
                        timed_out: List[str] = []
                        now = time.monotonic()
                        for fp, (ar, started) in active.items():
                            if now - started > self.timeout:
                                timed_out.append(fp)

                        if timed_out:
                            # Kill current pool to stop timed-out workers.
                            pool.terminate()
                            pool.join()

                            for fp in timed_out:
                                logger.warning(
                                    "Timeout parsing %s (>%ss); skipping.",
                                    fp,
                                    self.timeout,
                                )
                                progress.advance(task_id, advance=1)
                                active.pop(fp, None)
                                results[fp] = {}

                            # Re-queue remaining active tasks (they were killed too)
                            for fp in list(active.keys()):
                                pending.append(fp)
                            active.clear()

                            pool = ctx.Pool(
                                processes=self.pool_size, maxtasksperchild=50
                            )

                    if not finished:
                        time.sleep(0.01)

            finally:
                try:
                    pool.close()
                    pool.join()
                except Exception:
                    pass

        cache.save()

        # Build global symbol table for inter-procedural analysis.
        try:
            from pyaegis.core.call_graph import GlobalSymbolTable

            gst = GlobalSymbolTable.build(results.keys())
            self.symbol_table = gst

            # Optional debug stats when available.
            if hasattr(gst, "dump_stats"):
                stats = gst.dump_stats()
                logger.debug(
                    "GlobalSymbolTable built: %d modules, %d functions, %d import aliases",
                    stats.get("modules", 0),
                    stats.get("functions", 0),
                    stats.get("import_aliases", 0),
                )
        except Exception as e:
            logger.warning("Failed to build GlobalSymbolTable: %s", e)
            self.symbol_table = None

        return results


class _progress_ctx:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._progress = None

    def __enter__(self):
        if not self.enabled:
            return _NullProgress()
        try:
            from rich.progress import (
                BarColumn,
                MofNCompleteColumn,
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeElapsedColumn,
                TimeRemainingColumn,
            )

            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                transient=True,
            )
            self._progress.start()
            return self._progress
        except Exception:
            return _NullProgress()

    def __exit__(self, exc_type, exc, tb):
        if self._progress is not None:
            try:
                self._progress.stop()
            except Exception:
                pass
        return False


class _NullProgress:
    def add_task(self, *_args, **_kwargs):
        return 0

    def advance(self, *_args, **_kwargs):
        return None
