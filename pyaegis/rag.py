"""
PyAegis Local RAG (Retrieval-Augmented Generation) Engine
=========================================================

零运维本地语义搜索，基于 sqlite-vec 扩展。
所有代码块、向量索引和查询历史均存储在单个 .sqlite 文件中。

功能：
- 索引 Python 代码块（函数/类级别）
- 语义相似度搜索（基于文本向量）
- 为 LLM 提供相关代码上下文
- 支持增量更新（文件变更时只重建变更部分）

依赖：
    pip install pyaegis[rag]  # sqlite-vec + 可选 embedding 后端

用法::

    from pyaegis.rag import CodeRAG
    rag = CodeRAG(db_path=".pyaegis_rag.sqlite")
    rag.index_directory("src/")
    results = rag.search("SQL injection via user input", top_k=5)
    context = rag.build_context(results)
"""

from __future__ import annotations

import ast
import hashlib
import os
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

try:
    import sqlite_vec

    _SQLITE_VEC_AVAILABLE = True
except ImportError:
    _SQLITE_VEC_AVAILABLE = False

# Embedding dimension for simple TF-IDF-style bag-of-words fallback
_FALLBACK_DIM = 128

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CodeChunk:
    """A unit of indexable code (function, class, or module-level block)."""

    chunk_id: str  # sha256 of (file_path + name + source)
    file_path: str
    name: str  # function/class name or '<module>'
    kind: str  # 'function' | 'class' | 'module'
    source: str  # raw source text
    start_line: int
    end_line: int
    docstring: str = ""


@dataclass
class SearchResult:
    """A single RAG search result."""

    chunk: CodeChunk
    score: float  # cosine similarity (higher = more relevant)

    def __str__(self) -> str:
        return (
            f"[{self.score:.3f}] {self.chunk.file_path}:{self.chunk.start_line} "
            f"{self.chunk.kind} {self.chunk.name}"
        )


# ---------------------------------------------------------------------------
# Embedding backend
# ---------------------------------------------------------------------------


class _BagOfWordsEmbedder:
    """
    Zero-dependency fallback embedder.
    Produces a fixed-length vector from keyword frequency.
    Not as good as a real model but works offline with no API.
    """

    # Security-domain vocabulary for better relevance
    _VOCAB = [
        "input",
        "request",
        "user",
        "query",
        "param",
        "data",
        "sql",
        "exec",
        "eval",
        "os",
        "subprocess",
        "shell",
        "command",
        "file",
        "path",
        "read",
        "write",
        "open",
        "import",
        "pickle",
        "yaml",
        "json",
        "xml",
        "html",
        "escape",
        "sanitize",
        "validate",
        "auth",
        "password",
        "token",
        "secret",
        "key",
        "hash",
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "cookie",
        "session",
        "csrf",
        "xss",
        "injection",
        "taint",
        "source",
        "sink",
        "sanitizer",
        "return",
        "raise",
        "exception",
        "error",
        "log",
        "debug",
        "warning",
        "http",
        "url",
        "redirect",
        "response",
        "header",
        "body",
        "payload",
        "format",
        "string",
        "bytes",
        "encode",
        "decode",
        "base64",
        "random",
        "seed",
        "sleep",
        "thread",
        "process",
        "network",
        "socket",
        "connect",
        "send",
        "recv",
        "bind",
        "listen",
        "accept",
        "class",
        "def",
        "self",
        "super",
        "init",
        "call",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "flask",
        "django",
        "fastapi",
        "route",
        "view",
        "model",
        "database",
        "cursor",
        "execute",
        "fetch",
        "commit",
        "rollback",
        "transaction",
        "admin",
        "permission",
        "role",
        "access",
        "policy",
        "rule",
        "check",
        "assert",
        "test",
        "mock",
        "patch",
        "fixture",
        "pytest",
        "unittest",
        "coverage",
        "scan",
        "analyze",
        "detect",
        "report",
        "finding",
        "severity",
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "cwe",
        "owasp",
        "vuln",
        "exploit",
        "attack",
        "mitigation",
        "fix",
        "remediation",
        "patch",
    ]

    _VOCAB_INDEX = {w: i for i, w in enumerate(_VOCAB)}
    DIM = len(_VOCAB)

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.DIM
        words = text.lower().split()
        for w in words:
            # Exact match
            if w in self._VOCAB_INDEX:
                vec[self._VOCAB_INDEX[w]] += 1.0
            # Partial match (substring)
            else:
                for vocab_word, idx in self._VOCAB_INDEX.items():
                    if vocab_word in w or w in vocab_word:
                        vec[idx] += 0.3
        # L2 normalise
        norm = sum(x * x for x in vec) ** 0.5
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec


_DEFAULT_EMBEDDER = _BagOfWordsEmbedder()
_EMBED_DIM = _BagOfWordsEmbedder.DIM


# ---------------------------------------------------------------------------
# Code chunker
# ---------------------------------------------------------------------------


def _chunk_file(file_path: str) -> List[CodeChunk]:
    """Extract function/class-level chunks from a Python file."""
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    lines = source.splitlines()
    chunks: List[CodeChunk] = []

    def _get_source(node: ast.AST) -> str:
        start = node.lineno - 1  # type: ignore[attr-defined]
        end = node.end_lineno  # type: ignore[attr-defined]
        return "\n".join(lines[start:end])

    def _get_docstring(node: ast.AST) -> str:
        try:
            return ast.get_docstring(node) or ""  # type: ignore[arg-type]
        except Exception:
            return ""

    def _make_id(file_path: str, name: str, src: str) -> str:
        h = hashlib.sha256(f"{file_path}:{name}:{src}".encode()).hexdigest()
        return h[:16]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            src = _get_source(node)
            doc = _get_docstring(node)
            chunks.append(
                CodeChunk(
                    chunk_id=_make_id(file_path, node.name, src),
                    file_path=file_path,
                    name=node.name,
                    kind="function",
                    source=src,
                    start_line=node.lineno,
                    end_line=node.end_lineno,  # type: ignore[attr-defined]
                    docstring=doc,
                )
            )
        elif isinstance(node, ast.ClassDef):
            src = _get_source(node)
            doc = _get_docstring(node)
            chunks.append(
                CodeChunk(
                    chunk_id=_make_id(file_path, node.name, src),
                    file_path=file_path,
                    name=node.name,
                    kind="class",
                    source=src,
                    start_line=node.lineno,
                    end_line=node.end_lineno,  # type: ignore[attr-defined]
                    docstring=doc,
                )
            )

    # If no functions/classes, index the whole file as one chunk
    if not chunks:
        chunks.append(
            CodeChunk(
                chunk_id=_make_id(file_path, "<module>", source),
                file_path=file_path,
                name="<module>",
                kind="module",
                source=source[:4000],  # cap at 4KB
                start_line=1,
                end_line=len(lines),
            )
        )

    return chunks


# ---------------------------------------------------------------------------
# Vector serialisation helpers
# ---------------------------------------------------------------------------


def _serialize_vec(vec: List[float]) -> bytes:
    """Pack a list of floats to BLOB (little-endian float32)."""
    return struct.pack(f"{len(vec)}f", *vec)


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# CodeRAG
# ---------------------------------------------------------------------------


class CodeRAG:
    """
    Local-first RAG engine for Python codebases.

    Uses sqlite-vec for vector storage when available; falls back to
    pure-Python cosine similarity over SQLite BLOBs otherwise.
    """

    def __init__(
        self,
        db_path: str = ".pyaegis_rag.sqlite",
        embedder=None,
    ) -> None:
        self.db_path = db_path
        self.embedder = embedder or _DEFAULT_EMBEDDER
        self._dim = getattr(self.embedder, "DIM", _EMBED_DIM)
        self._conn = self._open_db()

    def _open_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        if _SQLITE_VEC_AVAILABLE:
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            conn.enable_load_extension(False)
        conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema(conn)
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chunks (
                chunk_id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                start_line INTEGER,
                end_line INTEGER,
                docstring TEXT,
                file_mtime REAL,
                embedding BLOB
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_file ON chunks(file_path)")
        # sqlite-vec virtual table for ANN search
        if _SQLITE_VEC_AVAILABLE:
            conn.execute(
                f"""
                CREATE VIRTUAL TABLE IF NOT EXISTS vec_chunks
                USING vec0(chunk_id TEXT PRIMARY KEY, embedding float[{self._dim}])
                """
            )
        conn.commit()

    def _file_mtime(self, file_path: str) -> float:
        try:
            return os.path.getmtime(file_path)
        except OSError:
            return 0.0

    def _is_stale(self, file_path: str) -> bool:
        """Return True if the file has changed since last index."""
        cur = self._conn.execute(
            "SELECT MAX(file_mtime) FROM chunks WHERE file_path = ?",
            (file_path,),
        )
        row = cur.fetchone()
        if not row or row[0] is None:
            return True
        return self._file_mtime(file_path) > row[0]

    def _remove_file(self, file_path: str) -> None:
        """Remove all chunks for a file."""
        if _SQLITE_VEC_AVAILABLE:
            ids = [
                r[0]
                for r in self._conn.execute(
                    "SELECT chunk_id FROM chunks WHERE file_path = ?", (file_path,)
                )
            ]
            for cid in ids:
                self._conn.execute("DELETE FROM vec_chunks WHERE chunk_id = ?", (cid,))
        self._conn.execute("DELETE FROM chunks WHERE file_path = ?", (file_path,))

    def index_file(self, file_path: str, force: bool = False) -> int:
        """Index a single Python file. Returns number of chunks indexed."""
        if not force and not self._is_stale(file_path):
            return 0
        self._remove_file(file_path)
        chunks = _chunk_file(file_path)
        mtime = self._file_mtime(file_path)
        for chunk in chunks:
            text = f"{chunk.name} {chunk.docstring} {chunk.source}"
            vec = self.embedder.embed(text)
            blob = _serialize_vec(vec)
            self._conn.execute(
                """
                INSERT OR REPLACE INTO chunks
                (chunk_id, file_path, name, kind, source, start_line, end_line, docstring, file_mtime, embedding)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chunk.chunk_id,
                    chunk.file_path,
                    chunk.name,
                    chunk.kind,
                    chunk.source,
                    chunk.start_line,
                    chunk.end_line,
                    chunk.docstring,
                    mtime,
                    blob,
                ),
            )
            if _SQLITE_VEC_AVAILABLE:
                self._conn.execute(
                    "DELETE FROM vec_chunks WHERE chunk_id = ?",
                    (chunk.chunk_id,),
                )
                self._conn.execute(
                    "INSERT INTO vec_chunks(chunk_id, embedding) VALUES (?, ?)",
                    (chunk.chunk_id, blob),
                )
        self._conn.commit()
        return len(chunks)

    def index_directory(
        self,
        directory: str,
        recursive: bool = True,
        force: bool = False,
    ) -> Tuple[int, int]:
        """Index all Python files in a directory.

        Returns (files_processed, chunks_indexed).
        """
        total_files = 0
        total_chunks = 0
        pattern = "**/*.py" if recursive else "*.py"
        for py_file in Path(directory).glob(pattern):
            n = self.index_file(str(py_file), force=force)
            if n > 0:
                total_files += 1
                total_chunks += n
        return total_files, total_chunks

    def search(
        self,
        query: str,
        top_k: int = 5,
        kind_filter: Optional[str] = None,
    ) -> List[SearchResult]:
        """Search for code chunks semantically similar to the query."""
        query_vec = self.embedder.embed(query)

        if _SQLITE_VEC_AVAILABLE:
            blob = _serialize_vec(query_vec)
            rows = self._conn.execute(
                """
                SELECT v.chunk_id, v.distance
                FROM vec_chunks v
                ORDER BY vec_distance_cosine(v.embedding, ?) ASC
                LIMIT ?
                """,
                (blob, top_k * 3),
            ).fetchall()
            chunk_ids = [r[0] for r in rows]
            if not chunk_ids:
                return []
            placeholders = ",".join(["?"] * len(chunk_ids))
            meta_rows = self._conn.execute(
                f"SELECT chunk_id, file_path, name, kind, source, start_line, end_line, docstring "
                f"FROM chunks WHERE chunk_id IN ({placeholders})",
                chunk_ids,
            ).fetchall()
            meta_map = {r[0]: r for r in meta_rows}
            results = []
            for cid, dist in rows:
                if cid not in meta_map:
                    continue
                r = meta_map[cid]
                chunk = CodeChunk(
                    chunk_id=r[0],
                    file_path=r[1],
                    name=r[2],
                    kind=r[3],
                    source=r[4],
                    start_line=r[5],
                    end_line=r[6],
                    docstring=r[7] or "",
                )
                if kind_filter and chunk.kind != kind_filter:
                    continue
                score = max(0.0, 1.0 - (dist or 0.0))
                results.append(SearchResult(chunk=chunk, score=score))
            return sorted(results, key=lambda x: x.score, reverse=True)[:top_k]
        else:
            # Pure-Python fallback: load all embeddings and compute cosine similarity
            rows = self._conn.execute(
                "SELECT chunk_id, file_path, name, kind, source, start_line, end_line, docstring, embedding FROM chunks"
            ).fetchall()
            results = []
            for row in rows:
                cid, fp, name, kind, source, sl, el, doc, blob = row
                if kind_filter and kind != kind_filter:
                    continue
                if blob is None:
                    continue
                n = len(blob) // 4
                stored_vec = list(struct.unpack(f"{n}f", blob))
                score = _cosine_similarity(query_vec, stored_vec)
                chunk = CodeChunk(
                    chunk_id=cid,
                    file_path=fp,
                    name=name,
                    kind=kind,
                    source=source,
                    start_line=sl,
                    end_line=el,
                    docstring=doc or "",
                )
                results.append(SearchResult(chunk=chunk, score=score))
            results.sort(key=lambda x: x.score, reverse=True)
            return results[:top_k]

    def build_context(
        self,
        results: List[SearchResult],
        max_chars: int = 4000,
    ) -> str:
        """Build a formatted context string for LLM consumption."""
        parts = []
        total = 0
        for res in results:
            chunk = res.chunk
            header = f"# {chunk.file_path}:{chunk.start_line} ({chunk.kind} {chunk.name}, score={res.score:.3f})\n"
            body = chunk.source
            entry = header + body + "\n"
            if total + len(entry) > max_chars:
                break
            parts.append(entry)
            total += len(entry)
        return "\n".join(parts)

    def stats(self) -> dict:
        """Return index statistics."""
        total = self._conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        by_kind = {
            row[0]: row[1]
            for row in self._conn.execute(
                "SELECT kind, COUNT(*) FROM chunks GROUP BY kind"
            ).fetchall()
        }
        files = self._conn.execute(
            "SELECT COUNT(DISTINCT file_path) FROM chunks"
        ).fetchone()[0]
        return {
            "total_chunks": total,
            "indexed_files": files,
            "by_kind": by_kind,
            "db_path": self.db_path,
            "sqlite_vec": _SQLITE_VEC_AVAILABLE,
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CodeRAG":
        return self

    def __exit__(self, *_) -> None:
        self.close()
