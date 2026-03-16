"""Tests for pyaegis.rag -- local RAG engine."""
from __future__ import annotations

import textwrap
from pathlib import Path

from pyaegis.rag import CodeRAG, _chunk_file, _cosine_similarity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_py(tmp_path: Path, name: str, src: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _chunk_file
# ---------------------------------------------------------------------------


def test_chunk_file_functions(tmp_path):
    f = _write_py(
        tmp_path,
        "sample.py",
        (
            "def foo(x):\n"
            "    # Foo does stuff.\n"
            "    return x + 1\n"
            "\n"
            "def bar():\n"
            "    pass\n"
        ),
    )
    chunks = _chunk_file(str(f))
    names = [c.name for c in chunks]
    assert "foo" in names
    assert "bar" in names
    for c in chunks:
        assert c.kind == "function"
        assert c.file_path == str(f)
        assert c.chunk_id


def test_chunk_file_class(tmp_path):
    f = _write_py(
        tmp_path,
        "cls.py",
        (
            "class MyClass:\n"
            "    # A class.\n"
            "    def method(self):\n"
            "        pass\n"
        ),
    )
    chunks = _chunk_file(str(f))
    kinds = {c.kind for c in chunks}
    assert "class" in kinds


def test_chunk_file_nonexistent():
    chunks = _chunk_file("/does/not/exist.py")
    assert chunks == []


def test_chunk_file_syntax_error(tmp_path):
    f = _write_py(tmp_path, "bad.py", "def foo(:\n    pass\n")
    chunks = _chunk_file(str(f))
    assert isinstance(chunks, list)


# ---------------------------------------------------------------------------
# _cosine_similarity
# ---------------------------------------------------------------------------


def test_cosine_similarity_identical():
    v = [1.0, 0.0, 0.0]
    assert abs(_cosine_similarity(v, v) - 1.0) < 1e-6


def test_cosine_similarity_orthogonal():
    v1 = [1.0, 0.0]
    v2 = [0.0, 1.0]
    assert abs(_cosine_similarity(v1, v2)) < 1e-6


def test_cosine_similarity_zero_vector():
    v = [0.0, 0.0, 0.0]
    assert _cosine_similarity(v, v) == 0.0


# ---------------------------------------------------------------------------
# CodeRAG -- basic index + search
# ---------------------------------------------------------------------------


def test_rag_index_and_search(tmp_path):
    f = _write_py(
        tmp_path,
        "auth.py",
        (
            "def authenticate_user(username, password):\n"
            "    # Check user credentials against the database.\n"
            "    return check_db(username, password)\n"
            "\n"
            "def logout(session):\n"
            "    # Invalidate the user session.\n"
            "    session.clear()\n"
        ),
    )
    rag = CodeRAG(db_path=":memory:")
    n = rag.index_file(str(f))
    assert n >= 2

    results = rag.search("user authentication credentials", top_k=3)
    assert len(results) > 0
    names = [r.chunk.name for r in results]
    assert "authenticate_user" in names
    rag.close()


def test_rag_index_directory(tmp_path):
    _write_py(tmp_path, "a.py", "def alpha(): pass\n")
    _write_py(tmp_path, "b.py", "def beta(): pass\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    _write_py(sub, "c.py", "def gamma(): pass\n")

    rag = CodeRAG(db_path=":memory:")
    files, chunks = rag.index_directory(str(tmp_path))
    assert files >= 2
    assert chunks >= 2
    stats = rag.stats()
    assert stats["indexed_files"] >= 2
    rag.close()


def test_rag_no_reindex_unchanged(tmp_path):
    f = _write_py(tmp_path, "stable.py", "def stable(): pass\n")
    db = tmp_path / "rag.sqlite"
    rag = CodeRAG(db_path=str(db))
    n1 = rag.index_file(str(f))
    n2 = rag.index_file(str(f))
    assert n1 > 0
    assert n2 == 0
    rag.close()


def test_rag_force_reindex(tmp_path):
    f = _write_py(tmp_path, "x.py", "def x(): pass\n")
    db = tmp_path / "rag.sqlite"
    rag = CodeRAG(db_path=str(db))
    rag.index_file(str(f))
    n = rag.index_file(str(f), force=True)
    assert n > 0
    rag.close()


def test_rag_kind_filter(tmp_path):
    f = _write_py(
        tmp_path,
        "mixed.py",
        ("class Foo:\n" "    pass\n" "\n" "def bar():\n" "    pass\n"),
    )
    rag = CodeRAG(db_path=":memory:")
    rag.index_file(str(f))
    results = rag.search("foo bar", top_k=10, kind_filter="function")
    for r in results:
        assert r.chunk.kind == "function"
    rag.close()


def test_rag_build_context(tmp_path):
    f = _write_py(tmp_path, "ctx.py", "def hello(): pass\n")
    rag = CodeRAG(db_path=":memory:")
    rag.index_file(str(f))
    results = rag.search("hello", top_k=1)
    ctx = rag.build_context(results, max_chars=5000)
    assert "hello" in ctx
    rag.close()


def test_rag_stats_empty():
    rag = CodeRAG(db_path=":memory:")
    s = rag.stats()
    assert s["total_chunks"] == 0
    assert s["indexed_files"] == 0
    rag.close()


def test_rag_context_manager(tmp_path):
    f = _write_py(tmp_path, "cm.py", "def cm(): pass\n")
    with CodeRAG(db_path=":memory:") as rag:
        rag.index_file(str(f))
        results = rag.search("cm")
        assert isinstance(results, list)
