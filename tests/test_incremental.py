"""Tests for pyaegis.core.incremental – git-diff based incremental scanning."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyaegis.core.incremental import get_changed_files, get_affected_files


# ---------------------------------------------------------------------------
# get_changed_files
# ---------------------------------------------------------------------------

class TestGetChangedFiles:
    """Unit tests for get_changed_files()."""

    def test_returns_list_on_success(self, tmp_path: Path):
        """Happy-path: git returns two changed .py files."""
        mock_stdout = "pyaegis/core/parser.py\npyaegis/core/scanner.py\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=mock_stdout,
            )
            # Create dummy files so os.path.exists passes
            (tmp_path / "pyaegis" / "core").mkdir(parents=True)
            (tmp_path / "pyaegis" / "core" / "parser.py").touch()
            (tmp_path / "pyaegis" / "core" / "scanner.py").touch()

            result = get_changed_files(repo_path=str(tmp_path))

        assert len(result) == 2
        assert all(f.endswith(".py") for f in result)

    def test_filters_non_py_files(self, tmp_path: Path):
        """Non-.py files must be excluded from the result."""
        mock_stdout = "README.md\npyaegis/cli.py\nsetup.cfg\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_stdout)
            (tmp_path / "pyaegis").mkdir()
            (tmp_path / "pyaegis" / "cli.py").touch()

            result = get_changed_files(repo_path=str(tmp_path))

        assert len(result) == 1
        assert result[0].endswith("cli.py")

    def test_returns_empty_on_nonzero_returncode(self, tmp_path: Path):
        """If git exits non-zero, return empty list (not an exception)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=128, stdout="")
            result = get_changed_files(repo_path=str(tmp_path))
        assert result == []

    def test_returns_empty_on_subprocess_error(self, tmp_path: Path):
        """SubprocessError (e.g. git not found) must not propagate."""
        with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
            result = get_changed_files(repo_path=str(tmp_path))
        assert result == []

    def test_filters_missing_files(self, tmp_path: Path):
        """Files listed by git but not on disk (deleted) are excluded."""
        mock_stdout = "pyaegis/deleted.py\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_stdout)
            # Do NOT create the file – simulate a deletion race-condition
            result = get_changed_files(repo_path=str(tmp_path))
        assert result == []

    def test_passes_correct_git_args(self, tmp_path: Path):
        """Verify the exact git command issued."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            get_changed_files(base_ref="main", target_ref="feature", repo_path=str(tmp_path))

        call_args = mock_run.call_args
        cmd = call_args[0][0]  # positional first arg
        assert cmd == ["git", "diff", "--name-only", "--diff-filter=ACM", "main", "feature"]


# ---------------------------------------------------------------------------
# get_affected_files
# ---------------------------------------------------------------------------

class TestGetAffectedFiles:
    """Unit tests for get_affected_files()."""

    def _make_symbol_table(self, module_map: dict, imports: dict):
        """Build a minimal mock GlobalSymbolTable."""
        st = MagicMock()
        st.module_for_file.side_effect = lambda f: module_map.get(f)
        st.imports = imports
        return st

    def test_returns_changed_files_when_no_symbol_table(self, tmp_path: Path):
        changed = [str(tmp_path / "a.py")]
        result = get_affected_files(changed, symbol_table=None)
        assert result == set(changed)

    def test_includes_dependents(self, tmp_path: Path):
        """B.py imports from A (changed) → B.py is added to affected set."""
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        a.touch()
        b.touch()

        st = self._make_symbol_table(
            module_map={str(a): "mypackage.a"},
            imports={
                str(b): {"a": "mypackage.a"},
            },
        )

        result = get_affected_files([str(a)], symbol_table=st)
        assert str(a) in result
        assert str(b) in result

    def test_excludes_unrelated_files(self, tmp_path: Path):
        """C.py doesn't import A → should NOT appear in affected."""
        a = tmp_path / "a.py"
        c = tmp_path / "c.py"
        a.touch()
        c.touch()

        st = self._make_symbol_table(
            module_map={str(a): "mypackage.a"},
            imports={
                str(c): {"utils": "mypackage.utils"},
            },
        )

        result = get_affected_files([str(a)], symbol_table=st)
        assert str(c) not in result

    def test_skips_nonexistent_dependent_files(self, tmp_path: Path):
        """Dependent listed in symbol table but missing on disk → skip it."""
        a = tmp_path / "a.py"
        a.touch()
        ghost = str(tmp_path / "ghost.py")  # does NOT exist

        st = self._make_symbol_table(
            module_map={str(a): "pkg.a"},
            imports={
                ghost: {"a": "pkg.a"},
            },
        )

        result = get_affected_files([str(a)], symbol_table=st)
        assert ghost not in result

    def test_empty_changed_files(self, tmp_path: Path):
        st = self._make_symbol_table({}, {})
        result = get_affected_files([], symbol_table=st)
        assert result == set()
