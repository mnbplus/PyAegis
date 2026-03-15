"""CLI incremental mode should include dependent files.

This test validates ROADMAP P4 behaviour:
- when a file changes, also re-scan files that import it.

We craft a repo where only a.py changes, but b.py becomes vulnerable because it
calls into a.py.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


def test_incremental_scans_dependents(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")

    # Commit 1: helper returns constant => should be safe.
    (repo / "a.py").write_text(
        """

def get_cmd():
    return 'safe'
""".lstrip(),
        encoding="utf-8",
    )
    (repo / "b.py").write_text(
        """
import os
from a import get_cmd

def run():
    os.system(get_cmd())
""".lstrip(),
        encoding="utf-8",
    )

    _git(repo, "add", "a.py", "b.py")
    _git(repo, "commit", "-m", "init")

    # Commit 2: only a.py changes; it now returns tainted input.
    (repo / "a.py").write_text(
        """

def get_cmd():
    return input()
""".lstrip(),
        encoding="utf-8",
    )

    _git(repo, "add", "a.py")
    _git(repo, "commit", "-m", "change helper")

    # Incremental scan should include b.py even though only a.py changed.
    # base-ref must be explicit because this repo is created in the test.
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyaegis.cli",
            "scan",
            str(repo),
            "--incremental",
            "--base-ref",
            "HEAD~1",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        cwd=str(repo),
    )

    assert result.returncode == 1
    # The finding should be in b.py where the sink is.
    assert "b.py" in result.stdout
    assert "os.system" in result.stdout
