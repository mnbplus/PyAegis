from __future__ import annotations
import subprocess
import os
from typing import List, Optional, Set


def get_changed_files(
    base_ref: str = "HEAD~1",
    target_ref: str = "HEAD",
    repo_path: str = ".",
) -> List[str]:
    """Get list of Python files changed between two git refs.

    Args:
        base_ref: Base git ref (default: HEAD~1, i.e. last commit)
        target_ref: Target ref (default: HEAD)
        repo_path: Path to git repository

    Returns:
        List of absolute paths to changed .py files
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACM", base_ref, target_ref],
            cwd=os.path.abspath(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return []
        files = [
            os.path.join(os.path.abspath(repo_path), f.strip())
            for f in result.stdout.splitlines()
            if f.strip().endswith(".py")
        ]
        return [f for f in files if os.path.exists(f)]
    except (subprocess.SubprocessError, FileNotFoundError):
        return []


def get_affected_files(
    changed_files: List[str],
    symbol_table,  # GlobalSymbolTable
    repo_path: str = ".",
) -> Set[str]:
    """Expand changed files to include files that import them (dependents).

    If file A.py changed, and B.py imports from A, B.py might also need re-scanning.
    """
    if symbol_table is None:
        return set(changed_files)

    changed_modules: Set[str] = set()
    for f in changed_files:
        mod = symbol_table.module_for_file(f)
        if mod:
            changed_modules.add(mod)

    affected = set(changed_files)
    # Find files that import any changed module
    for filepath, imports in symbol_table.imports.items():
        for local_name, qualname in imports.items():
            # Check if any part of the qualname matches a changed module
            for mod in changed_modules:
                if qualname.startswith(mod):
                    if os.path.exists(filepath):
                        affected.add(filepath)
                    break

    return affected
