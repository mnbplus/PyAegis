"""PyAegis Technical Debt Analyser.

Combines Git churn metrics with cyclomatic complexity (via radon) to surface
high-risk code hotspots.  The resulting DebtReport can be fed directly to an
LLM for long-term refactoring guidance.

Usage (programmatic)::

    from pyaegis.debt import DebtAnalyser
    report = DebtAnalyser(repo_root=".").analyse()
    for h in report.hotspots[:5]:
        print(h)

Usage (CLI)::

    pyaegis debt [--repo .] [--top 10] [--json]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# radon is an optional dependency; guard gracefully so the rest of PyAegis
# still imports even if the user hasn't installed it yet.
try:
    from radon.complexity import cc_rank, cc_visit
    from radon.raw import analyze as raw_analyze

    _RADON_AVAILABLE = True
except ImportError:  # pragma: no cover
    _RADON_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FileMetrics:
    """Aggregated metrics for a single source file."""

    path: str
    """Repo-relative path."""

    churn: int = 0
    """Number of commits that touched this file."""

    bug_fix_commits: int = 0
    """Commits whose message matches a bug-fix heuristic."""

    max_complexity: int = 0
    """Highest cyclomatic complexity of any function/method in the file."""

    avg_complexity: float = 0.0
    """Average cyclomatic complexity across all functions/methods."""

    complexity_rank: str = "A"
    """radon rank for max_complexity (A–F)."""

    sloc: int = 0
    """Source lines of code."""

    @property
    def debt_score(self) -> float:
        """Composite risk score.  Higher = more technical debt.

        Formula: churn * 0.4 + bug_fix_commits * 0.4 + max_complexity * 0.2
        Weights are intentionally simple and tunable.
        """
        return self.churn * 0.4 + self.bug_fix_commits * 0.4 + self.max_complexity * 0.2

    def __str__(self) -> str:
        return (
            f"{self.path}  "
            f"score={self.debt_score:.1f}  "
            f"churn={self.churn}  "
            f"bug_fixes={self.bug_fix_commits}  "
            f"max_cc={self.max_complexity}({self.complexity_rank})  "
            f"sloc={self.sloc}"
        )


@dataclass
class DebtReport:
    """Result of a full debt analysis run."""

    repo_root: str
    hotspots: List[FileMetrics] = field(default_factory=list)
    """Files sorted by debt_score descending."""

    errors: List[str] = field(default_factory=list)
    """Non-fatal errors encountered during analysis."""

    def to_dict(self) -> dict:
        return {
            "repo_root": self.repo_root,
            "hotspots": [
                {
                    "path": h.path,
                    "debt_score": round(h.debt_score, 2),
                    "churn": h.churn,
                    "bug_fix_commits": h.bug_fix_commits,
                    "max_complexity": h.max_complexity,
                    "avg_complexity": round(h.avg_complexity, 2),
                    "complexity_rank": h.complexity_rank,
                    "sloc": h.sloc,
                }
                for h in self.hotspots
            ],
            "errors": self.errors,
        }

    def to_llm_prompt(self, top: int = 5) -> str:
        """Build a structured prompt context for LLM-based refactoring advice."""
        lines = [
            "The following files in this Python codebase have been identified as "
            "high-risk technical debt hotspots, ranked by a composite score that "
            "combines Git churn frequency, bug-fix commit density, and cyclomatic "
            "complexity.  Please provide specific, actionable long-term refactoring "
            "strategies for each file.",
            "",
        ]
        for i, h in enumerate(self.hotspots[:top], 1):
            lines.append(
                f"{i}. {h.path}\n"
                f"   - Modified {h.churn} times in Git history\n"
                f"   - {h.bug_fix_commits} commits appear to be bug fixes\n"
                f"   - Max cyclomatic complexity: {h.max_complexity} (rank {h.complexity_rank})\n"
                f"   - SLOC: {h.sloc}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Bug-fix commit heuristic
# ---------------------------------------------------------------------------

_BUG_KEYWORDS = (
    "fix",
    "bug",
    "error",
    "issue",
    "crash",
    "defect",
    "patch",
    "hotfix",
    "revert",
    "regression",
)


def _is_bug_fix(message: str) -> bool:
    """Return True if the commit message looks like a bug fix."""
    msg = message.lower()
    return any(kw in msg for kw in _BUG_KEYWORDS)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _run_git(args: List[str], cwd: str) -> Tuple[str, int]:
    """Run a git command, return (stdout, returncode)."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout, result.returncode
    except FileNotFoundError:
        return "", 1


def _collect_git_churn(repo_root: str) -> Dict[str, FileMetrics]:
    """Return a dict mapping repo-relative path -> FileMetrics with churn data."""
    metrics: Dict[str, FileMetrics] = {}

    # --follow-renames tracks files across renames; --diff-filter=d excludes deletions
    stdout, rc = _run_git(
        ["log", "--pretty=format:%H %s", "--name-only", "--diff-filter=d"],
        cwd=repo_root,
    )
    if rc != 0 or not stdout.strip():
        return metrics

    current_is_bug_fix = False
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Lines that start with a 40-char hex hash are commit header lines
        parts = line.split(" ", 1)
        if len(parts[0]) == 40 and all(c in "0123456789abcdef" for c in parts[0]):
            msg = parts[1] if len(parts) > 1 else ""
            current_is_bug_fix = _is_bug_fix(msg)
        else:
            # This is a file path touched by the previous commit
            # Normalise to forward-slash repo-relative path
            norm = line.replace("\\", "/")
            if norm not in metrics:
                metrics[norm] = FileMetrics(path=norm)
            metrics[norm].churn += 1
            if current_is_bug_fix:
                metrics[norm].bug_fix_commits += 1

    return metrics


# ---------------------------------------------------------------------------
# Complexity helpers
# ---------------------------------------------------------------------------


def _collect_complexity(repo_root: str, metrics: Dict[str, FileMetrics]) -> List[str]:
    """Enrich FileMetrics with radon complexity data.  Returns list of error strings."""
    errors: List[str] = []
    if not _RADON_AVAILABLE:
        errors.append(
            "radon is not installed; complexity metrics skipped. "
            "Run: pip install radon"
        )
        return errors

    for rel_path, fm in metrics.items():
        if not rel_path.endswith(".py"):
            continue
        abs_path = os.path.join(repo_root, rel_path.replace("/", os.sep))
        if not os.path.isfile(abs_path):
            continue
        try:
            source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"Cannot read {rel_path}: {exc}")
            continue

        # Cyclomatic complexity
        try:
            blocks = cc_visit(source)
            if blocks:
                complexities = [b.complexity for b in blocks]
                fm.max_complexity = max(complexities)
                fm.avg_complexity = sum(complexities) / len(complexities)
                fm.complexity_rank = cc_rank(fm.max_complexity)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"cc_visit failed for {rel_path}: {exc}")

        # Raw metrics (SLOC)
        try:
            raw = raw_analyze(source)
            fm.sloc = raw.sloc
        except Exception as exc:  # noqa: BLE001
            errors.append(f"raw_analyze failed for {rel_path}: {exc}")

    return errors


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------


class DebtAnalyser:
    """Orchestrates git churn + complexity analysis to produce a DebtReport."""

    def __init__(
        self,
        repo_root: str = ".",
        python_only: bool = True,
        min_churn: int = 2,
    ) -> None:
        self.repo_root = str(Path(repo_root).resolve())
        self.python_only = python_only
        self.min_churn = min_churn

    def analyse(self, top: Optional[int] = None) -> DebtReport:
        """Run the full analysis and return a DebtReport.

        Args:
            top: If set, truncate hotspots list to this many entries.
        """
        report = DebtReport(repo_root=self.repo_root)

        # Step 1: Git churn
        metrics = _collect_git_churn(self.repo_root)

        # Step 2: Filter to Python files with sufficient churn
        if self.python_only:
            metrics = {
                k: v
                for k, v in metrics.items()
                if k.endswith(".py") and v.churn >= self.min_churn
            }
        else:
            metrics = {k: v for k, v in metrics.items() if v.churn >= self.min_churn}

        # Step 3: Complexity enrichment
        errors = _collect_complexity(self.repo_root, metrics)
        report.errors.extend(errors)

        # Step 4: Sort by debt score
        hotspots = sorted(metrics.values(), key=lambda m: m.debt_score, reverse=True)
        if top is not None:
            hotspots = hotspots[:top]
        report.hotspots = hotspots

        return report


# ---------------------------------------------------------------------------
# CLI entry point (called from cli.py via `pyaegis debt`)
# ---------------------------------------------------------------------------


def run_cli(args) -> int:  # noqa: ANN001
    """Entry point for `pyaegis debt` subcommand.

    args should have: repo (str), top (int), json_output (bool).
    """
    analyser = DebtAnalyser(repo_root=args.repo)
    report = analyser.analyse(top=args.top)

    if report.errors:
        for err in report.errors:
            print(f"[WARN] {err}", file=sys.stderr)

    if args.json_output:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        if not report.hotspots:
            print("No hotspots found (try lowering --min-churn).")
            return 0
        print(
            f"\nTop {len(report.hotspots)} technical debt hotspots in {report.repo_root}\n"
        )
        print(
            f"{'File':<55} {'Score':>6} {'Churn':>6} {'BugFix':>7} {'MaxCC':>6} {'Rank':>5} {'SLOC':>6}"
        )
        print("-" * 95)
        for h in report.hotspots:
            print(
                f"{h.path:<55} {h.debt_score:>6.1f} {h.churn:>6} "
                f"{h.bug_fix_commits:>7} {h.max_complexity:>6} {h.complexity_rank:>5} {h.sloc:>6}"
            )
        print()
        print("--- LLM Prompt Context ---")
        print(report.to_llm_prompt())

    return 0
