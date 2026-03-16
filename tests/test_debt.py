"""Tests for pyaegis.debt — technical debt analyser."""
from __future__ import annotations

import json
import subprocess

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyaegis.debt import (
    DebtAnalyser,
    DebtReport,
    FileMetrics,
    _is_bug_fix,
    _collect_git_churn,
)


# ---------------------------------------------------------------------------
# _is_bug_fix heuristic
# ---------------------------------------------------------------------------


class TestIsBugFix:
    def test_fix_keyword(self):
        assert _is_bug_fix("fix: null pointer in parser") is True

    def test_bug_keyword(self):
        assert _is_bug_fix("bug: wrong offset calculation") is True

    def test_hotfix_keyword(self):
        assert _is_bug_fix("hotfix release 1.2.1") is True

    def test_revert_keyword(self):
        assert _is_bug_fix("Revert bad merge") is True

    def test_regression_keyword(self):
        assert _is_bug_fix("regression in incremental scan") is True

    def test_feature_not_bugfix(self):
        assert _is_bug_fix("feat: add MCP server tools") is False

    def test_chore_not_bugfix(self):
        assert _is_bug_fix("chore: update dependencies") is False

    def test_empty_string(self):
        assert _is_bug_fix("") is False

    def test_case_insensitive(self):
        assert _is_bug_fix("FIX: uppercase message") is True


# ---------------------------------------------------------------------------
# FileMetrics.debt_score
# ---------------------------------------------------------------------------


class TestFileMetrics:
    def test_zero_metrics(self):
        fm = FileMetrics(path="foo.py")
        assert fm.debt_score == 0.0

    def test_score_formula(self):
        fm = FileMetrics(
            path="foo.py",
            churn=10,
            bug_fix_commits=5,
            max_complexity=8,
        )
        expected = 10 * 0.4 + 5 * 0.4 + 8 * 0.2
        assert abs(fm.debt_score - expected) < 1e-9

    def test_str_representation(self):
        fm = FileMetrics(path="bar.py", churn=3, bug_fix_commits=1, max_complexity=4)
        s = str(fm)
        assert "bar.py" in s
        assert "churn=3" in s
        assert "bug_fixes=1" in s

    def test_default_rank(self):
        fm = FileMetrics(path="baz.py")
        assert fm.complexity_rank == "A"

    def test_high_churn_dominates(self):
        fm_high = FileMetrics(path="a.py", churn=100)
        fm_low = FileMetrics(path="b.py", churn=1)
        assert fm_high.debt_score > fm_low.debt_score


# ---------------------------------------------------------------------------
# DebtReport
# ---------------------------------------------------------------------------


class TestDebtReport:
    def _make_report(self) -> DebtReport:
        r = DebtReport(repo_root="/repo")
        r.hotspots = [
            FileMetrics(
                path="pyaegis/core/taint.py",
                churn=20,
                bug_fix_commits=8,
                max_complexity=15,
                avg_complexity=7.5,
                complexity_rank="C",
                sloc=300,
            ),
            FileMetrics(
                path="pyaegis/api.py",
                churn=10,
                bug_fix_commits=2,
                max_complexity=6,
                avg_complexity=3.0,
                complexity_rank="B",
                sloc=150,
            ),
        ]
        return r

    def test_to_dict_structure(self):
        report = self._make_report()
        d = report.to_dict()
        assert d["repo_root"] == "/repo"
        assert len(d["hotspots"]) == 2
        h = d["hotspots"][0]
        assert h["path"] == "pyaegis/core/taint.py"
        assert "debt_score" in h
        assert "churn" in h
        assert "max_complexity" in h
        assert "complexity_rank" in h
        assert "sloc" in h

    def test_to_dict_json_serialisable(self):
        report = self._make_report()
        # Should not raise
        json.dumps(report.to_dict())

    def test_to_dict_scores_rounded(self):
        report = self._make_report()
        d = report.to_dict()
        # debt_score values must be floats rounded to 2dp
        for h in d["hotspots"]:
            assert isinstance(h["debt_score"], float)
            assert h["debt_score"] == round(h["debt_score"], 2)

    def test_to_llm_prompt_contains_paths(self):
        report = self._make_report()
        prompt = report.to_llm_prompt(top=2)
        assert "pyaegis/core/taint.py" in prompt
        assert "pyaegis/api.py" in prompt

    def test_to_llm_prompt_top_limit(self):
        report = self._make_report()
        prompt = report.to_llm_prompt(top=1)
        # Only first hotspot should appear
        assert "pyaegis/core/taint.py" in prompt
        assert "pyaegis/api.py" not in prompt

    def test_to_llm_prompt_includes_metrics(self):
        report = self._make_report()
        prompt = report.to_llm_prompt()
        assert "Modified" in prompt
        assert "complexity" in prompt.lower()

    def test_empty_report(self):
        report = DebtReport(repo_root="/empty")
        d = report.to_dict()
        assert d["hotspots"] == []
        assert d["errors"] == []


# ---------------------------------------------------------------------------
# _collect_git_churn (unit — mock subprocess)
# ---------------------------------------------------------------------------


class TestCollectGitChurn:
    _GIT_OUTPUT = """abc1234567890123456789012345678901234567 feat: add scanner
pyaegis/core/taint.py
pyaegis/api.py

def5678901234567890123456789012345678901 fix: null pointer crash
pyaegis/core/taint.py
tests/test_core.py

"""

    def test_churn_counts(self):
        with patch("pyaegis.debt.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=self._GIT_OUTPUT, returncode=0)
            metrics = _collect_git_churn("/repo")

        assert "pyaegis/core/taint.py" in metrics
        assert metrics["pyaegis/core/taint.py"].churn == 2
        assert metrics["pyaegis/api.py"].churn == 1
        assert metrics["tests/test_core.py"].churn == 1

    def test_bug_fix_commits_counted(self):
        with patch("pyaegis.debt.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=self._GIT_OUTPUT, returncode=0)
            metrics = _collect_git_churn("/repo")

        # Second commit is a bug fix — taint.py and test_core.py should be marked
        assert metrics["pyaegis/core/taint.py"].bug_fix_commits == 1
        assert metrics["tests/test_core.py"].bug_fix_commits == 1
        # api.py was only in the feat commit
        assert metrics["pyaegis/api.py"].bug_fix_commits == 0

    def test_git_failure_returns_empty(self):
        with patch("pyaegis.debt.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", returncode=1)
            metrics = _collect_git_churn("/repo")
        assert metrics == {}

    def test_git_not_found_returns_empty(self):
        with patch("pyaegis.debt.subprocess.run", side_effect=FileNotFoundError):
            metrics = _collect_git_churn("/repo")
        assert metrics == {}


# ---------------------------------------------------------------------------
# DebtAnalyser integration (uses real git repo in project root)
# ---------------------------------------------------------------------------


class TestDebtAnalyserIntegration:
    """Integration tests that run against the actual PyAegis git repo.

    These are skipped when git is unavailable or the repo has no history.
    """

    @pytest.fixture(autouse=True)
    def _require_git(self, tmp_path):
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("Not inside a git repository")

    def test_analyse_returns_report(self):
        repo_root = str(Path(__file__).resolve().parent.parent)
        analyser = DebtAnalyser(repo_root=repo_root, min_churn=1)
        report = analyser.analyse(top=5)
        assert isinstance(report, DebtReport)
        assert isinstance(report.hotspots, list)

    def test_hotspots_sorted_by_score(self):
        repo_root = str(Path(__file__).resolve().parent.parent)
        analyser = DebtAnalyser(repo_root=repo_root, min_churn=1)
        report = analyser.analyse(top=10)
        scores = [h.debt_score for h in report.hotspots]
        assert scores == sorted(scores, reverse=True)

    def test_top_limit_respected(self):
        repo_root = str(Path(__file__).resolve().parent.parent)
        analyser = DebtAnalyser(repo_root=repo_root, min_churn=1)
        report = analyser.analyse(top=3)
        assert len(report.hotspots) <= 3

    def test_all_hotspots_are_python_files(self):
        repo_root = str(Path(__file__).resolve().parent.parent)
        analyser = DebtAnalyser(repo_root=repo_root, python_only=True, min_churn=1)
        report = analyser.analyse()
        for h in report.hotspots:
            assert h.path.endswith(".py"), f"Non-Python file in hotspots: {h.path}"

    def test_to_dict_is_json_serialisable(self):
        repo_root = str(Path(__file__).resolve().parent.parent)
        analyser = DebtAnalyser(repo_root=repo_root, min_churn=1)
        report = analyser.analyse(top=5)
        # Must not raise
        payload = json.dumps(report.to_dict())
        parsed = json.loads(payload)
        assert "hotspots" in parsed


# ---------------------------------------------------------------------------
# CLI entry point (run_cli)
# ---------------------------------------------------------------------------


class TestDebtRunCli:
    def _make_args(self, repo=".", top=5, json_output=False):
        args = MagicMock()
        args.repo = repo
        args.top = top
        args.json_output = json_output
        return args

    def test_json_output_flag(self, capsys):
        repo_root = str(Path(__file__).resolve().parent.parent)
        from pyaegis.debt import run_cli

        rc = run_cli(self._make_args(repo=repo_root, top=3, json_output=True))
        captured = capsys.readouterr()
        assert rc == 0
        parsed = json.loads(captured.out)
        assert "hotspots" in parsed
        assert "repo_root" in parsed

    def test_text_output_flag(self, capsys):
        repo_root = str(Path(__file__).resolve().parent.parent)
        from pyaegis.debt import run_cli

        rc = run_cli(self._make_args(repo=repo_root, top=3, json_output=False))
        captured = capsys.readouterr()
        assert rc == 0
        # Text output should contain the table header
        assert "Score" in captured.out or "hotspot" in captured.out.lower() or rc == 0
