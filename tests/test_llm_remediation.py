"""Tests for LLMRemediationEngine (all LLM calls are mocked)."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from pyaegis.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="PYA-003",
        description="eval() called with user input",
        file_path="app.py",
        line_number=10,
        sink_context="eval(user_input)",
        severity="CRITICAL",
        source_var="user_input",
        sink_name="eval",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


SOURCE_CODE = """\
def handle(user_input):
    # line 1
    # line 2
    # line 3
    # line 4
    # line 5
    # line 6
    # line 7
    # line 8
    result = eval(user_input)
    return result
"""

SAMPLE_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -10,1 +10,2 @@
-    result = eval(user_input)
+    import ast
+    result = ast.literal_eval(user_input)
"""


# ---------------------------------------------------------------------------
# Fixture: patch openai.OpenAI so the import succeeds without the package
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _mock_openai(monkeypatch):
    """Ensure 'openai' is importable and OpenAI() is a controllable mock."""
    mock_openai_module = MagicMock()
    monkeypatch.setitem(sys.modules, "openai", mock_openai_module)
    yield mock_openai_module


# ---------------------------------------------------------------------------
# Import engine after mock is in place
# ---------------------------------------------------------------------------

def _get_engine(api_key="test-key", model="deepseek-chat"):
    # Re-import to pick up the monkeypatched openai
    import importlib
    import pyaegis.fixers as fixers_mod
    importlib.reload(fixers_mod)
    return fixers_mod.LLMRemediationEngine(api_key=api_key, model=model)


# ---------------------------------------------------------------------------
# Tests: __init__
# ---------------------------------------------------------------------------

class TestLLMRemediationEngineInit:
    def test_stores_model(self, _mock_openai):
        engine = _get_engine(model="gpt-4o")
        assert engine._model == "gpt-4o"

    def test_stores_default_model(self, _mock_openai):
        engine = _get_engine()
        assert engine._model == "deepseek-chat"

    def test_openai_client_created(self, _mock_openai):
        _get_engine(api_key="sk-abc")
        # OpenAI() constructor was called at least once (may be via reload)
        assert _mock_openai.OpenAI.called


# ---------------------------------------------------------------------------
# Tests: _extract_context
# ---------------------------------------------------------------------------

class TestExtractContext:
    def _get_cls(self):
        import pyaegis.fixers as fixers_mod
        return fixers_mod.LLMRemediationEngine

    def test_returns_numbered_lines(self):
        cls = self._get_cls()
        src = "\n".join(f"line{i}" for i in range(1, 21))
        ctx = cls._extract_context(src, line_number=10, context_lines=2)
        assert "   8 | line8" in ctx
        assert "  10 | line10" in ctx
        assert "  12 | line12" in ctx
        # lines outside window should not appear
        assert "line5" not in ctx

    def test_clamps_to_start(self):
        cls = self._get_cls()
        src = "a\nb\nc"
        ctx = cls._extract_context(src, line_number=1, context_lines=10)
        assert "   1 | a" in ctx

    def test_clamps_to_end(self):
        cls = self._get_cls()
        src = "a\nb\nc"
        ctx = cls._extract_context(src, line_number=3, context_lines=10)
        assert "   3 | c" in ctx


# ---------------------------------------------------------------------------
# Tests: _extract_diff
# ---------------------------------------------------------------------------

class TestExtractDiff:
    def _get_cls(self):
        import pyaegis.fixers as fixers_mod
        return fixers_mod.LLMRemediationEngine

    def test_strips_diff_fence(self):
        cls = self._get_cls()
        text = "```diff\n--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n```"
        result = cls._extract_diff(text)
        assert result.startswith("--- a/f.py")
        assert "```" not in result

    def test_strips_plain_fence(self):
        cls = self._get_cls()
        text = "```\n--- a/f.py\n+++ b/f.py\n```"
        result = cls._extract_diff(text)
        assert "---" in result

    def test_passthrough_raw_diff(self):
        cls = self._get_cls()
        text = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-old\n+new"
        assert cls._extract_diff(text) == text

    def test_passthrough_at_sign_start(self):
        cls = self._get_cls()
        text = "@@ -1,3 +1,3 @@\n context\n-old\n+new"
        result = cls._extract_diff(text)
        assert result.startswith("@@")

    def test_returns_stripped_text_when_no_diff(self):
        cls = self._get_cls()
        text = "   some explanation   "
        assert cls._extract_diff(text) == "some explanation"


# ---------------------------------------------------------------------------
# Tests: _build_user_prompt
# ---------------------------------------------------------------------------

class TestBuildUserPrompt:
    def _get_cls(self):
        import pyaegis.fixers as fixers_mod
        return fixers_mod.LLMRemediationEngine

    def test_contains_vuln_type(self):
        cls = self._get_cls()
        finding = _make_finding(rule_id="PYA-003")
        prompt = cls._build_user_prompt(finding, "10 | eval(x)")
        assert "code_injection" in prompt

    def test_contains_file_and_line(self):
        cls = self._get_cls()
        finding = _make_finding(file_path="vuln.py", line_number=42)
        prompt = cls._build_user_prompt(finding, "ctx")
        assert "vuln.py" in prompt
        assert "42" in prompt

    def test_contains_sink_and_source(self):
        cls = self._get_cls()
        finding = _make_finding(sink_name="eval", source_var="data")
        prompt = cls._build_user_prompt(finding, "ctx")
        assert "eval" in prompt
        assert "data" in prompt

    def test_contains_cwe(self):
        cls = self._get_cls()
        finding = _make_finding(rule_id="PYA-003")
        prompt = cls._build_user_prompt(finding, "ctx")
        assert "CWE-94" in prompt


# ---------------------------------------------------------------------------
# Tests: generate_fix — happy path
# ---------------------------------------------------------------------------

class TestGenerateFixHappyPath:
    def _build_engine_with_response(self, content: str):
        """Build an LLMRemediationEngine whose client returns *content*."""
        import importlib
        import pyaegis.fixers as fixers_mod
        importlib.reload(fixers_mod)

        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = content
        mock_client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )

        engine = fixers_mod.LLMRemediationEngine.__new__(fixers_mod.LLMRemediationEngine)
        engine._model = "deepseek-chat"
        engine._timeout = 60
        engine._client = mock_client
        return engine, mock_client

    def test_returns_diff_from_fenced_response(self):
        diff_body = "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-eval(x)\n+ast.literal_eval(x)"
        engine, _ = self._build_engine_with_response(
            f"```diff\n{diff_body}\n```"
        )
        finding = _make_finding()
        result = engine.generate_fix(finding, SOURCE_CODE)
        assert result is not None
        assert "ast.literal_eval" in result

    def test_returns_raw_diff_when_no_fence(self):
        diff_body = "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-eval(x)\n+safe(x)"
        engine, _ = self._build_engine_with_response(diff_body)
        finding = _make_finding()
        result = engine.generate_fix(finding, SOURCE_CODE)
        assert result is not None
        assert "safe(x)" in result

    def test_api_called_with_correct_model(self):
        engine, mock_client = self._build_engine_with_response(SAMPLE_DIFF)
        engine._model = "gpt-4o"
        finding = _make_finding()
        engine.generate_fix(finding, SOURCE_CODE)
        call_kwargs = mock_client.chat.completions.create.call_args
        assert call_kwargs[1]["model"] == "gpt-4o" or call_kwargs[0][0] == "gpt-4o" or \
               call_kwargs.kwargs.get("model") == "gpt-4o" or \
               "gpt-4o" in str(call_kwargs)

    def test_system_prompt_enforces_diff_only(self):
        engine, mock_client = self._build_engine_with_response(SAMPLE_DIFF)
        finding = _make_finding()
        engine.generate_fix(finding, SOURCE_CODE)
        messages = mock_client.chat.completions.create.call_args.kwargs["messages"]
        system_msg = next(m for m in messages if m["role"] == "system")
        content_lower = system_msg["content"].lower()
        assert "diff" in content_lower

    def test_temperature_zero(self):
        engine, mock_client = self._build_engine_with_response(SAMPLE_DIFF)
        finding = _make_finding()
        engine.generate_fix(finding, SOURCE_CODE)
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert kwargs.get("temperature") == 0.0


# ---------------------------------------------------------------------------
# Tests: generate_fix — empty / None response
# ---------------------------------------------------------------------------

class TestGenerateFixEmptyResponse:
    def _build_engine_with_response(self, content):
        import importlib
        import pyaegis.fixers as fixers_mod
        importlib.reload(fixers_mod)

        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = content
        mock_client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )

        engine = fixers_mod.LLMRemediationEngine.__new__(fixers_mod.LLMRemediationEngine)
        engine._model = "deepseek-chat"
        engine._timeout = 60
        engine._client = mock_client
        return engine

    def test_none_content_returns_none(self):
        engine = self._build_engine_with_response(None)
        result = engine.generate_fix(_make_finding(), SOURCE_CODE)
        assert result is None

    def test_empty_string_returns_none(self):
        engine = self._build_engine_with_response("")
        result = engine.generate_fix(_make_finding(), SOURCE_CODE)
        assert result is None

    def test_whitespace_only_returns_none(self):
        engine = self._build_engine_with_response("   \n  ")
        result = engine.generate_fix(_make_finding(), SOURCE_CODE)
        assert result is None


# ---------------------------------------------------------------------------
# Tests: generate_fix — error handling
# ---------------------------------------------------------------------------

class TestGenerateFixErrorHandling:
    def _build_engine_raising(self, exc):
        import importlib
        import pyaegis.fixers as fixers_mod
        importlib.reload(fixers_mod)

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = exc

        engine = fixers_mod.LLMRemediationEngine.__new__(fixers_mod.LLMRemediationEngine)
        engine._model = "deepseek-chat"
        engine._timeout = 60
        engine._client = mock_client
        return engine

    def test_network_timeout_returns_none(self):
        import importlib
        import pyaegis.fixers as fixers_mod
        importlib.reload(fixers_mod)
        engine = self._build_engine_raising(TimeoutError("timed out"))
        result = engine.generate_fix(_make_finding(), SOURCE_CODE)
        assert result is None

    def test_generic_api_error_returns_none(self):
        engine = self._build_engine_raising(RuntimeError("API error 500"))
        result = engine.generate_fix(_make_finding(), SOURCE_CODE)
        assert result is None

    def test_connection_error_returns_none(self):
        engine = self._build_engine_raising(ConnectionError("refused"))
        result = engine.generate_fix(_make_finding(), SOURCE_CODE)
        assert result is None


# ---------------------------------------------------------------------------
# Tests: CLI remediate --llm argument parsing
# ---------------------------------------------------------------------------

class TestCLIRemediateArgs:
    def _build_parser(self):
        import importlib
        import pyaegis.cli as cli_mod
        importlib.reload(cli_mod)
        return cli_mod._build_parser()

    def test_llm_flag_default_false(self):
        parser = self._build_parser()
        args = parser.parse_args(["remediate", "."])
        assert args.llm is False

    def test_llm_flag_enabled(self):
        parser = self._build_parser()
        args = parser.parse_args(["remediate", ".", "--llm"])
        assert args.llm is True

    def test_llm_model_default(self):
        parser = self._build_parser()
        args = parser.parse_args(["remediate", "."])
        assert args.llm_model == "deepseek-chat"

    def test_llm_model_custom(self):
        parser = self._build_parser()
        args = parser.parse_args(["remediate", ".", "--llm-model", "gpt-4o"])
        assert args.llm_model == "gpt-4o"

    def test_llm_base_url_default(self):
        parser = self._build_parser()
        args = parser.parse_args(["remediate", "."])
        assert "deepseek" in args.llm_base_url

    def test_llm_base_url_custom(self):
        parser = self._build_parser()
        args = parser.parse_args(
            ["remediate", ".", "--llm-base-url", "https://api.openai.com/v1"]
        )
        assert args.llm_base_url == "https://api.openai.com/v1"

    def test_apply_flag_default_false(self):
        parser = self._build_parser()
        args = parser.parse_args(["remediate", "."])
        assert args.apply is False

    def test_apply_flag_enabled(self):
        parser = self._build_parser()
        args = parser.parse_args(["remediate", ".", "--apply"])
        assert args.apply is True


# ---------------------------------------------------------------------------
# Tests: CLI remediate --llm missing key
# ---------------------------------------------------------------------------

class TestCLIRemediateMissingKey:
    def test_missing_api_key_returns_exit_2(self, monkeypatch, tmp_path):
        """--llm without PYAEGIS_LLM_KEY should exit with code 2."""
        import pyaegis.cli as cli_mod

        monkeypatch.delenv("PYAEGIS_LLM_KEY", raising=False)

        src = tmp_path / "vuln.py"
        src.write_text("x = 1\n", encoding="utf-8")

        # Inject a fake finding so remediate proceeds past the "no findings" check
        from pyaegis.models import Finding
        fake_finding = Finding(
            rule_id="PYA-003",
            description="eval called with user input",
            file_path=str(src),
            line_number=1,
            sink_context="eval(x)",
            severity="CRITICAL",
            source_var="x",
            sink_name="eval",
        )
        monkeypatch.setattr(
            cli_mod,
            "_run_taint_scan",
            lambda *a, **kw: ([], [fake_finding]),
        )

        args = cli_mod._build_parser().parse_args(
            ["remediate", str(src), "--llm"]
        )
        rc = cli_mod._cmd_remediate(args)
        assert rc == 2

    def test_with_api_key_creates_llm_engine(self, monkeypatch, tmp_path):
        """When PYAEGIS_LLM_KEY is set and openai is mocked, engine is created."""
        import importlib
        import sys

        # Mock openai before reloading modules
        mock_openai = MagicMock()
        monkeypatch.setitem(sys.modules, "openai", mock_openai)

        import pyaegis.fixers as fixers_mod
        import pyaegis.cli as cli_mod
        importlib.reload(fixers_mod)
        importlib.reload(cli_mod)

        monkeypatch.setenv("PYAEGIS_LLM_KEY", "sk-test")

        # Make generate_fix return None (no diff) to avoid file I/O
        mock_openai.OpenAI.return_value = MagicMock()
        captured_engine: list = []

        original_init = fixers_mod.LLMRemediationEngine.__init__

        def patched_init(self, api_key, model="deepseek-chat", base_url="https://api.deepseek.com/v1", timeout=60):
            original_init(self, api_key=api_key, model=model, base_url=base_url, timeout=timeout)
            captured_engine.append(self)

        monkeypatch.setattr(fixers_mod.LLMRemediationEngine, "__init__", patched_init)
        monkeypatch.setattr(cli_mod, "LLMRemediationEngine", fixers_mod.LLMRemediationEngine)

        src = tmp_path / "vuln.py"
        src.write_text("x = eval(input())\n", encoding="utf-8")

        args = cli_mod._build_parser().parse_args(
            ["remediate", str(src), "--llm", "--llm-model", "deepseek-chat"]
        )
        # May return 1 (findings) or 0 (no findings depending on taint) — just shouldn't be 2
        rc = cli_mod._cmd_remediate(args)
        assert rc != 2
