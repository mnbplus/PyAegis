"""PyAegis built-in remediation suggestions (P3) + LLM-powered auto-remediation."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Optional

from .models import Finding


@dataclass(frozen=True)
class Remediation:
    vuln_type: str
    title: str
    snippet: str
    explanation: str = ""
    example_after: str = ""


class RemediationEngine:

    _REMEDIATIONS = {
        "command_injection": Remediation(
            vuln_type="command_injection",
            title="Avoid shell=True; use subprocess list form",
            snippet="import subprocess\nsubprocess.run(['echo', user_input], check=True)",
            explanation="Passing shell=True with user-controlled input allows attackers to inject arbitrary shell commands.",
            example_after="import subprocess\nsubprocess.run(['echo', user_input], check=True)",
        ),
        "sql_injection": Remediation(
            vuln_type="sql_injection",
            title="Use parameterized queries",
            snippet='query = "SELECT * FROM users WHERE name = %s"\ncursor.execute(query, (name,))',
            explanation="String-formatted SQL queries allow attackers to manipulate query logic via injected SQL.",
            example_after='query = "SELECT * FROM users WHERE name = %s"\ncursor.execute(query, (name,))',
        ),
        "code_injection": Remediation(
            vuln_type="code_injection",
            title="Replace eval with ast.literal_eval",
            snippet="import ast\nresult = ast.literal_eval(user_input)",
            explanation="eval() executes arbitrary Python code; use ast.literal_eval for safe literal parsing.",
            example_after="import ast\nresult = ast.literal_eval(user_input)",
        ),
        "hardcoded_secret": Remediation(
            vuln_type="hardcoded_secret",
            title="Load secrets from environment variables",
            snippet='import os\nAPI_KEY = os.environ.get("API_KEY", "")',
            explanation="Hardcoded secrets are exposed in source control; load them from environment variables instead.",
            example_after='import os\nAPI_KEY = os.environ.get("API_KEY", "")',
        ),
        "deserialization": Remediation(
            vuln_type="deserialization",
            title="Avoid pickle on untrusted data; prefer JSON",
            snippet="import json\nobj = json.loads(untrusted_text)",
            explanation="pickle.loads() on untrusted data allows arbitrary code execution; use JSON or safe alternatives.",
            example_after="import json\nobj = json.loads(untrusted_text)",
        ),
        "path_traversal": Remediation(
            vuln_type="path_traversal",
            title="Normalize paths with pathlib.Path.resolve()",
            snippet="from pathlib import Path\nuser_path = Path(base_dir, user_input).resolve()\nif not str(user_path).startswith(str(base_dir)):\n    raise ValueError('path traversal')",
            explanation="Unsanitized path components allow traversal outside intended directories.",
            example_after="from pathlib import Path\nuser_path = Path(base_dir, user_input).resolve()\nif not str(user_path).startswith(str(base_dir)):\n    raise ValueError('path traversal')",
        ),
    }

    _GENERIC = Remediation(
        vuln_type="generic",
        title="Validate and sanitize untrusted input",
        snippet="ALLOWED = {'a', 'b'}\nif value not in ALLOWED:\n    raise ValueError",
        explanation="Untrusted input should be validated against an allowlist before use.",
        example_after="ALLOWED = {'a', 'b'}\nif value not in ALLOWED:\n    raise ValueError",
    )

    def get_remediation(self, vuln_type_or_finding) -> Remediation:
        if isinstance(vuln_type_or_finding, str):
            key = (vuln_type_or_finding or "").strip().lower()
        else:
            key = _infer_vuln_type_from_finding(vuln_type_or_finding)
        return self._REMEDIATIONS.get(key, self._GENERIC)

    def get_hint(self, finding) -> str:
        rem = self.get_remediation(finding)
        return rem.explanation or rem.title

    def _rewrite_line(self, line: str, finding) -> Optional[str]:
        """Attempt a simple single-line rewrite based on vuln type.

        Returns the rewritten line string (with trailing newline preserved) or
        None if no rewrite rule matched.
        """
        vuln_type = _infer_vuln_type_from_finding(finding)
        trailing = "\n" if line.endswith("\n") else ""
        stripped = line.rstrip("\n")

        if vuln_type == "code_injection":
            # eval( -> ast.literal_eval(
            if re.search(r"\beval\s*\(", stripped):
                return re.sub(r"\beval\s*\(", "ast.literal_eval(", stripped) + trailing
        if vuln_type == "command_injection":
            # shell=True -> shell=False
            if "shell=True" in stripped:
                return stripped.replace("shell=True", "shell=False") + trailing
        if vuln_type == "path_traversal":
            # open(user_input -> open(Path(base_dir / user_input).resolve()
            pass  # too complex for single-line rewrite
        return None

    def generate_fix_patch(self, finding, source_code: str) -> Optional[str]:
        """Generate a unified-diff patch string for a finding.

        Returns a unified diff string or None if no automatic rewrite is available.
        """
        lines = source_code.splitlines(keepends=True)
        line_idx = (finding.line_number or 0) - 1
        if line_idx < 0 or line_idx >= len(lines):
            return None

        original_line = lines[line_idx]
        rewritten = self._rewrite_line(original_line, finding)
        if rewritten is None or rewritten == original_line:
            return None

        new_lines = lines[:line_idx] + [rewritten] + lines[line_idx + 1:]
        diff = difflib.unified_diff(
            lines,
            new_lines,
            fromfile=f"a/{finding.file_path}",
            tofile=f"b/{finding.file_path}",
            lineterm="",
        )
        return "\n".join(diff)


# ---------------------------------------------------------------------------
# LLM-powered remediation engine
# ---------------------------------------------------------------------------


class LLMRemediationEngine:
    """Generate unified-diff fix patches by calling an LLM API.

    Uses the OpenAI-compatible interface so it works with DeepSeek, OpenAI,
    and any other provider that exposes the same HTTP API shape.

    Parameters
    ----------
    api_key:
        API key for the LLM provider.
    model:
        Model identifier (default: ``deepseek-chat``).
    base_url:
        Base URL of the OpenAI-compatible API endpoint.
    timeout:
        HTTP request timeout in seconds (default: 60).
    """

    _SYSTEM_PROMPT = (
        "You are a senior Python security engineer. "
        "Fix the vulnerability in the code. "
        "Output ONLY a unified diff patch. No explanations."
    )

    def __init__(
        self,
        api_key: str,
        model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com/v1",
        timeout: int = 60,
    ) -> None:
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'openai' package is required for LLM remediation. "
                "Install it with: pip install 'openai>=1.0.0'"
            ) from exc

        self._model = model
        self._timeout = timeout
        self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_fix(
        self,
        finding: Finding,
        source_code: str,
        context_lines: int = 5,
    ) -> Optional[str]:
        """Call the LLM API and return a unified-diff patch string.

        Parameters
        ----------
        finding:
            A :class:`~pyaegis.models.Finding` dataclass instance.
        source_code:
            Complete source text of the vulnerable file.
        context_lines:
            Number of lines before/after the vulnerable line to include in the
            prompt context window.

        Returns
        -------
        str or None
            A unified diff patch string, or ``None`` if the LLM produced no
            usable output or an API error occurred.
        """
        code_context = self._extract_context(
            source_code, finding.line_number, context_lines
        )
        user_prompt = self._build_user_prompt(finding, code_context)

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": self._SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=1024,
            )
        except Exception as exc:  # pragma: no cover
            import logging
            logging.getLogger("pyaegis").error(
                "LLMRemediationEngine: API call failed: %s", exc
            )
            return None

        raw = (response.choices[0].message.content or "").strip()
        return self._extract_diff(raw) or None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_context(source_code: str, line_number: int, context_lines: int) -> str:
        """Return *context_lines* lines around *line_number* (1-based)."""
        lines = source_code.splitlines()
        idx = max(0, line_number - 1)  # convert to 0-based
        start = max(0, idx - context_lines)
        end = min(len(lines), idx + context_lines + 1)
        # prefix each line with its 1-based line number
        numbered = [
            f"{lineno:>4} | {text}"
            for lineno, text in enumerate(lines[start:end], start=start + 1)
        ]
        return "\n".join(numbered)

    @staticmethod
    def _build_user_prompt(finding: Finding, code_context: str) -> str:
        vuln_type = _infer_vuln_type_from_finding(finding)
        cwe = _VULN_TYPE_TO_CWE.get(vuln_type, "CWE-unknown")
        return (
            f"Vulnerability: {vuln_type} ({cwe})\n"
            f"File: {finding.file_path}\n"
            f"Line: {finding.line_number}\n"
            f"Sink: {finding.sink_name}\n"
            f"Source variable: {finding.source_var}\n"
            f"\nVulnerable code context:\n```python\n{code_context}\n```\n"
            f"\nOutput the minimal unified diff to fix this vulnerability:"
        )

    @staticmethod
    def _extract_diff(text: str) -> str:
        """Strip markdown fences and return the raw diff block.

        Some models wrap the diff in ```diff ... ``` fences.
        """
        # Try to strip ```diff fences
        fence_match = re.search(
            r"```(?:diff)?\s*\n(.*?)\n```", text, re.DOTALL | re.IGNORECASE
        )
        if fence_match:
            return fence_match.group(1).strip()
        # If the text already looks like a diff (starts with --- or @@) return as-is
        stripped = text.strip()
        if stripped.startswith(("---", "@@", "+", "-")):
            return stripped
        return stripped


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_VULN_TYPE_TO_CWE: dict[str, str] = {
    "command_injection": "CWE-78",
    "sql_injection": "CWE-89",
    "code_injection": "CWE-94",
    "hardcoded_secret": "CWE-798",
    "deserialization": "CWE-502",
    "path_traversal": "CWE-22",
    "generic": "CWE-20",
}


def _infer_vuln_type_from_finding(finding) -> str:
    rule_id = (getattr(finding, "rule_id", "") or "").strip().upper()
    rule_map = {
        "PYA-001": "command_injection",
        "PYA-002": "sql_injection",
        "PYA-003": "code_injection",
        "PYA-004": "deserialization",
        "PYA-006": "path_traversal",
    }
    if rule_id in rule_map:
        return rule_map[rule_id]

    haystack = " ".join([
        getattr(finding, "sink_name", "") or "",
        getattr(finding, "sink_context", "") or "",
        getattr(finding, "description", "") or "",
    ]).lower()

    if re.search(r"subprocess|os\.system|shell", haystack):
        return "command_injection"
    if re.search(r"sql|cursor|execute|query", haystack):
        return "sql_injection"
    if re.search(r"\beval\b|\bexec\b", haystack):
        return "code_injection"
    if re.search(r"pickle|yaml\.load", haystack):
        return "deserialization"
    if re.search(r"path|open\(|unlink", haystack):
        return "path_traversal"
    if re.search(r"secret|token|password", haystack):
        return "hardcoded_secret"
    return "generic"


def format_remediation_hint(
    finding,
    fmt: str = "text",
    engine: Optional[RemediationEngine] = None,
) -> str:
    engine = engine or RemediationEngine()
    rem = engine.get_remediation(finding)

    if fmt == "md":
        lines = [
            "### Remediation",
            "**" + rem.title + "**",
            "vuln_type: `" + rem.vuln_type + "`",
            "",
            "```python",
            rem.snippet,
            "```",
            "",
        ]
        return "\n".join(lines)

    indented = "\n".join("    " + ln for ln in rem.snippet.splitlines())
    return (
        "  Remediation:\n"
        "  - Type: " + rem.vuln_type + "\n"
        "  - Title: " + rem.title + "\n"
        "  - Snippet:\n" + indented + "\n"
    )
