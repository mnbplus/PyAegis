"""PyAegis Remediation Engine — Rule-based auto-fix suggestions (P3).

Design goals:
- Zero external dependencies (no LLM required)
- Template-driven: each vulnerability type maps to a concrete code snippet
- generate_fix_patch(): best-effort unified-diff patch for simple single-line sinks
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import Finding


# ---------------------------------------------------------------------------
# Remediation data model
# ---------------------------------------------------------------------------


@dataclass
class Remediation:
    """A structured remediation suggestion for a single finding."""

    rule_id: str
    title: str
    explanation: str
    example_before: str
    example_after: str
    references: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """One-line summary suitable for inline reporter output."""
        return f"{self.title}: {self.explanation}"

    def full_text(self) -> str:
        lines = [
            f"  Remediation : {self.title}",
            f"  Explanation : {self.explanation}",
            "  Before      :",
        ]
        for ln in self.example_before.splitlines():
            lines.append(f"    {ln}")
        lines.append("  After       :")
        for ln in self.example_after.splitlines():
            lines.append(f"    {ln}")
        if self.references:
            lines.append("  References  :")
            for ref in self.references:
                lines.append(f"    - {ref}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remediation templates
# ---------------------------------------------------------------------------

_SQL_INJECTION = Remediation(
    rule_id="PYA-001",
    title="Use parameterised queries",
    explanation=(
        "Never concatenate or format user input directly into SQL strings. "
        "Pass values as bound parameters so the database driver handles escaping."
    ),
    example_before=(
        '# UNSAFE\n'
        'query = "SELECT * FROM users WHERE name = \'" + username + "\'"\n'
        'cursor.execute(query)'
    ),
    example_after=(
        '# SAFE\n'
        'query = "SELECT * FROM users WHERE name = %s"\n'
        'cursor.execute(query, (username,))  # or use ? for sqlite3'
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders",
    ],
)

_CMD_INJECTION = Remediation(
    rule_id="PYA-002",
    title="Use subprocess list form (avoid shell=True)",
    explanation=(
        "Passing a string with shell=True allows shell metacharacter injection. "
        "Pass a list of arguments instead; the OS kernel executes the binary directly."
    ),
    example_before=(
        '# UNSAFE\n'
        'import subprocess\n'
        'subprocess.run(f"convert {user_file} output.png", shell=True)'
    ),
    example_after=(
        '# SAFE\n'
        'import subprocess\n'
        'subprocess.run(["convert", user_file, "output.png"])  # list form, no shell'
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://docs.python.org/3/library/subprocess.html#security-considerations",
    ],
)

_EVAL_EXEC = Remediation(
    rule_id="PYA-003",
    title="Replace eval/exec with ast.literal_eval or a safe parser",
    explanation=(
        "eval() and exec() execute arbitrary Python code. "
        "For data parsing use ast.literal_eval() (handles str/int/float/list/dict/bool/None). "
        "For expressions consider a dedicated expression library."
    ),
    example_before=(
        '# UNSAFE\n'
        'result = eval(user_input)'
    ),
    example_after=(
        '# SAFE - for literal data structures\n'
        'import ast\n'
        'result = ast.literal_eval(user_input)  # raises ValueError on non-literals\n'
        '\n'
        '# SAFE - for config / serialised data, prefer json\n'
        'import json\n'
        'result = json.loads(user_input)'
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/95.html",
        "https://docs.python.org/3/library/ast.html#ast.literal_eval",
    ],
)

_HARDCODED_SECRET = Remediation(
    rule_id="PYA-004",
    title="Load secrets from environment variables or a secrets manager",
    explanation=(
        "Hard-coded credentials are exposed in source control and logs. "
        "Read them at runtime from environment variables, or use a dedicated "
        "secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)."
    ),
    example_before=(
        '# UNSAFE\n'
        'API_KEY = "sk-abc123secret"\n'
        'DB_PASSWORD = "hunter2"'
    ),
    example_after=(
        '# SAFE\n'
        'import os\n'
        'API_KEY = os.environ["API_KEY"]          # raises KeyError if missing\n'
        '# or\n'
        'API_KEY = os.getenv("API_KEY", "")      # returns default\n'
        '\n'
        '# With python-dotenv for local dev:\n'
        '# from dotenv import load_dotenv; load_dotenv()'
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://12factor.net/config",
    ],
)

_PICKLE = Remediation(
    rule_id="PYA-005",
    title="Replace pickle with json or a safe serialisation library",
    explanation=(
        "pickle.loads() executes arbitrary Python bytecode embedded in the payload. "
        "For plain data use json.dumps/loads or msgpack. "
        "For ML model weights use format-specific safe loaders (safetensors, ONNX)."
    ),
    example_before=(
        '# UNSAFE\n'
        'import pickle\n'
        'obj = pickle.loads(untrusted_data)'
    ),
    example_after=(
        '# SAFE - for plain data\n'
        'import json\n'
        'obj = json.loads(untrusted_data)\n'
        '\n'
        '# If you MUST use pickle, only load data you signed yourself:\n'
        'import hmac, hashlib\n'
        '# verify HMAC signature before unpickling'
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/502.html",
        "https://docs.python.org/3/library/pickle.html#restricting-globals",
    ],
)

_OS_SYSTEM = Remediation(
    rule_id="PYA-006",
    title="Replace os.system / os.popen with subprocess",
    explanation=(
        "os.system() passes the command to the shell verbatim. "
        "Use subprocess.run() with a list of arguments to avoid shell injection."
    ),
    example_before=(
        '# UNSAFE\n'
        'import os\n'
        'os.system("rm -rf " + user_path)'
    ),
    example_after=(
        '# SAFE\n'
        'import subprocess\n'
        'subprocess.run(["rm", "-rf", user_path], check=True)'
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://docs.python.org/3/library/subprocess.html",
    ],
)

_GENERIC = Remediation(
    rule_id="GENERIC",
    title="Validate and sanitise untrusted input",
    explanation=(
        "Untrusted data reaches a sensitive sink without validation. "
        "Ensure the value is checked against an allowlist, length-limited, "
        "and encoded/escaped appropriately for the target context."
    ),
    example_before="# Untrusted input used directly in a sensitive operation",
    example_after=(
        '# Validate / allowlist\n'
        'ALLOWED = {"a", "b", "c"}\n'
        'if value not in ALLOWED:\n'
        '    raise ValueError(f"Invalid value: {value!r}")'
    ),
    references=["https://owasp.org/www-project-top-ten/"],
)


# rule_id -> template
_RULE_MAP: Dict[str, Remediation] = {
    "PYA-001": _SQL_INJECTION,
    "PYA-002": _CMD_INJECTION,
    "PYA-003": _EVAL_EXEC,
    "PYA-004": _HARDCODED_SECRET,
    "PYA-005": _PICKLE,
    "PYA-006": _OS_SYSTEM,
}

# Sink-name keyword -> template fallback
_SINK_KEYWORD_MAP: List[tuple] = [
    (r"sql|execute|query|cursor", _SQL_INJECTION),
    (r"subprocess|popen", _CMD_INJECTION),
    (r"eval|exec", _EVAL_EXEC),
    (r"pickle|unpickle", _PICKLE),
    (r"secret|password|token|api.?key|credential", _HARDCODED_SECRET),
    (r"os\.system|os\.popen", _OS_SYSTEM),
]


# ---------------------------------------------------------------------------
# RemediationEngine
# ---------------------------------------------------------------------------


class RemediationEngine:
    """Rule-based remediation engine - no LLM required.

    Usage::

        engine = RemediationEngine()
        rem = engine.get_remediation(finding)
        print(rem.full_text())

        patch = engine.generate_fix_patch(finding, source_code)
        if patch:
            print(patch)
    """

    def get_hint(self, finding: Finding) -> str:
        """Return a concise one-line fix hint for *finding*.

        Convenience wrapper used by reporters and the ``remediate`` CLI command.
        """
        return self.get_remediation(finding).summary()

    def get_remediation(self, finding: Finding) -> Remediation:
        """Return the best matching Remediation for *finding*.

        Lookup order:
        1. Exact rule_id match
        2. Keyword match on sink_name / description / sink_context
        3. Generic fallback
        """
        rule_id = (finding.rule_id or "").strip().upper()
        if rule_id in _RULE_MAP:
            return _RULE_MAP[rule_id]

        haystack = " ".join([
            getattr(finding, "sink_name", "") or "",
            finding.description or "",
            finding.sink_context or "",
        ]).lower()

        for pattern, remediation in _SINK_KEYWORD_MAP:
            if re.search(pattern, haystack):
                return remediation

        return _GENERIC

    def generate_fix_patch(
        self,
        finding: Finding,
        source_code: str,
    ) -> Optional[str]:
        """Attempt to generate a unified-diff patch for *finding*.

        Best-effort line-level transformation. Returns None when no
        automatic rewrite pattern matches the offending line.
        """
        if not source_code or not finding.file_path:
            return None

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
        patch = "\n".join(diff)
        return patch if patch.strip() else None

    # ------------------------------------------------------------------
    # Internal line-rewrite helpers
    # ------------------------------------------------------------------

    def _rewrite_line(self, line: str, finding: Finding) -> Optional[str]:
        """Try each rewriter in turn; return first non-None result."""
        rewriters = [
            self._rewrite_eval,
            self._rewrite_exec,
            self._rewrite_os_system,
            self._rewrite_pickle_loads,
        ]
        for rw in rewriters:
            result = rw(line)
            if result is not None:
                return result
        return None

    @staticmethod
    def _rewrite_eval(line: str) -> Optional[str]:
        """eval(x) -> ast.literal_eval(x)"""
        stripped = line.rstrip("\n\r")
        m = re.match(r"^(\s*)(.*?)\beval\((.+)\)(\s*)$", stripped)
        if not m:
            return None
        indent, prefix, args, trail = m.group(1), m.group(2), m.group(3), m.group(4)
        rewritten = f"{indent}{prefix}ast.literal_eval({args}){trail}"
        # Preserve original line ending
        ending = line[len(stripped):]
        return rewritten + ending

    @staticmethod
    def _rewrite_exec(line: str) -> Optional[str]:
        """exec(x) -> # exec(x)  [commented out with note]"""
        stripped = line.rstrip("\n\r")
        m = re.match(r"^(\s*)exec\((.+)\)(\s*)$", stripped)
        if not m:
            return None
        indent, args, trail = m.group(1), m.group(2), m.group(3)
        rewritten = f"{indent}# UNSAFE exec removed - review: exec({args})  # TODO: replace with safe alternative{trail}"
        ending = line[len(stripped):]
        return rewritten + ending

    @staticmethod
    def _rewrite_os_system(line: str) -> Optional[str]:
        """os.system(x) -> subprocess.run([...]) hint"""
        stripped = line.rstrip("\n\r")
        m = re.match(r"^(\s*)os\.system\((.+)\)(\s*)$", stripped)
        if not m:
            return None
        indent, args, trail = m.group(1), m.group(2), m.group(3)
        rewritten = f"{indent}subprocess.run({args}, shell=False)  # TODO: convert arg to list{trail}"
        ending = line[len(stripped):]
        return rewritten + ending

    @staticmethod
    def _rewrite_pickle_loads(line: str) -> Optional[str]:
        """pickle.loads(x) -> json.loads(x) hint"""
        stripped = line.rstrip("\n\r")
        m = re.match(r"^(\s*)(.*?)pickle\.loads\((.+)\)(\s*)$", stripped)
        if not m:
            return None
        indent, prefix, args, trail = m.group(1), m.group(2), m.group(3), m.group(4)
        rewritten = f"{indent}{prefix}json.loads({args})  # TODO: ensure data is trusted JSON{trail}"
        ending = line[len(stripped):]
        return rewritten + ending
