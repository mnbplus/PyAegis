"""Tests for pyaegis.fixers — built-in remediation engine."""

from __future__ import annotations

from pyaegis.fixers import RemediationEngine, format_remediation_hint
from pyaegis.models import Finding


def make_finding(
    rule_id="PYA-001",
    severity="HIGH",
    description="taint flow detected",
    file_path="test_app.py",
    line_number=1,
    source_var="user_input",
    sink_context="subprocess.run(cmd, shell=True)",
    sink_name="subprocess.run",
):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        description=description,
        file_path=file_path,
        line_number=line_number,
        source_var=source_var,
        sink_context=sink_context,
        sink_name=sink_name,
    )


def test_engine_get_remediation_by_vuln_type():
    eng = RemediationEngine()
    rem = eng.get_remediation("command_injection")
    assert rem.vuln_type == "command_injection"
    assert "subprocess" in rem.snippet


def test_format_remediation_hint_text_contains_title_and_snippet():
    f = make_finding(rule_id="PYA-001")
    out = format_remediation_hint(f, fmt="text")
    assert "Remediation" in out
    assert "Snippet" in out


def test_format_remediation_hint_md_contains_code_fence():
    f = make_finding(rule_id="PYA-003", sink_context="eval(x)", sink_name="eval")
    out = format_remediation_hint(f, fmt="md")
    assert "```python" in out
    assert "ast.literal_eval" in out
