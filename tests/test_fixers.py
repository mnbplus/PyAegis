"""Tests for pyaegis.fixers — RemediationEngine."""

from __future__ import annotations

import pytest

from pyaegis.fixers import RemediationEngine, Remediation, _RULE_MAP, _GENERIC
from pyaegis.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    rule_id="PYA-001",
    severity="HIGH",
    description="taint flow detected",
    file_path="test_app.py",
    line_number=1,
    source_var="user_input",
    sink_context="cursor.execute(query)",
    sink_name="execute",
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


# ---------------------------------------------------------------------------
# get_remediation — rule_id lookup
# ---------------------------------------------------------------------------


class TestGetRemediationByRuleId:
    def setup_method(self):
        self.engine = RemediationEngine()

    def test_pya001_sql_injection(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-001"))
        assert rem.rule_id == "PYA-001"
        assert "parameteris" in rem.title.lower() or "parameteri" in rem.title.lower()
        assert "%s" in rem.example_after or "?" in rem.example_after

    def test_pya002_cmd_injection(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-002"))
        assert rem.rule_id == "PYA-002"
        assert "shell" in rem.title.lower() or "subprocess" in rem.title.lower()

    def test_pya003_eval_exec(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-003"))
        assert rem.rule_id == "PYA-003"
        assert "ast.literal_eval" in rem.example_after

    def test_pya004_hardcoded_secret(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-004"))
        assert rem.rule_id == "PYA-004"
        assert "os.environ" in rem.example_after or "os.getenv" in rem.example_after

    def test_pya005_pickle(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-005"))
        assert rem.rule_id == "PYA-005"
        assert "json" in rem.example_after

    def test_pya006_os_system(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-006"))
        assert rem.rule_id == "PYA-006"
        assert "subprocess" in rem.example_after

    def test_unknown_rule_falls_back_to_generic(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-999", sink_name="", sink_context="", description=""))
        assert rem.rule_id == "GENERIC"


# ---------------------------------------------------------------------------
# get_remediation — sink-name heuristic fallback
# ---------------------------------------------------------------------------


class TestGetRemediationBySinkHeuristic:
    def setup_method(self):
        self.engine = RemediationEngine()

    def test_sql_keyword_in_sink(self):
        f = make_finding(rule_id="PYA-999", sink_name="cursor.execute", sink_context="", description="")
        rem = self.engine.get_remediation(f)
        assert rem.rule_id == "PYA-001"

    def test_eval_keyword_in_description(self):
        f = make_finding(rule_id="PYA-999", sink_name="", sink_context="eval(user_input)", description="eval usage")
        rem = self.engine.get_remediation(f)
        assert rem.rule_id == "PYA-003"

    def test_pickle_keyword_in_sink(self):
        f = make_finding(rule_id="PYA-999", sink_name="pickle.loads", sink_context="", description="")
        rem = self.engine.get_remediation(f)
        assert rem.rule_id == "PYA-005"

    def test_subprocess_keyword(self):
        f = make_finding(rule_id="PYA-999", sink_name="subprocess.run", sink_context="", description="")
        rem = self.engine.get_remediation(f)
        assert rem.rule_id == "PYA-002"


# ---------------------------------------------------------------------------
# Remediation.summary() and full_text()
# ---------------------------------------------------------------------------


class TestRemediationFormatting:
    def setup_method(self):
        self.engine = RemediationEngine()

    def test_summary_is_nonempty_string(self):
        for rule_id in _RULE_MAP:
            f = make_finding(rule_id=rule_id)
            rem = self.engine.get_remediation(f)
            s = rem.summary()
            assert isinstance(s, str) and len(s) > 10

    def test_full_text_contains_before_after(self):
        for rule_id in _RULE_MAP:
            f = make_finding(rule_id=rule_id)
            rem = self.engine.get_remediation(f)
            txt = rem.full_text()
            assert "Before" in txt
            assert "After" in txt

    def test_full_text_contains_references(self):
        rem = self.engine.get_remediation(make_finding(rule_id="PYA-001"))
        txt = rem.full_text()
        assert "References" in txt
        assert "http" in txt


# ---------------------------------------------------------------------------
# generate_fix_patch
# ---------------------------------------------------------------------------


class TestGenerateFixPatch:
    def setup_method(self):
        self.engine = RemediationEngine()

    def _finding(self, line_number, file_path="app.py", rule_id="PYA-003"):
        return make_finding(rule_id=rule_id, file_path=file_path, line_number=line_number)

    def test_eval_rewrite_produces_patch(self):
        source = 'result = eval(user_input)\n'
        f = self._finding(1)
        patch = self.engine.generate_fix_patch(f, source)
        assert patch is not None
        assert "ast.literal_eval" in patch
        assert "@@" in patch  # unified diff header

    def test_exec_rewrite_produces_patch(self):
        source = 'exec(user_code)\n'
        f = self._finding(1)
        patch = self.engine.generate_fix_patch(f, source)
        assert patch is not None
        assert "exec" in patch

    def test_os_system_rewrite_produces_patch(self):
        source = 'os.system(user_cmd)\n'
        f = self._finding(1, rule_id="PYA-006")
        patch = self.engine.generate_fix_patch(f, source)
        assert patch is not None
        assert "subprocess.run" in patch

    def test_pickle_loads_rewrite_produces_patch(self):
        source = 'data = pickle.loads(raw)\n'
        f = self._finding(1, rule_id="PYA-005")
        patch = self.engine.generate_fix_patch(f, source)
        assert patch is not None
        assert "json.loads" in patch

    def test_no_patch_when_no_pattern_matches(self):
        source = 'x = some_func(a, b)\n'
        f = self._finding(1, rule_id="PYA-001")
        patch = self.engine.generate_fix_patch(f, source)
        assert patch is None

    def test_no_patch_on_empty_source(self):
        f = self._finding(1)
        assert self.engine.generate_fix_patch(f, "") is None

    def test_no_patch_on_out_of_range_line(self):
        source = 'x = 1\n'
        f = self._finding(99)
        assert self.engine.generate_fix_patch(f, source) is None

    def test_multiline_source_correct_line_targeted(self):
        source = 'a = 1\nb = 2\nresult = eval(user_input)\nd = 4\n'
        f = self._finding(3)
        patch = self.engine.generate_fix_patch(f, source)
        assert patch is not None
        assert "ast.literal_eval" in patch
        # Lines 1,2,4 unchanged
        assert "-result = eval" in patch
        assert "+result = ast.literal_eval" in patch

    def test_patch_diff_format(self):
        source = 'result = eval(x)\n'
        f = self._finding(1)
        patch = self.engine.generate_fix_patch(f, source)
        assert patch.startswith("--- a/")
        assert "+++ b/" in patch
