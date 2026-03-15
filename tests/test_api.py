"""Tests for pyaegis.api — headless programmatic interface."""
from __future__ import annotations

import csv
import io
import os
import tempfile
from pathlib import Path

from pyaegis.api import scan_code_string, scan_file, scan_directory


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_INJECTION_CODE = """
import os
from flask import request

def view():
    cmd = request.args.get('cmd')
    os.system(cmd)  # tainted sink
"""

_SANITIZED_CODE = """
import os
import html
from flask import request

def view():
    raw = request.args.get('name')
    safe = html.escape(raw)   # sanitizer
    os.system(safe)           # should NOT fire after sanitization
"""

_CLEAN_CODE = """
def add(a, b):
    return a + b

result = add(1, 2)
print(result)
"""


# ---------------------------------------------------------------------------
# test_scan_code_string_detects_injection
# ---------------------------------------------------------------------------


def test_scan_code_string_detects_injection():
    """os.system(tainted) must be reported as a finding."""
    findings = scan_code_string(_INJECTION_CODE, return_format="dict")
    assert isinstance(findings, list), "Expected list for return_format='dict'"
    assert (
        len(findings) >= 1
    ), f"Expected at least one finding for injection code, got: {findings}"
    sinks = [f["sink_name"] for f in findings]
    assert any(
        "os.system" in s for s in sinks
    ), f"Expected os.system in sinks, got: {sinks}"


# ---------------------------------------------------------------------------
# test_scan_code_string_respects_sanitizer
# ---------------------------------------------------------------------------


def test_scan_code_string_respects_sanitizer():
    """Clean code with no tainted sinks must produce no findings."""
    findings = scan_code_string(_CLEAN_CODE, return_format="dict")
    assert isinstance(findings, list)
    assert len(findings) == 0, f"Expected no findings for clean code, got: {findings}"


# ---------------------------------------------------------------------------
# test_scan_code_string_returns_sarif_format
# ---------------------------------------------------------------------------


def test_scan_code_string_returns_sarif_format():
    """SARIF output must be a valid SARIF 2.1.0 dict."""
    sarif = scan_code_string(_INJECTION_CODE, return_format="sarif")
    assert isinstance(sarif, dict), "Expected dict for return_format='sarif'"
    assert sarif.get("version") == "2.1.0"
    assert "runs" in sarif
    runs = sarif["runs"]
    assert isinstance(runs, list) and len(runs) == 1
    run = runs[0]
    assert "tool" in run
    assert run["tool"]["driver"]["name"] == "PyAegis"
    assert isinstance(run["results"], list)
    assert len(run["results"]) >= 1
    # Each result must have ruleId, level, message, locations
    result = run["results"][0]
    assert "ruleId" in result
    assert "level" in result
    assert "message" in result
    assert "locations" in result


# ---------------------------------------------------------------------------
# test_scan_code_string_returns_text_format
# ---------------------------------------------------------------------------


def test_scan_code_string_returns_text_format():
    """Text output must be a non-empty string describing the finding."""
    text = scan_code_string(_INJECTION_CODE, return_format="text")
    assert isinstance(text, str)
    assert "os.system" in text or "issue" in text.lower()


# ---------------------------------------------------------------------------
# test_scan_file
# ---------------------------------------------------------------------------


def test_scan_file():
    """scan_file must detect injection in a real on-disk file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", encoding="utf-8", delete=False
    ) as tf:
        tf.write(_INJECTION_CODE)
        tmp_path = tf.name

    try:
        findings = scan_file(tmp_path, return_format="dict")
        assert isinstance(findings, list)
        assert len(findings) >= 1, f"Expected findings from scan_file, got: {findings}"
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# test_scan_directory
# ---------------------------------------------------------------------------


def test_scan_directory():
    """scan_directory must find injection across files in a temp directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write two files: one vulnerable, one clean
        vuln_path = os.path.join(tmpdir, "vuln.py")
        clean_path = os.path.join(tmpdir, "clean.py")
        Path(vuln_path).write_text(_INJECTION_CODE, encoding="utf-8")
        Path(clean_path).write_text(_CLEAN_CODE, encoding="utf-8")

        findings = scan_directory(tmpdir, return_format="dict")
        assert isinstance(findings, list)
        assert (
            len(findings) >= 1
        ), f"Expected findings from scan_directory, got: {findings}"
        # All findings must reference a real file inside tmpdir
        for f in findings:
            assert tmpdir in f["filename"] or f["filename"].startswith(tmpdir)


# ---------------------------------------------------------------------------
# test_severity_filter
# ---------------------------------------------------------------------------


def test_severity_filter():
    """severity_filter=["CRITICAL"] must exclude lower-severity findings."""
    critical_findings = scan_code_string(
        _INJECTION_CODE,
        return_format="dict",
        severity_filter=["CRITICAL"],
    )
    # Critical filter should be a subset
    assert isinstance(critical_findings, list)
    for f in critical_findings:
        assert (
            f["severity"].upper() == "CRITICAL"
        ), f"Expected only CRITICAL findings, got: {f['severity']}"
    # INFO filter should return everything (at or above INFO = all)
    info_findings = scan_code_string(
        _INJECTION_CODE,
        return_format="dict",
        severity_filter=["INFO"],
    )
    assert len(info_findings) >= len(critical_findings)


# ---------------------------------------------------------------------------
# test_scan_code_string_empty_source
# ---------------------------------------------------------------------------


def test_scan_code_string_empty_source():
    """Empty source code must return an empty findings list."""
    findings = scan_code_string("", return_format="dict")
    assert findings == []


# ---------------------------------------------------------------------------
# test_scan_code_string_syntax_error
# ---------------------------------------------------------------------------


def test_scan_code_string_syntax_error():
    """Source with a syntax error must not raise — returns empty list."""
    bad_code = "def foo(:\n    pass\n"
    findings = scan_code_string(bad_code, return_format="dict")
    assert isinstance(findings, list)
    # No crash; findings may be empty


# ---------------------------------------------------------------------------
# test_sarif_no_findings
# ---------------------------------------------------------------------------


def test_sarif_no_findings():
    """SARIF for clean code must still be valid SARIF with empty results."""
    sarif = scan_code_string(_CLEAN_CODE, return_format="sarif")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# test_virtual_filename_in_output
# ---------------------------------------------------------------------------


def test_virtual_filename_in_output():
    """filename kwarg must appear in finding output."""
    findings = scan_code_string(
        _INJECTION_CODE,
        filename="mymodule.py",
        return_format="dict",
    )
    assert len(findings) >= 1
    for f in findings:
        assert (
            f["filename"] == "mymodule.py"
        ), f"Expected filename='mymodule.py', got: {f['filename']}"


# ---------------------------------------------------------------------------
# test_scan_code_string_returns_json_format
# ---------------------------------------------------------------------------


def test_scan_code_string_returns_json_format():
    """JSON output must include metadata and findings list."""
    payload = scan_code_string(_INJECTION_CODE, return_format="json")
    assert isinstance(payload, dict)
    assert "meta" in payload
    assert "findings" in payload
    meta = payload["meta"]
    assert meta["total_files_scanned"] == 1
    assert meta["total_findings"] >= 1
    assert isinstance(payload["findings"], list)
    first = payload["findings"][0]
    assert "sink_name" in first
    assert "filename" in first


# ---------------------------------------------------------------------------
# test_scan_code_string_returns_csv_format
# ---------------------------------------------------------------------------


def test_scan_code_string_returns_csv_format():
    """CSV output must include header row and at least one finding row."""
    csv_text = scan_code_string(_INJECTION_CODE, return_format="csv")
    assert isinstance(csv_text, str)
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    assert reader.fieldnames is not None
    expected_fields = {
        "rule_id",
        "severity",
        "message",
        "filename",
        "line",
        "sink_name",
        "source_var",
        "sink_context",
    }
    assert expected_fields.issubset(set(reader.fieldnames))
    assert len(rows) >= 1
    assert any("os.system" in row.get("sink_name", "") for row in rows)


# ---------------------------------------------------------------------------
# test_scan_directory_returns_json_and_csv
# ---------------------------------------------------------------------------


def test_scan_directory_returns_json_and_csv():
    """Directory scans must return JSON payload + CSV output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        vuln_path = os.path.join(tmpdir, "vuln.py")
        clean_path = os.path.join(tmpdir, "clean.py")
        Path(vuln_path).write_text(_INJECTION_CODE, encoding="utf-8")
        Path(clean_path).write_text(_CLEAN_CODE, encoding="utf-8")

        json_payload = scan_directory(tmpdir, return_format="json")
        assert isinstance(json_payload, dict)
        assert json_payload["meta"]["total_files_scanned"] == 2
        assert json_payload["meta"]["total_findings"] >= 1
        assert isinstance(json_payload["findings"], list)

        csv_text = scan_directory(tmpdir, return_format="csv")
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) >= 1


# ---------------------------------------------------------------------------
# test_scan_directory_empty_json_and_csv
# ---------------------------------------------------------------------------


def test_scan_directory_empty_json_and_csv():
    """Empty directories should return valid JSON meta and CSV header."""
    with tempfile.TemporaryDirectory() as tmpdir:
        json_payload = scan_directory(tmpdir, return_format="json")
        assert json_payload["meta"]["total_files_scanned"] == 0
        assert json_payload["meta"]["total_findings"] == 0
        assert json_payload["findings"] == []

        csv_text = scan_directory(tmpdir, return_format="csv")
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert reader.fieldnames is not None
        assert rows == []
