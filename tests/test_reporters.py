import io
import json
from pyaegis.models import Finding, ScanResult
from pyaegis.reporters import (
    TextReporter,
    JSONReporter,
    SARIFReporter,
)


def _make_result():
    """创建测试用的 ScanResult。"""
    findings = [
        Finding(
            rule_id="PYA-103",
            description="OS command injection.",
            file_path="app.py",
            line_number=10,
            sink_context="handler",
            severity="CRITICAL",
            source_var="user_input",
        )
    ]
    return ScanResult(
        total_files=5,
        findings=findings,
        duration_seconds=0.123,
    )


def test_text_reporter_with_findings():
    buf = io.StringIO()
    reporter = TextReporter(buf)
    reporter.report(_make_result())
    output = buf.getvalue()
    assert "CRITICAL" in output
    assert "PYA-103" in output
    assert "app.py" in output


def test_text_reporter_no_findings():
    buf = io.StringIO()
    reporter = TextReporter(buf)
    result = ScanResult(total_files=3)
    reporter.report(result)
    output = buf.getvalue()
    assert "No vulnerabilities" in output


def test_json_reporter_structure():
    buf = io.StringIO()
    reporter = JSONReporter(buf)
    reporter.report(_make_result())
    data = json.loads(buf.getvalue())
    assert "meta" in data
    assert data["meta"]["total_files_scanned"] == 5
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "PYA-103"


def test_sarif_reporter_structure(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("print('hi')\n", encoding="utf-8")

    buf = io.StringIO()
    reporter = SARIFReporter(buf)
    reporter.report(
        ScanResult(
            total_files=1,
            findings=[
                Finding(
                    rule_id="PYA-103",
                    description="OS command injection.",
                    file_path=str(p),
                    line_number=1,
                    sink_context="handler",
                    severity="CRITICAL",
                    source_var="user_input",
                )
            ],
            duration_seconds=0.1,
        )
    )
    data = json.loads(buf.getvalue())
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "PYA-103"
    assert results[0]["level"] == "error"
    region = results[0]["locations"][0]["physicalLocation"]["region"]
    assert region["snippet"]["text"] == "print('hi')"
