import io

from pyaegis.models import Finding, ScanResult
from pyaegis.reporters import CSVReporter, HTMLReporter


def _make_result():
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
    return ScanResult(total_files=5, findings=findings, duration_seconds=0.123)


def test_csv_reporter_structure():
    buf = io.StringIO()
    reporter = CSVReporter(buf)
    reporter.report(_make_result())
    out = buf.getvalue()
    assert "rule_id" in out.splitlines()[0]
    assert "PYA-103" in out


def test_html_reporter_structure():
    buf = io.StringIO()
    reporter = HTMLReporter(buf)
    reporter.report(_make_result())
    out = buf.getvalue()
    assert "<!DOCTYPE html>" in out
    assert "PyAegis Security Scan Report" in out
    assert "PYA-103" in out
