import subprocess
import sys
import tempfile
import os


def test_version_flag():
    result = subprocess.run(
        [sys.executable, "-m", "pyaegis.cli", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "PyAegis v" in result.stdout


def test_missing_target_shows_help():
    result = subprocess.run(
        [sys.executable, "-m", "pyaegis.cli"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_nonexistent_target():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyaegis.cli",
            "/nonexistent/path",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1


def test_ruleset_option():
    """Test that --ruleset xxe loads the XXE rules."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test file that has XXE vulnerability
        test_file = os.path.join(tmpdir, "test.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(
                """
from xml.etree import ElementTree as ET

def f(request):
    data = request.data
    ET.fromstring(data)
"""
            )

        # Run scan with xxe ruleset
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pyaegis.cli",
                "scan",
                tmpdir,
                "--ruleset",
                "xxe",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )

        # Should find the vulnerability
        assert result.returncode == 1  # findings exist
        assert "fromstring" in result.stdout or "XXE" in result.stdout


def test_ruleset_unknown():
    """Test that unknown ruleset shows error."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyaegis.cli",
            "scan",
            ".",
            "--ruleset",
            "nonexistent_ruleset",
            "--quiet",
        ],
        capture_output=True,
        text=True,
    )

    # Should error
    assert result.returncode == 2
    assert "Unknown ruleset" in result.stderr or "unknown" in result.stderr.lower()


def test_ruleset_xxe_detects_et_fromstring():
    """Test that xxe ruleset detects ET.fromstring."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "app.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(
                """
import xml.etree.ElementTree as ET

# Imported global framework object should still be recognized as taint source
# via attribute sources like "request.data".
from flask import request

def parse_xml():
    data = request.data
    return ET.fromstring(data)
"""
            )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pyaegis.cli",
                "scan",
                tmpdir,
                "--ruleset",
                "xxe",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )

        # Should find the vulnerability
        assert result.returncode == 1
