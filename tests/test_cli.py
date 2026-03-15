import subprocess
import sys


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
