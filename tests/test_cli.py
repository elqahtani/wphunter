"""Tests for CLI argument validation."""
import subprocess
import sys
import os

SCANNER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner.py")


def _run(*args):
    """Run scanner.py with args, return (returncode, stderr)."""
    result = subprocess.run(
        [sys.executable, SCANNER, *args],
        capture_output=True, text=True,
    )
    return result.returncode, result.stderr + result.stdout


class TestCLIValidation:

    def test_no_args_fails(self):
        code, output = _run()
        assert code != 0
        assert "At least one of --input or --wp-version is required" in output

    def test_missing_input_file(self):
        code, output = _run("-i", "/nonexistent/file.csv")
        assert code != 0
        assert "File not found" in output

    def test_invalid_type(self):
        code, output = _run("-i", "dummy.csv", "--type", "invalid")
        assert code != 0

    def test_invalid_source(self):
        code, output = _run("-i", "dummy.csv", "--source", "invalid")
        assert code != 0

    def test_invalid_format(self):
        code, output = _run("-i", "dummy.csv", "--format", "xml")
        assert code != 0

    def test_invalid_min_severity(self):
        code, output = _run("-i", "dummy.csv", "--min-severity", "extreme")
        assert code != 0

    def test_help_shows_all_flags(self):
        code, output = _run("--help")
        assert code == 0
        assert "--input" in output
        assert "--type" in output
        assert "--wp-version" in output
        assert "--source" in output
        assert "--threads" in output
        assert "--min-severity" in output
