"""Tests for plugin/theme list parsers (3 input formats)."""
import os
import tempfile

import pytest

from parsers import parse_plugins


def _write_tmp(content: str) -> str:
    """Write content to a temp file, return path."""
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class TestSimpleCSV:
    """Simple slug,version format."""

    def test_basic(self):
        path = _write_tmp("elementor,3.6.0\nwoocommerce,6.0.0\n")
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0"), ("woocommerce", "6.0.0")]

    def test_comments_ignored(self):
        path = _write_tmp("# comment\nelementor,3.6.0\n# another\n")
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0")]

    def test_empty_lines_ignored(self):
        path = _write_tmp("\nelementor,3.6.0\n\nwoocommerce,6.0.0\n\n")
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0"), ("woocommerce", "6.0.0")]

    def test_empty_file(self):
        path = _write_tmp("")
        result = parse_plugins(path)
        os.unlink(path)
        assert result == []

    def test_whitespace_trimmed(self):
        path = _write_tmp("  elementor , 3.6.0 \n")
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0")]


class TestWpCliCSV:
    """wp-cli CSV output: wp plugin list --format=csv."""

    def test_basic(self):
        content = (
            "name,status,update,version,update_version,auto_update\n"
            "elementor,active,none,3.6.0,,off\n"
            "contact-form-7,active,none,5.5.0,,off\n"
        )
        path = _write_tmp(content)
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0"), ("contact-form-7", "5.5.0")]

    def test_header_only(self):
        path = _write_tmp("name,status,update,version\n")
        result = parse_plugins(path)
        os.unlink(path)
        assert result == []

    def test_comments_in_wpcli(self):
        content = (
            "name,status,update,version\n"
            "# skip this\n"
            "elementor,active,none,3.6.0\n"
        )
        path = _write_tmp(content)
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0")]


class TestTabSeparated:
    """Tab-separated wp-cli output."""

    def test_basic(self):
        content = (
            "name\tstatus\tupdate\tversion\n"
            "elementor\tactive\tnone\t3.6.0\n"
            "woocommerce\tactive\tnone\t6.0.0\n"
        )
        path = _write_tmp(content)
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0"), ("woocommerce", "6.0.0")]

    def test_simple_tab(self):
        """Simple tab-separated without header (slug\tversion)."""
        path = _write_tmp("elementor\t3.6.0\nwoocommerce\t6.0.0\n")
        result = parse_plugins(path)
        os.unlink(path)
        assert result == [("elementor", "3.6.0"), ("woocommerce", "6.0.0")]


class TestFixtures:
    """Test with actual fixture files."""

    FIXTURES_DIR = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "test_fixtures"
    )

    def test_plugins_txt(self):
        path = os.path.join(self.FIXTURES_DIR, "plugins.txt")
        result = parse_plugins(path)
        assert len(result) == 3
        slugs = [slug for slug, _ in result]
        assert "elementor" in slugs
        assert "contact-form-7" in slugs
        assert "woocommerce" in slugs

    def test_wpcli_csv(self):
        path = os.path.join(self.FIXTURES_DIR, "wpcli-output.csv")
        result = parse_plugins(path)
        assert len(result) == 4
        slugs = [slug for slug, _ in result]
        assert "akismet" in slugs
