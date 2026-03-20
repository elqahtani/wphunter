"""Tests for remote WordPress fingerprinting (no network calls)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from parsers.remote import RemoteScanner, PluginInfo, RemoteScanResult

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_fixtures")


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


class TestWordPressDetection:

    def test_is_wordpress(self):
        html = _read_fixture("clean_page.html")
        scanner = RemoteScanner("http://example.com")
        assert scanner._is_wordpress(html) is True

    def test_not_wordpress(self):
        scanner = RemoteScanner("http://example.com")
        assert scanner._is_wordpress("<html><body>Hello</body></html>") is False

    def test_wp_version_extraction(self):
        html = _read_fixture("clean_page.html")
        scanner = RemoteScanner("http://example.com")
        assert scanner._extract_wp_version(html) == "6.4.3"

    def test_wp_version_not_found(self):
        scanner = RemoteScanner("http://example.com")
        assert scanner._extract_wp_version("<html></html>") is None


class TestPluginExtraction:

    def test_extract_plugins_from_html(self):
        html = _read_fixture("clean_page.html")
        scanner = RemoteScanner("http://example.com")
        plugins = scanner._extract_plugins_from_html(html)
        slugs = [slug for slug, _ in plugins]
        assert "flavor" in slugs
        assert "flavor-developer" in slugs

    def test_extract_plugin_versions(self):
        html = _read_fixture("clean_page.html")
        scanner = RemoteScanner("http://example.com")
        plugins = dict(scanner._extract_plugins_from_html(html))
        assert plugins.get("flavor") == "2.1.0"
        assert plugins.get("flavor-developer") == "1.0.0"


class TestThemeExtraction:

    def test_extract_theme_from_html(self):
        html = _read_fixture("clean_page.html")
        scanner = RemoteScanner("http://example.com")
        theme = scanner._extract_theme_from_html(html)
        assert theme is not None
        assert theme[0] == "flavor"
        assert theme[1] == "1.2.3"


class TestReadmeParsing:

    def test_parse_readme_version(self):
        readme = "=== My Plugin ===\nStable tag: 3.2.1\nRequires at least: 5.0\n"
        assert RemoteScanner._parse_readme_version(readme) == "3.2.1"

    def test_parse_readme_no_version(self):
        assert RemoteScanner._parse_readme_version("No version here") is None

    def test_parse_style_css_version(self):
        css = "/*\nTheme Name: Flavor\nVersion: 2.0.5\nAuthor: Someone\n*/"
        assert RemoteScanner._parse_style_css_version(css) == "2.0.5"


class TestRemoteScanResult:

    def test_to_plugin_tuples(self):
        result = RemoteScanResult(url="http://example.com")
        result.plugins = [
            PluginInfo(slug="elementor", version="3.6.0", source="html_parse"),
            PluginInfo(slug="jetpack", version=None, source="wpjson"),
            PluginInfo(slug="woocommerce", version="6.0.0", source="readme"),
        ]
        tuples = result.to_plugin_tuples()
        assert ("elementor", "3.6.0") in tuples
        assert ("woocommerce", "6.0.0") in tuples
        # jetpack has no version, should be excluded
        assert len(tuples) == 2

    def test_to_theme_tuples(self):
        result = RemoteScanResult(url="http://example.com")
        result.theme = PluginInfo(slug="flavor", version="1.2.3", source="html_parse")
        assert result.to_theme_tuples() == [("flavor", "1.2.3")]

    def test_to_theme_tuples_none(self):
        result = RemoteScanResult(url="http://example.com")
        assert result.to_theme_tuples() == []
