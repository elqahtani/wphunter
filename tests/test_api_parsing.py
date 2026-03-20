"""Tests for API response parsing (no network calls)."""
from apis.wpvulndb import _parse_vuln, _extract_cve_id
from apis.wpscan import _parse_wpscan_vulns


class TestWpvulndbParsing:

    def test_parse_vuln_basic(self):
        vuln = {
            "name": "SQL Injection",
            "uuid": "abc-123",
            "impact": {"cvss": {"score": "9.8", "severity": "c"}},
            "operator": {"max_version": "2.0.0", "unfixed": "0"},
            "source": [
                {"id": "CVE-2024-1234", "name": "CVE-2024-1234",
                 "link": "https://example.com"}
            ],
        }
        result = _parse_vuln(vuln, "my-plugin", "1.0.0")
        assert result.package == "my-plugin"
        assert result.version == "1.0.0"
        assert result.cve_id == "CVE-2024-1234"
        assert result.cvss_score == 9.8
        assert result.severity == "CRITICAL"
        assert result.summary == "SQL Injection"
        assert result.fix_version == "2.0.0"
        assert result.source == "wpvulndb"
        assert "https://example.com" in result.references

    def test_parse_vuln_no_cvss(self):
        vuln = {
            "name": "XSS Vulnerability",
            "uuid": "def-456",
            "source": [],
        }
        result = _parse_vuln(vuln, "test", "1.0")
        assert result.cvss_score is None
        assert result.severity == "UNKNOWN"

    def test_parse_vuln_unfixed(self):
        vuln = {
            "name": "Open Redirect",
            "uuid": "ghi-789",
            "operator": {"max_version": "99.0.0", "unfixed": "1"},
            "source": [],
        }
        result = _parse_vuln(vuln, "test", "1.0")
        assert result.fix_version == ""

    def test_parse_vuln_summary_fallback(self):
        vuln = {
            "name": "",
            "uuid": "jkl-012",
            "source": [
                {"description": "[en] Some description", "link": ""}
            ],
        }
        result = _parse_vuln(vuln, "test", "1.0")
        assert result.summary == "Some description"

    def test_extract_cve_from_id(self):
        vuln = {"source": [{"id": "CVE-2024-9999", "name": "something"}]}
        assert _extract_cve_id(vuln) == "CVE-2024-9999"

    def test_extract_cve_from_name(self):
        vuln = {"source": [{"id": "12345", "name": "CVE-2024-8888"}]}
        assert _extract_cve_id(vuln) == "CVE-2024-8888"

    def test_extract_cve_fallback_uuid(self):
        vuln = {"uuid": "fallback-id", "source": [{"id": "123", "name": "abc"}]}
        assert _extract_cve_id(vuln) == "fallback-id"


class TestWpscanParsing:

    def test_parse_basic(self):
        vulns = [
            {
                "id": "wp-vuln-1",
                "title": "Auth Bypass",
                "fixed_in": "2.0.0",
                "cvss": {"score": 8.1, "rating": "high"},
                "references": {
                    "cve": ["2024-5678"],
                    "url": ["https://example.com/advisory"],
                },
            }
        ]
        result = _parse_wpscan_vulns(vulns, "my-plugin", "1.5.0")
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2024-5678"
        assert result[0].cvss_score == 8.1
        assert result[0].severity == "HIGH"
        assert result[0].fix_version == "2.0.0"
        assert result[0].source == "wpscan"
        assert "https://example.com/advisory" in result[0].references

    def test_parse_filters_by_version(self):
        vulns = [{"id": "1", "title": "Old", "fixed_in": "1.0.0",
                  "references": {}}]
        result = _parse_wpscan_vulns(vulns, "test", "2.0.0")
        assert len(result) == 0

    def test_parse_no_cve_uses_id(self):
        vulns = [{"id": "wp-id-123", "title": "Bug", "references": {}}]
        result = _parse_wpscan_vulns(vulns, "test", "1.0.0")
        assert result[0].cve_id == "wp-id-123"

    def test_parse_no_cvss(self):
        vulns = [{"id": "1", "title": "Bug", "references": {}}]
        result = _parse_wpscan_vulns(vulns, "test", "1.0.0")
        assert result[0].cvss_score is None
        assert result[0].severity == "UNKNOWN"

    def test_parse_empty_list(self):
        assert _parse_wpscan_vulns([], "test", "1.0") == []
