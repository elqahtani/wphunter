"""Tests for VulnResult dataclass."""
from models import VulnResult


class TestVulnResult:

    def test_severity_from_score_critical(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       cvss_score=9.8)
        assert v.severity == "CRITICAL"

    def test_severity_from_score_high(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       cvss_score=7.5)
        assert v.severity == "HIGH"

    def test_severity_from_score_medium(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       cvss_score=5.0)
        assert v.severity == "MEDIUM"

    def test_severity_from_score_low(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       cvss_score=2.0)
        assert v.severity == "LOW"

    def test_severity_explicit_not_overridden(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       cvss_score=9.8, severity="HIGH")
        assert v.severity == "HIGH"

    def test_url_auto_generated(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234")
        assert v.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"

    def test_url_not_generated_for_non_cve(self):
        v = VulnResult(package="test", version="1.0", cve_id="some-uuid")
        assert v.url == ""

    def test_url_not_overridden(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       url="https://custom.url")
        assert v.url == "https://custom.url"

    def test_references_default_empty_list(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234")
        assert v.references == []

    def test_cvss_display_with_score(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       cvss_score=9.8)
        assert v.cvss_display == "9.8 C"

    def test_cvss_display_no_score(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234")
        assert v.cvss_display == "N/A"

    def test_severity_short(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234",
                       severity="HIGH")
        assert v.severity_short == "H"

    def test_severity_short_unknown(self):
        v = VulnResult(package="test", version="1.0", cve_id="CVE-2024-1234")
        assert v.severity_short == "?"
