"""Tests for vulnerability deduplication logic."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner import _dedup_vulns
from models import VulnResult


def _vuln(package="test", cve_id="CVE-2024-1234", cvss_score=None,
          references=None, source="wpvulndb"):
    return VulnResult(
        package=package, version="1.0", cve_id=cve_id,
        cvss_score=cvss_score, source=source,
        references=references,
    )


class TestDedup:

    def test_no_duplicates(self):
        vulns = [_vuln(cve_id="CVE-2024-0001"), _vuln(cve_id="CVE-2024-0002")]
        result = _dedup_vulns(vulns)
        assert len(result) == 2

    def test_exact_duplicate_kept_once(self):
        vulns = [_vuln(cve_id="CVE-2024-0001"), _vuln(cve_id="CVE-2024-0001")]
        result = _dedup_vulns(vulns)
        assert len(result) == 1

    def test_prefers_entry_with_cvss(self):
        v1 = _vuln(cvss_score=None, source="wpscan")
        v2 = _vuln(cvss_score=9.8, source="wpvulndb")
        result = _dedup_vulns([v1, v2])
        assert len(result) == 1
        assert result[0].cvss_score == 9.8
        assert result[0].source == "wpvulndb"

    def test_prefers_entry_with_more_refs(self):
        v1 = _vuln(references=["ref1"])
        v2 = _vuln(references=["ref1", "ref2", "ref3"])
        result = _dedup_vulns([v1, v2])
        assert len(result) == 1
        assert len(result[0].references) == 3

    def test_different_packages_not_deduped(self):
        v1 = _vuln(package="plugin-a", cve_id="CVE-2024-0001")
        v2 = _vuln(package="plugin-b", cve_id="CVE-2024-0001")
        result = _dedup_vulns([v1, v2])
        assert len(result) == 2

    def test_empty_list(self):
        assert _dedup_vulns([]) == []

    def test_single_item(self):
        vulns = [_vuln()]
        result = _dedup_vulns(vulns)
        assert len(result) == 1
