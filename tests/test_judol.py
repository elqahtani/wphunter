"""Tests for judol injection detection (no network calls)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detectors.judol import (
    JudolDetector, JudolScanResult, GAMBLING_KEYWORDS,
    GAMBLING_DOMAIN_PATTERNS,
)

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_fixtures")


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


class TestKeywordScanning:

    def test_clean_page_no_keywords(self):
        html = _read_fixture("clean_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._scan_keywords(html, result)
        # Clean page should have zero high-confidence hits
        assert result.keyword_confidence_hits.get("high", 0) == 0

    def test_infected_page_has_keywords(self):
        html = _read_fixture("infected_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._scan_keywords(html, result)
        assert result.keyword_confidence_hits.get("high", 0) > 0
        assert "slot gacor" in result.gambling_keywords_found
        assert "togel hongkong" in result.gambling_keywords_found
        assert "judi online" in result.gambling_keywords_found


class TestHiddenElements:

    def test_detect_display_none(self):
        html = _read_fixture("infected_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._find_hidden_elements(html, result)
        assert len(result.hidden_elements) > 0
        methods = [h.hiding_method for h in result.hidden_elements]
        assert "display:none" in methods

    def test_clean_page_no_hidden(self):
        html = _read_fixture("clean_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._find_hidden_elements(html, result)
        assert len(result.hidden_elements) == 0


class TestSuspiciousLinks:

    def test_detect_gambling_domains(self):
        html = _read_fixture("infected_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._find_suspicious_links(html, "http://example.com", result)
        assert len(result.suspicious_links) > 0
        domains = [l.domain for l in result.suspicious_links]
        assert any("slot" in d for d in domains)

    def test_clean_page_no_suspicious_links(self):
        html = _read_fixture("clean_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._find_suspicious_links(html, "http://example.com", result)
        assert len(result.suspicious_links) == 0


class TestSuspiciousScripts:

    def test_detect_external_gambling_scripts(self):
        html = _read_fixture("infected_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._find_suspicious_scripts(html, result)
        assert len(result.suspicious_scripts) > 0
        assert any("slot" in s for s in result.suspicious_scripts)

    def test_clean_page_no_suspicious_scripts(self):
        html = _read_fixture("clean_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._find_suspicious_scripts(html, result)
        assert len(result.suspicious_scripts) == 0


class TestVerdict:

    def test_infected_verdict(self):
        result = JudolScanResult(target_url="http://example.com")
        result.keyword_confidence_hits = {"high": 30}
        result.gambling_keywords_found = {"slot gacor": 10, "judi online": 5}
        result.hidden_elements = [
            type("HE", (), {"tag": "div", "hiding_method": "display:none",
                           "text_content": "slot", "gambling_keywords": ["slot gacor"]})()
        ]
        result.suspicious_links = [
            type("SL", (), {"url": "http://slot88.xyz", "anchor_text": "slot",
                           "domain": "slot88.xyz", "reason": "gambling_domain"})()
        ]

        detector = JudolDetector("http://example.com")
        detector._determine_verdict(result)

        assert result.is_infected is True
        assert result.infection_type == "judol"

    def test_clean_verdict(self):
        result = JudolScanResult(target_url="http://example.com")
        detector = JudolDetector("http://example.com")
        detector._determine_verdict(result)
        assert result.is_infected is False
        assert result.infection_type == "clean"


class TestContentAnalysis:

    def test_full_content_analysis_infected(self):
        html = _read_fixture("infected_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._analyze_content(html, "http://example.com", result)

        # Should find keywords, hidden elements, suspicious links, and scripts
        assert result.keyword_confidence_hits.get("high", 0) > 0
        assert len(result.hidden_elements) > 0
        assert len(result.suspicious_links) > 0
        assert len(result.suspicious_scripts) > 0

    def test_full_content_analysis_clean(self):
        html = _read_fixture("clean_page.html")
        detector = JudolDetector("http://example.com")
        result = JudolScanResult(target_url="http://example.com")
        detector._analyze_content(html, "http://example.com", result)

        assert result.keyword_confidence_hits.get("high", 0) == 0
        assert len(result.hidden_elements) == 0
        assert len(result.suspicious_links) == 0
        assert len(result.suspicious_scripts) == 0


class TestJudolScanResult:

    def test_to_dict(self):
        result = JudolScanResult(target_url="http://example.com")
        d = result.to_dict()
        assert d["target_url"] == "http://example.com"
        assert "serp" in d
        assert "cloaking" in d
        assert "content" in d
        assert d["is_infected"] is False


class TestGamblingDomainPatterns:

    def test_slot_domain(self):
        assert any(p.search("slot88gacor.xyz") for p in GAMBLING_DOMAIN_PATTERNS)

    def test_togel_domain(self):
        assert any(p.search("togel-hongkong.top") for p in GAMBLING_DOMAIN_PATTERNS)

    def test_clean_domain(self):
        assert not any(p.search("wordpress.org") for p in GAMBLING_DOMAIN_PATTERNS)
