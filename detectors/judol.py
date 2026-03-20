"""Judol (Indonesian gambling spam) injection detector for WordPress sites.

Detects gambling content injection via:
  1. Google SERP check — indexed gambling pages
  2. Cloaking detection — different content for bots vs humans
  3. Content analysis — keywords, hidden elements, suspicious links, scripts
"""
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests

from config import (
    GOOGLE_CSE_API_KEY, GOOGLE_CSE_ID,
    GOOGLEBOT_USER_AGENT, REQUEST_TIMEOUT,
)


# ── Gambling Keyword Database ────────────────────────────────────────────────

GAMBLING_KEYWORDS = {
    "high": [
        "slot gacor", "slot88", "slot777", "togel", "togel hongkong",
        "togel singapore", "togel sydney", "bandar togel", "judi online",
        "judi bola", "sbobet", "sbobet88", "rtp live", "rtp slot",
        "bocoran rtp", "maxwin", "scatter hitam", "deposit pulsa",
        "slot deposit", "daftar slot", "link alternatif", "situs gacor",
        "slot terpercaya", "judi slot", "agen slot", "pragmatic play",
        "pg soft", "habanero slot", "bonus new member", "slot online",
        "casino online", "poker online", "dominoqq", "bandarqq",
        "pkv games", "slot dana", "slot gopay", "slot ovo",
        # International gambling terms
        "online casino", "live casino", "sports betting", "online gambling",
        "vavada", "1xbet", "mostbet", "melbet", "pin-up casino",
        "betway", "bet365", "stake casino",
    ],
    "medium": [
        "jackpot", "bonus deposit", "freebet", "freespin", "free spin",
        "bet online", "taruhan", "bandar", "agen bola", "parlay",
        "mix parlay", "handicap", "over under", "livescore",
        "withdraw", "turnover", "rollover",
    ],
    "low": [
        "gacor", "scatter", "wild", "rtp",
        "deposit", "bonus", "promo", "daftar",
    ],
}

# Keywords specifically for URL/slug detection (broader than content keywords)
GAMBLING_URL_KEYWORDS = [
    "slot", "togel", "judi", "casino", "poker", "sbobet", "gambling",
    "betting", "vavada", "1xbet", "mostbet", "melbet", "pin-up",
    "gacor", "maxwin", "judol", "bandar", "toto", "kasyno",
    "roulette", "blackjack", "baccarat",
]

GAMBLING_DOMAIN_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"slot\d*", r"togel", r"judi", r"casino", r"poker",
        r"sbobet", r"gacor", r"bet\d+", r"judol",
        r"pragmatic", r"maxwin", r"toto\d*", r"bandar",
        r"vavada", r"1xbet", r"mostbet", r"melbet", r"pin-?up",
        r"kasyno", r"gambling", r"roulette", r"baccarat",
    ]
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".online", ".site", ".fun", ".bid", ".win"}

# Hidden CSS patterns
HIDDEN_CSS_PATTERNS = [
    (r"display\s*:\s*none", "display:none"),
    (r"visibility\s*:\s*hidden", "visibility:hidden"),
    (r"position\s*:\s*absolute[^;]*left\s*:\s*-\d+", "position:absolute+left:-9999px"),
    (r"font-size\s*:\s*0", "font-size:0"),
    (r"z-index\s*:\s*-\d+", "z-index:-1"),
    (r"opacity\s*:\s*0(?:[;\s]|$)", "opacity:0"),
    (r"overflow\s*:\s*hidden[^;]*(?:height|width)\s*:\s*0", "overflow:hidden+size:0"),
    (r"text-indent\s*:\s*-\d{4,}", "text-indent:-9999"),
    (r"color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255)", "color:white"),
]

# Spam directories commonly created by attackers
SPAM_DIRS = ["/docs/", "/go/", "/link/", "/out/", "/redirect/", "/slot/",
             "/judi/", "/togel/", "/casino/", "/sbobet/"]

# SERP search queries
SERP_QUERIES = [
    "slot gacor", "togel", "judi online", "casino online",
    "sbobet", "rtp live", "poker online",
]


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class CloakingResult:
    url: str
    is_cloaked: bool
    human_size: int
    bot_size: int
    size_ratio: float
    gambling_keywords_in_diff: List[str]
    diff_sample: str

@dataclass
class HiddenElement:
    tag: str
    hiding_method: str
    text_content: str
    gambling_keywords: List[str]

@dataclass
class SuspiciousLink:
    url: str
    anchor_text: str
    domain: str
    reason: str

@dataclass
class SerpResult:
    query: str
    total_results: int
    sample_urls: List[str]
    sample_titles: List[str]

@dataclass
class JudolScanResult:
    target_url: str
    scan_timestamp: str = ""

    # SERP
    serp_results: List[SerpResult] = field(default_factory=list)
    serp_gambling_total: int = 0

    # Cloaking
    pages_checked: int = 0
    cloaked_pages: List[CloakingResult] = field(default_factory=list)

    # Content
    gambling_keywords_found: Dict[str, int] = field(default_factory=dict)
    keyword_confidence_hits: Dict[str, int] = field(default_factory=dict)
    hidden_elements: List[HiddenElement] = field(default_factory=list)
    suspicious_links: List[SuspiciousLink] = field(default_factory=list)
    suspicious_scripts: List[str] = field(default_factory=list)
    spam_directories: List[str] = field(default_factory=list)

    # Overall
    is_infected: bool = False
    confidence: str = "low"
    infection_type: str = "clean"
    severity: str = "low"

    def __post_init__(self):
        if not self.scan_timestamp:
            self.scan_timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "target_url": self.target_url,
            "scan_timestamp": self.scan_timestamp,
            "is_infected": self.is_infected,
            "confidence": self.confidence,
            "infection_type": self.infection_type,
            "severity": self.severity,
            "serp": {
                "total_gambling_results": self.serp_gambling_total,
                "queries": [
                    {"query": s.query, "results": s.total_results,
                     "urls": s.sample_urls, "titles": s.sample_titles}
                    for s in self.serp_results
                ],
            },
            "cloaking": {
                "pages_checked": self.pages_checked,
                "cloaked_pages": [
                    {"url": c.url, "is_cloaked": c.is_cloaked,
                     "size_ratio": round(c.size_ratio, 2),
                     "keywords": c.gambling_keywords_in_diff,
                     "diff_sample": c.diff_sample}
                    for c in self.cloaked_pages
                ],
            },
            "content": {
                "gambling_keywords": self.gambling_keywords_found,
                "confidence_hits": self.keyword_confidence_hits,
                "hidden_elements": [
                    {"tag": h.tag, "method": h.hiding_method,
                     "text": h.text_content[:200], "keywords": h.gambling_keywords}
                    for h in self.hidden_elements
                ],
                "suspicious_links": [
                    {"url": l.url, "anchor": l.anchor_text,
                     "domain": l.domain, "reason": l.reason}
                    for l in self.suspicious_links
                ],
                "suspicious_scripts": self.suspicious_scripts,
                "spam_directories": self.spam_directories,
            },
        }


# ── Detector ─────────────────────────────────────────────────────────────────

class JudolDetector:
    """Detect gambling spam injection on a WordPress site."""

    HUMAN_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self, url: str, timeout: int = REQUEST_TIMEOUT, delay_ms: int = 100):
        self.base_url = url.rstrip("/")
        self.timeout = timeout
        self.delay_s = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.verify = True

    def scan(self) -> JudolScanResult:
        """Run full judol detection scan."""
        result = JudolScanResult(target_url=self.base_url)

        print("[*] --- Judol Injection Detection ---")

        # Layer 1: Google SERP check
        self._check_serp(result)

        # Layer 2: Cloaking detection
        self._detect_cloaking(result)

        # Layer 3: Content analysis
        html = self._fetch_as_human(self.base_url)
        if html:
            self._analyze_content(html, self.base_url, result)

        # Also check bot version for hidden content
        bot_html = self._fetch_as_bot(self.base_url)
        if bot_html and bot_html != html:
            self._analyze_content(bot_html, self.base_url, result)

        # Check spam directories
        self._check_spam_dirs(result)

        # Check sitemap
        self._check_sitemap(result)

        # Determine overall verdict
        self._determine_verdict(result)

        return result

    # ── Layer 1: SERP ────────────────────────────────────────────────────

    def _check_serp(self, result: JudolScanResult):
        """Check Google for indexed gambling content on this domain."""
        domain = urlparse(self.base_url).netloc
        print(f"[*] Layer 1: Google SERP check for {domain}")

        if GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID:
            self._check_serp_api(domain, result)
        else:
            print("    [*] No Google CSE API key set — generating manual search URLs")
            print("    [*] Set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID for automated SERP check")
            for query in SERP_QUERIES:
                full_query = f"site:{domain} {query}"
                search_url = f"https://www.google.com/search?q={full_query.replace(' ', '+')}"
                result.serp_results.append(SerpResult(
                    query=full_query, total_results=0,
                    sample_urls=[search_url], sample_titles=["Manual check required"],
                ))
            print(f"    [*] Generated {len(SERP_QUERIES)} manual search URLs")

    def _check_serp_api(self, domain: str, result: JudolScanResult):
        """Use Google Custom Search API to check for gambling results."""
        for query in SERP_QUERIES:
            full_query = f"site:{domain} {query}"
            try:
                resp = self.session.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={
                        "key": GOOGLE_CSE_API_KEY,
                        "cx": GOOGLE_CSE_ID,
                        "q": full_query,
                    },
                    timeout=self.timeout,
                )
                if resp.status_code != 200:
                    continue
                data = resp.json()
                total = int(data.get("searchInformation", {}).get("totalResults", 0))
                items = data.get("items", [])
                serp = SerpResult(
                    query=full_query,
                    total_results=total,
                    sample_urls=[i.get("link", "") for i in items[:5]],
                    sample_titles=[i.get("title", "") for i in items[:5]],
                )
                result.serp_results.append(serp)
                result.serp_gambling_total += total
                if total > 0:
                    print(f"    [!] SERP hit: '{query}' — {total} results")
            except requests.RequestException:
                continue

    # ── Layer 2: Cloaking ────────────────────────────────────────────────

    def _detect_cloaking(self, result: JudolScanResult):
        """Detect cloaking by comparing human vs bot responses."""
        print("[*] Layer 2: Cloaking detection")

        pages_to_check = [
            self.base_url,
            f"{self.base_url}/feed/",
            f"{self.base_url}/?s=slot",
            f"{self.base_url}/page/2/",
        ]

        for url in pages_to_check:
            cr = self._compare_responses(url)
            if cr:
                result.pages_checked += 1
                if cr.is_cloaked:
                    result.cloaked_pages.append(cr)
                    print(f"    [!] Cloaking detected: {url} "
                          f"(ratio: {cr.size_ratio:.1f}x, "
                          f"keywords: {len(cr.gambling_keywords_in_diff)})")

        if not result.cloaked_pages:
            print("    [+] No cloaking detected")

    def _compare_responses(self, url: str) -> Optional[CloakingResult]:
        """Fetch URL as human and bot, compare content."""
        human = self._fetch_as_human(url)
        bot = self._fetch_as_bot(url)

        if not human or not bot:
            return None

        human_text = self._strip_html(human)
        bot_text = self._strip_html(bot)

        human_size = len(human)
        bot_size = len(bot)
        ratio = bot_size / human_size if human_size > 0 else 1.0

        # Find content only in bot version
        human_words = set(human_text.lower().split())
        bot_words = set(bot_text.lower().split())
        diff_words = bot_words - human_words
        diff_text = " ".join(list(diff_words)[:200])

        # Check for gambling keywords in diff
        gambling_in_diff = []
        diff_lower = diff_text.lower()
        for kw in GAMBLING_KEYWORDS["high"] + GAMBLING_KEYWORDS["medium"]:
            if kw.lower() in diff_lower:
                gambling_in_diff.append(kw)

        is_cloaked = (ratio > 1.5 and gambling_in_diff) or len(gambling_in_diff) >= 3

        return CloakingResult(
            url=url,
            is_cloaked=is_cloaked,
            human_size=human_size,
            bot_size=bot_size,
            size_ratio=ratio,
            gambling_keywords_in_diff=gambling_in_diff,
            diff_sample=diff_text[:500],
        )

    # ── Layer 3: Content Analysis ────────────────────────────────────────

    def _analyze_content(self, html: str, url: str, result: JudolScanResult):
        """Deep content analysis for gambling indicators."""
        # 3a: Keyword matching
        self._scan_keywords(html, result)

        # 3b: Hidden elements
        self._find_hidden_elements(html, result)

        # 3c: Suspicious outbound links
        self._find_suspicious_links(html, url, result)

        # 3d: Suspicious scripts/iframes
        self._find_suspicious_scripts(html, result)

    def _scan_keywords(self, html: str, result: JudolScanResult):
        """Scan HTML for gambling keywords by confidence level."""
        html_lower = html.lower()
        for level, keywords in GAMBLING_KEYWORDS.items():
            for kw in keywords:
                count = html_lower.count(kw.lower())
                if count > 0:
                    result.gambling_keywords_found[kw] = (
                        result.gambling_keywords_found.get(kw, 0) + count
                    )
                    result.keyword_confidence_hits[level] = (
                        result.keyword_confidence_hits.get(level, 0) + count
                    )

    def _find_hidden_elements(self, html: str, result: JudolScanResult):
        """Find elements hidden via CSS that contain gambling content."""
        # Find elements with inline style containing hiding patterns
        # Pattern: <tag ... style="...hiding_css..." ...>text</tag>
        tag_pattern = re.compile(
            r'<(\w+)\s[^>]*style="([^"]*)"[^>]*>(.*?)</\1>',
            re.IGNORECASE | re.DOTALL
        )

        for match in tag_pattern.finditer(html):
            tag = match.group(1)
            style = match.group(2)
            content = self._strip_html(match.group(3))

            if not content.strip():
                continue

            for css_re, method_name in HIDDEN_CSS_PATTERNS:
                if re.search(css_re, style, re.IGNORECASE):
                    # Check if hidden content has gambling keywords
                    content_lower = content.lower()
                    found_kws = []
                    for kw in GAMBLING_KEYWORDS["high"] + GAMBLING_KEYWORDS["medium"]:
                        if kw.lower() in content_lower:
                            found_kws.append(kw)

                    if found_kws:
                        result.hidden_elements.append(HiddenElement(
                            tag=tag,
                            hiding_method=method_name,
                            text_content=content[:300],
                            gambling_keywords=found_kws,
                        ))
                    break

    def _find_suspicious_links(self, html: str, page_url: str,
                                result: JudolScanResult):
        """Find outbound links pointing to gambling domains."""
        link_pattern = re.compile(
            r'<a\s[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )

        page_domain = urlparse(page_url).netloc
        seen_domains = set()

        for match in link_pattern.finditer(html):
            href = match.group(1)
            anchor = self._strip_html(match.group(2)).strip()

            try:
                parsed = urlparse(href)
                domain = parsed.netloc.lower()
            except (ValueError, AttributeError):
                continue

            # Skip same-domain and already-seen
            if domain == page_domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            reason = None

            # Check domain against gambling patterns
            for pat in GAMBLING_DOMAIN_PATTERNS:
                if pat.search(domain):
                    reason = "gambling_domain"
                    break

            # Check suspicious TLD
            if not reason:
                for tld in SUSPICIOUS_TLDS:
                    if domain.endswith(tld):
                        # Only flag if anchor text also has gambling keywords
                        anchor_lower = anchor.lower()
                        for kw in GAMBLING_KEYWORDS["high"]:
                            if kw.lower() in anchor_lower:
                                reason = "suspicious_tld_with_gambling_anchor"
                                break
                        break

            # Check anchor text for gambling keywords
            if not reason:
                anchor_lower = anchor.lower()
                for kw in GAMBLING_KEYWORDS["high"]:
                    if kw.lower() in anchor_lower:
                        reason = "gambling_anchor_text"
                        break

            if reason:
                result.suspicious_links.append(SuspiciousLink(
                    url=href, anchor_text=anchor[:100],
                    domain=domain, reason=reason,
                ))

    def _find_suspicious_scripts(self, html: str, result: JudolScanResult):
        """Find suspicious external scripts and iframes."""
        # External scripts
        script_pattern = re.compile(
            r'<script[^>]*src="(https?://[^"]+)"', re.IGNORECASE
        )
        page_domain = urlparse(self.base_url).netloc

        for match in script_pattern.finditer(html):
            src = match.group(1)
            try:
                domain = urlparse(src).netloc.lower()
            except (ValueError, AttributeError):
                continue
            if domain == page_domain:
                continue
            for pat in GAMBLING_DOMAIN_PATTERNS:
                if pat.search(domain) or pat.search(src):
                    result.suspicious_scripts.append(src)
                    break

        # Hidden iframes
        iframe_pattern = re.compile(
            r'<iframe[^>]*(?:style="[^"]*(?:display\s*:\s*none|width\s*:\s*0|height\s*:\s*0)[^"]*")[^>]*src="([^"]+)"',
            re.IGNORECASE
        )
        for match in iframe_pattern.finditer(html):
            result.suspicious_scripts.append(f"iframe:{match.group(1)}")

        # Obfuscated JS patterns
        obfuscation_patterns = [
            r'eval\s*\(\s*atob\s*\(',
            r'document\.write\s*\(\s*unescape\s*\(',
            r'String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){10,}',
            r'\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}',
        ]
        for pat in obfuscation_patterns:
            if re.search(pat, html, re.IGNORECASE):
                result.suspicious_scripts.append(f"obfuscated_js:{pat[:40]}")

    def _check_spam_dirs(self, result: JudolScanResult):
        """Check for attacker-created spam directories."""
        print("[*] Layer 3: Checking spam directories")
        for path in SPAM_DIRS:
            url = f"{self.base_url}{path}"
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, allow_redirects=True,
                    headers={"User-Agent": self.HUMAN_UA},
                )
                if resp.status_code == 200:
                    # Check if the page has gambling content
                    text_lower = resp.text.lower()
                    has_gambling = any(
                        kw.lower() in text_lower
                        for kw in GAMBLING_KEYWORDS["high"][:10]
                    )
                    if has_gambling:
                        result.spam_directories.append(path)
                        print(f"    [!] Spam directory found: {path}")
            except requests.RequestException:
                continue

    def _check_sitemap(self, result: JudolScanResult):
        """Check sitemap.xml for suspicious URLs and crawl pages for gambling content."""
        print("[*] Layer 4: Sitemap analysis")

        sitemap = self._fetch_as_human(f"{self.base_url}/sitemap.xml")
        if not sitemap:
            # Try wp-sitemap.xml (WordPress 5.5+ default)
            sitemap = self._fetch_as_human(f"{self.base_url}/wp-sitemap.xml")
        if not sitemap:
            print("    [*] No sitemap found — skipping page crawl")
            return

        # Extract all URLs from sitemap (handle both sitemap index and urlset)
        url_pattern = re.compile(r'<loc>(.*?)</loc>', re.IGNORECASE)
        all_urls = []
        for m in url_pattern.finditer(sitemap):
            url = m.group(1).strip()
            # Strip CDATA wrapper if present
            if url.startswith('<![CDATA['):
                url = url[9:]
            if url.endswith(']]>'):
                url = url[:-3]
            all_urls.append(url.strip())

        # If this is a sitemap index, fetch child sitemaps
        if '<sitemapindex' in sitemap.lower():
            child_urls = []
            for sitemap_url in all_urls[:5]:  # Max 5 child sitemaps
                child_xml = self._fetch_as_human(sitemap_url)
                if child_xml:
                    for m in url_pattern.finditer(child_xml):
                        u = m.group(1).strip()
                        if u.startswith('<![CDATA['):
                            u = u[9:]
                        if u.endswith(']]>'):
                            u = u[:-3]
                        child_urls.append(u.strip())
            all_urls = child_urls

        if not all_urls:
            return

        print(f"    [*] Found {len(all_urls)} URLs in sitemap")

        # Phase 1: Check ALL URLs for gambling keywords in path/slug
        # Use word boundary matching to avoid false positives (e.g. "judith" ≠ "judi")
        gambling_urls = []
        clean_urls = []
        gambling_url_patterns = [
            re.compile(r'(?:^|[-_/])' + re.escape(kw) + r'(?:[-_/\d]|$)', re.IGNORECASE)
            for kw in GAMBLING_URL_KEYWORDS
        ]
        for url in all_urls:
            path_lower = urlparse(url).path.lower()
            is_gambling = False
            for pat in gambling_url_patterns:
                if pat.search(path_lower):
                    gambling_urls.append(url)
                    is_gambling = True
                    break
            if not is_gambling:
                clean_urls.append(url)

        if gambling_urls:
            result.spam_directories.append(f"sitemap:{len(gambling_urls)}_gambling_urls")
            print(f"    [!] Sitemap contains {len(gambling_urls)} gambling-related URLs")
            for url in gambling_urls[:10]:
                print(f"        {url}")

        # Phase 2: Crawl gambling URLs for evidence
        gambling_to_crawl = gambling_urls[:5]
        if gambling_to_crawl:
            print(f"    [*] Crawling {len(gambling_to_crawl)} gambling URLs for content analysis...")
            for page_url in gambling_to_crawl:
                html = self._fetch_as_human(page_url)
                if html:
                    self._analyze_content(html, page_url, result)
                    print(f"    [!] Analyzed gambling page: {page_url}")
                if self.delay_s:
                    time.sleep(self.delay_s)

        # Phase 3: Crawl sample of clean-looking pages for hidden injection
        # Spread sampling across sitemap: start, middle, end
        sample_size = min(20, len(clean_urls))
        if sample_size > 0 and len(clean_urls) > sample_size:
            step = max(1, len(clean_urls) // sample_size)
            pages_to_check = [clean_urls[i] for i in range(0, len(clean_urls), step)][:sample_size]
        else:
            pages_to_check = clean_urls[:sample_size]

        if pages_to_check:
            print(f"    [*] Crawling {len(pages_to_check)} pages for hidden gambling content...")
            infected_pages = 0
            for page_url in pages_to_check:
                html = self._fetch_as_human(page_url)
                if not html:
                    continue
                # Quick keyword scan on page content
                text_lower = html.lower()
                page_high_hits = sum(
                    1 for kw in GAMBLING_KEYWORDS["high"]
                    if kw.lower() in text_lower
                )
                if page_high_hits >= 3:
                    infected_pages += 1
                    self._analyze_content(html, page_url, result)
                    print(f"    [!] Infected page: {page_url} ({page_high_hits} keywords)")

                if self.delay_s:
                    time.sleep(self.delay_s)

            if infected_pages:
                print(f"    [!] {infected_pages}/{len(pages_to_check)} crawled pages contain gambling content")
            else:
                print(f"    [+] {len(pages_to_check)} crawled pages are clean")

    # ── Verdict ──────────────────────────────────────────────────────────

    def _determine_verdict(self, result: JudolScanResult):
        """Determine overall infection status and confidence."""
        score = 0

        # Cloaking with gambling keywords = very strong signal
        if result.cloaked_pages:
            score += 40
            for cp in result.cloaked_pages:
                score += len(cp.gambling_keywords_in_diff) * 5

        # Hidden elements with gambling = strong signal
        if result.hidden_elements:
            score += 30

        # High-confidence keyword hits
        high_hits = result.keyword_confidence_hits.get("high", 0)
        score += min(high_hits * 2, 30)

        # Suspicious links
        gambling_links = [l for l in result.suspicious_links if l.reason == "gambling_domain"]
        score += min(len(gambling_links) * 10, 30)

        # Spam directories
        score += len(result.spam_directories) * 15

        # SERP results
        score += min(result.serp_gambling_total * 5, 30)

        # Suspicious scripts
        score += len(result.suspicious_scripts) * 10

        # Determine verdict
        if score >= 50:
            result.is_infected = True
            result.infection_type = "judol"
            if score >= 80:
                result.confidence = "confirmed"
                result.severity = "critical"
            elif score >= 50:
                result.confidence = "high"
                result.severity = "high"
        elif score >= 25:
            result.is_infected = True
            result.infection_type = "judol"
            result.confidence = "medium"
            result.severity = "medium"
        elif score >= 10:
            result.is_infected = False
            result.confidence = "low"
            result.severity = "low"
            result.infection_type = "suspicious"
        else:
            result.is_infected = False
            result.confidence = "low"
            result.severity = "low"
            result.infection_type = "clean"

        # Print verdict
        status = "INFECTED" if result.is_infected else "CLEAN"
        color_map = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}
        print(f"\n[*] Judol Detection Verdict: {status}")
        print(f"    Confidence: {result.confidence}")
        print(f"    Severity: {result.severity}")
        print(f"    Type: {result.infection_type}")
        print(f"    Score: {score}/100+")

        if result.gambling_keywords_found:
            top_kw = sorted(result.gambling_keywords_found.items(),
                           key=lambda x: x[1], reverse=True)[:5]
            print(f"    Top keywords: {', '.join(f'{k}({v})' for k, v in top_kw)}")

    # ── Helpers ──────────────────────────────────────────────────────────

    def _fetch_as_human(self, url: str) -> Optional[str]:
        """Fetch URL with human User-Agent."""
        try:
            resp = self.session.get(
                url, timeout=self.timeout,
                headers={"User-Agent": self.HUMAN_UA},
                allow_redirects=True,
            )
            return resp.text if resp.status_code == 200 else None
        except requests.RequestException:
            return None

    def _fetch_as_bot(self, url: str) -> Optional[str]:
        """Fetch URL with Googlebot User-Agent."""
        try:
            resp = self.session.get(
                url, timeout=self.timeout,
                headers={"User-Agent": GOOGLEBOT_USER_AGENT},
                allow_redirects=True,
            )
            return resp.text if resp.status_code == 200 else None
        except requests.RequestException:
            return None

    @staticmethod
    def _strip_html(html: str) -> str:
        """Remove HTML tags, return text only."""
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
