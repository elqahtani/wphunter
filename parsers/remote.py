"""Remote WordPress fingerprinting — detect WP version, plugins, themes from a URL."""
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import requests

from config import DEFAULT_USER_AGENT, REQUEST_TIMEOUT


# REST API namespace → plugin slug mapping
NAMESPACE_MAP = {
    "wc": "woocommerce",
    "wc-analytics": "woocommerce",
    "jetpack": "jetpack",
    "yoast": "wordpress-seo",
    "wp-seo": "wordpress-seo",
    "elementor": "elementor",
    "contact-form-7": "contact-form-7",
    "akismet": "akismet",
    "wordfence": "wordfence",
    "updraftplus": "updraftplus",
    "rsssl": "really-simple-ssl",
    "wp-mail-smtp": "wp-mail-smtp",
    "redirection": "redirection",
    "aioseo": "all-in-one-seo-pack",
    "wpforms": "wpforms-lite",
    "classic-editor": "classic-editor",
    "litespeed": "litespeed-cache",
    "rank-math": "seo-by-rank-math",
    "monsterinsights": "google-analytics-for-wordpress",
    "duplicator": "duplicator",
    "w3-total-cache": "w3-total-cache",
    "wp-super-cache": "wp-super-cache",
    "all-in-one-wp-migration": "all-in-one-wp-migration",
    "ithemes-security": "better-wp-security",
    "sucuri": "sucuri-scanner",
}


@dataclass
class PluginInfo:
    slug: str
    version: Optional[str]
    source: str  # "html_parse", "readme", "wpjson", "aggressive", "style_css"


@dataclass
class RemoteScanResult:
    url: str
    is_wordpress: bool = False
    wp_version: Optional[str] = None
    theme: Optional[PluginInfo] = None
    plugins: List[PluginInfo] = field(default_factory=list)

    def to_plugin_tuples(self) -> List[Tuple[str, str]]:
        """Convert detected plugins to (slug, version) tuples for vuln scanning."""
        return [
            (p.slug, p.version) for p in self.plugins if p.version
        ]

    def to_theme_tuples(self) -> List[Tuple[str, str]]:
        """Convert detected theme to (slug, version) tuples."""
        if self.theme and self.theme.version:
            return [(self.theme.slug, self.theme.version)]
        return []


class RemoteScanner:
    """Fingerprint a WordPress site remotely."""

    def __init__(self, url: str, user_agent: str = DEFAULT_USER_AGENT,
                 timeout: int = REQUEST_TIMEOUT, threads: int = 10,
                 delay_ms: int = 100):
        self.base_url = url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.delay_s = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.session.verify = True

    def scan(self, aggressive: bool = False) -> RemoteScanResult:
        """Run full fingerprinting scan."""
        result = RemoteScanResult(url=self.base_url)

        # Phase 1: Passive — fetch homepage
        html = self._fetch(self.base_url)
        if not html:
            print("    [!] Could not fetch target URL")
            return result

        # Check if it's WordPress
        result.is_wordpress = self._is_wordpress(html)
        if not result.is_wordpress:
            print("    [!] Target does not appear to be WordPress")
            return result

        print("    [+] WordPress detected")

        # Extract WP version from meta generator
        result.wp_version = self._extract_wp_version(html)
        if result.wp_version:
            print(f"    [+] WordPress version: {result.wp_version}")

        # Extract plugins from HTML source (CSS/JS ?ver= params)
        html_plugins = self._extract_plugins_from_html(html)
        seen_slugs = set()
        for slug, ver in html_plugins:
            if slug not in seen_slugs:
                result.plugins.append(PluginInfo(slug=slug, version=ver, source="html_parse"))
                seen_slugs.add(slug)

        # Extract theme from HTML
        theme_info = self._extract_theme_from_html(html)
        if theme_info:
            result.theme = PluginInfo(slug=theme_info[0], version=theme_info[1], source="html_parse")
            print(f"    [+] Theme: {theme_info[0]}@{theme_info[1] or '?'}")

        # Try RSS feed for WP version if not found
        if not result.wp_version:
            result.wp_version = self._extract_version_from_feed()
            if result.wp_version:
                print(f"    [+] WordPress version (from feed): {result.wp_version}")

        # Phase 1b: REST API namespaces
        api_plugins = self._extract_plugins_from_wpjson()
        for slug in api_plugins:
            if slug not in seen_slugs:
                result.plugins.append(PluginInfo(slug=slug, version=None, source="wpjson"))
                seen_slugs.add(slug)

        print(f"    [+] Phase 1 (passive): {len(result.plugins)} plugins detected")

        # Phase 2: Confirm versions via readme.txt / style.css
        self._confirm_versions(result, seen_slugs)

        # Phase 3: Aggressive enumeration
        if aggressive:
            self._aggressive_enum(result, seen_slugs)

        return result

    def _fetch(self, url: str) -> Optional[str]:
        """Fetch a URL, return text or None."""
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            resp.raise_for_status()
            return resp.text
        except requests.RequestException:
            return None

    def _head(self, url: str) -> Optional[int]:
        """HEAD request, return status code or None."""
        try:
            resp = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            return resp.status_code
        except requests.RequestException:
            return None

    def _is_wordpress(self, html: str) -> bool:
        """Detect if the site is WordPress."""
        indicators = [
            "wp-content/",
            "wp-includes/",
            "/wp-json/",
            'name="generator" content="WordPress',
            "wp-emoji-release.min.js",
        ]
        html_lower = html.lower()
        return any(ind.lower() in html_lower for ind in indicators)

    def _extract_wp_version(self, html: str) -> Optional[str]:
        """Extract WP version from <meta name="generator">."""
        match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)',
            html, re.IGNORECASE
        )
        return match.group(1) if match else None

    def _extract_version_from_feed(self) -> Optional[str]:
        """Extract WP version from /feed/ RSS generator tag."""
        feed = self._fetch(f"{self.base_url}/feed/")
        if not feed:
            return None
        match = re.search(r'wordpress\.org/\?v=([\d.]+)', feed, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_plugins_from_html(self, html: str) -> List[Tuple[str, Optional[str]]]:
        """Extract plugin slugs and versions from wp-content/plugins/ references."""
        pattern = re.compile(
            r'/wp-content/plugins/([a-z0-9_-]+)/[^"\']*?\?ver=([\d.]+)',
            re.IGNORECASE
        )
        no_ver_pattern = re.compile(
            r'/wp-content/plugins/([a-z0-9_-]+)/',
            re.IGNORECASE
        )
        results = {}
        # First pass: find slugs with versions
        for match in pattern.finditer(html):
            slug = match.group(1).lower()
            results[slug] = match.group(2)
        # Second pass: find slugs without versions
        for match in no_ver_pattern.finditer(html):
            slug = match.group(1).lower()
            if slug not in results:
                results[slug] = None
        return list(results.items())

    def _extract_theme_from_html(self, html: str) -> Optional[Tuple[str, Optional[str]]]:
        """Extract active theme slug and version from wp-content/themes/ references."""
        pattern = re.compile(
            r'/wp-content/themes/([a-z0-9_-]+)/[^"\']*?\?ver=([\d.]+)',
            re.IGNORECASE
        )
        no_ver_pattern = re.compile(
            r'/wp-content/themes/([a-z0-9_-]+)/',
            re.IGNORECASE
        )
        themes = {}
        # First pass: find themes with versions
        for match in pattern.finditer(html):
            slug = match.group(1).lower()
            themes[slug] = match.group(2)
        # Second pass: find themes without versions
        for match in no_ver_pattern.finditer(html):
            slug = match.group(1).lower()
            if slug not in themes:
                themes[slug] = None

        # Also check <body class="..."> for theme slug
        body_match = re.search(r'<body\s+class="[^"]*theme-([a-z0-9_-]+)', html, re.IGNORECASE)
        if body_match:
            slug = body_match.group(1).lower()
            if slug not in themes:
                themes[slug] = None

        if themes:
            slug = next(iter(themes))
            return (slug, themes[slug])
        return None

    def _extract_plugins_from_wpjson(self) -> List[str]:
        """Query /wp-json/ REST API and map namespaces to plugin slugs."""
        data = self._fetch(f"{self.base_url}/wp-json/")
        if not data:
            return []
        try:
            import json
            api_data = json.loads(data)
        except (ValueError, TypeError):
            return []

        namespaces = api_data.get("namespaces", [])
        found = []
        for ns in namespaces:
            prefix = ns.split("/")[0]
            if prefix in NAMESPACE_MAP:
                slug = NAMESPACE_MAP[prefix]
                if slug not in found:
                    found.append(slug)
        return found

    def _confirm_versions(self, result: RemoteScanResult, seen_slugs: set):
        """Phase 2: Fetch readme.txt for each plugin to confirm version."""
        plugins_to_check = [p for p in result.plugins if not p.version]
        if not plugins_to_check:
            return

        print(f"    [*] Phase 2: confirming versions for {len(plugins_to_check)} plugins...")

        def _check_readme(plugin: PluginInfo):
            readme = self._fetch(
                f"{self.base_url}/wp-content/plugins/{plugin.slug}/readme.txt"
            )
            if readme:
                ver = self._parse_readme_version(readme)
                if ver:
                    plugin.version = ver
                    plugin.source = "readme"
            if self.delay_s:
                time.sleep(self.delay_s)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            list(executor.map(_check_readme, plugins_to_check))

        # Also confirm theme version via style.css
        if result.theme and not result.theme.version:
            css = self._fetch(
                f"{self.base_url}/wp-content/themes/{result.theme.slug}/style.css"
            )
            if css:
                ver = self._parse_style_css_version(css)
                if ver:
                    result.theme.version = ver
                    result.theme.source = "style_css"

    def _aggressive_enum(self, result: RemoteScanResult, seen_slugs: set):
        """Phase 3: Brute-force top plugin slugs via HEAD requests."""
        print(f"    [*] Phase 3 (aggressive): enumerating top plugins...")

        found_count = 0

        def _probe(slug: str) -> Optional[PluginInfo]:
            if slug in seen_slugs:
                return None
            status = self._head(
                f"{self.base_url}/wp-content/plugins/{slug}/readme.txt"
            )
            if self.delay_s:
                time.sleep(self.delay_s)
            if status == 200:
                readme = self._fetch(
                    f"{self.base_url}/wp-content/plugins/{slug}/readme.txt"
                )
                ver = self._parse_readme_version(readme) if readme else None
                return PluginInfo(slug=slug, version=ver, source="aggressive")
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(_probe, slug): slug for slug in TOP_PLUGINS}
            for future in as_completed(futures):
                info = future.result()
                if info:
                    result.plugins.append(info)
                    seen_slugs.add(info.slug)
                    found_count += 1
                    print(f"    [+] Found: {info.slug}@{info.version or '?'}")

        print(f"    [+] Phase 3: {found_count} additional plugins found")

    @staticmethod
    def _parse_readme_version(readme: str) -> Optional[str]:
        """Parse 'Stable tag: X.X.X' from readme.txt."""
        match = re.search(r'Stable\s+tag:\s*([\d.]+)', readme, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def _parse_style_css_version(css: str) -> Optional[str]:
        """Parse 'Version: X.X.X' from theme style.css header."""
        match = re.search(r'Version:\s*([\d.]+)', css, re.IGNORECASE)
        return match.group(1) if match else None


# Top 100 most popular WordPress plugins for aggressive enumeration
TOP_PLUGINS = [
    "akismet", "contact-form-7", "woocommerce", "wordpress-seo", "elementor",
    "classic-editor", "jetpack", "wpforms-lite", "wordfence", "really-simple-ssl",
    "updraftplus", "litespeed-cache", "all-in-one-seo-pack", "wp-mail-smtp",
    "duplicate-post", "google-sitemap-generator", "redirection", "wp-super-cache",
    "w3-total-cache", "tinymce-advanced", "regenerate-thumbnails", "sucuri-scanner",
    "wp-fastest-cache", "google-analytics-for-wordpress", "seo-by-rank-math",
    "all-in-one-wp-migration", "better-wp-security", "wp-optimize",
    "tablepress", "cookie-notice", "autoptimize", "insert-headers-and-footers",
    "duplicator", "limit-login-attempts-reloaded", "loginizer",
    "user-role-editor", "mailchimp-for-wp", "antispam-bee", "wordpress-importer",
    "advanced-custom-fields", "shortcodes-ultimate", "easy-table-of-contents",
    "wp-smushit", "imagify", "ewww-image-optimizer",
    "coming-soon", "under-construction-page", "maintenance",
    "custom-post-type-ui", "members", "theme-my-login",
    "ninja-forms", "formidable", "wps-hide-login", "two-factor",
    "disable-comments", "simple-custom-css", "custom-css-js",
    "header-footer-code-manager", "wp-cerber",
    "all-in-one-wp-security-and-firewall", "defender-security",
    "backwpup", "blogvault-real-time-backup", "starter-templates",
    "astra-sites", "royal-elementor-addons", "essential-addons-for-elementor-lite",
    "happy-elementor-addons", "premium-addons-for-elementor",
    "beaver-builder-lite-version", "brizy", "spectra",
    "google-analytics-dashboard-for-wp", "site-kit-by-google",
    "optinmonster", "popup-maker", "popup-builder",
    "woo-checkout-field-editor-pro", "checkout-plugins-stripe-woo",
    "woocommerce-payments", "woocommerce-gateway-stripe",
    "wordpress-popular-posts", "yet-another-related-posts-plugin",
    "social-warfare", "translatepress-multilingual", "polylang",
    "loco-translate", "gtranslate", "broken-link-checker",
    "health-check", "query-monitor", "debug-bar",
    "amp", "fb-instant-articles", "wordpress-social-login",
    "nextgen-gallery", "envira-gallery-lite", "modula-best-grid-gallery",
    "mega-menu", "flavor", "flavor-starter",
]
