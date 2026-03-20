import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from config import WPVULNDB_API_URL
from models import VulnResult


# Severity letter mapping from WPVulnerability API
_SEVERITY_MAP = {
    "c": "CRITICAL",
    "h": "HIGH",
    "m": "MEDIUM",
    "l": "LOW",
    "n": "UNKNOWN",
}


def _fetch_one_wpvulndb(slug: str, version: str,
                        component_type: str) -> List[VulnResult]:
    """Fetch vulnerabilities for a single component from WPVulnerability.net."""
    try:
        resp = requests.get(
            f"{WPVULNDB_API_URL}/{component_type}/{slug}/",
            timeout=15,
            headers={"Accept": "application/json"},
        )

        if resp.status_code == 404:
            print(f"    [-] {slug}: not found")
            return []

        resp.raise_for_status()
        data = resp.json()

        if data.get("error") != 0:
            print(f"    [!] {slug}: API error — {data.get('message', 'unknown')}")
            return []

        plugin_data = data.get("data", {})
        vulns = plugin_data.get("vulnerability") or []
        results = []

        for vuln in vulns:
            if not _is_affected(vuln, version):
                continue
            results.append(_parse_vuln(vuln, slug, version))

        print(f"    [+] {slug}@{version}: {len(results)} vulns")
        return results

    except requests.RequestException as e:
        print(f"    [!] {slug}: API error — {e}")
        return []


def query_wpvulndb(plugins: List[Tuple[str, str]],
                    component_type: str = "plugin",
                    max_workers: int = 1) -> List[VulnResult]:
    """Query WPVulnerability.net API (free, no API key needed).

    API: GET https://www.wpvulnerability.net/{component_type}/{slug}/
    Supports component_type: plugin, theme.
    Uses ThreadPoolExecutor for concurrent requests when max_workers > 1.
    """
    print("[*] WPVulnerability.net: free API, no key required")
    if max_workers > 1:
        print(f"[*] Using {max_workers} concurrent threads")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_fetch_one_wpvulndb, slug, version, component_type): slug
            for slug, version in plugins
        }
        for future in as_completed(futures):
            results.extend(future.result())

    return results


def query_wpvulndb_core(version: str) -> List[VulnResult]:
    """Query WPVulnerability.net for WordPress core vulnerabilities.

    API: GET https://www.wpvulnerability.net/core/{version}/
    """
    print(f"[*] WPVulnerability.net: querying WordPress core {version}")

    try:
        resp = requests.get(
            f"{WPVULNDB_API_URL}/core/{version}/",
            timeout=15,
            headers={"Accept": "application/json"},
        )

        if resp.status_code == 404:
            print(f"    [-] wordpress-core@{version}: not found")
            return []

        resp.raise_for_status()
        data = resp.json()

        if data.get("error") != 0:
            print(f"    [!] wordpress-core: API error — {data.get('message', 'unknown')}")
            return []

        core_data = data.get("data", {})
        vulns = core_data.get("vulnerability") or []
        results = []

        for vuln in vulns:
            if not _is_affected(vuln, version):
                continue
            results.append(_parse_vuln(vuln, "wordpress-core", version))

        print(f"    [+] wordpress-core@{version}: {len(results)} vulns")
        return results

    except requests.RequestException as e:
        print(f"    [!] wordpress-core: API error — {e}")
        return []


def _parse_vuln(vuln: dict, package: str, version: str) -> VulnResult:
    """Parse a single vulnerability entry into a VulnResult."""
    cve_id = _extract_cve_id(vuln)

    # Extract CVSS
    impact = vuln.get("impact") or {}
    cvss_data = impact.get("cvss") or {}
    cvss_score = None
    severity = "UNKNOWN"

    if cvss_data.get("score"):
        try:
            cvss_score = float(cvss_data["score"])
        except (ValueError, TypeError):
            pass

    sev_letter = cvss_data.get("severity", "")
    if sev_letter in _SEVERITY_MAP:
        severity = _SEVERITY_MAP[sev_letter]

    # Extract fix version from operator
    operator = vuln.get("operator", {})
    fix_version = ""
    if operator.get("max_version") and operator.get("unfixed") != "1":
        fix_version = operator["max_version"]

    # Summary: use vuln name or first source description
    summary = vuln.get("name", "")
    if not summary:
        sources = vuln.get("source", [])
        for src in sources:
            desc = src.get("description", "")
            if desc:
                summary = desc.replace("[en] ", "").replace("[ja] ", "")
                break

    # Collect all reference URLs from sources
    refs = []
    for src in vuln.get("source", []):
        link = src.get("link", "")
        if link:
            refs.append(link)

    return VulnResult(
        package=package,
        version=version,
        cve_id=cve_id,
        cvss_score=cvss_score,
        severity=severity,
        summary=summary[:150],
        fix_version=fix_version,
        source="wpvulndb",
        references=refs,
    )


def _extract_cve_id(vuln: dict) -> str:
    """Extract CVE ID from vulnerability sources."""
    sources = vuln.get("source", [])
    for src in sources:
        src_id = src.get("id", "")
        if src_id.startswith("CVE-"):
            return src_id
        src_name = src.get("name", "")
        if src_name.startswith("CVE-"):
            return src_name

    # Fallback to UUID
    return vuln.get("uuid", "unknown")


def _is_affected(vuln: dict, version: str) -> bool:
    """Check if version is affected using WPVulnerability operator logic.

    Mirrors PHP's version_compare behavior:
      - max_operator "lt" + max_version "5.3.2" means: affected if version < 5.3.2
      - max_operator "lte" means: affected if version <= max_version
      - min_operator "gte" + min_version "3.0" means: affected if version >= 3.0
    """
    operator = vuln.get("operator", {})
    if not operator:
        return True

    max_ver = operator.get("max_version")
    max_op = operator.get("max_operator", "")
    min_ver = operator.get("min_version")
    min_op = operator.get("min_operator", "")

    # Check minimum version constraint
    if min_ver and min_op:
        cmp = _cmp_ver(version, min_ver)
        if min_op == "gt" and cmp <= 0:
            return False
        if min_op == "gte" and cmp < 0:
            return False

    # Check maximum version constraint
    if max_ver and max_op:
        cmp = _cmp_ver(version, max_ver)
        if max_op == "lt" and cmp >= 0:
            return False
        if max_op == "lte" and cmp > 0:
            return False

    return True


def _cmp_ver(v1: str, v2: str) -> int:
    """Compare two version strings."""
    def norm(v):
        return [int(p) if p.isdigit() else 0 for p in v.split('.')]

    p1, p2 = norm(v1), norm(v2)
    max_len = max(len(p1), len(p2))
    p1 += [0] * (max_len - len(p1))
    p2 += [0] * (max_len - len(p2))

    for a, b in zip(p1, p2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0
