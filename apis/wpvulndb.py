import requests
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


def query_wpvulndb(plugins: List[Tuple[str, str]]) -> List[VulnResult]:
    """Query WPVulnerability.net API (free, no API key needed).

    API: GET https://www.wpvulnerability.net/plugin/{slug}/
    Returns all known vulnerabilities for a plugin, with CVSS scores,
    CVE IDs, and cross-references from 6 sources (CVE, WPScan, Wordfence,
    Patchstack, EUVD, JVN).
    """
    print("[*] WPVulnerability.net: free API, no key required")

    results = []
    for slug, version in plugins:
        try:
            resp = requests.get(
                f"{WPVULNDB_API_URL}/plugin/{slug}/",
                timeout=15,
                headers={"Accept": "application/json"},
            )

            if resp.status_code == 404:
                print(f"    [-] {slug}: not found")
                continue

            resp.raise_for_status()
            data = resp.json()

            if data.get("error") != 0:
                print(f"    [!] {slug}: API error — {data.get('message', 'unknown')}")
                continue

            plugin_data = data.get("data", {})
            vulns = plugin_data.get("vulnerability") or []
            found = 0

            for vuln in vulns:
                # Version check using operator logic
                if not _is_affected(vuln, version):
                    continue

                # Extract CVE ID from sources
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
                            # Clean [en] prefix
                            summary = desc.replace("[en] ", "").replace("[ja] ", "")
                            break

                # Collect all reference URLs from sources
                refs = []
                for src in vuln.get("source", []):
                    link = src.get("link", "")
                    if link:
                        refs.append(link)

                results.append(VulnResult(
                    package=slug,
                    version=version,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=severity,
                    summary=summary[:150],
                    fix_version=fix_version,
                    source="wpvulndb",
                    references=refs,
                ))
                found += 1

            print(f"    [+] {slug}@{version}: {found} vulns")

        except requests.RequestException as e:
            print(f"    [!] {slug}: API error — {e}")

    return results


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
