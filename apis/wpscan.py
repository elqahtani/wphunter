import requests
from typing import List, Tuple, Set

from config import WPSCAN_API_URL, WPSCAN_API_KEYS
from models import VulnResult

_exhausted_keys: Set[str] = set()
_counter = 0


def _get_available_key() -> str:
    """Round-robin key selection, skipping exhausted keys."""
    global _counter
    available = [k for k in WPSCAN_API_KEYS if k not in _exhausted_keys]
    if not available:
        _exhausted_keys.clear()
        available = WPSCAN_API_KEYS
    if not available:
        return ""
    key = available[_counter % len(available)]
    _counter += 1
    return key


def query_wpscan(plugins: List[Tuple[str, str]]) -> List[VulnResult]:
    """Query WPScan API v3 with key rotation.

    Free tier: 25 requests/day per key.
    """
    if not WPSCAN_API_KEYS:
        print("[!] No WPSCAN_API_KEYS set.")
        print("[!] Set env: export WPSCAN_API_KEYS='key1,key2,...'")
        print("[!] Register free at: https://wpscan.com/register")
        return []

    print(f"[*] WPScan: using {len(WPSCAN_API_KEYS)} API key(s)")

    results = []
    for slug, version in plugins:
        api_key = _get_available_key()
        if not api_key:
            print("[!] All WPScan API keys exhausted")
            break

        headers = {"Authorization": f"Token token={api_key}"}

        try:
            resp = requests.get(
                f"{WPSCAN_API_URL}/plugins/{slug}",
                headers=headers,
                timeout=15,
            )

            if resp.status_code == 401:
                print(f"[!] WPScan key invalid, removing from rotation")
                _exhausted_keys.add(api_key)
                continue
            if resp.status_code == 403:
                print(f"[!] WPScan key rate-limited, rotating...")
                _exhausted_keys.add(api_key)
                # Retry once with next key
                api_key = _get_available_key()
                if not api_key:
                    print("[!] All keys exhausted")
                    break
                headers = {"Authorization": f"Token token={api_key}"}
                resp = requests.get(
                    f"{WPSCAN_API_URL}/plugins/{slug}",
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code in (401, 403):
                    _exhausted_keys.add(api_key)
                    continue
            if resp.status_code == 404:
                print(f"    [-] {slug}: not found in WPScan")
                continue

            resp.raise_for_status()
            data = resp.json()

            plugin_data = data.get(slug, {})
            vulns = plugin_data.get("vulnerabilities", [])
            found = 0

            for vuln in vulns:
                if not _is_affected(vuln, version):
                    continue

                cve_ids = vuln.get("references", {}).get("cve", [])
                cve_id = f"CVE-{cve_ids[0]}" if cve_ids else vuln.get("id", "unknown")

                cvss_data = vuln.get("cvss") or {}
                cvss_score = cvss_data.get("score")
                cvss_rating = cvss_data.get("rating", "")

                fix_ver = vuln.get("fixed_in", "")

                # Collect reference URLs
                refs = []
                for ref_type, ref_list in vuln.get("references", {}).items():
                    if ref_type == "url" and isinstance(ref_list, list):
                        refs.extend(ref_list)

                results.append(VulnResult(
                    package=slug,
                    version=version,
                    cve_id=cve_id,
                    cvss_score=float(cvss_score) if cvss_score else None,
                    severity=cvss_rating.upper() if cvss_rating else "UNKNOWN",
                    summary=vuln.get("title", "")[:150],
                    fix_version=str(fix_ver) if fix_ver else "",
                    source="wpscan",
                    references=refs,
                ))
                found += 1

            print(f"    [+] {slug}@{version}: {found} vulns")

        except requests.RequestException as e:
            print(f"    [!] {slug}: API error — {e}")

    return results


def _is_affected(vuln: dict, version: str) -> bool:
    """Check if version < fixed_in."""
    fixed_in = vuln.get("fixed_in")
    if not fixed_in:
        return True
    try:
        return _cmp_ver(version, str(fixed_in)) < 0
    except (ValueError, TypeError):
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
