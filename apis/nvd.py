import time
import requests
from typing import List

from config import NVD_URL, NVD_API_KEY, NVD_RATE_LIMIT
from models import VulnResult

_last_request_time = 0.0


def _rate_limit():
    global _last_request_time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < NVD_RATE_LIMIT:
        time.sleep(NVD_RATE_LIMIT - elapsed)
    _last_request_time = time.time()


def enrich_with_nvd(vulns: List[VulnResult]) -> List[VulnResult]:
    """Enrich results with CVSS scores from NVD for CVEs missing scores."""
    needs = [v for v in vulns if v.cvss_score is None and v.cve_id.startswith("CVE-")]
    if not needs:
        return vulns

    print(f"[*] NVD: enriching {len(needs)} CVEs with CVSS scores...")

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for vuln in needs:
        _rate_limit()
        try:
            resp = requests.get(
                NVD_URL,
                params={"cveId": vuln.cve_id},
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

            items = data.get("vulnerabilities", [])
            if not items:
                continue

            cve_data = items[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            score, severity = _extract_cvss(metrics)
            if score is not None:
                vuln.cvss_score = score
                vuln.severity = severity

            if not vuln.summary:
                for desc in cve_data.get("descriptions", []):
                    if desc.get("lang") == "en":
                        vuln.summary = desc["value"][:150]
                        break

        except requests.RequestException as e:
            print(f"    [!] NVD error for {vuln.cve_id}: {e}")

    return vulns


def _extract_cvss(metrics: dict) -> tuple:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key, [])
        if items:
            cvss = items[0].get("cvssData", {})
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "UNKNOWN")
            if score is not None:
                return float(score), severity.upper()
    return None, "UNKNOWN"
