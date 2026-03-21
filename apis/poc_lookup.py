"""POC / Exploit lookup for CVEs.

Queries free public sources to determine if a public exploit or POC exists
for each CVE found during vulnerability scanning.

Sources (all free, no auth required):
  - Shodan CVEDB — EPSS score + KEV boolean
  - CISA KEV — Known Exploited Vulnerabilities catalog
  - nomi-sec PoC-in-GitHub — GitHub POC repositories
  - Exploit-DB CSV — Exploit database entries
  - Nuclei Templates — Detection template existence check
  - NVD API — References tagged "Exploit"
"""

import csv
import io
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

from config import (
    SHODAN_CVEDB_URL,
    NOMI_SEC_POC_URL,
    CISA_KEV_URL,
    EXPLOITDB_CSV_URL,
    NUCLEI_TEMPLATES_RAW_URL,
    POC_CACHE_DIR,
    SHODAN_RATE_LIMIT,
    NOMI_SEC_RATE_LIMIT,
    NVD_URL,
    NVD_API_KEY,
    NVD_RATE_LIMIT,
)


@dataclass
class PocResult:
    cve_id: str
    epss_score: Optional[float] = None       # 0.0–1.0
    epss_percentile: Optional[float] = None  # 0.0–1.0
    exploited_in_wild: bool = False           # CISA KEV
    ransomware_use: str = ""                  # "Known" / "Unknown" / ""
    exploit_db: list = field(default_factory=list)    # [{id, title, url}]
    github_pocs: list = field(default_factory=list)   # [{url, name, stars, description}]
    has_nuclei_template: bool = False
    nuclei_template_url: str = ""
    nvd_exploit_refs: list = field(default_factory=list)  # URLs tagged "Exploit"

    @property
    def status(self) -> str:
        """Highest-priority status label."""
        if self.exploited_in_wild:
            return "EXPLOITED IN WILD"
        if self.exploit_db:
            return "PUBLIC EXPLOIT"
        if self.github_pocs:
            return "PUBLIC POC"
        if self.has_nuclei_template:
            return "NUCLEI TEMPLATE"
        if self.nvd_exploit_refs:
            return "EXPLOIT REFS"
        return "NO KNOWN POC"

    @property
    def severity_color(self) -> str:
        """Rich color for status."""
        colors = {
            "EXPLOITED IN WILD": "bold red",
            "PUBLIC EXPLOIT": "red",
            "PUBLIC POC": "yellow",
            "NUCLEI TEMPLATE": "yellow",
            "EXPLOIT REFS": "blue",
            "NO KNOWN POC": "dim",
        }
        return colors.get(self.status, "dim")

    @property
    def details_text(self) -> str:
        """Human-readable details string for the table."""
        parts = []
        if self.exploited_in_wild:
            parts.append("CISA KEV")
        if self.exploit_db:
            ids = ", ".join(f"EDB-{e['id']}" for e in self.exploit_db[:3])
            parts.append(ids)
        if self.github_pocs:
            count = len(self.github_pocs)
            top_stars = max((p.get("stars", 0) for p in self.github_pocs), default=0)
            star_str = f" (★{top_stars})" if top_stars > 0 else ""
            parts.append(f"{count} GitHub repo{'s' if count != 1 else ''}{star_str}")
        if self.has_nuclei_template:
            parts.append("nuclei template")
        if self.nvd_exploit_refs and not parts:
            parts.append(f"{len(self.nvd_exploit_refs)} NVD ref{'s' if len(self.nvd_exploit_refs) != 1 else ''}")
        if not parts:
            parts.append("—")
        return ", ".join(parts)

    def to_dict(self) -> dict:
        """JSON-serializable representation."""
        return {
            "cve_id": self.cve_id,
            "status": self.status,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "exploited_in_wild": self.exploited_in_wild,
            "ransomware_use": self.ransomware_use,
            "exploit_db": self.exploit_db,
            "github_pocs": self.github_pocs,
            "has_nuclei_template": self.has_nuclei_template,
            "nuclei_template_url": self.nuclei_template_url,
            "nvd_exploit_refs": self.nvd_exploit_refs,
        }


class PocLookup:
    """Look up public exploit/POC availability for CVEs."""

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or POC_CACHE_DIR)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._kev_data: Optional[dict] = None
        self._exploitdb_data: Optional[dict] = None
        self._last_shodan_time = 0.0
        self._last_nomi_time = 0.0
        self._last_nvd_time = 0.0

    def lookup_all(self, cve_ids: list) -> dict:
        """Lookup POC status for multiple CVEs.

        Returns: {cve_id: PocResult}
        """
        if not cve_ids:
            return {}

        print(f"[*] POC Lookup: checking {len(cve_ids)} CVEs...")

        # Load bulk cached data
        self._load_kev_cache()
        self._load_exploitdb_cache()

        results = {}
        for i, cve_id in enumerate(cve_ids):
            print(f"    [{i+1}/{len(cve_ids)}] {cve_id}", end="", flush=True)
            result = PocResult(cve_id=cve_id)

            # Check cached bulk sources first (instant)
            self._check_kev(result)
            self._check_exploitdb(result)

            # Live API queries
            self._query_shodan_cvedb(result)
            self._query_nomi_sec(result)
            self._check_nuclei_template(result)
            self._query_nvd_exploit_refs(result)

            results[cve_id] = result
            print(f" → {result.status}")

        # Summary
        with_poc = sum(1 for r in results.values() if r.status != "NO KNOWN POC")
        kev_count = sum(1 for r in results.values() if r.exploited_in_wild)
        print(f"[*] POC Lookup complete: {with_poc}/{len(results)} CVEs have public exploits or POCs")
        if kev_count:
            print(f"[!] {kev_count} CVE{'s' if kev_count != 1 else ''} actively exploited in the wild (CISA KEV)")

        return results

    # ── Bulk cached sources ──────────────────────────────────────────────

    def _load_kev_cache(self):
        """Download and cache CISA KEV JSON (24h TTL)."""
        cache_file = self.cache_dir / "kev.json"
        if self._is_cache_valid(cache_file, max_age_hours=24):
            try:
                with open(cache_file, "r") as f:
                    data = json.load(f)
                self._kev_data = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
                print(f"[*] KEV cache loaded ({len(self._kev_data)} entries)")
                return
            except (json.JSONDecodeError, KeyError):
                pass

        print("[*] Downloading CISA KEV catalog...")
        try:
            resp = requests.get(CISA_KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            with open(cache_file, "w") as f:
                json.dump(data, f)

            self._kev_data = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
            print(f"[*] KEV catalog cached ({len(self._kev_data)} entries)")
        except requests.RequestException as e:
            print(f"[!] KEV download failed: {e}")
            self._kev_data = {}

    def _load_exploitdb_cache(self):
        """Download and cache Exploit-DB CSV (7d TTL)."""
        cache_file = self.cache_dir / "exploitdb.csv"
        if self._is_cache_valid(cache_file, max_age_hours=168):
            try:
                self._exploitdb_data = self._parse_exploitdb_csv(cache_file)
                print(f"[*] Exploit-DB cache loaded ({len(self._exploitdb_data)} CVE mappings)")
                return
            except Exception:
                pass

        print("[*] Downloading Exploit-DB CSV...")
        try:
            resp = requests.get(EXPLOITDB_CSV_URL, timeout=60)
            resp.raise_for_status()

            with open(cache_file, "wb") as f:
                f.write(resp.content)

            self._exploitdb_data = self._parse_exploitdb_csv(cache_file)
            print(f"[*] Exploit-DB CSV cached ({len(self._exploitdb_data)} CVE mappings)")
        except requests.RequestException as e:
            print(f"[!] Exploit-DB download failed: {e}")
            self._exploitdb_data = {}

    def _parse_exploitdb_csv(self, csv_path: Path) -> dict:
        """Parse Exploit-DB CSV into {cve_id: [{id, title, url}]}."""
        mapping = {}
        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    codes = row.get("codes", "")
                    exploit_id = row.get("id", "")
                    title = row.get("description", "")
                    for code in codes.split(";"):
                        code = code.strip()
                        if code.startswith("CVE-"):
                            if code not in mapping:
                                mapping[code] = []
                            mapping[code].append({
                                "id": exploit_id,
                                "title": title[:100],
                                "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                            })
        except Exception as e:
            print(f"[!] Error parsing Exploit-DB CSV: {e}")
        return mapping

    # ── Per-CVE checks ───────────────────────────────────────────────────

    def _check_kev(self, result: PocResult):
        """Check CISA KEV for this CVE."""
        if not self._kev_data:
            return
        kev_entry = self._kev_data.get(result.cve_id)
        if kev_entry:
            result.exploited_in_wild = True
            result.ransomware_use = kev_entry.get("knownRansomwareCampaignUse", "")

    def _check_exploitdb(self, result: PocResult):
        """Check Exploit-DB for this CVE."""
        if not self._exploitdb_data:
            return
        entries = self._exploitdb_data.get(result.cve_id, [])
        result.exploit_db = entries

    def _query_shodan_cvedb(self, result: PocResult):
        """Query Shodan CVEDB for EPSS score and KEV confirmation."""
        self._rate_limit_shodan()
        try:
            resp = requests.get(
                f"{SHODAN_CVEDB_URL}/{result.cve_id}",
                timeout=10,
            )
            if resp.status_code == 404:
                return
            resp.raise_for_status()
            data = resp.json()

            epss = data.get("epss")
            if epss is not None:
                result.epss_score = round(float(epss), 4)

            epss_pct = data.get("epss_percentile")
            if epss_pct is not None:
                result.epss_percentile = round(float(epss_pct), 4)

            # Shodan also has KEV indicator
            if data.get("kev") and not result.exploited_in_wild:
                result.exploited_in_wild = True

        except requests.RequestException:
            pass

    def _query_nomi_sec(self, result: PocResult):
        """Query nomi-sec PoC-in-GitHub for GitHub POC repos."""
        self._rate_limit_nomi()
        try:
            resp = requests.get(
                NOMI_SEC_POC_URL,
                params={"cve_id": result.cve_id},
                timeout=10,
            )
            if resp.status_code == 404:
                return
            resp.raise_for_status()
            data = resp.json()

            pocs = data.get("pocs", [])
            for poc in pocs:
                result.github_pocs.append({
                    "url": poc.get("html_url", ""),
                    "name": poc.get("full_name", ""),
                    "stars": poc.get("stargazers_count", 0),
                    "description": (poc.get("description") or "")[:100],
                })

            # Sort by stars descending
            result.github_pocs.sort(key=lambda p: p.get("stars", 0), reverse=True)

        except requests.RequestException:
            pass

    def _check_nuclei_template(self, result: PocResult):
        """Check if a nuclei template exists for this CVE via HTTP HEAD."""
        match = re.match(r"CVE-(\d{4})-(\d+)", result.cve_id)
        if not match:
            return

        year = match.group(1)
        template_url = f"{NUCLEI_TEMPLATES_RAW_URL}/{year}/{result.cve_id}.yaml"

        try:
            resp = requests.head(template_url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                result.has_nuclei_template = True
                result.nuclei_template_url = template_url
        except requests.RequestException:
            pass

    def _query_nvd_exploit_refs(self, result: PocResult):
        """Query NVD for references tagged 'Exploit'."""
        self._rate_limit_nvd()
        try:
            headers = {}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY

            resp = requests.get(
                NVD_URL,
                params={"cveId": result.cve_id},
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 404:
                return
            resp.raise_for_status()
            data = resp.json()

            items = data.get("vulnerabilities", [])
            if not items:
                return

            cve_data = items[0].get("cve", {})
            refs = cve_data.get("references", [])
            for ref in refs:
                tags = ref.get("tags", [])
                if "Exploit" in tags:
                    result.nvd_exploit_refs.append(ref.get("url", ""))

        except requests.RequestException:
            pass

    # ── Rate limiting ────────────────────────────────────────────────────

    def _rate_limit_shodan(self):
        now = time.time()
        elapsed = now - self._last_shodan_time
        if elapsed < SHODAN_RATE_LIMIT:
            time.sleep(SHODAN_RATE_LIMIT - elapsed)
        self._last_shodan_time = time.time()

    def _rate_limit_nomi(self):
        now = time.time()
        elapsed = now - self._last_nomi_time
        if elapsed < NOMI_SEC_RATE_LIMIT:
            time.sleep(NOMI_SEC_RATE_LIMIT - elapsed)
        self._last_nomi_time = time.time()

    def _rate_limit_nvd(self):
        now = time.time()
        elapsed = now - self._last_nvd_time
        if elapsed < NVD_RATE_LIMIT:
            time.sleep(NVD_RATE_LIMIT - elapsed)
        self._last_nvd_time = time.time()

    # ── Cache helpers ────────────────────────────────────────────────────

    @staticmethod
    def _is_cache_valid(path: Path, max_age_hours: int) -> bool:
        """Check if a cache file exists and is within TTL."""
        if not path.exists():
            return False
        mtime = path.stat().st_mtime
        age_hours = (time.time() - mtime) / 3600
        return age_hours < max_age_hours
