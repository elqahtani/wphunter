import os
import random
from typing import List


# === WPScan API keys (supports rotation) ===
_wpscan_keys_raw = os.environ.get("WPSCAN_API_KEYS", "")
WPSCAN_API_KEYS: List[str] = [k.strip() for k in _wpscan_keys_raw.split(",") if k.strip()]

# NVD API key (optional, for CVSS enrichment)
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# === API URLs ===
WPSCAN_API_URL = "https://wpscan.com/api/v3"
WPVULNDB_API_URL = "https://www.wpvulnerability.net"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD rate limit
NVD_RATE_LIMIT = 0.6 if NVD_API_KEY else 6.0
