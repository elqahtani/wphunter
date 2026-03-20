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

# === Google Custom Search (optional, for SERP judol check) ===
GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID", "")

# === Claude AI (optional, for --ai analysis) ===
AI_MODEL = "claude-sonnet-4-20250514"
AI_MODEL_OAUTH = "claude-haiku-4-5-20251001"  # OAuth tokens only support haiku

# === Remote scan settings ===
DEFAULT_USER_AGENT = "wphunter/1.0 (+https://github.com/elqahtani/wphunter)"
GOOGLEBOT_USER_AGENT = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)
REQUEST_TIMEOUT = 10
DEFAULT_THREADS = 10
DEFAULT_DELAY_MS = 100
