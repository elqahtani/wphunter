# wphunter

A Python CLI tool to scan WordPress **plugins, themes, and core** for known CVE vulnerabilities **without accessing the live site**. Just export your plugin/theme list with `wp-cli` and scan it offline.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  <img src="docs/banner.png" alt="wphunter banner" width="600">
</p>

## Why This Tool?

I wanted to audit the plugins on my WordPress site — quickly check which ones had known CVEs. But every existing tool either needed a live URL or didn't support WordPress at all:

| Tool | Scan from plugin list? | Needs live site? |
|------|:----------------------:|:----------------:|
| WPScan CLI | No | Yes (URL) |
| Wordfence CLI | No | Yes (filesystem) |
| Trivy | No | WordPress not supported |
| osv-scanner | No | WordPress not supported |
| Snyk | No | WordPress not supported |

**wphunter** fills this gap. Export your plugin/theme list and core version, transfer to your machine, scan offline. No WAF triggers, no firewall issues, no authentication needed.

## Features

- **Offline scanning** — no access to your WordPress site required, just the plugin/theme list
- **Plugins, themes & core** — scan all three WordPress component types for known CVEs
- **Multiple vulnerability sources** — WPScan API, WPVulnerability.net, or both combined
- **Free by default** — WPVulnerability.net requires no API key and aggregates 6 databases (CVE, WPScan, Wordfence, Patchstack, EUVD, JVN)
- **Smart deduplication** — when using both sources, duplicates are merged keeping the richest data
- **Version-aware matching** — only reports vulnerabilities that affect your installed version
- **Multiple input formats** — simple CSV, `wp-cli` CSV output, or tab-separated
- **Multiple output formats** — terminal table, JSON, or CSV
- **NVD enrichment** — optionally fetches CVSS scores from NIST NVD for entries missing scores
- **Concurrent requests** — parallel API calls with `--threads` for fast scanning of large lists
- **API key rotation** — rotate multiple WPScan API keys to bypass the 25 req/day limit
- **CI/CD friendly** — exits with code 1 when vulnerabilities are found

## Quick Start

### Installation

```bash
git clone https://github.com/elqahtani/wphunter.git
cd wphunter
pip install -r requirements.txt
```

### Basic Scan (no API key needed)

```bash
python scanner.py -i plugins.csv
```

That's it. This uses WPVulnerability.net which is completely free.

### Get Your Plugin/Theme List & Core Version

On your WordPress server:

```bash
# Plugins
wp plugin list --format=csv > plugins.csv

# Themes
wp theme list --format=csv > themes.csv

# Core version
wp core version
# Output: 6.4.3
```

Transfer the CSV files to your machine (scp, rsync, copy-paste). Then scan.

## Usage

```bash
# Scan plugins with free source (default)
python scanner.py -i plugins.csv

# Scan themes
python scanner.py -i themes.csv --type theme

# Scan WordPress core version
python scanner.py --wp-version 6.4.3

# Combined: plugins + core
python scanner.py -i plugins.csv --wp-version 6.4.3

# Combined: themes + core
python scanner.py -i themes.csv --type theme --wp-version 6.4.3

# Scan with WPScan API
python scanner.py -i plugins.csv --source wpscan

# Maximum coverage: both sources, deduplicated
python scanner.py -i plugins.csv --source both

# JSON output
python scanner.py -i plugins.csv -f json -o report.json

# CSV output for spreadsheets
python scanner.py -i plugins.csv -f csv -o report.csv

# Skip NVD enrichment (faster)
python scanner.py -i plugins.csv --no-enrich

# Parallel requests (faster for large lists)
python scanner.py -i plugins.csv --threads 10

# Only critical + high (CI/CD: fail build on serious vulns only)
python scanner.py -i plugins.csv --min-severity high

# Quiet mode (no banner)
python scanner.py -i plugins.csv --no-banner
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | — | Plugin/theme list file path |
| `-t, --type` | `plugin` | Component type for input file: `plugin` or `theme` |
| `--wp-version` | — | WordPress core version to scan (e.g. `6.4.3`) |
| `-s, --source` | `wpvulndb` | Vulnerability source: `wpscan`, `wpvulndb`, or `both` |
| `-f, --format` | `table` | Output format: `table`, `json`, or `csv` |
| `-o, --output` | *(stdout)* | Write results to file |
| `--no-enrich` | `false` | Skip NVD CVSS enrichment |
| `--no-banner` | `false` | Skip ASCII banner |
| `--threads` | `1` | Number of concurrent API requests (e.g. `10` for large lists) |
| `--min-severity` | — | Minimum severity to report: `critical`, `high`, `medium`, or `low` |

At least one of `--input` or `--wp-version` is required.

## Input Formats

The tool auto-detects the format from your file. The same formats work for both plugins and themes.

**Simple CSV** (manual):
```
elementor,3.6.0
contact-form-7,5.5.0
woocommerce,6.0.0
```

**wp-cli CSV output** (`wp plugin list --format=csv` or `wp theme list --format=csv`):
```
name,status,update,version,update_version,auto_update
elementor,active,none,3.6.0,,off
contact-form-7,active,none,5.5.0,,off
```

**Tab-separated** (`wp plugin list` or `wp theme list`):
```
elementor	active	none	3.6.0
contact-form-7	active	none	5.5.0
```

Lines starting with `#` are treated as comments and ignored.

## Vulnerability Sources

| Source | Vulns Found* | API Key? | Rate Limit | Databases |
|--------|:-----------:|:--------:|:----------:|-----------|
| **WPVulnerability.net** | 108 | No | None | CVE + WPScan + Wordfence + Patchstack + EUVD + JVN |
| **WPScan API** | 74 | Required | 25 req/day/key | WPScan curated database |
| **Both (deduplicated)** | 120 | WPScan only | Combined | All of the above |

*\*Tested with the same 8 plugins (elementor, woocommerce, jetpack, etc.)*

**Recommendation:** use `--source both` for maximum coverage. The tool deduplicates automatically.

### WPScan API Setup

1. Register a free account at [wpscan.com](https://wpscan.com/register)
2. Get your API token (25 requests/day on free tier)
3. Set the environment variable:

```bash
export WPSCAN_API_KEYS="your_key_here"
```

**Key rotation:** register multiple accounts and provide comma-separated keys:

```bash
export WPSCAN_API_KEYS="key1,key2,key3"
```

The tool rotates between keys using round-robin and automatically skips exhausted ones.

### NVD Enrichment (Optional)

Some vulnerability entries are missing CVSS scores. The tool can fetch them from NIST NVD:

```bash
# Without key: 1 request per 6 seconds
python scanner.py -i plugins.csv

# With key: 10x faster
export NVD_API_KEY="your_nvd_key"
python scanner.py -i plugins.csv
```

Get a free NVD API key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key).

Skip enrichment entirely with `--no-enrich`.

## Output

### Table (default)

<p align="center">
  <img src="docs/output.png" alt="wphunter table output" width="700">
</p>

Color-coded severity levels with CVSS scores, fix versions, and a summary panel.

<details>
<summary>Full scan output (text)</summary>

```
┬ ┬┌─┐┬ ┬┬ ┬┌┐┌┌┬┐┌─┐┬─┐
│││├─┘├─┤│ ││││ │ ├┤ ├┬┘
└┴┘┴  ┴ ┴└─┘┘└┘ ┴ └─┘┴└─

WordPress Plugin, Theme & Core Vulnerability Scanner
Sources: WPScan API | WPVulnerability.net | NVD

[*] Found 8 plugins in live-plugins.csv
    akismet@5.3.1
    all-in-one-seo-pack@4.2.0
    elementor@3.6.0
    hello@1.7.2
    jetpack@11.0
    really-simple-ssl@6.0.0
    updraftplus@1.22.24
    woocommerce@6.0.0

[*] --- WPVulnerability.net ---
[*] WPVulnerability.net: free API, no key required
    [+] akismet@5.3.1: 0 vulns
    [+] all-in-one-seo-pack@4.2.0: 10 vulns
    [+] elementor@3.6.0: 31 vulns
    [+] hello@1.7.2: 0 vulns
    [+] jetpack@11.0: 16 vulns
    [+] really-simple-ssl@6.0.0: 4 vulns
    [+] updraftplus@1.22.24: 12 vulns
    [+] woocommerce@6.0.0: 35 vulns
[*] WPVulnerability.net: 108 vulnerabilities

  wphunter -- live-plugins.csv (Critical + High)
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ CVE              ┃ Plugin                  ┃  CVSS  ┃  Severity  ┃ Summary                                ┃ Fix      ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ CVE-2023-48777   │ elementor@3.6.0         │ 9.9 C  │  CRITICAL  │ Contributor+ Arbitrary File Upload to  │ 3.18.2   │
│                  │                         │        │            │ RCE                                    │          │
├──────────────────┼─────────────────────────┼────────┼────────────┼────────────────────────────────────────┼──────────┤
│ CVE-2024-10924   │ really-simple-ssl@6.0.0 │ 9.8 C  │  CRITICAL  │ Authentication Bypass (admin takeover) │ 9.1.1.1  │
├──────────────────┼─────────────────────────┼────────┼────────────┼────────────────────────────────────────┼──────────┤
│ CVE-2022-1329    │ elementor@3.6.0         │ 8.8 H  │    HIGH    │ Subscriber+ Arbitrary File Upload      │ 3.6.2    │
├──────────────────┼─────────────────────────┼────────┼────────────┼────────────────────────────────────────┼──────────┤
│ CVE-2024-10957   │ updraftplus@1.22.24     │ 8.8 H  │    HIGH    │ PHP Object Injection via Backup        │ 1.24.12  │
├──────────────────┼─────────────────────────┼────────┼────────────┼────────────────────────────────────────┼──────────┤
│ CVE-2024-24934   │ elementor@3.6.0         │ 8.5 H  │    HIGH    │ Contributor+ Arbitrary File Upload     │ 3.19.1   │
├──────────────────┼─────────────────────────┼────────┼────────────┼────────────────────────────────────────┼──────────┤
│ CVE-2023-47504   │ elementor@3.6.0         │ 7.5 H  │    HIGH    │ Missing Authorization to Setting       │ 3.16.5   │
│                  │                         │        │            │ Change                                 │          │
├──────────────────┼─────────────────────────┼────────┼────────────┼────────────────────────────────────────┼──────────┤
│ CVE-2023-32960   │ updraftplus@1.22.24     │ 7.1 H  │    HIGH    │ Sensitive Data Exposure via Backup Log │ 1.23.4   │
└──────────────────┴─────────────────────────┴────────┴────────────┴────────────────────────────────────────┴──────────┘

  Total: 108 vulnerabilities (2 CRITICAL, 5 HIGH, 37 MEDIUM, 1 LOW)
  Source: wpvulndb (WPVulnerability.net)
  Recommended: elementor -> 3.18.2, really-simple-ssl -> 9.1.1.1
```
</details>

### JSON

```bash
python scanner.py -i plugins.csv -f json -o report.json
```

<details>
<summary>Example JSON output</summary>

```json
{
  "scan": {
    "input_file": "plugins.csv",
    "source": "wpvulndb",
    "type": "wordpress"
  },
  "summary": {
    "total": 108,
    "critical": 2,
    "high": 5,
    "medium": 37,
    "low": 1,
    "unknown": 63
  },
  "vulnerabilities": [
    {
      "plugin": "elementor",
      "version": "3.6.0",
      "cve_id": "CVE-2023-48777",
      "cvss_score": 9.9,
      "severity": "CRITICAL",
      "summary": "Contributor+ Arbitrary File Upload to RCE",
      "fix_version": "3.18.2",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-48777",
      "source": "wpvulndb",
      "references": [
        "https://www.wordfence.com/threat-intel/vulnerabilities/id/...",
        "https://patchstack.com/database/vulnerability/elementor/..."
      ]
    },
    {
      "plugin": "really-simple-ssl",
      "version": "6.0.0",
      "cve_id": "CVE-2024-10924",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "summary": "Authentication Bypass (admin takeover)",
      "fix_version": "9.1.1.1",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-10924",
      "source": "wpvulndb",
      "references": ["..."]
    }
  ]
}
```
</details>

### CSV

```bash
python scanner.py -i plugins.csv -f csv -o report.csv
```

Opens in any spreadsheet application. References are semicolon-separated within cells.

## Exit Codes

| Code | Meaning |
|:----:|---------|
| `0` | No vulnerabilities found |
| `1` | Vulnerabilities found |

Use this in CI/CD pipelines to fail builds when vulnerable plugins are detected. Combine with `--min-severity high` to only fail on critical and high severity vulnerabilities.

## Severity Levels

Based on CVSS v3 scores:

| Level | CVSS Range | Indicator |
|-------|:----------:|:---------:|
| Critical | 9.0 - 10.0 | `9.8 C` |
| High | 7.0 - 8.9 | `8.8 H` |
| Medium | 4.0 - 6.9 | `5.3 M` |
| Low | 0.1 - 3.9 | `2.1 L` |
| Unknown | No score | `? ?` |

## How It Works

```
  [WordPress Server]              [Your Machine]
        |                              |
   wp plugin list                  wphunter/
   wp theme list                    scanner.py
   wp core version                     |
        |                              v
        v                     +------------------+
  +--------------+            | Parse plugins/   |
  | plugins.csv  | --------> | themes from      |
  | themes.csv   |    scp    | CSV/TXT          |
  | core: 6.4.3  |           +---+----+---------+
  +--------------+                |    |
                     +------------+    +--------+
                     |                          |
                     v                          v
            +----------------+       +-----------------+
            | WPVulnerability|       |   WPScan API    |
            | .net (FREE)    |       |   (API key)     |
            | 6 databases    |       |   curated DB    |
            +-------+--------+       +--------+--------+
                    |                          |
                    +--------+  +-------------+
                             |  |
                             v  v
                     +-----------------+
                     |  Deduplicate    |
                     |  + NVD Enrich   |
                     +--------+--------+
                              |
                    +---------+---------+
                    |         |         |
                    v         v         v
                 [Table]   [JSON]    [CSV]
```

1. **Export** your plugin/theme list and core version with `wp-cli`
2. **Transfer** the CSV files to your local machine
3. **Scan** — the tool queries vulnerability APIs for each component+version
4. **Review** — results in terminal table, JSON, or CSV

The tool never touches your WordPress site. It only needs the exported lists.

### Full Site Audit Example

```bash
# On WordPress server: export everything
wp plugin list --format=csv > plugins.csv
wp theme list --format=csv > themes.csv
wp core version > wp-version.txt

# On your machine: scan all components
WP_VER=$(cat wp-version.txt)

# Plugins + core
python scanner.py -i plugins.csv --wp-version $WP_VER --source both

# Themes (separate run because --type is different)
python scanner.py -i themes.csv --type theme --source both
```

## Project Structure

```
wphunter/
├── scanner.py              # CLI entry point
├── config.py               # API keys, URLs, rate limits
├── models.py               # VulnResult dataclass
├── reporter.py             # Output: table, JSON, CSV
├── requirements.txt        # requests, rich
├── .env.example            # Environment variable template
├── apis/
│   ├── wpscan.py           # WPScan API v3 client
│   ├── wpvulndb.py         # WPVulnerability.net client
│   └── nvd.py              # NVD CVSS enrichment
├── parsers/
│   └── wordpress.py        # Plugin/theme list parser (3 formats)
├── docker-test/            # Docker WordPress for testing
│   └── docker-compose.yml
└── test_fixtures/
    └── plugins.txt         # Sample plugin list
```

## Docker Test Environment

Want to test with a real WordPress? Spin one up with Docker:

```bash
cd docker-test
docker compose up -d db wordpress

# Install WordPress
docker compose run --rm wpcli core install \
  --url=http://localhost:8888 \
  --title="Test Site" \
  --admin_user=admin \
  --admin_password=admin123 \
  --admin_email=admin@test.local \
  --skip-email

# Install some old plugins
docker compose run --rm wpcli plugin install elementor --version=3.6.0 --activate
docker compose run --rm wpcli plugin install contact-form-7 --version=5.5.0 --activate
docker compose run --rm wpcli plugin install woocommerce --version=6.0.0 --activate

# Export and scan
docker compose run --rm wpcli plugin list --format=csv > live-plugins.csv
docker compose run --rm wpcli theme list --format=csv > live-themes.csv
WP_VER=$(docker compose run --rm wpcli core version | tr -d '\r')
cd ..

# Scan plugins + core
python scanner.py -i docker-test/live-plugins.csv --wp-version $WP_VER --source both

# Scan themes
python scanner.py -i docker-test/live-themes.csv --type theme --source both
```

## Limitations

- **Known CVEs only** — this tool checks public vulnerability databases. It cannot detect zero-day vulnerabilities, custom code bugs, or misconfigurations.
- **No live site scanning** — by design. It does not check for exposed files, directory listings, weak passwords, or server misconfigurations. Use WPScan CLI for that.
- **Slugs must match** — the slug in your CSV must match the WordPress.org slug (e.g., `wordpress-seo` not `yoast-seo` for plugins, `flavor` not `flavor developer` for themes).
- **No theme/core auto-detection** — you must specify `--type theme` for theme files and `--wp-version` for core scanning.

## Requirements

- Python 3.7+
- `requests` >= 2.28.0
- `rich` >= 13.0.0

## Related

- [WPScan](https://github.com/wpscanteam/wpscan) — WordPress security scanner (live site scanning, Ruby)
- [wordpress-vulnerable-scanner](https://github.com/robdotec/wordpress-vulnerable-scanner) — WordPress CVE scanner (Rust, live site + manifest)
- [WPVulnerability.net](https://www.wpvulnerability.net/) — Free WordPress vulnerability database (6 aggregated sources)

## License

MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for **authorized security testing and auditing only**. Always get proper authorization before scanning systems you don't own. The authors are not responsible for misuse.
