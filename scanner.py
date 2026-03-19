#!/usr/bin/env python3
"""wphunter — WordPress Plugin Vulnerability Scanner.

Scan WordPress plugins for known CVEs without accessing the live site.

Sources:
  - WPVulnerability.net (free, no key, aggregates 6 databases)
  - WPScan API (requires free API key, 25 req/day)
  - Both sources combined for maximum coverage

Input: plugin list file (simple CSV, wp-cli output, or tab-separated)

Usage:
  python scanner.py -i plugins.txt
  python scanner.py -i plugins.txt --source wpscan
  python scanner.py -i plugins.txt --source both
  python scanner.py -i plugins.txt -f json -o report.json
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console

from parsers import parse_plugins
from apis.wpscan import query_wpscan
from apis.wpvulndb import query_wpvulndb
from apis.nvd import enrich_with_nvd
from reporter import report_table, report_json, report_csv, print_banner


def _dedup_vulns(vulns):
    """Deduplicate vulnerabilities by (package, cve_id).

    When both sources report the same CVE, prefer the one with more data.
    """
    seen = {}
    for v in vulns:
        key = (v.package, v.cve_id)
        if key in seen:
            existing = seen[key]
            # Prefer the one with CVSS score
            if v.cvss_score is not None and existing.cvss_score is None:
                seen[key] = v
            # Prefer the one with more references
            elif len(v.references or []) > len(existing.references or []):
                seen[key] = v
        else:
            seen[key] = v
    return list(seen.values())


def main():
    parser = argparse.ArgumentParser(
        description="wphunter — WordPress Plugin Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Input formats:
  Simple:     slug,version (one per line)
  wp-cli:     wp plugin list --format=csv (pipe output to file)

Source options:
  wpscan      WPScan API (requires WPSCAN_API_KEYS env, 25 req/day/key)
  wpvulndb    WPVulnerability.net (free, no key, 6 aggregated databases)
  both        Query both, deduplicate, maximum coverage

Examples:
  %(prog)s -i plugins.txt
  %(prog)s -i plugins.txt --source both
  %(prog)s -i plugins.txt --source wpscan -f json -o report.json
  wp plugin list --format=csv > plugins.csv && %(prog)s -i plugins.csv
        """,
    )
    parser.add_argument("--input", "-i", required=True, help="Plugin list file")
    parser.add_argument(
        "--source", "-s", default="wpvulndb",
        choices=["wpscan", "wpvulndb", "both"],
        help="Vulnerability data source (default: wpvulndb)",
    )
    parser.add_argument(
        "--format", "-f", default="table",
        choices=["table", "json", "csv"],
        help="Output format (default: table)",
    )
    parser.add_argument("--output", "-o", help="Write results to file")
    parser.add_argument("--no-enrich", action="store_true", help="Skip NVD CVSS enrichment")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner")

    args = parser.parse_args()
    console = Console(stderr=True)

    if not args.no_banner and args.format == "table":
        print_banner(console)

    # Validate input
    if not os.path.isfile(args.input):
        console.print(f"[red][!] File not found: {args.input}[/red]")
        sys.exit(1)

    # Parse plugin list
    try:
        plugins = parse_plugins(args.input)
    except Exception as e:
        console.print(f"[red][!] Failed to parse {args.input}: {e}[/red]")
        sys.exit(1)

    if not plugins:
        print("[*] No plugins found in input file.")
        sys.exit(0)

    print(f"[*] Found {len(plugins)} plugins in {args.input}")
    for slug, ver in plugins:
        print(f"    {slug}@{ver}")
    print()

    # Query vulnerability sources
    vulns = []
    source_label = args.source

    if args.source in ("wpscan", "both"):
        print("[*] --- WPScan API ---")
        wpscan_results = query_wpscan(plugins)
        vulns.extend(wpscan_results)
        print(f"[*] WPScan: {len(wpscan_results)} vulnerabilities\n")

    if args.source in ("wpvulndb", "both"):
        print("[*] --- WPVulnerability.net ---")
        wpvuln_results = query_wpvulndb(plugins)
        vulns.extend(wpvuln_results)
        print(f"[*] WPVulnerability.net: {len(wpvuln_results)} vulnerabilities\n")

    # Deduplicate when using both sources
    if args.source == "both":
        before = len(vulns)
        vulns = _dedup_vulns(vulns)
        print(f"[*] Deduplicated: {before} -> {len(vulns)} unique vulnerabilities\n")
        source_label = "wpscan + wpvulndb"

    # NVD enrichment for missing CVSS
    if not args.no_enrich and vulns:
        vulns = enrich_with_nvd(vulns)

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda v: (sev_order.get(v.severity, 5), v.package))

    # Report
    input_name = os.path.basename(args.input)
    report_fns = {"table": report_table, "json": report_json, "csv": report_csv}
    report_fns[args.format](vulns, input_name, source_label, args.output)

    # CI exit code
    if vulns:
        sys.exit(1)


if __name__ == "__main__":
    main()
