#!/usr/bin/env python3
"""wphunter — WordPress Vulnerability Scanner.

Scan WordPress plugins, themes, and core for known CVEs without accessing
the live site.

Sources:
  - WPVulnerability.net (free, no key, aggregates 6 databases)
  - WPScan API (requires free API key, 25 req/day)
  - Both sources combined for maximum coverage

Input: plugin/theme list file (simple CSV, wp-cli output, or tab-separated)

Usage:
  python scanner.py -i plugins.txt
  python scanner.py -i themes.csv --type theme
  python scanner.py --wp-version 6.4.3
  python scanner.py -i plugins.txt --wp-version 6.4.3
  python scanner.py -i plugins.txt --source both -f json -o report.json
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console

from parsers import parse_plugins
from apis.wpscan import query_wpscan, query_wpscan_core
from apis.wpvulndb import query_wpvulndb, query_wpvulndb_core
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
        description="wphunter — WordPress Vulnerability Scanner",
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
  %(prog)s -i themes.csv --type theme
  %(prog)s --wp-version 6.4.3
  %(prog)s -i plugins.txt --wp-version 6.4.3
  %(prog)s -i plugins.txt --source both -f json -o report.json
        """,
    )
    parser.add_argument("--input", "-i", help="Plugin/theme list file")
    parser.add_argument(
        "--type", "-t", default="plugin",
        choices=["plugin", "theme"],
        help="Component type for input file (default: plugin)",
    )
    parser.add_argument(
        "--wp-version", help="WordPress core version to scan (e.g. 6.4.3)",
    )
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
    parser.add_argument(
        "--threads", default=1, type=int,
        help="Number of concurrent API requests (default: 1)",
    )

    args = parser.parse_args()
    console = Console(stderr=True)

    # At least one of --input or --wp-version is required
    if not args.input and not args.wp_version:
        console.print("[red][!] At least one of --input or --wp-version is required[/red]")
        parser.print_usage(sys.stderr)
        sys.exit(1)

    if not args.no_banner and args.format == "table":
        print_banner(console)

    component_type = args.type
    component_label = f"{component_type}s"
    items = []

    # Parse plugin/theme list if provided
    if args.input:
        if not os.path.isfile(args.input):
            console.print(f"[red][!] File not found: {args.input}[/red]")
            sys.exit(1)

        try:
            items = parse_plugins(args.input)
        except Exception as e:
            console.print(f"[red][!] Failed to parse {args.input}: {e}[/red]")
            sys.exit(1)

        if not items:
            print(f"[*] No {component_label} found in input file.")
        else:
            print(f"[*] Found {len(items)} {component_label} in {args.input}")
            for slug, ver in items:
                print(f"    {slug}@{ver}")
            print()

    if args.wp_version:
        print(f"[*] WordPress core version: {args.wp_version}\n")

    # Query vulnerability sources
    vulns = []
    source_label = args.source

    workers = max(1, args.threads)

    if args.source in ("wpscan", "both"):
        print("[*] --- WPScan API ---")
        if items:
            wpscan_results = query_wpscan(items, component_type, max_workers=workers)
            vulns.extend(wpscan_results)
            print(f"[*] WPScan ({component_label}): {len(wpscan_results)} vulnerabilities\n")
        if args.wp_version:
            core_results = query_wpscan_core(args.wp_version)
            vulns.extend(core_results)
            print(f"[*] WPScan (core): {len(core_results)} vulnerabilities\n")

    if args.source in ("wpvulndb", "both"):
        print("[*] --- WPVulnerability.net ---")
        if items:
            wpvuln_results = query_wpvulndb(items, component_type, max_workers=workers)
            vulns.extend(wpvuln_results)
            print(f"[*] WPVulnerability.net ({component_label}): {len(wpvuln_results)} vulnerabilities\n")
        if args.wp_version:
            core_results = query_wpvulndb_core(args.wp_version)
            vulns.extend(core_results)
            print(f"[*] WPVulnerability.net (core): {len(core_results)} vulnerabilities\n")

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
    input_name = os.path.basename(args.input) if args.input else f"core-{args.wp_version}"
    report_fns = {"table": report_table, "json": report_json, "csv": report_csv}
    report_fns[args.format](vulns, input_name, source_label, args.output)

    # CI exit code
    if vulns:
        sys.exit(1)


if __name__ == "__main__":
    main()
