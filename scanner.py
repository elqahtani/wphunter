#!/usr/bin/env python3
"""wphunter — WordPress Vulnerability & Judol Injection Scanner.

Scan WordPress plugins, themes, and core for known CVEs. Optionally detect
gambling spam (judol) injection via remote scanning.

Sources:
  - WPVulnerability.net (free, no key, aggregates 6 databases)
  - WPScan API (requires free API key, 25 req/day)
  - Both sources combined for maximum coverage

Usage:
  python scanner.py -i plugins.txt
  python scanner.py --url https://target.com --detect-judol
  python scanner.py --url https://target.com --source both --detect-judol --ai
  python scanner.py connect
"""

import argparse
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console

from parsers import parse_plugins
from apis.wpscan import query_wpscan, query_wpscan_core
from apis.wpvulndb import query_wpvulndb, query_wpvulndb_core
from apis.nvd import enrich_with_nvd
from reporter import (
    report_table, report_json, report_csv, print_banner,
    report_judol_table, report_ai_analysis, print_token_usage,
    report_poc_table,
)


def _dedup_vulns(vulns):
    """Deduplicate vulnerabilities by (package, cve_id).

    When both sources report the same CVE, prefer the one with more data.
    """
    seen = {}
    for v in vulns:
        key = (v.package, v.cve_id)
        if key in seen:
            existing = seen[key]
            if v.cvss_score is not None and existing.cvss_score is None:
                seen[key] = v
            elif len(v.references or []) > len(existing.references or []):
                seen[key] = v
        else:
            seen[key] = v
    return list(seen.values())


def _handle_connect(console):
    """Handle 'connect' subcommand."""
    from auth import interactive_connect
    interactive_connect()


def _handle_auth_status(console):
    """Handle 'auth-status' subcommand."""
    from auth import resolve_credential
    cred = resolve_credential()
    if cred:
        console.print("[green]Authenticated[/green]")
        console.print(f"  Type: {cred.auth_type}")
        console.print(f"  Source: {cred.source}")
        console.print(f"  Billing: {cred.billing_mode}")
        console.print(f"  Token: {cred.token[:12]}...{cred.token[-4:]}")
    else:
        console.print("[yellow]Not authenticated. Run: python scanner.py connect[/yellow]")


def _handle_disconnect(console):
    """Handle 'disconnect' subcommand."""
    config_path = Path.home() / ".wphunter" / "auth.json"
    if config_path.exists():
        config_path.unlink()
        console.print("[green]Disconnected. Saved credential removed.[/green]")
    else:
        console.print("[dim]No saved credential found.[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="wphunter — WordPress Vulnerability & Judol Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  connect         Connect to Claude AI for analysis features
  auth-status     Show current authentication status
  disconnect      Remove saved Claude AI credential

Input formats:
  Simple:     slug,version (one per line)
  wp-cli:     wp plugin list --format=csv (pipe output to file)

Source options:
  wpscan      WPScan API (requires WPSCAN_API_KEYS env, 25 req/day/key)
  wpvulndb    WPVulnerability.net (free, no key, 6 aggregated databases)
  both        Query both, deduplicate, maximum coverage

Examples:
  %(prog)s -i plugins.txt
  %(prog)s -i plugins.txt --poc
  %(prog)s --url https://target.com --detect-judol
  %(prog)s --url https://target.com --source both --detect-judol --poc --ai
  %(prog)s -i plugins.txt --wp-version 6.4.3 --source both --poc
  %(prog)s connect
        """,
    )

    # Subcommands
    parser.add_argument("command", nargs="?", default=None,
                        choices=["connect", "auth-status", "disconnect"],
                        help="Subcommand (connect, auth-status, disconnect)")

    # Input modes
    parser.add_argument("--input", "-i", help="Plugin/theme list file")
    parser.add_argument("--url", help="Target WordPress URL to scan remotely")
    parser.add_argument(
        "--type", "-t", default="plugin",
        choices=["plugin", "theme"],
        help="Component type for input file (default: plugin)",
    )
    parser.add_argument(
        "--wp-version", help="WordPress core version to scan (e.g. 6.4.3)",
    )

    # Vulnerability scan options
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
    parser.add_argument(
        "--min-severity", default=None,
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to report/fail (e.g. high = critical + high only)",
    )

    # Remote scan options
    parser.add_argument("--aggressive", action="store_true",
                        help="Enable brute-force plugin enumeration (~100 requests)")
    parser.add_argument("--delay", type=int, default=100,
                        help="Delay between requests in ms (default: 100)")

    # Judol detection
    parser.add_argument("--detect-judol", action="store_true",
                        help="Enable gambling spam injection detection")

    # POC lookup
    parser.add_argument("--poc", action="store_true",
                        help="Look up public exploits/POCs for discovered CVEs")

    # AI analysis
    parser.add_argument("--ai", action="store_true",
                        help="Enable AI analysis (requires authentication)")
    parser.add_argument("--ai-model", default="",
                        help="Claude model for AI analysis (default: claude-sonnet-4-20250514)")

    # Safety
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip confirmation prompts")

    args = parser.parse_args()
    console = Console(stderr=True)

    # Handle subcommands
    if args.command == "connect":
        _handle_connect(console)
        return
    if args.command == "auth-status":
        _handle_auth_status(console)
        return
    if args.command == "disconnect":
        _handle_disconnect(console)
        return

    # At least one input mode required
    if not args.input and not args.wp_version and not args.url:
        console.print("[red][!] At least one of --input, --wp-version, or --url is required[/red]")
        parser.print_usage(sys.stderr)
        sys.exit(1)

    if not args.no_banner and args.format == "table":
        print_banner(console)

    component_type = args.type
    component_label = f"{component_type}s"
    items = []
    wp_version = args.wp_version
    judol_result = None
    ai_analysis = None
    tracker = None
    remote_result = None
    poc_results = None

    # ── Pre-check: AI auth ────────────────────────────────────────────────
    ai_cred = None
    if args.ai:
        from auth import resolve_credential
        ai_cred = resolve_credential()
        if not ai_cred:
            console.print("[red][!] AI analysis requires authentication.[/red]")
            console.print("[yellow]    Run: python scanner.py connect[/yellow]")
            sys.exit(1)
        if ai_cred.auth_type == "oauth_token":
            from apis.ai_analyzer import _HAS_AGENT_SDK
            if not _HAS_AGENT_SDK:
                console.print("[red][!] OAuth tokens require claude-agent-sdk for AI analysis.[/red]")
                console.print("[yellow]    pip install claude-agent-sdk  (requires Python 3.10+)[/yellow]")
                sys.exit(1)
            from config import AI_MODEL
            console.print(f"[dim][*] OAuth + Claude Agent SDK — using {AI_MODEL}[/dim]")

    # ── Remote scanning ──────────────────────────────────────────────────
    if args.url:
        # Disclaimer for remote scanning
        if not args.yes:
            console.print("[yellow][!] You are about to scan a remote URL.[/yellow]")
            console.print("[yellow]    Only scan sites you own or have authorization to test.[/yellow]")
            confirm = input("    Continue? [y/N]: ").strip().lower()
            if confirm != "y":
                console.print("[dim]Scan cancelled.[/dim]")
                sys.exit(0)

        print(f"\n[*] === Remote Scan: {args.url} ===\n")

        from parsers.remote import RemoteScanner

        scanner = RemoteScanner(
            url=args.url,
            threads=max(1, args.threads) if args.threads > 1 else 10,
            delay_ms=args.delay,
        )
        remote_result = scanner.scan(aggressive=args.aggressive)

        if not remote_result.is_wordpress:
            console.print("[red][!] Target is not a WordPress site. Aborting.[/red]")
            sys.exit(1)

        # Use detected WP version if not explicitly set
        if remote_result.wp_version and not wp_version:
            wp_version = remote_result.wp_version

        # Merge detected plugins into items
        remote_plugins = remote_result.to_plugin_tuples()
        if remote_plugins:
            items.extend(remote_plugins)
            print(f"\n[*] Detected {len(remote_plugins)} plugins with versions:")
            for slug, ver in remote_plugins:
                print(f"    {slug}@{ver}")

        # Detected themes
        remote_themes = remote_result.to_theme_tuples()
        if remote_themes:
            print(f"[*] Detected {len(remote_themes)} theme(s):")
            for slug, ver in remote_themes:
                print(f"    {slug}@{ver}")

        print()

    # ── Parse input file ─────────────────────────────────────────────────
    if args.input:
        if not os.path.isfile(args.input):
            console.print(f"[red][!] File not found: {args.input}[/red]")
            sys.exit(1)

        try:
            file_items = parse_plugins(args.input)
        except Exception as e:
            console.print(f"[red][!] Failed to parse {args.input}: {e}[/red]")
            sys.exit(1)

        if not file_items:
            print(f"[*] No {component_label} found in input file.")
        else:
            items.extend(file_items)
            print(f"[*] Found {len(file_items)} {component_label} in {args.input}")
            for slug, ver in file_items:
                print(f"    {slug}@{ver}")
            print()

    if wp_version:
        print(f"[*] WordPress core version: {wp_version}\n")

    # ── Vulnerability scanning ───────────────────────────────────────────
    vulns = []
    source_label = args.source
    workers = max(1, args.threads)

    if items or wp_version:
        if args.source in ("wpscan", "both"):
            print("[*] --- WPScan API ---")
            if items:
                wpscan_results = query_wpscan(items, component_type, max_workers=workers)
                vulns.extend(wpscan_results)
                print(f"[*] WPScan ({component_label}): {len(wpscan_results)} vulnerabilities\n")

            # Also scan themes from remote if available
            if args.url and remote_result and remote_result.to_theme_tuples():
                theme_results = query_wpscan(remote_result.to_theme_tuples(), "theme",
                                             max_workers=workers)
                vulns.extend(theme_results)
                print(f"[*] WPScan (themes): {len(theme_results)} vulnerabilities\n")

            if wp_version:
                core_results = query_wpscan_core(wp_version)
                vulns.extend(core_results)
                print(f"[*] WPScan (core): {len(core_results)} vulnerabilities\n")

        if args.source in ("wpvulndb", "both"):
            print("[*] --- WPVulnerability.net ---")
            if items:
                wpvuln_results = query_wpvulndb(items, component_type, max_workers=workers)
                vulns.extend(wpvuln_results)
                print(f"[*] WPVulnerability.net ({component_label}): {len(wpvuln_results)} vulnerabilities\n")

            if args.url and remote_result and remote_result.to_theme_tuples():
                theme_results = query_wpvulndb(remote_result.to_theme_tuples(), "theme",
                                               max_workers=workers)
                vulns.extend(theme_results)
                print(f"[*] WPVulnerability.net (themes): {len(theme_results)} vulnerabilities\n")

            if wp_version:
                core_results = query_wpvulndb_core(wp_version)
                vulns.extend(core_results)
                print(f"[*] WPVulnerability.net (core): {len(core_results)} vulnerabilities\n")

        if args.source == "both":
            before = len(vulns)
            vulns = _dedup_vulns(vulns)
            print(f"[*] Deduplicated: {before} -> {len(vulns)} unique vulnerabilities\n")
            source_label = "wpscan + wpvulndb"

        if not args.no_enrich and vulns:
            vulns = enrich_with_nvd(vulns)

    # Severity filtering
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    if args.min_severity:
        min_rank = sev_order[args.min_severity.upper()]
        total_before = len(vulns)
        vulns = [v for v in vulns if sev_order.get(v.severity, 4) <= min_rank]
        filtered = total_before - len(vulns)
        if filtered:
            print(f"[*] Filtered: {filtered} vulns below {args.min_severity.upper()} severity\n")

    vulns.sort(key=lambda v: (sev_order.get(v.severity, 5), v.package))

    # ── POC lookup ────────────────────────────────────────────────────────
    if args.poc and vulns:
        from apis.poc_lookup import PocLookup

        poc = PocLookup()
        cve_ids = list({v.cve_id for v in vulns if v.cve_id.startswith("CVE-")})
        if cve_ids:
            poc_results = poc.lookup_all(cve_ids)
            print()

    # ── Judol detection ──────────────────────────────────────────────────
    if args.detect_judol:
        if not args.url:
            console.print("[red][!] --detect-judol requires --url[/red]")
            sys.exit(1)

        from detectors.judol import JudolDetector

        detector = JudolDetector(url=args.url, timeout=10, delay_ms=args.delay)
        judol_result = detector.scan()

    # ── AI analysis ──────────────────────────────────────────────────────
    if args.ai and ai_cred:
        from apis.token_tracker import TokenTracker
        from apis.ai_analyzer import AIAnalyzer

        tracker = TokenTracker(is_subscription=ai_cred.is_subscription)
        analyzer = AIAnalyzer(
            credential=ai_cred, tracker=tracker,
            model=args.ai_model if args.ai_model else "",
        )

        if judol_result:
            ai_analysis = analyzer.analyze_judol(judol_result)
        elif vulns:
            ai_analysis = analyzer.analyze_vulns(vulns)

    # ── Report ───────────────────────────────────────────────────────────
    input_name = (
        os.path.basename(args.input) if args.input
        else args.url if args.url
        else f"core-{wp_version}"
    )

    if args.format == "json":
        _report_json_combined(vulns, judol_result, ai_analysis, tracker,
                             poc_results, input_name, source_label, args.output)
    else:
        # Vulnerability report
        report_fns = {"table": report_table, "csv": report_csv}
        report_fns[args.format](vulns, input_name, source_label, args.output)

        # POC report (table only)
        if poc_results and args.format == "table":
            report_poc_table(poc_results, Console())

        # Judol report (table only)
        if judol_result and args.format == "table":
            report_judol_table(judol_result, Console())

        # AI analysis
        if ai_analysis and args.format == "table":
            report_ai_analysis(ai_analysis, Console())

        # Token usage
        if tracker and args.format == "table":
            print_token_usage(tracker, Console())

    # CI exit code
    exit_code = 0
    if vulns:
        exit_code = 1
    if judol_result and judol_result.is_infected:
        exit_code = 2
    if exit_code:
        sys.exit(exit_code)


def _report_json_combined(vulns, judol_result, ai_analysis, tracker,
                          poc_results, input_name, source_label, output_file):
    """Combined JSON output with vulns + judol + AI + POC."""
    from collections import Counter

    sev_counts = Counter(v.severity for v in vulns)

    output = {
        "scan": {
            "input_file": input_name,
            "source": source_label,
            "type": "wordpress",
        },
        "summary": {
            "total": len(vulns),
            "critical": sev_counts.get("CRITICAL", 0),
            "high": sev_counts.get("HIGH", 0),
            "medium": sev_counts.get("MEDIUM", 0),
            "low": sev_counts.get("LOW", 0),
            "unknown": sev_counts.get("UNKNOWN", 0),
        },
        "vulnerabilities": [
            {
                "plugin": v.package, "version": v.version,
                "cve_id": v.cve_id, "cvss_score": v.cvss_score,
                "severity": v.severity, "summary": v.summary,
                "fix_version": v.fix_version, "url": v.url,
                "source": v.source, "references": v.references,
            }
            for v in vulns
        ],
    }

    if poc_results:
        output["poc"] = {
            cve_id: r.to_dict() for cve_id, r in poc_results.items()
        }

    if judol_result:
        output["judol"] = judol_result.to_dict()

    if ai_analysis:
        output["ai_analysis"] = ai_analysis

    if tracker and tracker.total_api_calls > 0:
        output["ai_usage"] = tracker.to_dict()

    import json
    json_str = json.dumps(output, indent=2, ensure_ascii=False)
    if output_file:
        with open(output_file, "w") as f:
            f.write(json_str)
        print(f"[*] JSON written to {output_file}")
    else:
        print(json_str)


if __name__ == "__main__":
    main()
