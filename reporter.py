import csv
import io
import json
import sys
from typing import List, Optional
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from models import VulnResult
from apis.token_tracker import TokenTracker


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}


def print_banner(console: Console):
    banner = """[bold cyan]
┬ ┬┌─┐┬ ┬┬ ┬┌┐┌┌┬┐┌─┐┬─┐
│││├─┘├─┤│ ││││ │ ├┤ ├┬┘
└┴┘┴  ┴ ┴└─┘┘└┘ ┴ └─┘┴└─
[/bold cyan]
[dim]WordPress Plugin, Theme & Core Vulnerability Scanner[/dim]
[dim]Sources: WPScan API | WPVulnerability.net | NVD[/dim]
"""
    console.print(banner)


def report_table(vulns: List[VulnResult], input_file: str,
                 source_name: str, output_file: Optional[str] = None):
    """Rich terminal table output."""
    out = open(output_file, 'w') if output_file else sys.stdout
    console = Console(file=out)

    if not vulns:
        console.print(Panel(
            "[green]No vulnerabilities found![/green]",
            title=f"wphunter -- {input_file}",
        ))
        if output_file:
            out.close()
        return

    table = Table(
        title=f"wphunter -- {input_file} (via {source_name})",
        show_lines=True,
    )
    table.add_column("Component", style="cyan", min_width=18)
    table.add_column("CVE", style="bold", min_width=16)
    table.add_column("CVSS", justify="center", min_width=8)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("Summary", min_width=35)
    table.add_column("Fix", style="green", min_width=8)

    for v in vulns:
        color = SEVERITY_COLORS.get(v.severity, "dim")
        cvss_text = Text(v.cvss_display)
        cvss_text.stylize(color)
        sev_text = Text(v.severity)
        sev_text.stylize(color)

        table.add_row(
            f"{v.package}@{v.version}",
            v.cve_id,
            cvss_text,
            sev_text,
            v.summary[:55],
            v.fix_version or "-",
        )

    console.print(table)

    # Summary
    sev_counts = Counter(v.severity for v in vulns)
    parts = []
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        count = sev_counts.get(level, 0)
        if count:
            c = SEVERITY_COLORS[level]
            parts.append(f"[{c}]{count} {level}[/{c}]")

    fixes = {}
    for v in vulns:
        if v.fix_version and v.package not in fixes:
            fixes[v.package] = v.fix_version

    console.print()
    console.print(f"  Total: [bold]{len(vulns)}[/bold] vulnerabilities ({', '.join(parts)})")
    console.print(f"  Source: {source_name}")
    if fixes:
        fix_str = ", ".join(f"{p} -> {v}" for p, v in fixes.items())
        console.print(f"  Recommended updates: {fix_str}")
    console.print()

    if output_file:
        out.close()
        Console().print(f"[green]Results written to {output_file}[/green]")


def report_json(vulns: List[VulnResult], input_file: str,
                source_name: str, output_file: Optional[str] = None):
    """JSON output."""
    sev_counts = Counter(v.severity for v in vulns)

    output = {
        "scan": {
            "input_file": input_file,
            "source": source_name,
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
                "plugin": v.package,
                "version": v.version,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "summary": v.summary,
                "fix_version": v.fix_version,
                "url": v.url,
                "source": v.source,
                "references": v.references,
            }
            for v in vulns
        ],
    }

    json_str = json.dumps(output, indent=2, ensure_ascii=False)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(json_str)
        print(f"[*] JSON written to {output_file}")
    else:
        print(json_str)


def report_csv(vulns: List[VulnResult], input_file: str,
               source_name: str, output_file: Optional[str] = None):
    """CSV output."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Plugin", "Version", "CVE ID", "CVSS", "Severity",
        "Summary", "Fix Version", "URL", "Source", "References",
    ])

    for v in vulns:
        writer.writerow([
            v.package, v.version, v.cve_id,
            v.cvss_score or "", v.severity, v.summary,
            v.fix_version, v.url, v.source,
            "; ".join(v.references) if v.references else "",
        ])

    csv_str = buf.getvalue()
    if output_file:
        with open(output_file, 'w') as f:
            f.write(csv_str)
        print(f"[*] CSV written to {output_file}")
    else:
        print(csv_str)


def report_poc_table(poc_results: dict, console: Optional[Console] = None):
    """Display POC/exploit lookup results as a rich table.

    Args:
        poc_results: {cve_id: PocResult} from PocLookup.lookup_all()
        console: Rich console instance
    """
    if console is None:
        console = Console()

    if not poc_results:
        return

    POC_STATUS_COLORS = {
        "EXPLOITED IN WILD": "bold red",
        "PUBLIC EXPLOIT": "red",
        "PUBLIC POC": "yellow",
        "NUCLEI TEMPLATE": "yellow",
        "EXPLOIT REFS": "blue",
        "NO KNOWN POC": "dim",
    }

    POC_STATUS_ICONS = {
        "EXPLOITED IN WILD": "🔴",
        "PUBLIC EXPLOIT": "🟠",
        "PUBLIC POC": "🟡",
        "NUCLEI TEMPLATE": "🟡",
        "EXPLOIT REFS": "🔵",
        "NO KNOWN POC": "⚪",
    }

    table = Table(title="POC / Exploit Lookup", show_lines=True)
    table.add_column("CVE", style="bold", min_width=18)
    table.add_column("EPSS", justify="center", min_width=6)
    table.add_column("Status", min_width=20)
    table.add_column("Details", min_width=25)

    # Sort: exploited in wild first, then by EPSS descending
    status_order = {
        "EXPLOITED IN WILD": 0, "PUBLIC EXPLOIT": 1, "PUBLIC POC": 2,
        "NUCLEI TEMPLATE": 3, "EXPLOIT REFS": 4, "NO KNOWN POC": 5,
    }
    sorted_results = sorted(
        poc_results.values(),
        key=lambda r: (status_order.get(r.status, 9), -(r.epss_score or 0)),
    )

    for r in sorted_results:
        color = POC_STATUS_COLORS.get(r.status, "dim")
        icon = POC_STATUS_ICONS.get(r.status, "")

        epss_str = f"{r.epss_score:.2f}" if r.epss_score is not None else "—"
        epss_text = Text(epss_str)
        if r.epss_score is not None and r.epss_score >= 0.5:
            epss_text.stylize("bold red")
        elif r.epss_score is not None and r.epss_score >= 0.1:
            epss_text.stylize("yellow")

        status_text = Text(f"{icon} {r.status}")
        status_text.stylize(color)

        table.add_row(r.cve_id, epss_text, status_text, r.details_text)

    console.print()
    console.print(table)

    # Summary line
    total = len(poc_results)
    with_poc = sum(1 for r in poc_results.values() if r.status != "NO KNOWN POC")
    kev_count = sum(1 for r in poc_results.values() if r.exploited_in_wild)
    top_epss = max(poc_results.values(), key=lambda r: r.epss_score or 0)

    console.print()
    console.print(f"  {with_poc}/{total} CVEs have public exploits or POCs")
    if kev_count:
        console.print(f"  [bold red]{kev_count} CVE{'s' if kev_count != 1 else ''} actively exploited in the wild (CISA KEV)[/bold red]")
    if top_epss.epss_score is not None and top_epss.epss_score > 0:
        pct = int(top_epss.epss_score * 100)
        console.print(f"  Top EPSS: {top_epss.cve_id} ({pct}% exploit probability)")
    console.print()


def report_judol_table(judol_result, console: Optional[Console] = None):
    """Display judol detection results as a rich table."""
    if console is None:
        console = Console()

    # Verdict panel
    if judol_result.is_infected:
        color = "bold red" if judol_result.severity in ("critical", "high") else "yellow"
        verdict_text = (
            f"[{color}]INFECTED — {judol_result.infection_type.upper()}[/{color}]\n"
            f"Confidence: {judol_result.confidence}\n"
            f"Severity: {judol_result.severity.upper()}"
        )
    else:
        verdict_text = (
            "[green]CLEAN[/green]\n"
            f"Confidence: {judol_result.confidence}"
        )

    console.print(Panel(verdict_text, title="Judol Detection Result", border_style="cyan"))

    # Cloaking results
    if judol_result.cloaked_pages:
        table = Table(title="Cloaked Pages", show_lines=True)
        table.add_column("URL", style="cyan")
        table.add_column("Size Ratio", justify="center")
        table.add_column("Gambling Keywords", style="red")

        for cp in judol_result.cloaked_pages:
            table.add_row(
                cp.url[:60],
                f"{cp.size_ratio:.1f}x",
                ", ".join(cp.gambling_keywords_in_diff[:5]),
            )
        console.print(table)

    # Hidden elements
    if judol_result.hidden_elements:
        table = Table(title="Hidden Gambling Elements", show_lines=True)
        table.add_column("Tag", style="dim")
        table.add_column("Method", style="yellow")
        table.add_column("Content", style="red")
        table.add_column("Keywords")

        for he in judol_result.hidden_elements[:10]:
            table.add_row(
                he.tag, he.hiding_method,
                he.text_content[:50], ", ".join(he.gambling_keywords[:3]),
            )
        console.print(table)

    # Suspicious links
    if judol_result.suspicious_links:
        table = Table(title="Suspicious Outbound Links", show_lines=True)
        table.add_column("Domain", style="red")
        table.add_column("Anchor Text")
        table.add_column("Reason", style="yellow")

        for sl in judol_result.suspicious_links[:15]:
            table.add_row(sl.domain, sl.anchor_text[:40], sl.reason)
        console.print(table)

    # Top keywords
    if judol_result.gambling_keywords_found:
        top_kw = sorted(judol_result.gambling_keywords_found.items(),
                       key=lambda x: x[1], reverse=True)[:10]
        table = Table(title="Top Gambling Keywords Found", show_lines=True)
        table.add_column("Keyword", style="red")
        table.add_column("Count", justify="right")
        for kw, count in top_kw:
            table.add_row(kw, str(count))
        console.print(table)

    # Spam directories
    if judol_result.spam_directories:
        dirs_str = ", ".join(judol_result.spam_directories)
        console.print(f"\n  [red]Spam directories:[/red] {dirs_str}")

    # Suspicious scripts
    if judol_result.suspicious_scripts:
        console.print(f"\n  [red]Suspicious scripts:[/red] {len(judol_result.suspicious_scripts)} found")
        for s in judol_result.suspicious_scripts[:5]:
            console.print(f"    {s[:80]}")

    console.print()


def report_ai_analysis(ai_result: dict, console: Optional[Console] = None):
    """Display AI analysis results."""
    if console is None:
        console = Console()

    if not ai_result:
        return

    if "raw_analysis" in ai_result:
        console.print(Panel(ai_result["raw_analysis"][:2000],
                           title="AI Analysis", border_style="cyan"))
        return

    content_parts = []
    if "executive_summary" in ai_result:
        content_parts.append(f"[bold]Summary:[/bold] {ai_result['executive_summary']}")
    if "executive_summary_id" in ai_result:
        content_parts.append(f"[bold]Ringkasan:[/bold] {ai_result['executive_summary_id']}")
    if "severity_assessment" in ai_result:
        content_parts.append(f"\n[bold]Severity:[/bold] {ai_result['severity_assessment']}")
    if "likely_infection_vector" in ai_result:
        content_parts.append(f"[bold]Infection Vector:[/bold] {ai_result['likely_infection_vector']}")
    if "remediation_steps" in ai_result:
        content_parts.append("\n[bold]Remediation Steps:[/bold]")
        for i, step in enumerate(ai_result["remediation_steps"], 1):
            content_parts.append(f"  {i}. {step}")

    if content_parts:
        console.print(Panel("\n".join(content_parts),
                           title="AI Analysis", border_style="cyan"))


def print_token_usage(tracker: TokenTracker, console: Optional[Console] = None):
    """Print token usage summary at the end of scan."""
    if tracker.total_api_calls == 0:
        return

    if console is None:
        console = Console()

    breakdown = tracker.get_cost_breakdown()

    # Build breakdown lines
    breakdown_lines = []
    for purpose, data in breakdown.items():
        tokens = data["input_tokens"] + data["output_tokens"]
        breakdown_lines.append(
            f"  {purpose.replace('_', ' '):<20} {data['calls']} call(s)"
            f"  {tokens:>8,} tok  ${data['cost']:.4f}"
        )

    if tracker.is_subscription:
        billing = "Claude Pro/Max subscription"
        cost_line = f"${tracker.total_cost:.4f} (covered by subscription)"
    else:
        billing = "pay-per-token (API key)"
        cost_line = f"${tracker.total_cost:.4f}"

    content = (
        f"API Calls:      {tracker.total_api_calls}\n"
        f"Input Tokens:   {tracker.total_input_tokens:,}\n"
        f"Output Tokens:  {tracker.total_output_tokens:,}\n"
        f"Total Tokens:   {tracker.total_tokens:,}\n"
        f"\nBreakdown:\n"
        + "\n".join(breakdown_lines) + "\n"
        f"\nTotal Cost:     {cost_line}\n"
        f"Billing:        {billing}"
    )

    if not tracker.is_subscription:
        content += (
            "\n\nUsing Claude Pro/Max? Run 'python scanner.py connect'\n"
            "to use your subscription quota instead of pay-per-token."
        )

    console.print()
    console.print(Panel(content, title="AI Token Usage", border_style="cyan", expand=False))
