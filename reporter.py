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
