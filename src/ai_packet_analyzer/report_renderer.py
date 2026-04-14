"""
Report rendering module.
Formats analysis results into beautiful console output using Rich.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .ai_engine import AnalysisReport, Finding, Severity


# Severity colors
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!!!]",
    Severity.HIGH: "[!!]",
    Severity.MEDIUM: "[!]",
    Severity.LOW: "[i]",
    Severity.INFO: "[~]",
}


def render_report(report: AnalysisReport, console: Console | None = None, verbose: bool = False) -> None:
    """
    Render an analysis report to the console.

    Args:
        report: The analysis report to display.
        console: Rich console instance (created if not provided).
        verbose: If True, show additional statistics.
    """
    if console is None:
        console = Console()

    mode_label = "CONNECTIVITY TROUBLESHOOTING" if report.mode == "troubleshooting" else "SECURITY AUDIT"
    mode_color = "bold cyan" if report.mode == "troubleshooting" else "bold red"

    # Header
    console.print()
    console.print(Panel(
        f"[{mode_color}]AI Packet Analyzer — {mode_label}[/{mode_color}]",
        box=box.DOUBLE,
        style="bold",
    ))
    console.print()

    # Summary
    console.print(Panel(report.summary, title="[bold]Summary[/bold]", box=box.ROUNDED))
    console.print()

    # Statistics table (if verbose)
    if verbose and report.statistics:
        _render_statistics(report.statistics, console)

    # Findings
    if report.findings:
        _render_findings(report.findings, console)
    else:
        console.print(Panel(
            "[green]No issues found in this capture.[/green]",
            title="Findings",
            box=box.ROUNDED,
        ))

    # Severity summary bar
    _render_severity_bar(report, console)


def _render_statistics(stats: dict, console: Console) -> None:
    """Render the statistics section."""
    table = Table(title="Capture Statistics", box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Metric", style="bold cyan", min_width=25)
    table.add_column("Value", justify="right")

    table.add_row("Total Packets", f"{stats.get('total_packets', 0):,}")
    table.add_row("Capture Duration", f"{stats.get('duration_seconds', 0):.2f}s")
    table.add_row("Total Bytes", f"{stats.get('total_bytes', 0):,}")
    table.add_row("Unique Source IPs", str(stats.get("unique_src_ips", 0)))
    table.add_row("Unique Destination IPs", str(stats.get("unique_dst_ips", 0)))
    table.add_row("Unique Conversations", str(stats.get("unique_conversations", 0)))

    console.print(table)
    console.print()

    # Protocol breakdown
    protocols = stats.get("protocols", {})
    if protocols:
        proto_table = Table(title="Protocol Breakdown", box=box.SIMPLE_HEAD)
        proto_table.add_column("Protocol", style="bold")
        proto_table.add_column("Packets", justify="right")
        for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
            if count > 0:
                proto_table.add_row(proto, f"{count:,}")
        console.print(proto_table)
        console.print()

    # Application protocols
    app_protos = stats.get("application_protocols", {})
    if app_protos:
        app_table = Table(title="Application Protocols", box=box.SIMPLE_HEAD)
        app_table.add_column("Protocol", style="bold")
        app_table.add_column("Packets", justify="right")
        for proto, count in sorted(app_protos.items(), key=lambda x: -x[1])[:15]:
            app_table.add_row(proto, f"{count:,}")
        console.print(app_table)
        console.print()

    # Top talkers
    top_talkers = stats.get("top_talkers", {})
    if top_talkers:
        talk_table = Table(title="Top Source IPs (Talkers)", box=box.SIMPLE_HEAD)
        talk_table.add_column("IP Address", style="bold")
        talk_table.add_column("Packets Sent", justify="right")
        for ip, count in list(top_talkers.items())[:10]:
            talk_table.add_row(ip, f"{count:,}")
        console.print(talk_table)
        console.print()


def _render_findings(findings: list[Finding], console: Console) -> None:
    """Render the findings list."""
    console.print(f"[bold]Findings ({len(findings)}):[/bold]")
    console.print()

    for i, finding in enumerate(findings, 1):
        sev = finding.severity
        color = SEVERITY_COLORS[sev]
        icon = SEVERITY_ICONS[sev]

        # Finding header
        header = Text()
        header.append(f" {icon} ", style=color)
        header.append(f"{sev.value}", style=color)
        header.append(f" — {finding.title}")

        panel_content = []

        # Description
        panel_content.append(f"[bold]Description:[/bold] {finding.description}")

        # Category
        if finding.category:
            panel_content.append(f"[bold]Category:[/bold] {finding.category}")

        # Details
        if finding.details:
            panel_content.append("")
            panel_content.append("[bold]Details:[/bold]")
            for detail in finding.details:
                panel_content.append(f"  • {detail}")

        # Recommendation
        if finding.recommendation:
            panel_content.append("")
            panel_content.append(f"[bold green]Recommendation:[/bold green] {finding.recommendation}")

        border_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }.get(sev, "white")

        console.print(Panel(
            "\n".join(panel_content),
            title=header,
            border_style=border_color,
            box=box.ROUNDED,
        ))
        console.print()


def _render_severity_bar(report: AnalysisReport, console: Console) -> None:
    """Render a severity summary bar at the bottom."""
    counts = report.count_by_severity()
    total = sum(counts.values())

    if total == 0:
        return

    bar = Text("  Severity Summary: ")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = counts.get(sev.value, 0)
        if count > 0:
            bar.append(f" {sev.value}: {count} ", style=SEVERITY_COLORS[sev])
            bar.append("  ")

    console.print(Panel(bar, box=box.HEAVY))
    console.print()


def render_report_to_string(report: AnalysisReport, verbose: bool = False) -> str:
    """Render a report to a plain-text string (for file output or testing)."""
    from io import StringIO
    string_io = StringIO()
    console = Console(file=string_io, force_terminal=False, width=120)
    render_report(report, console=console, verbose=verbose)
    return string_io.getvalue()
