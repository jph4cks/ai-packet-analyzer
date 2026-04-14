"""
Interactive CLI for the AI Packet Analyzer.
Provides a user-friendly menu-driven interface for pcap analysis.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import box

from .packet_parser import parse_pcap, PacketStats
from .ai_engine import analyze_connectivity, analyze_security, AnalysisReport
from .report_renderer import render_report


console = Console()

BANNER = r"""
    _    ___   ____            _        _
   / \  |_ _| |  _ \ __ _  ___| | _____| |_
  / _ \  | |  | |_) / _` |/ __| |/ / _ \ __|
 / ___ \ | |  |  __/ (_| | (__|   <  __/ |_
/_/   \_\___| |_|   \__,_|\___|_|\_\___|\__|
    _                _
   / \   _ __   __ _| |_   _ _______ _ __
  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ___ \| | | | (_| | | |_| |/ /  __/ |
/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                        |___/
"""


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="AI Packet Analyzer — AI-powered pcap analysis for connectivity troubleshooting and security auditing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ai-packet-analyzer capture.pcap
  ai-packet-analyzer capture.pcap --mode troubleshoot
  ai-packet-analyzer capture.pcap --mode security
  ai-packet-analyzer capture.pcap --mode troubleshoot --ip 192.168.1.10 --port 80
  ai-packet-analyzer capture.pcap --verbose
        """,
    )
    parser.add_argument(
        "pcap_file",
        nargs="?",
        help="Path to the pcap/pcapng file to analyze.",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["troubleshoot", "security", "interactive"],
        default="interactive",
        help="Analysis mode: troubleshoot, security, or interactive (default: interactive).",
    )
    parser.add_argument(
        "--ip",
        action="append",
        help="Filter analysis to specific IP address(es). Can be specified multiple times.",
    )
    parser.add_argument(
        "--port",
        type=int,
        action="append",
        help="Filter analysis to specific port(s). Can be specified multiple times.",
    )
    parser.add_argument(
        "--description", "-d",
        help="Problem description for connectivity troubleshooting.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed statistics in the report.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Maximum number of packets to analyze (default: all).",
    )
    parser.add_argument(
        "--output", "-o",
        help="Save report output to a text file.",
    )

    args = parser.parse_args()

    # Show banner
    console.print(BANNER, style="bold cyan")
    console.print(Panel(
        "[bold]AI-Powered Network Packet Analyzer[/bold]\n"
        "Connectivity Troubleshooting & Security Auditing",
        box=box.DOUBLE,
        style="cyan",
    ))
    console.print()

    # Get pcap file
    pcap_path = args.pcap_file
    if not pcap_path:
        pcap_path = Prompt.ask("[bold cyan]Enter the path to the pcap file[/bold cyan]")

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {pcap_path}")
        sys.exit(1)

    if not pcap_path.suffix.lower() in (".pcap", ".pcapng", ".cap"):
        console.print("[bold yellow]Warning:[/bold yellow] File does not have a standard pcap extension. Attempting to parse anyway...")

    # Parse pcap
    console.print(f"\n[bold]Parsing[/bold] {pcap_path.name}...")
    try:
        stats = parse_pcap(str(pcap_path), max_packets=args.max_packets)
    except Exception as e:
        console.print(f"[bold red]Error parsing pcap file:[/bold red] {e}")
        sys.exit(1)

    console.print(f"[green]Loaded {stats.total_packets:,} packets[/green] ({stats.total_bytes:,} bytes, {stats.duration_seconds:.2f}s)")
    console.print()

    # Determine mode
    mode = args.mode
    if mode == "interactive":
        mode = _interactive_mode_selection()

    # Run analysis based on mode
    if mode == "troubleshoot":
        report = _run_troubleshooting(stats, args)
    elif mode == "security":
        report = _run_security_audit(stats, args)
    else:
        console.print(f"[bold red]Unknown mode:[/bold red] {mode}")
        sys.exit(1)

    # Render report
    render_report(report, console=console, verbose=args.verbose)

    # Save to file if requested
    if args.output:
        from .report_renderer import render_report_to_string
        output_text = render_report_to_string(report, verbose=args.verbose)
        Path(args.output).write_text(output_text)
        console.print(f"[green]Report saved to {args.output}[/green]")


def _interactive_mode_selection() -> str:
    """Interactively ask the user which analysis mode to use."""
    console.print("[bold]What type of analysis would you like to perform?[/bold]\n")
    console.print("  [cyan][1][/cyan] Connectivity Troubleshooting")
    console.print("      Diagnose network connectivity issues: failed connections,")
    console.print("      DNS errors, packet loss, routing problems, and more.\n")
    console.print("  [red][2][/red] Security Audit")
    console.print("      Find unencrypted traffic, exposed credentials, cleartext")
    console.print("      protocols, and sensitive data in network traffic.\n")

    choice = Prompt.ask(
        "[bold]Select mode[/bold]",
        choices=["1", "2"],
        default="1",
    )

    return "troubleshoot" if choice == "1" else "security"


def _run_troubleshooting(stats: PacketStats, args) -> AnalysisReport:
    """Run connectivity troubleshooting analysis."""
    filter_ips = args.ip
    filter_ports = args.port
    description = args.description

    # Check if multiple issues were found and offer to narrow down
    # First, do a broad scan
    initial_report = analyze_connectivity(stats)
    issue_count = len(initial_report.findings)

    if issue_count > 3 and not (filter_ips or filter_ports or description) and args.mode == "interactive":
        console.print(f"\n[bold yellow]Multiple issues detected ({issue_count} findings).[/bold yellow]")
        console.print("To get a more focused analysis, you can provide additional context.\n")

        if Confirm.ask("Would you like to narrow down the analysis?", default=True):
            description = Prompt.ask(
                "[bold]Describe the problem you're experiencing[/bold]",
                default="",
            )
            ip_input = Prompt.ask(
                "[bold]Enter IP address(es) involved (comma-separated, or press Enter to skip)[/bold]",
                default="",
            )
            port_input = Prompt.ask(
                "[bold]Enter port(s) involved (comma-separated, or press Enter to skip)[/bold]",
                default="",
            )

            if ip_input.strip():
                filter_ips = [ip.strip() for ip in ip_input.split(",") if ip.strip()]
            if port_input.strip():
                try:
                    filter_ports = [int(p.strip()) for p in port_input.split(",") if p.strip()]
                except ValueError:
                    console.print("[yellow]Invalid port number(s), skipping port filter.[/yellow]")

            if description.strip():
                description = description.strip()
            else:
                description = None

    report = analyze_connectivity(
        stats,
        problem_description=description or None,
        filter_ips=filter_ips,
        filter_ports=filter_ports,
    )

    return report


def _run_security_audit(stats: PacketStats, args) -> AnalysisReport:
    """Run security audit analysis."""
    report = analyze_security(
        stats,
        filter_ips=args.ip,
        filter_ports=args.port,
    )

    return report


if __name__ == "__main__":
    main()
