"""
Interactive CLI for the AI Packet Analyzer.
Provides a user-friendly menu-driven interface for pcap analysis
with optional LLM-enhanced deep analysis.
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
from .report_renderer import render_report, render_llm_analysis


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
  # Basic usage (heuristic analysis only)
  ai-packet-analyzer capture.pcap
  ai-packet-analyzer capture.pcap --mode troubleshoot
  ai-packet-analyzer capture.pcap --mode security

  # With LLM-enhanced analysis
  ai-packet-analyzer capture.pcap --llm openai
  ai-packet-analyzer capture.pcap --llm anthropic --llm-model claude-sonnet-4-20250514
  ai-packet-analyzer capture.pcap --llm openrouter --llm-model anthropic/claude-sonnet-4
  ai-packet-analyzer capture.pcap --llm ollama --llm-model llama3
  ai-packet-analyzer capture.pcap --llm local --llm-base-url http://localhost:1234/v1/chat/completions

  # LLM with interactive follow-up questions
  ai-packet-analyzer capture.pcap --llm openai --interactive-llm

  # Filtering
  ai-packet-analyzer capture.pcap --mode troubleshoot --ip 192.168.1.10 --port 80
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

    # ─── LLM Options ───
    llm_group = parser.add_argument_group("LLM-Enhanced Analysis")
    llm_group.add_argument(
        "--llm",
        metavar="PROVIDER",
        help=(
            "Enable LLM deep analysis. Providers: openai, anthropic, openrouter, "
            "local, ollama, lmstudio, chatgpt, claude."
        ),
    )
    llm_group.add_argument(
        "--llm-api-key",
        metavar="KEY",
        help="API key for the LLM provider (or set via environment variable).",
    )
    llm_group.add_argument(
        "--llm-model",
        metavar="MODEL",
        help="Model name to use (default depends on provider).",
    )
    llm_group.add_argument(
        "--llm-base-url",
        metavar="URL",
        help="Custom API endpoint URL (for local LLMs or proxies).",
    )
    llm_group.add_argument(
        "--llm-temperature",
        type=float,
        default=0.3,
        metavar="TEMP",
        help="LLM temperature (0.0-1.0, default: 0.3).",
    )
    llm_group.add_argument(
        "--llm-max-tokens",
        type=int,
        default=4096,
        metavar="N",
        help="Max tokens for LLM response (default: 4096).",
    )
    llm_group.add_argument(
        "--interactive-llm",
        action="store_true",
        help="After LLM analysis, enter an interactive Q&A loop to ask follow-up questions.",
    )
    llm_group.add_argument(
        "--llm-question",
        metavar="QUESTION",
        help="Ask a specific question to the LLM instead of running the default analysis.",
    )
    llm_group.add_argument(
        "--list-providers",
        action="store_true",
        help="List all supported LLM providers and exit.",
    )

    args = parser.parse_args()

    # Handle --list-providers
    if args.list_providers:
        from .llm_providers import list_providers
        console.print(list_providers())
        sys.exit(0)

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

    # Run heuristic analysis
    if mode == "troubleshoot":
        report = _run_troubleshooting(stats, args)
    elif mode == "security":
        report = _run_security_audit(stats, args)
    else:
        console.print(f"[bold red]Unknown mode:[/bold red] {mode}")
        sys.exit(1)

    # Render heuristic report
    render_report(report, console=console, verbose=args.verbose)

    # ─── LLM-Enhanced Analysis ───
    llm_result = None

    # If no --llm flag, offer LLM in interactive mode
    if not args.llm and args.mode == "interactive":
        llm_result = _offer_llm_interactively(stats, report, mode, args)
    elif args.llm:
        llm_result = _run_llm_analysis(stats, report, mode, args)

    # Interactive follow-up loop
    if args.interactive_llm and args.llm:
        _interactive_llm_loop(stats, report, mode, args, llm_result)

    # Save to file
    if args.output:
        from .report_renderer import render_report_to_string
        output_text = render_report_to_string(report, verbose=args.verbose, llm_result=llm_result)
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


def _offer_llm_interactively(stats, report, mode, args):
    """In interactive mode, offer LLM analysis after heuristic results."""
    console.print()
    console.print("[bold]Would you like to run LLM-enhanced deep analysis?[/bold]\n")
    console.print("  An LLM can provide root cause analysis, attack chain identification,")
    console.print("  compliance impact assessment, and correlated findings.\n")
    console.print("  Supported providers: [cyan]openai[/cyan], [cyan]anthropic[/cyan], [cyan]openrouter[/cyan], [cyan]local/ollama[/cyan]\n")

    if not Confirm.ask("Enable LLM analysis?", default=False):
        return None

    provider = Prompt.ask(
        "[bold]LLM provider[/bold]",
        choices=["openai", "anthropic", "openrouter", "local"],
        default="openai",
    )

    api_key = None
    if provider != "local":
        from .llm_providers import ENV_KEYS, LLMProvider
        provider_enum = {
            "openai": LLMProvider.OPENAI,
            "anthropic": LLMProvider.ANTHROPIC,
            "openrouter": LLMProvider.OPENROUTER,
        }.get(provider)
        env_var = ENV_KEYS.get(provider_enum, "")
        existing_key = __import__("os").environ.get(env_var, "")

        if existing_key:
            console.print(f"  [green]Using API key from {env_var}[/green]")
        else:
            api_key = Prompt.ask(f"[bold]Enter your API key[/bold] (or set {env_var})")

    model = Prompt.ask("[bold]Model name[/bold] (press Enter for default)", default="")
    model = model.strip() or None

    # Create config and run
    from .llm_providers import LLMConfig
    config = LLMConfig.from_args(
        provider=provider,
        api_key=api_key,
        model=model,
    )

    return _execute_llm_analysis(config, stats, report, mode, args)


def _run_llm_analysis(stats, report, mode, args):
    """Run LLM analysis from CLI arguments."""
    from .llm_providers import LLMConfig, validate_config

    try:
        config = LLMConfig.from_args(
            provider=args.llm,
            api_key=args.llm_api_key,
            model=args.llm_model,
            base_url=args.llm_base_url,
            temperature=args.llm_temperature,
            max_tokens=args.llm_max_tokens,
        )
    except ValueError as e:
        console.print(f"[bold red]LLM Configuration Error:[/bold red] {e}")
        return None

    # Validate
    is_valid, error_msg = validate_config(config)
    if not is_valid:
        console.print(f"[bold red]LLM Error:[/bold red] {error_msg}")
        return None

    return _execute_llm_analysis(config, stats, report, mode, args)


def _execute_llm_analysis(config, stats, report, mode, args):
    """Execute the LLM analysis and render results."""
    from .llm_analyzer import run_llm_analysis

    mode_str = "security" if mode == "security" else "troubleshooting"
    problem_desc = getattr(args, 'description', None)
    custom_question = getattr(args, 'llm_question', None)

    console.print()
    with console.status(
        f"[bold magenta]Running LLM deep analysis ({config.provider.value} / {config.get_model()})...[/bold magenta]",
        spinner="dots",
    ):
        llm_result = run_llm_analysis(
            config=config,
            stats=stats,
            report=report,
            mode=mode_str,
            problem_description=problem_desc,
            custom_question=custom_question,
        )

    # Render the LLM output
    render_llm_analysis(llm_result, console=console)

    return llm_result


def _interactive_llm_loop(stats, report, mode, args, initial_llm_result):
    """Interactive follow-up Q&A loop with the LLM."""
    from .llm_providers import LLMConfig
    from .llm_analyzer import run_interactive_followup

    try:
        config = LLMConfig.from_args(
            provider=args.llm,
            api_key=args.llm_api_key,
            model=args.llm_model,
            base_url=args.llm_base_url,
            temperature=args.llm_temperature,
            max_tokens=args.llm_max_tokens,
        )
    except ValueError:
        return

    mode_str = "security" if mode == "security" else "troubleshooting"
    previous_analysis = initial_llm_result.content if initial_llm_result and initial_llm_result.success else None

    console.print(Panel(
        "[bold]Interactive LLM Q&A[/bold]\n"
        "Ask follow-up questions about the packet capture.\n"
        "Type [bold cyan]quit[/bold cyan] or [bold cyan]exit[/bold cyan] to stop.",
        box=box.ROUNDED,
        style="magenta",
    ))

    while True:
        console.print()
        question = Prompt.ask("[bold magenta]Your question[/bold magenta]")

        if question.strip().lower() in ("quit", "exit", "q", ""):
            console.print("[dim]Exiting interactive LLM session.[/dim]")
            break

        with console.status("[bold magenta]Thinking...[/bold magenta]", spinner="dots"):
            followup_result = run_interactive_followup(
                config=config,
                stats=stats,
                report=report,
                mode=mode_str,
                question=question,
                previous_analysis=previous_analysis,
            )

        render_llm_analysis(followup_result, console=console)

        # Accumulate context for conversation continuity
        if followup_result.success:
            previous_analysis = (
                (previous_analysis or "")
                + f"\n\n---\nQ: {question}\nA: {followup_result.content}"
            )


if __name__ == "__main__":
    main()
