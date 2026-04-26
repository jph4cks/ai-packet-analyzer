"""
Rich-based live dashboard for the live-capture mode.

Renders a continuously refreshing summary of capture progress (packet rate,
top talkers, protocol mix) while :func:`live_capture.capture_live` is running.

The UI runs in the calling thread; capture runs in Scapy's ``AsyncSniffer``
thread, so updates are non-blocking.
"""

from __future__ import annotations

import time
from typing import Any

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .live_capture import LiveCaptureOptions, capture_live
from .packet_parser import PacketStats


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{n:,} {unit}"
        n = n / 1024
    return f"{n:,.1f} GB"


def _build_dashboard(
    stats: PacketStats,
    options: LiveCaptureOptions,
    elapsed: float,
) -> Panel:
    """Render a single frame of the live dashboard."""
    header = Table.grid(expand=True)
    header.add_column(justify="left")
    header.add_column(justify="right")
    iface = options.interface or "default"
    bpf = options.bpf_filter or "(none)"
    header.add_row(
        Text(f"Interface: {iface}    Filter: {bpf}", style="cyan"),
        Text(f"Elapsed: {elapsed:6.1f}s", style="magenta"),
    )

    # ─── Counters ───
    counters = Table.grid(expand=True, padding=(0, 2))
    counters.add_column(justify="left")
    counters.add_column(justify="right")
    pps = stats.total_packets / elapsed if elapsed > 0 else 0.0
    counters.add_row("Total packets", f"[bold green]{stats.total_packets:,}[/bold green]")
    counters.add_row("Total bytes", f"[bold]{_format_bytes(stats.total_bytes)}[/bold]")
    counters.add_row("Packets/sec", f"[yellow]{pps:,.1f}[/yellow]")
    counters.add_row("TCP / UDP / ICMP", f"{stats.tcp_packets:,} / {stats.udp_packets:,} / {stats.icmp_packets:,}")
    counters.add_row("ARP / DNS / Other", f"{stats.arp_packets:,} / {stats.dns_packets:,} / {stats.other_packets:,}")
    if stats.tcp_packets:
        counters.add_row(
            "TCP SYN / SYN-ACK / RST",
            f"{stats.tcp_syn_count:,} / {stats.tcp_syn_ack_count:,} / [red]{stats.tcp_rst_count:,}[/red]",
        )
    if stats.cleartext_sessions:
        counters.add_row(
            "Cleartext sessions",
            f"[bold red]{len(stats.cleartext_sessions):,}[/bold red]",
        )
    if stats.potential_credentials:
        counters.add_row(
            "Potential credentials",
            f"[bold red blink]{len(stats.potential_credentials):,}[/bold red blink]",
        )

    # ─── Top talkers ───
    talkers = Table(title="Top Talkers (src IP)", expand=True, show_header=True, header_style="bold cyan")
    talkers.add_column("Source IP")
    talkers.add_column("Packets", justify="right")
    talkers.add_column("Bytes", justify="right")
    for ip, count in list(stats.src_ips.most_common(5)):
        talkers.add_row(ip, f"{count:,}", _format_bytes(stats.bytes_per_ip.get(ip, 0)))
    if not stats.src_ips:
        talkers.add_row("[dim]waiting for packets…[/dim]", "", "")

    # ─── Top protocols ───
    protos = Table(title="Top Protocols", expand=True, show_header=True, header_style="bold cyan")
    protos.add_column("Protocol")
    protos.add_column("Packets", justify="right")
    for proto, count in list(stats.protocols_used.most_common(5)):
        protos.add_row(str(proto), f"{count:,}")
    if not stats.protocols_used:
        protos.add_row("[dim]…[/dim]", "")

    # Layout: stack the counters above the two side-by-side tables.
    side_by_side = Table.grid(expand=True)
    side_by_side.add_column(ratio=1)
    side_by_side.add_column(ratio=1)
    side_by_side.add_row(talkers, protos)

    body = Group(header, counters, side_by_side)
    return Panel(
        body,
        title="[bold]AI Packet Analyzer — Live Capture[/bold]",
        subtitle="[dim]Press Ctrl+C to stop[/dim]",
        border_style="cyan",
    )


def run_live_capture_with_ui(
    options: LiveCaptureOptions,
    console: Console | None = None,
    refresh_per_second: int = 4,
) -> PacketStats:
    """Run a live capture while rendering a Rich dashboard.

    Args:
        options: Capture configuration.
        console: Optional Rich :class:`Console`. A new one is created if
            omitted.
        refresh_per_second: Dashboard refresh rate. Capped to keep CPU usage
            modest during high-rate captures.

    Returns:
        The final :class:`PacketStats` once capture stops.
    """
    console = console or Console()
    started = time.monotonic()

    # Holder cells the Live updater reads from. The capture callback only has
    # to mutate these — actual rendering happens in the Live loop.
    state: dict[str, Any] = {"stats": PacketStats(), "elapsed": 0.0}

    def _on_packet(_pkt: Any, current: PacketStats) -> None:
        state["stats"] = current
        state["elapsed"] = time.monotonic() - started

    # We render the dashboard in the main thread via Live; capture happens
    # asynchronously inside ``capture_live`` (AsyncSniffer thread).
    with Live(
        Align.center(Panel("Starting capture…", border_style="cyan")),
        console=console,
        refresh_per_second=refresh_per_second,
        transient=False,
    ) as live:
        # Start a background thread that refreshes the panel on a timer; we
        # cannot block here because capture_live itself blocks.
        import threading

        stop_render = threading.Event()

        def _render_loop() -> None:
            while not stop_render.is_set():
                stats = state["stats"]
                elapsed = state["elapsed"] or (time.monotonic() - started)
                live.update(_build_dashboard(stats, options, elapsed))
                time.sleep(1.0 / max(refresh_per_second, 1))

        render_thread = threading.Thread(target=_render_loop, daemon=True)
        render_thread.start()
        try:
            final_stats = capture_live(options, on_packet=_on_packet)
        finally:
            stop_render.set()
            render_thread.join(timeout=1.0)
            # Final frame.
            live.update(_build_dashboard(
                final_stats if "final_stats" in locals() else state["stats"],
                options,
                time.monotonic() - started,
            ))

    return final_stats


__all__ = ["run_live_capture_with_ui"]
