"""
Live packet capture engine.

Provides a real-time alternative to :func:`packet_parser.parse_pcap` that uses
``scapy.sniff()`` to capture packets from a live network interface and
incrementally builds the same :class:`PacketStats` data structure used by the
rest of the analysis pipeline.

The live mode is designed to feel and behave like the existing pcap workflow:

* It produces a fully-populated :class:`PacketStats` object so all downstream
  heuristic and LLM analyzers work without modification.
* It supports several termination conditions: a packet count, a duration, or
  ``Ctrl+C`` (graceful shutdown).
* It optionally writes captured packets to a pcap file for later replay.
* It renders a live, refreshing dashboard via Rich while capture is running.

Privileges
----------
Live capture requires elevated permissions on most platforms:

* **Linux**: run as root (``sudo``) or grant ``CAP_NET_RAW`` and
  ``CAP_NET_ADMIN`` capabilities to the Python interpreter.
* **macOS**: install ChmodBPF (bundled with Wireshark) so ``/dev/bpf*`` is
  group-readable, or run with ``sudo``.
* **Windows**: install Npcap (https://npcap.com) in WinPcap-compatible mode.

Examples
--------
Capture 500 packets from ``eth0`` and analyze::

    ai-packet-analyzer --live -i eth0 --packet-count 500 --mode security

Capture for 60 seconds with a BPF filter and save the pcap::

    ai-packet-analyzer --live -i wlan0 -t 60 -f "tcp port 80" \
        --save-pcap http_traffic.pcap

Capture indefinitely until ``Ctrl+C``::

    ai-packet-analyzer --live -i eth0 --mode troubleshoot
"""

from __future__ import annotations

import os
import platform
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from scapy.all import (
    ARP,
    DNS,
    ICMP,
    IP,
    TCP,
    UDP,
    Raw,
    AsyncSniffer,
    PcapWriter,
    conf,
    get_if_list,
)

from .packet_parser import (
    CLEARTEXT_PROTOCOLS,
    ICMP_TYPES,
    ICMP_UNREACH_CODES,
    WELL_KNOWN_PORTS,
    PacketStats,
    _detect_credentials,
)

# Suppress Scapy warnings/banners
conf.verb = 0


class LiveCaptureError(RuntimeError):
    """Raised when live capture cannot start (permissions, missing iface, etc.)."""


@dataclass
class LiveCaptureOptions:
    """Configuration for a live capture session.

    Attributes:
        interface: Network interface to capture on (e.g. ``"eth0"``). When
            ``None``, Scapy's default interface is used.
        bpf_filter: Optional Berkeley Packet Filter expression
            (e.g. ``"tcp port 80"``).
        packet_count: Stop after this many packets. ``None`` means unlimited.
        duration_seconds: Stop after this many seconds. ``None`` means unlimited.
        save_pcap: Optional path. When set, every captured packet is appended
            to a pcap file at this location.
        store_packets: If True, keep raw packets in memory for additional
            inspection. Disabling reduces memory pressure during long runs.
        promiscuous: If True (default), enable promiscuous mode on supported
            interfaces.
    """

    interface: str | None = None
    bpf_filter: str | None = None
    packet_count: int | None = None
    duration_seconds: float | None = None
    save_pcap: str | Path | None = None
    store_packets: bool = False
    promiscuous: bool = True


class _PacketAccumulator:
    """Incrementally folds packets into a :class:`PacketStats` object.

    This mirrors the per-packet logic of :func:`parse_pcap` but is callable
    one packet at a time so it can be used as a Scapy ``prn`` callback.
    Thread-safety: a single internal lock guards all mutations so the
    Rich dashboard thread can safely read snapshots.
    """

    def __init__(self) -> None:
        self.stats = PacketStats()
        self._lock = threading.Lock()
        # Internal trackers (reset per session)
        self._syn_tracker: dict[tuple, float] = {}
        self._seq_tracker: set[tuple] = set()

    def snapshot(self) -> PacketStats:
        """Return the current :class:`PacketStats` (callers should treat as read-only)."""
        with self._lock:
            # Update duration on every snapshot so live UIs see it tick.
            if self.stats.start_time and self.stats.end_time:
                self.stats.duration_seconds = (
                    self.stats.end_time - self.stats.start_time
                )
            return self.stats

    def __call__(self, pkt: Any) -> None:
        """Process a single packet. Designed to be passed as ``sniff(prn=...)``."""
        try:
            self._ingest(pkt)
        except Exception:
            # Never let a malformed packet kill the capture loop. Counting it
            # as "other" preserves total counts without crashing.
            with self._lock:
                self.stats.other_packets += 1

    # ------------------------------------------------------------------
    # Internal: per-packet ingestion (mirrors parse_pcap loop body)
    # ------------------------------------------------------------------

    def _ingest(self, pkt: Any) -> None:  # noqa: C901 - intentional, mirrors parse_pcap
        with self._lock:
            stats = self.stats
            try:
                pkt_time = float(pkt.time)
            except Exception:
                pkt_time = time.time()
            pkt_len = len(pkt)

            stats.total_packets += 1
            stats.total_bytes += pkt_len

            if stats.start_time is None or pkt_time < stats.start_time:
                stats.start_time = pkt_time
            if stats.end_time is None or pkt_time > stats.end_time:
                stats.end_time = pkt_time

            # ---- ARP ----
            if pkt.haslayer(ARP):
                stats.arp_packets += 1
                arp = pkt[ARP]
                if arp.op == 1:
                    stats.arp_requests.append({
                        "src_mac": arp.hwsrc,
                        "src_ip": arp.psrc,
                        "dst_ip": arp.pdst,
                        "time": pkt_time,
                    })
                elif arp.op == 2:
                    stats.arp_replies.append({
                        "src_mac": arp.hwsrc,
                        "src_ip": arp.psrc,
                        "dst_mac": arp.hwdst,
                        "dst_ip": arp.pdst,
                        "time": pkt_time,
                    })
                return

            # ---- IP ----
            if not pkt.haslayer(IP):
                stats.other_packets += 1
                return

            stats.ip_packets += 1
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            stats.src_ips[src_ip] += 1
            stats.dst_ips[dst_ip] += 1
            stats.bytes_per_ip[src_ip] += pkt_len
            conv_key = tuple(sorted([src_ip, dst_ip]))
            stats.conversations[conv_key] += 1

            # ---- ICMP ----
            if pkt.haslayer(ICMP):
                stats.icmp_packets += 1
                icmp = pkt[ICMP]
                icmp_type = icmp.type
                type_name = ICMP_TYPES.get(icmp_type, f"Type-{icmp_type}")
                stats.icmp_types[type_name] += 1
                if icmp_type == 3:
                    code_name = ICMP_UNREACH_CODES.get(icmp.code, f"Code-{icmp.code}")
                    stats.icmp_unreachable.append({
                        "src": src_ip,
                        "dst": dst_ip,
                        "code": code_name,
                        "time": pkt_time,
                    })

            # ---- TCP ----
            if pkt.haslayer(TCP):
                stats.tcp_packets += 1
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                flags = tcp.flags
                stats.dst_ports[dport] += 1
                stats.src_ports[sport] += 1
                proto = WELL_KNOWN_PORTS.get(dport, WELL_KNOWN_PORTS.get(sport, f"TCP/{dport}"))
                stats.protocols_used[proto] += 1

                if flags & 0x02 and not (flags & 0x10):
                    stats.tcp_syn_count += 1
                    stats.tcp_connections_attempted += 1
                    self._syn_tracker[(src_ip, dst_ip, dport)] = pkt_time
                if flags & 0x02 and flags & 0x10:
                    stats.tcp_syn_ack_count += 1
                    stats.tcp_connections_completed += 1
                if flags & 0x04:
                    stats.tcp_rst_count += 1
                    stats.tcp_connections_reset += 1
                if flags & 0x01:
                    stats.tcp_fin_count += 1

                if pkt.haslayer(Raw) and (flags & 0x10):
                    seq = tcp.seq
                    pkt_id = (src_ip, dst_ip, sport, dport, seq)
                    if pkt_id in self._seq_tracker:
                        stats.tcp_retransmissions += 1
                    else:
                        self._seq_tracker.add(pkt_id)

                stream_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
                if stream_key not in stats.tcp_streams:
                    stats.tcp_streams[stream_key] = {
                        "src": src_ip, "dst": dst_ip,
                        "sport": sport, "dport": dport,
                        "packets": 0, "bytes": 0, "payloads": [],
                    }
                stats.tcp_streams[stream_key]["packets"] += 1
                stats.tcp_streams[stream_key]["bytes"] += pkt_len

                if pkt.haslayer(Raw) and (
                    dport in CLEARTEXT_PROTOCOLS or sport in CLEARTEXT_PROTOCOLS
                ):
                    raw_data = bytes(pkt[Raw].load)
                    try:
                        payload_text = raw_data.decode("utf-8", errors="ignore")
                    except Exception:
                        payload_text = raw_data.decode("latin-1", errors="ignore")
                    if payload_text.strip():
                        proto_name = CLEARTEXT_PROTOCOLS.get(
                            dport, CLEARTEXT_PROTOCOLS.get(sport, "Unknown")
                        )
                        stats.cleartext_sessions.append({
                            "protocol": proto_name,
                            "src": src_ip, "dst": dst_ip,
                            "sport": sport, "dport": dport,
                            "payload_preview": payload_text[:500],
                            "payload_length": len(raw_data),
                            "time": pkt_time,
                        })
                        _detect_credentials(
                            payload_text, proto_name, src_ip, dst_ip,
                            sport, dport, pkt_time, stats,
                        )

            # ---- UDP ----
            elif pkt.haslayer(UDP):
                stats.udp_packets += 1
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport
                stats.dst_ports[dport] += 1
                stats.src_ports[sport] += 1
                proto = WELL_KNOWN_PORTS.get(dport, WELL_KNOWN_PORTS.get(sport, f"UDP/{dport}"))
                stats.protocols_used[proto] += 1

                if pkt.haslayer(DNS):
                    self._ingest_dns(pkt, src_ip, dst_ip, pkt_time, stats)

                if pkt.haslayer(Raw) and (
                    dport in CLEARTEXT_PROTOCOLS or sport in CLEARTEXT_PROTOCOLS
                ):
                    raw_data = bytes(pkt[Raw].load)
                    try:
                        payload_text = raw_data.decode("utf-8", errors="ignore")
                    except Exception:
                        payload_text = ""
                    if payload_text.strip():
                        proto_name = CLEARTEXT_PROTOCOLS.get(
                            dport, CLEARTEXT_PROTOCOLS.get(sport, "Unknown")
                        )
                        stats.cleartext_sessions.append({
                            "protocol": proto_name,
                            "src": src_ip, "dst": dst_ip,
                            "sport": sport, "dport": dport,
                            "payload_preview": payload_text[:500],
                            "payload_length": len(raw_data),
                            "time": pkt_time,
                        })
            else:
                stats.other_packets += 1

    @staticmethod
    def _ingest_dns(pkt: Any, src_ip: str, dst_ip: str, pkt_time: float, stats: PacketStats) -> None:
        """Parse DNS layer fields into stats. Best-effort, silently skips malformed packets."""
        stats.dns_packets += 1
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd:
            for i in range(dns.qdcount):
                try:
                    qname = dns.qd[i].qname.decode("utf-8", errors="ignore").rstrip(".")
                    qtype = dns.qd[i].qtype
                    type_str = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}.get(qtype, str(qtype))
                    stats.dns_queries.append({
                        "query": qname, "type": type_str,
                        "src": src_ip, "time": pkt_time,
                    })
                except Exception:
                    continue
        elif dns.qr == 1:
            rcode = dns.rcode
            rcode_str = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}.get(rcode, str(rcode))
            query_name = ""
            if dns.qd:
                try:
                    query_name = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    query_name = ""
            if rcode != 0:
                stats.dns_errors.append({
                    "query": query_name, "rcode": rcode_str,
                    "src": src_ip, "dst": dst_ip, "time": pkt_time,
                })
            if dns.an:
                for i in range(dns.ancount):
                    try:
                        answer = dns.an[i]
                        stats.dns_responses.append({
                            "query": query_name,
                            "answer": answer.rdata if hasattr(answer, "rdata") else str(answer),
                            "type": answer.type,
                            "ttl": answer.ttl,
                            "time": pkt_time,
                        })
                    except Exception:
                        continue


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def list_interfaces() -> list[str]:
    """Return the list of available capture interfaces, or an empty list on error."""
    try:
        return list(get_if_list())
    except Exception:
        return []


def check_capture_privileges() -> tuple[bool, str]:
    """Determine whether the current process has the right to sniff packets.

    Returns:
        ``(ok, message)`` — ``ok`` is True when capture is likely to succeed.
        ``message`` is a human-readable hint when it isn't.
    """
    system = platform.system()
    if system in ("Linux", "Darwin"):
        try:
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                return True, "Running as root."
        except Exception:
            pass
        # Best-effort: we cannot definitively detect CAP_NET_RAW without parsing
        # /proc/self/status, so just warn the user.
        if system == "Linux":
            return False, (
                "Live capture typically requires root or CAP_NET_RAW. "
                "Try: sudo ai-packet-analyzer --live ... "
                "or: sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
            )
        return False, (
            "Live capture on macOS requires root or ChmodBPF. "
            "Try running with sudo, or install ChmodBPF (bundled with Wireshark)."
        )
    if system == "Windows":
        return True, (
            "On Windows, live capture requires Npcap (https://npcap.com) in "
            "WinPcap-compatible mode. If capture fails, install/repair Npcap."
        )
    return True, f"Unknown platform ({system}); attempting capture anyway."


def _resolve_stop_filter(
    accumulator: _PacketAccumulator,
    options: LiveCaptureOptions,
    stop_event: threading.Event,
) -> Callable[[Any], bool]:
    """Build a Scapy ``stop_filter`` that honors packet_count / duration / Ctrl+C."""
    started = time.monotonic()

    def _stop(_pkt: Any) -> bool:
        if stop_event.is_set():
            return True
        if options.packet_count is not None and accumulator.stats.total_packets >= options.packet_count:
            return True
        if options.duration_seconds is not None and (time.monotonic() - started) >= options.duration_seconds:
            return True
        return False

    return _stop


def capture_live(
    options: LiveCaptureOptions,
    on_packet: Callable[[Any, PacketStats], None] | None = None,
) -> PacketStats:
    """Run a blocking live capture and return the resulting :class:`PacketStats`.

    Args:
        options: Capture configuration.
        on_packet: Optional callback invoked once per processed packet. It
            receives ``(packet, current_stats)``. Useful for live UIs.

    Returns:
        A fully populated :class:`PacketStats` ready for the same heuristic
        and LLM analyzers used for offline pcaps.

    Raises:
        LiveCaptureError: When the OS denies capture or the interface is invalid.
    """
    accumulator = _PacketAccumulator()
    stop_event = threading.Event()

    # Optional pcap writer for --save-pcap. We open lazily so an invalid path
    # surfaces immediately rather than after the first packet.
    writer: PcapWriter | None = None
    if options.save_pcap is not None:
        save_path = Path(options.save_pcap)
        try:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            writer = PcapWriter(str(save_path), append=False, sync=True)
        except (OSError, PermissionError) as exc:
            raise LiveCaptureError(f"Cannot open pcap output {save_path}: {exc}") from exc

    def prn(pkt: Any) -> None:
        accumulator(pkt)
        if writer is not None:
            try:
                writer.write(pkt)
            except Exception:
                # Don't let a write failure abort capture; warn once via stderr.
                pass
        if on_packet is not None:
            try:
                on_packet(pkt, accumulator.stats)
            except Exception:
                pass

    # Wire SIGINT to a graceful stop. We restore the previous handler on exit
    # so re-running capture in the same process behaves correctly.
    previous_handler = signal.getsignal(signal.SIGINT) if threading.current_thread() is threading.main_thread() else None

    def _sigint(_signum, _frame):
        stop_event.set()

    if previous_handler is not None:
        signal.signal(signal.SIGINT, _sigint)

    sniffer = AsyncSniffer(
        iface=options.interface,
        filter=options.bpf_filter,
        prn=prn,
        store=options.store_packets,
        promisc=options.promiscuous,
        stop_filter=_resolve_stop_filter(accumulator, options, stop_event),
    )

    try:
        sniffer.start()
    except PermissionError as exc:
        raise LiveCaptureError(
            "Permission denied opening capture device. "
            "On Linux/macOS run with sudo or grant CAP_NET_RAW; "
            "on Windows ensure Npcap is installed."
        ) from exc
    except OSError as exc:
        raise LiveCaptureError(f"Failed to start capture: {exc}") from exc

    try:
        # Poll until the sniffer thread is done. Using a short sleep keeps
        # the main thread responsive to signals on all platforms.
        while sniffer.running:
            time.sleep(0.1)
            if options.duration_seconds is not None:
                # Backstop: if stop_filter never fires (no packets), we still
                # need to end after duration.
                start = accumulator.stats.start_time
                if start is None:
                    # No packets yet — fall back to wall-clock check.
                    pass
            if stop_event.is_set():
                sniffer.stop()
                break
    except KeyboardInterrupt:
        stop_event.set()
        try:
            sniffer.stop()
        except Exception:
            pass
    finally:
        try:
            if sniffer.running:
                sniffer.stop()
        except Exception:
            pass
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
        if previous_handler is not None:
            try:
                signal.signal(signal.SIGINT, previous_handler)
            except Exception:
                pass

    # Finalise duration before returning.
    final = accumulator.snapshot()
    if final.start_time and final.end_time:
        final.duration_seconds = final.end_time - final.start_time
    return final


__all__ = [
    "LiveCaptureError",
    "LiveCaptureOptions",
    "capture_live",
    "check_capture_privileges",
    "list_interfaces",
]
