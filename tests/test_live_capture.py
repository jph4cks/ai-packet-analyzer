"""Tests for the live-capture mode.

These tests never open a real socket. They drive the per-packet accumulator
directly and mock ``scapy.sniff()`` (via ``AsyncSniffer``) when exercising
``capture_live``.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from ai_packet_analyzer.live_capture import (
    LiveCaptureError,
    LiveCaptureOptions,
    _PacketAccumulator,
    capture_live,
    check_capture_privileges,
    list_interfaces,
)


# ---------------------------------------------------------------------------
# _PacketAccumulator unit tests (no sockets, no threads)
# ---------------------------------------------------------------------------


def _make_tcp_syn(src: str = "10.0.0.1", dst: str = "10.0.0.2", dport: int = 80):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=12345, dport=dport, flags="S")
    pkt.time = 1000.0
    return pkt


def _make_tcp_synack(src: str = "10.0.0.2", dst: str = "10.0.0.1", sport: int = 80):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=12345, flags="SA")
    pkt.time = 1000.1
    return pkt


def _make_dns_query(qname: str = "example.com"):
    raw = (
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=33333, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    # Re-parse so DNS field counts (qdcount, etc.) are populated as they
    # would be on the wire.
    pkt = Ether(bytes(raw))
    pkt.time = 1000.2
    return pkt


def _make_arp_request(src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2"):
    pkt = Ether() / ARP(op=1, psrc=src_ip, pdst=dst_ip, hwsrc="aa:bb:cc:dd:ee:ff")
    pkt.time = 1000.3
    return pkt


def _make_icmp_unreachable():
    pkt = Ether() / IP(src="10.0.0.99", dst="10.0.0.1") / ICMP(type=3, code=3)
    pkt.time = 1000.4
    return pkt


def _make_telnet_with_creds():
    payload = b"USER admin\r\nPASS hunter2\r\n"
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.5")
        / TCP(sport=44444, dport=23, flags="PA")
        / Raw(load=payload)
    )
    pkt.time = 1000.5
    return pkt


def test_accumulator_counts_basic_protocols():
    acc = _PacketAccumulator()
    acc(_make_tcp_syn())
    acc(_make_tcp_synack())
    acc(_make_dns_query())
    acc(_make_arp_request())
    acc(_make_icmp_unreachable())

    s = acc.snapshot()
    assert s.total_packets == 5
    assert s.tcp_packets == 2
    assert s.udp_packets == 1
    assert s.dns_packets == 1
    assert s.arp_packets == 1
    assert s.icmp_packets == 1
    assert s.tcp_syn_count == 1
    assert s.tcp_syn_ack_count == 1
    assert s.tcp_connections_attempted == 1
    assert s.tcp_connections_completed == 1


def test_accumulator_extracts_dns_query():
    acc = _PacketAccumulator()
    acc(_make_dns_query("perplexity.ai"))
    s = acc.snapshot()
    assert any(q["query"] == "perplexity.ai" for q in s.dns_queries)


def test_accumulator_detects_cleartext_credentials():
    acc = _PacketAccumulator()
    acc(_make_telnet_with_creds())
    s = acc.snapshot()
    # Telnet on port 23 is in CLEARTEXT_PROTOCOLS — should produce a session
    # entry and credential matches for USER/PASS.
    assert len(s.cleartext_sessions) == 1
    assert s.cleartext_sessions[0]["protocol"] == "Telnet"
    cred_types = {c["type"] for c in s.potential_credentials}
    assert any("Username" in t or "Password" in t for t in cred_types)


def test_accumulator_handles_malformed_packet_gracefully():
    acc = _PacketAccumulator()

    class BadPacket:
        time = "not-a-number"

        def __len__(self):
            raise RuntimeError("boom")

        def haslayer(self, _layer):
            return False

    acc(BadPacket())
    s = acc.snapshot()
    # Should not raise, and should be counted as "other".
    assert s.other_packets >= 1


def test_accumulator_tracks_duration():
    acc = _PacketAccumulator()
    pkt1 = _make_tcp_syn()
    pkt1.time = 100.0
    pkt2 = _make_tcp_synack()
    pkt2.time = 105.5
    acc(pkt1)
    acc(pkt2)
    s = acc.snapshot()
    assert s.start_time == 100.0
    assert s.end_time == 105.5
    assert s.duration_seconds == pytest.approx(5.5)


# ---------------------------------------------------------------------------
# capture_live integration with a mocked AsyncSniffer
# ---------------------------------------------------------------------------


class _FakeSniffer:
    """Stand-in for scapy.AsyncSniffer that synchronously feeds canned packets."""

    def __init__(self, packets, **kwargs):
        self._packets = list(packets)
        self._kwargs = kwargs
        self.running = False
        self._stop_filter = kwargs.get("stop_filter")
        self._prn = kwargs.get("prn")

    def start(self):
        self.running = True
        for pkt in self._packets:
            if self._prn is not None:
                self._prn(pkt)
            if self._stop_filter is not None and self._stop_filter(pkt):
                break
        self.running = False

    def stop(self):
        self.running = False


def test_capture_live_runs_with_mocked_sniffer():
    canned = [_make_tcp_syn(), _make_tcp_synack(), _make_dns_query()]

    def factory(**kwargs):
        return _FakeSniffer(canned, **kwargs)

    with patch("ai_packet_analyzer.live_capture.AsyncSniffer", side_effect=factory):
        stats = capture_live(LiveCaptureOptions(packet_count=3))

    assert stats.total_packets == 3
    assert stats.tcp_packets == 2
    assert stats.dns_packets == 1


def test_capture_live_save_pcap_creates_file(tmp_path: Path):
    canned = [_make_tcp_syn(), _make_dns_query()]

    def factory(**kwargs):
        return _FakeSniffer(canned, **kwargs)

    out = tmp_path / "out.pcap"
    with patch("ai_packet_analyzer.live_capture.AsyncSniffer", side_effect=factory):
        stats = capture_live(LiveCaptureOptions(packet_count=2, save_pcap=out))

    assert stats.total_packets == 2
    assert out.exists()
    assert out.stat().st_size > 0  # PCAP global header is at least 24 bytes


def test_capture_live_invalid_save_path_raises(tmp_path: Path):
    # A path inside a non-existent directory that we'll try to write to. Use
    # a path whose parent we can create, then make the file unwritable by
    # writing to a read-only directory.
    ro_dir = tmp_path / "readonly"
    ro_dir.mkdir()
    ro_dir.chmod(0o500)
    out = ro_dir / "denied.pcap"
    try:
        with pytest.raises(LiveCaptureError):
            capture_live(LiveCaptureOptions(save_pcap=out))
    finally:
        ro_dir.chmod(0o700)


def test_capture_live_permission_error_wrapped():
    def factory(**kwargs):
        sniffer = MagicMock()
        sniffer.start.side_effect = PermissionError("nope")
        sniffer.running = False
        return sniffer

    with patch("ai_packet_analyzer.live_capture.AsyncSniffer", side_effect=factory):
        with pytest.raises(LiveCaptureError) as exc_info:
            capture_live(LiveCaptureOptions())
    assert "Permission denied" in str(exc_info.value)


def test_capture_live_oserror_wrapped():
    def factory(**kwargs):
        sniffer = MagicMock()
        sniffer.start.side_effect = OSError("no such device")
        sniffer.running = False
        return sniffer

    with patch("ai_packet_analyzer.live_capture.AsyncSniffer", side_effect=factory):
        with pytest.raises(LiveCaptureError) as exc_info:
            capture_live(LiveCaptureOptions(interface="bogus0"))
    assert "Failed to start capture" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def test_list_interfaces_returns_list():
    ifaces = list_interfaces()
    assert isinstance(ifaces, list)
    # On most systems we expect at least loopback, but environments without
    # networking should still get a list (possibly empty).
    for iface in ifaces:
        assert isinstance(iface, str)


def test_check_capture_privileges_returns_tuple():
    ok, msg = check_capture_privileges()
    assert isinstance(ok, bool)
    assert isinstance(msg, str)
    assert msg  # never empty


def test_live_capture_options_defaults():
    opts = LiveCaptureOptions()
    assert opts.interface is None
    assert opts.bpf_filter is None
    assert opts.packet_count is None
    assert opts.duration_seconds is None
    assert opts.save_pcap is None
    assert opts.store_packets is False
    assert opts.promiscuous is True
