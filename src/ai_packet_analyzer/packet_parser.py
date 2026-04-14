"""
Core packet parsing engine using Scapy.
Extracts structured metadata from pcap/pcapng files for downstream analysis.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Raw,
    rdpcap,
    conf,
)

# Suppress Scapy warnings
conf.verb = 0

# Well-known ports for protocol identification
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Cleartext (unencrypted) protocols that may carry sensitive data
CLEARTEXT_PROTOCOLS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    513: "rlogin",
    514: "rsh",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
    3306: "MySQL",
    1433: "MSSQL",
}


@dataclass
class PacketStats:
    """Aggregated statistics from a pcap file."""

    total_packets: int = 0
    ip_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    dns_packets: int = 0
    other_packets: int = 0

    # Timing
    start_time: float | None = None
    end_time: float | None = None
    duration_seconds: float = 0.0

    # IP tracking
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    conversations: Counter = field(default_factory=Counter)

    # Port tracking
    dst_ports: Counter = field(default_factory=Counter)
    src_ports: Counter = field(default_factory=Counter)
    protocols_used: Counter = field(default_factory=Counter)

    # TCP analysis
    tcp_syn_count: int = 0
    tcp_syn_ack_count: int = 0
    tcp_rst_count: int = 0
    tcp_fin_count: int = 0
    tcp_retransmissions: int = 0
    tcp_connections_attempted: int = 0
    tcp_connections_completed: int = 0
    tcp_connections_reset: int = 0

    # DNS analysis
    dns_queries: list = field(default_factory=list)
    dns_responses: list = field(default_factory=list)
    dns_errors: list = field(default_factory=list)

    # ARP analysis
    arp_requests: list = field(default_factory=list)
    arp_replies: list = field(default_factory=list)

    # ICMP analysis
    icmp_types: Counter = field(default_factory=Counter)
    icmp_unreachable: list = field(default_factory=list)

    # Payload / cleartext
    cleartext_sessions: list = field(default_factory=list)
    potential_credentials: list = field(default_factory=list)
    sensitive_patterns: list = field(default_factory=list)

    # Byte totals
    total_bytes: int = 0
    bytes_per_ip: Counter = field(default_factory=Counter)

    # Raw packet data for deeper inspection
    raw_packets: list = field(default_factory=list)

    # TCP connection tracking
    tcp_streams: dict = field(default_factory=dict)


# ICMP type names
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# ICMP Destination Unreachable codes
ICMP_UNREACH_CODES = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
    9: "Network Administratively Prohibited",
    10: "Host Administratively Prohibited",
    13: "Communication Administratively Prohibited",
}


def parse_pcap(filepath: str | Path, max_packets: int | None = None) -> PacketStats:
    """
    Parse a pcap/pcapng file and return structured statistics.

    Args:
        filepath: Path to the pcap file.
        max_packets: Maximum number of packets to parse (None = all).

    Returns:
        PacketStats with all extracted metadata.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    packets = rdpcap(str(filepath))
    stats = PacketStats()
    stats.total_packets = len(packets)

    if max_packets:
        packets = packets[:max_packets]

    # Track TCP handshakes
    syn_tracker: dict[tuple, float] = {}  # (src, dst, dport) -> timestamp
    seq_tracker: set[tuple] = set()  # Track (src, dst, seq) for retransmission detection

    for pkt in packets:
        pkt_time = float(pkt.time)
        pkt_len = len(pkt)
        stats.total_bytes += pkt_len

        # Timing
        if stats.start_time is None or pkt_time < stats.start_time:
            stats.start_time = pkt_time
        if stats.end_time is None or pkt_time > stats.end_time:
            stats.end_time = pkt_time

        # ARP
        if pkt.haslayer(ARP):
            stats.arp_packets += 1
            arp = pkt[ARP]
            if arp.op == 1:  # Request
                stats.arp_requests.append({
                    "src_mac": arp.hwsrc,
                    "src_ip": arp.psrc,
                    "dst_ip": arp.pdst,
                    "time": pkt_time,
                })
            elif arp.op == 2:  # Reply
                stats.arp_replies.append({
                    "src_mac": arp.hwsrc,
                    "src_ip": arp.psrc,
                    "dst_mac": arp.hwdst,
                    "dst_ip": arp.pdst,
                    "time": pkt_time,
                })
            continue

        # IP layer
        if not pkt.haslayer(IP):
            stats.other_packets += 1
            continue

        stats.ip_packets += 1
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        stats.src_ips[src_ip] += 1
        stats.dst_ips[dst_ip] += 1
        stats.bytes_per_ip[src_ip] += pkt_len
        conv_key = tuple(sorted([src_ip, dst_ip]))
        stats.conversations[conv_key] += 1

        # ICMP
        if pkt.haslayer(ICMP):
            stats.icmp_packets += 1
            icmp = pkt[ICMP]
            icmp_type = icmp.type
            type_name = ICMP_TYPES.get(icmp_type, f"Type-{icmp_type}")
            stats.icmp_types[type_name] += 1

            if icmp_type == 3:  # Destination Unreachable
                code_name = ICMP_UNREACH_CODES.get(icmp.code, f"Code-{icmp.code}")
                stats.icmp_unreachable.append({
                    "src": src_ip,
                    "dst": dst_ip,
                    "code": code_name,
                    "time": pkt_time,
                })

        # TCP
        if pkt.haslayer(TCP):
            stats.tcp_packets += 1
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            flags = tcp.flags

            stats.dst_ports[dport] += 1
            stats.src_ports[sport] += 1

            # Protocol identification
            proto = WELL_KNOWN_PORTS.get(dport, WELL_KNOWN_PORTS.get(sport, f"TCP/{dport}"))
            stats.protocols_used[proto] += 1

            # TCP flag analysis
            if flags & 0x02 and not (flags & 0x10):  # SYN only
                stats.tcp_syn_count += 1
                stats.tcp_connections_attempted += 1
                syn_tracker[(src_ip, dst_ip, dport)] = pkt_time

            if flags & 0x02 and flags & 0x10:  # SYN-ACK
                stats.tcp_syn_ack_count += 1
                stats.tcp_connections_completed += 1

            if flags & 0x04:  # RST
                stats.tcp_rst_count += 1
                stats.tcp_connections_reset += 1

            if flags & 0x01:  # FIN
                stats.tcp_fin_count += 1

            # Retransmission detection (simplified)
            if pkt.haslayer(Raw) and (flags & 0x10):  # ACK with data
                seq = tcp.seq
                pkt_id = (src_ip, dst_ip, sport, dport, seq)
                if pkt_id in seq_tracker:
                    stats.tcp_retransmissions += 1
                else:
                    seq_tracker.add(pkt_id)

            # Track TCP stream
            stream_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
            if stream_key not in stats.tcp_streams:
                stats.tcp_streams[stream_key] = {
                    "src": src_ip,
                    "dst": dst_ip,
                    "sport": sport,
                    "dport": dport,
                    "packets": 0,
                    "bytes": 0,
                    "payloads": [],
                }
            stats.tcp_streams[stream_key]["packets"] += 1
            stats.tcp_streams[stream_key]["bytes"] += pkt_len

            # Extract payload for cleartext protocol analysis
            if pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                if dport in CLEARTEXT_PROTOCOLS or sport in CLEARTEXT_PROTOCOLS:
                    try:
                        payload_text = raw_data.decode("utf-8", errors="ignore")
                    except Exception:
                        payload_text = raw_data.decode("latin-1", errors="ignore")

                    if len(payload_text.strip()) > 0:
                        proto_name = CLEARTEXT_PROTOCOLS.get(
                            dport, CLEARTEXT_PROTOCOLS.get(sport, "Unknown")
                        )
                        stats.cleartext_sessions.append({
                            "protocol": proto_name,
                            "src": src_ip,
                            "dst": dst_ip,
                            "sport": sport,
                            "dport": dport,
                            "payload_preview": payload_text[:500],
                            "payload_length": len(raw_data),
                            "time": pkt_time,
                        })

                        # Credential detection patterns
                        _detect_credentials(payload_text, proto_name, src_ip, dst_ip, sport, dport, pkt_time, stats)

        # UDP
        elif pkt.haslayer(UDP):
            stats.udp_packets += 1
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport

            stats.dst_ports[dport] += 1
            stats.src_ports[sport] += 1

            proto = WELL_KNOWN_PORTS.get(dport, WELL_KNOWN_PORTS.get(sport, f"UDP/{dport}"))
            stats.protocols_used[proto] += 1

            # DNS analysis
            if pkt.haslayer(DNS):
                stats.dns_packets += 1
                dns = pkt[DNS]

                if dns.qr == 0 and dns.qd:  # Query
                    for i in range(dns.qdcount):
                        try:
                            qname = dns.qd[i].qname.decode("utf-8", errors="ignore").rstrip(".")
                            qtype = dns.qd[i].qtype
                            type_str = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}.get(qtype, str(qtype))
                            stats.dns_queries.append({
                                "query": qname,
                                "type": type_str,
                                "src": src_ip,
                                "time": pkt_time,
                            })
                        except Exception:
                            pass

                elif dns.qr == 1:  # Response
                    rcode = dns.rcode
                    rcode_str = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}.get(rcode, str(rcode))

                    query_name = ""
                    if dns.qd:
                        try:
                            query_name = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        except Exception:
                            pass

                    if rcode != 0:
                        stats.dns_errors.append({
                            "query": query_name,
                            "rcode": rcode_str,
                            "src": src_ip,
                            "dst": dst_ip,
                            "time": pkt_time,
                        })

                    if dns.an:
                        for i in range(dns.ancount):
                            try:
                                answer = dns.an[i]
                                stats.dns_responses.append({
                                    "query": query_name,
                                    "answer": answer.rdata if hasattr(answer, 'rdata') else str(answer),
                                    "type": answer.type,
                                    "ttl": answer.ttl,
                                    "time": pkt_time,
                                })
                            except Exception:
                                pass

            # Check cleartext UDP protocols
            if pkt.haslayer(Raw):
                if dport in CLEARTEXT_PROTOCOLS or sport in CLEARTEXT_PROTOCOLS:
                    raw_data = bytes(pkt[Raw].load)
                    try:
                        payload_text = raw_data.decode("utf-8", errors="ignore")
                    except Exception:
                        payload_text = ""
                    if len(payload_text.strip()) > 0:
                        proto_name = CLEARTEXT_PROTOCOLS.get(
                            dport, CLEARTEXT_PROTOCOLS.get(sport, "Unknown")
                        )
                        stats.cleartext_sessions.append({
                            "protocol": proto_name,
                            "src": src_ip,
                            "dst": dst_ip,
                            "sport": sport,
                            "dport": dport,
                            "payload_preview": payload_text[:500],
                            "payload_length": len(raw_data),
                            "time": pkt_time,
                        })
        else:
            stats.other_packets += 1

    # Calculate duration
    if stats.start_time and stats.end_time:
        stats.duration_seconds = stats.end_time - stats.start_time

    return stats


# Regex patterns for sensitive data detection
CREDENTIAL_PATTERNS = [
    (re.compile(r"USER\s+(\S+)", re.IGNORECASE), "Username (FTP/POP3)"),
    (re.compile(r"PASS\s+(\S+)", re.IGNORECASE), "Password (FTP/POP3)"),
    (re.compile(r"Authorization:\s*Basic\s+(\S+)", re.IGNORECASE), "HTTP Basic Auth"),
    (re.compile(r"Authorization:\s*Bearer\s+(\S+)", re.IGNORECASE), "Bearer Token"),
    (re.compile(r"password[=:]\s*(\S+)", re.IGNORECASE), "Password in payload"),
    (re.compile(r"passwd[=:]\s*(\S+)", re.IGNORECASE), "Password in payload"),
    (re.compile(r"api[_-]?key[=:]\s*(\S+)", re.IGNORECASE), "API Key"),
    (re.compile(r"token[=:]\s*(\S+)", re.IGNORECASE), "Auth Token"),
    (re.compile(r"secret[=:]\s*(\S+)", re.IGNORECASE), "Secret Value"),
    (re.compile(r"session[_-]?id[=:]\s*(\S+)", re.IGNORECASE), "Session ID"),
    (re.compile(r"AUTH\s+(LOGIN|PLAIN)\s*(\S*)", re.IGNORECASE), "SMTP Auth"),
    (re.compile(r"cookie:\s*(.+)", re.IGNORECASE), "HTTP Cookie"),
    (re.compile(r"set-cookie:\s*(.+)", re.IGNORECASE), "Set-Cookie Header"),
]

SENSITIVE_DATA_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN-like pattern"),
    (re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"), "Credit card-like pattern"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "Email address"),
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----"), "Private key"),
    (re.compile(r"-----BEGIN CERTIFICATE-----"), "Certificate"),
]


def _detect_credentials(
    payload: str,
    protocol: str,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    timestamp: float,
    stats: PacketStats,
) -> None:
    """Scan payload text for credential and sensitive data patterns."""
    for pattern, label in CREDENTIAL_PATTERNS:
        match = pattern.search(payload)
        if match:
            stats.potential_credentials.append({
                "type": label,
                "protocol": protocol,
                "matched_value": match.group(0)[:100],
                "src": src_ip,
                "dst": dst_ip,
                "sport": sport,
                "dport": dport,
                "time": timestamp,
            })

    for pattern, label in SENSITIVE_DATA_PATTERNS:
        match = pattern.search(payload)
        if match:
            stats.sensitive_patterns.append({
                "type": label,
                "protocol": protocol,
                "context": payload[max(0, match.start() - 20):match.end() + 20][:120],
                "src": src_ip,
                "dst": dst_ip,
                "time": timestamp,
            })
