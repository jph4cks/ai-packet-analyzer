"""
AI Analysis Engine.

Uses heuristic-based intelligence to analyze parsed packet data and generate
human-readable findings for both connectivity troubleshooting and security auditing.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

from .packet_parser import (
    CLEARTEXT_PROTOCOLS,
    WELL_KNOWN_PORTS,
    PacketStats,
)


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single analysis finding."""
    title: str
    severity: Severity
    description: str
    details: list[str] = field(default_factory=list)
    recommendation: str = ""
    category: str = ""


@dataclass
class AnalysisReport:
    """Complete analysis report."""
    mode: str  # "troubleshooting" or "security"
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)
    filtered: bool = False  # Whether analysis was filtered by user context

    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    def has_high(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)

    def count_by_severity(self) -> dict[str, int]:
        counts = {}
        for sev in Severity:
            counts[sev.value] = sum(1 for f in self.findings if f.severity == sev)
        return counts


# ─────────────────────────── Connectivity Troubleshooting ───────────────────────────

def analyze_connectivity(
    stats: PacketStats,
    problem_description: str | None = None,
    filter_ips: list[str] | None = None,
    filter_ports: list[int] | None = None,
) -> AnalysisReport:
    """
    Analyze packet capture for connectivity issues.

    Args:
        stats: Parsed packet statistics.
        problem_description: Optional user-provided description of the problem.
        filter_ips: Optional list of IPs to focus analysis on.
        filter_ports: Optional list of ports to focus analysis on.

    Returns:
        AnalysisReport with connectivity findings.
    """
    report = AnalysisReport(mode="troubleshooting")
    report.filtered = bool(filter_ips or filter_ports or problem_description)

    # Build general statistics
    report.statistics = _build_stats_summary(stats)

    # Run all connectivity checks
    _check_tcp_handshake_failures(stats, report, filter_ips, filter_ports)
    _check_tcp_resets(stats, report, filter_ips, filter_ports)
    _check_tcp_retransmissions(stats, report, filter_ips, filter_ports)
    _check_dns_failures(stats, report, filter_ips)
    _check_icmp_unreachable(stats, report, filter_ips)
    _check_icmp_issues(stats, report, filter_ips)
    _check_arp_issues(stats, report, filter_ips)
    _check_connection_asymmetry(stats, report, filter_ips, filter_ports)
    _check_high_latency_indicators(stats, report)
    _check_port_scan_patterns(stats, report, filter_ips)
    _check_black_hole(stats, report, filter_ips, filter_ports)

    # Generate summary
    report.summary = _generate_connectivity_summary(stats, report, problem_description)

    # Sort findings by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    report.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    return report


def _build_stats_summary(stats: PacketStats) -> dict:
    """Build a dictionary of general statistics."""
    return {
        "total_packets": stats.total_packets,
        "duration_seconds": round(stats.duration_seconds, 2),
        "protocols": {
            "TCP": stats.tcp_packets,
            "UDP": stats.udp_packets,
            "ICMP": stats.icmp_packets,
            "ARP": stats.arp_packets,
            "DNS": stats.dns_packets,
            "Other": stats.other_packets,
        },
        "unique_src_ips": len(stats.src_ips),
        "unique_dst_ips": len(stats.dst_ips),
        "unique_conversations": len(stats.conversations),
        "total_bytes": stats.total_bytes,
        "top_talkers": dict(stats.src_ips.most_common(10)),
        "top_destinations": dict(stats.dst_ips.most_common(10)),
        "top_ports": dict(stats.dst_ports.most_common(15)),
        "application_protocols": dict(stats.protocols_used.most_common(15)),
    }


def _matches_filter(
    src_ip: str | None = None,
    dst_ip: str | None = None,
    port: int | None = None,
    filter_ips: list[str] | None = None,
    filter_ports: list[int] | None = None,
) -> bool:
    """Check if a packet matches the user's IP/port filters."""
    if not filter_ips and not filter_ports:
        return True
    ip_match = True
    port_match = True
    if filter_ips:
        ip_match = (src_ip in filter_ips) or (dst_ip in filter_ips) if (src_ip or dst_ip) else False
    if filter_ports:
        port_match = (port in filter_ports) if port else False
    if filter_ips and filter_ports:
        return ip_match and port_match
    return ip_match if filter_ips else port_match


def _check_tcp_handshake_failures(stats: PacketStats, report: AnalysisReport, filter_ips, filter_ports):
    """Detect TCP connections that were attempted but never completed."""
    if stats.tcp_syn_count == 0:
        return

    failure_rate = 0
    if stats.tcp_connections_attempted > 0:
        completed = stats.tcp_connections_completed
        failure_rate = ((stats.tcp_connections_attempted - completed) / stats.tcp_connections_attempted) * 100

    if failure_rate > 20:
        severity = Severity.CRITICAL if failure_rate > 50 else Severity.HIGH
        report.findings.append(Finding(
            title="High TCP Handshake Failure Rate",
            severity=severity,
            category="TCP Connectivity",
            description=f"{failure_rate:.1f}% of TCP connections failed to complete the 3-way handshake.",
            details=[
                f"SYN packets sent: {stats.tcp_syn_count}",
                f"SYN-ACK received: {stats.tcp_syn_ack_count}",
                f"Connections attempted: {stats.tcp_connections_attempted}",
                f"Connections completed: {stats.tcp_connections_completed}",
            ],
            recommendation=(
                "Investigate whether the target host/port is reachable. "
                "Common causes: firewall blocking, service not running, network routing issue, "
                "or host down. Check with traceroute and verify service status."
            ),
        ))
    elif failure_rate > 5:
        report.findings.append(Finding(
            title="Moderate TCP Handshake Failure Rate",
            severity=Severity.MEDIUM,
            category="TCP Connectivity",
            description=f"{failure_rate:.1f}% of TCP connections did not complete the 3-way handshake.",
            details=[
                f"SYN packets: {stats.tcp_syn_count}",
                f"SYN-ACK packets: {stats.tcp_syn_ack_count}",
            ],
            recommendation="Some connection failures are normal, but investigate if users report intermittent connectivity.",
        ))


def _check_tcp_resets(stats: PacketStats, report: AnalysisReport, filter_ips, filter_ports):
    """Detect high RST rates indicating connection rejections."""
    if stats.tcp_rst_count == 0:
        return

    rst_ratio = stats.tcp_rst_count / max(stats.tcp_packets, 1) * 100

    if rst_ratio > 15:
        severity = Severity.HIGH if rst_ratio > 30 else Severity.MEDIUM
        report.findings.append(Finding(
            title="Elevated TCP Reset Rate",
            severity=severity,
            category="TCP Connectivity",
            description=f"{rst_ratio:.1f}% of TCP packets are RST (reset), indicating connections being forcefully terminated.",
            details=[
                f"RST packets: {stats.tcp_rst_count}",
                f"Total TCP packets: {stats.tcp_packets}",
                f"RST ratio: {rst_ratio:.1f}%",
            ],
            recommendation=(
                "TCP resets indicate the remote host is refusing connections or an intermediary "
                "(firewall, IDS) is killing them. Check: 1) Service is running on the target port, "
                "2) Firewall rules allow the traffic, 3) No IPS/IDS blocking the connections."
            ),
        ))


def _check_tcp_retransmissions(stats: PacketStats, report: AnalysisReport, filter_ips, filter_ports):
    """Detect TCP retransmissions indicating packet loss or congestion."""
    if stats.tcp_retransmissions == 0:
        return

    retrans_ratio = stats.tcp_retransmissions / max(stats.tcp_packets, 1) * 100

    if retrans_ratio > 5:
        severity = Severity.HIGH if retrans_ratio > 15 else Severity.MEDIUM
        report.findings.append(Finding(
            title="TCP Retransmissions Detected",
            severity=severity,
            category="Performance",
            description=f"{stats.tcp_retransmissions} retransmissions detected ({retrans_ratio:.1f}% of TCP traffic).",
            details=[
                f"Retransmitted packets: {stats.tcp_retransmissions}",
                f"Retransmission rate: {retrans_ratio:.1f}%",
            ],
            recommendation=(
                "Retransmissions indicate packet loss on the network path. Causes include: "
                "network congestion, lossy links (WiFi), MTU issues, or overloaded network devices. "
                "Run a path MTU discovery test and check interface error counters on switches/routers."
            ),
        ))


def _check_dns_failures(stats: PacketStats, report: AnalysisReport, filter_ips):
    """Detect DNS resolution failures."""
    if not stats.dns_errors:
        return

    nxdomain = [e for e in stats.dns_errors if e["rcode"] == "NXDOMAIN"]
    servfail = [e for e in stats.dns_errors if e["rcode"] == "SERVFAIL"]
    refused = [e for e in stats.dns_errors if e["rcode"] == "REFUSED"]

    if nxdomain:
        domains = list({e["query"] for e in nxdomain})[:10]
        report.findings.append(Finding(
            title="DNS NXDOMAIN Responses (Domain Not Found)",
            severity=Severity.HIGH if len(nxdomain) > 5 else Severity.MEDIUM,
            category="DNS",
            description=f"{len(nxdomain)} DNS queries returned NXDOMAIN (domain does not exist).",
            details=[f"Failed domain: {d}" for d in domains],
            recommendation=(
                "These domains could not be resolved. Check: 1) Domain name is spelled correctly, "
                "2) Domain is registered and active, 3) DNS records are published. "
                "If internal domains, check the internal DNS server configuration."
            ),
        ))

    if servfail:
        report.findings.append(Finding(
            title="DNS Server Failures (SERVFAIL)",
            severity=Severity.HIGH,
            category="DNS",
            description=f"{len(servfail)} DNS queries returned SERVFAIL — the DNS server failed to process the query.",
            details=[f"Failed query: {e['query']} (server: {e['dst']})" for e in servfail[:5]],
            recommendation=(
                "The DNS server encountered an internal error. This could indicate: "
                "DNS server overloaded, DNSSEC validation failure, or upstream DNS issues. "
                "Try an alternate DNS resolver (e.g., 8.8.8.8 or 1.1.1.1)."
            ),
        ))

    if refused:
        report.findings.append(Finding(
            title="DNS Queries Refused",
            severity=Severity.MEDIUM,
            category="DNS",
            description=f"{len(refused)} DNS queries were refused by the server.",
            details=[f"Refused query: {e['query']} (server: {e['dst']})" for e in refused[:5]],
            recommendation="The DNS server is refusing queries. Check DNS server ACLs and ensure the client is authorized to query.",
        ))


def _check_icmp_unreachable(stats: PacketStats, report: AnalysisReport, filter_ips):
    """Detect ICMP Destination Unreachable messages."""
    if not stats.icmp_unreachable:
        return

    # Group by code
    by_code = Counter(e["code"] for e in stats.icmp_unreachable)

    for code, count in by_code.most_common():
        severity = Severity.HIGH if "Host Unreachable" in code or "Network Unreachable" in code else Severity.MEDIUM
        affected = list({e["dst"] for e in stats.icmp_unreachable if e["code"] == code})[:5]

        report.findings.append(Finding(
            title=f"ICMP {code}",
            severity=severity,
            category="ICMP / Routing",
            description=f"{count} ICMP '{code}' messages received.",
            details=[f"Affected destination: {ip}" for ip in affected],
            recommendation=(
                f"'{code}' means the traffic cannot reach its destination. "
                "Check routing tables, firewall rules, and verify the target host/network is up."
            ),
        ))


def _check_icmp_issues(stats: PacketStats, report: AnalysisReport, filter_ips):
    """Analyze ICMP echo request/reply patterns for connectivity issues."""
    echo_req = stats.icmp_types.get("Echo Request", 0)
    echo_reply = stats.icmp_types.get("Echo Reply", 0)

    if echo_req > 0 and echo_reply == 0:
        report.findings.append(Finding(
            title="ICMP Echo Requests Without Replies",
            severity=Severity.HIGH,
            category="ICMP / Routing",
            description=f"{echo_req} ping requests were sent but no replies were received.",
            details=[f"Echo Requests: {echo_req}", f"Echo Replies: {echo_reply}"],
            recommendation=(
                "The target host is not responding to pings. Possible causes: "
                "1) Host is down, 2) ICMP blocked by firewall, 3) Network routing issue. "
                "Verify with traceroute and check firewall rules."
            ),
        ))
    elif echo_req > 0 and echo_reply > 0:
        loss_rate = ((echo_req - echo_reply) / echo_req) * 100
        if loss_rate > 10:
            report.findings.append(Finding(
                title="ICMP Packet Loss Detected",
                severity=Severity.MEDIUM,
                category="ICMP / Routing",
                description=f"{loss_rate:.1f}% of ping requests did not receive a reply.",
                details=[f"Requests: {echo_req}", f"Replies: {echo_reply}", f"Loss: {loss_rate:.1f}%"],
                recommendation="Packet loss may indicate network congestion, intermittent connectivity, or firewall rate limiting.",
            ))


def _check_arp_issues(stats: PacketStats, report: AnalysisReport, filter_ips):
    """Detect ARP anomalies like unanswered requests or potential spoofing."""
    if not stats.arp_requests:
        return

    # Check for unanswered ARP requests
    requested_ips = {r["dst_ip"] for r in stats.arp_requests}
    replied_ips = {r["src_ip"] for r in stats.arp_replies}
    unanswered = requested_ips - replied_ips

    if unanswered:
        report.findings.append(Finding(
            title="Unanswered ARP Requests",
            severity=Severity.MEDIUM if len(unanswered) < 5 else Severity.HIGH,
            category="ARP / Layer 2",
            description=f"{len(unanswered)} IP(s) did not reply to ARP requests — host(s) may be offline or unreachable on the local network.",
            details=[f"No ARP reply from: {ip}" for ip in list(unanswered)[:10]],
            recommendation=(
                "These hosts are either offline, not on this Layer 2 segment, or have a misconfigured IP. "
                "Verify they are on the correct VLAN/subnet."
            ),
        ))

    # Check for ARP spoofing (multiple MACs claiming same IP)
    ip_to_macs: dict[str, set] = {}
    for reply in stats.arp_replies:
        ip_to_macs.setdefault(reply["src_ip"], set()).add(reply["src_mac"])

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            report.findings.append(Finding(
                title="Potential ARP Spoofing Detected",
                severity=Severity.CRITICAL,
                category="ARP / Layer 2",
                description=f"Multiple MAC addresses ({len(macs)}) are claiming IP {ip}. This may indicate ARP spoofing.",
                details=[f"MAC: {mac}" for mac in macs],
                recommendation=(
                    "This is a strong indicator of ARP spoofing / man-in-the-middle attack. "
                    "Investigate immediately. Enable Dynamic ARP Inspection (DAI) on switches."
                ),
            ))


def _check_connection_asymmetry(stats: PacketStats, report: AnalysisReport, filter_ips, filter_ports):
    """Detect one-way traffic indicating routing or firewall issues."""
    for (ip1, ip2), count in stats.conversations.most_common():
        # Check if traffic is heavily one-directional
        sent_1_to_2 = sum(1 for s in [ip1] for d in [ip2] if stats.src_ips.get(s, 0) > 0)
        sent_2_to_1 = sum(1 for s in [ip2] for d in [ip1] if stats.src_ips.get(s, 0) > 0)

        # More accurate: count packets in each direction
        fwd = 0
        rev = 0
        for stream in stats.tcp_streams.values():
            if stream["src"] == ip1 and stream["dst"] == ip2:
                fwd += stream["packets"]
            elif stream["src"] == ip2 and stream["dst"] == ip1:
                rev += stream["packets"]

        if fwd > 10 and rev == 0:
            if filter_ips and ip1 not in filter_ips and ip2 not in filter_ips:
                continue
            report.findings.append(Finding(
                title="One-Way Traffic Detected",
                severity=Severity.MEDIUM,
                category="Routing / Firewall",
                description=f"Traffic from {ip1} → {ip2} ({fwd} packets) with no return traffic.",
                details=["This may indicate asymmetric routing, firewall blocking return traffic, or the remote host being unresponsive."],
                recommendation="Check routing tables for asymmetric paths. Verify firewall rules allow return traffic.",
            ))
            break  # Report top one


def _check_high_latency_indicators(stats: PacketStats, report: AnalysisReport):
    """Check for indicators of high latency or congestion."""
    if stats.tcp_retransmissions > 0 and stats.tcp_rst_count > 0:
        report.findings.append(Finding(
            title="Combined Retransmissions and Resets — Possible Network Congestion",
            severity=Severity.MEDIUM,
            category="Performance",
            description=(
                "Both TCP retransmissions and connection resets are present, "
                "which together strongly suggest network congestion or an overloaded destination."
            ),
            details=[
                f"Retransmissions: {stats.tcp_retransmissions}",
                f"Resets: {stats.tcp_rst_count}",
            ],
            recommendation="Check bandwidth utilization on the network path. Consider QoS policies or link upgrades.",
        ))


def _check_port_scan_patterns(stats: PacketStats, report: AnalysisReport, filter_ips):
    """Detect port scanning activity."""
    # Check if a single source is sending SYN to many destination ports
    src_port_spread: dict[str, set] = {}
    for stream in stats.tcp_streams.values():
        src_port_spread.setdefault(stream["src"], set()).add(stream["dport"])

    for src_ip, ports in src_port_spread.items():
        if len(ports) > 20:
            if filter_ips and src_ip not in filter_ips:
                continue
            report.findings.append(Finding(
                title="Possible Port Scan Detected",
                severity=Severity.INFO,
                category="Anomaly Detection",
                description=f"Host {src_ip} connected to {len(ports)} distinct destination ports.",
                details=[f"Sample ports: {sorted(list(ports))[:20]}"],
                recommendation="This may be a port scan or a multi-service client. Investigate if unexpected.",
            ))


def _check_black_hole(stats: PacketStats, report: AnalysisReport, filter_ips, filter_ports):
    """Detect traffic sent to IPs/ports with no response."""
    # Find destination IPs that never appear as source
    dst_only = set(stats.dst_ips.keys()) - set(stats.src_ips.keys())

    # Filter to significant counts
    significant = [(ip, stats.dst_ips[ip]) for ip in dst_only if stats.dst_ips[ip] > 5]
    significant.sort(key=lambda x: -x[1])

    if significant:
        top = significant[:5]
        if filter_ips:
            top = [(ip, c) for ip, c in top if ip in filter_ips]
        if top:
            report.findings.append(Finding(
                title="Traffic Black Hole — Packets Sent With No Return",
                severity=Severity.HIGH,
                category="Connectivity",
                description=f"{len(significant)} destination IP(s) received packets but never sent any return traffic in this capture.",
                details=[f"{ip}: {count} packets sent, 0 responses" for ip, count in top],
                recommendation=(
                    "These hosts appear unreachable or are silently dropping traffic. "
                    "This may indicate: host down, firewall dropping packets (stealth mode), or incorrect IP configuration."
                ),
            ))


def _generate_connectivity_summary(stats: PacketStats, report: AnalysisReport, problem_desc: str | None) -> str:
    """Generate a natural language summary of connectivity findings."""
    counts = report.count_by_severity()
    total_findings = sum(counts.values())

    lines = []
    lines.append(f"Analyzed {stats.total_packets:,} packets over {stats.duration_seconds:.1f} seconds.")
    lines.append(f"Detected {len(stats.src_ips)} unique source IPs and {len(stats.dst_ips)} unique destination IPs.")

    if total_findings == 0:
        lines.append("No connectivity issues detected in this capture.")
    else:
        parts = []
        if counts.get("CRITICAL", 0):
            parts.append(f"{counts['CRITICAL']} critical")
        if counts.get("HIGH", 0):
            parts.append(f"{counts['HIGH']} high")
        if counts.get("MEDIUM", 0):
            parts.append(f"{counts['MEDIUM']} medium")
        if counts.get("LOW", 0):
            parts.append(f"{counts['LOW']} low")
        if counts.get("INFO", 0):
            parts.append(f"{counts['INFO']} informational")
        lines.append(f"Found {total_findings} issue(s): {', '.join(parts)}.")

    if problem_desc:
        lines.append(f"\nUser-reported problem: {problem_desc}")
        lines.append("The analysis below is focused on findings relevant to this issue.")

    return "\n".join(lines)


# ─────────────────────────── Security Audit ───────────────────────────

def analyze_security(
    stats: PacketStats,
    filter_ips: list[str] | None = None,
    filter_ports: list[int] | None = None,
) -> AnalysisReport:
    """
    Analyze packet capture for security concerns, especially unencrypted sensitive traffic.

    Args:
        stats: Parsed packet statistics.
        filter_ips: Optional IP filter.
        filter_ports: Optional port filter.

    Returns:
        AnalysisReport with security findings.
    """
    report = AnalysisReport(mode="security")
    report.filtered = bool(filter_ips or filter_ports)
    report.statistics = _build_stats_summary(stats)

    _check_cleartext_protocols(stats, report, filter_ips, filter_ports)
    _check_credentials_in_traffic(stats, report, filter_ips)
    _check_sensitive_data(stats, report, filter_ips)
    _check_unencrypted_email(stats, report)
    _check_unencrypted_web(stats, report)
    _check_unencrypted_auth(stats, report)
    _check_dns_security(stats, report)
    _check_arp_spoofing(stats, report)
    _check_telnet_usage(stats, report)
    _check_ftp_usage(stats, report)
    _check_snmp_usage(stats, report)
    _check_suspicious_ports(stats, report)

    report.summary = _generate_security_summary(stats, report)

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    report.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    return report


def _check_cleartext_protocols(stats: PacketStats, report: AnalysisReport, filter_ips, filter_ports):
    """Identify usage of cleartext protocols."""
    cleartext_found: dict[str, int] = {}
    for session in stats.cleartext_sessions:
        proto = session["protocol"]
        if filter_ips and session["src"] not in (filter_ips or []) and session["dst"] not in (filter_ips or []):
            continue
        if filter_ports and session["dport"] not in (filter_ports or []) and session["sport"] not in (filter_ports or []):
            continue
        cleartext_found[proto] = cleartext_found.get(proto, 0) + 1

    # Also check by port usage
    for port, proto_name in CLEARTEXT_PROTOCOLS.items():
        count = stats.dst_ports.get(port, 0) + stats.src_ports.get(port, 0)
        if count > 0:
            cleartext_found[proto_name] = cleartext_found.get(proto_name, 0) + count

    if cleartext_found:
        report.findings.append(Finding(
            title="Unencrypted Protocol Usage Detected",
            severity=Severity.HIGH,
            category="Encryption",
            description=f"{len(cleartext_found)} unencrypted (cleartext) protocol(s) detected in the traffic.",
            details=[f"{proto}: {count} packet(s)" for proto, count in sorted(cleartext_found.items(), key=lambda x: -x[1])],
            recommendation=(
                "Migrate to encrypted alternatives: HTTP → HTTPS, FTP → SFTP/SCP, Telnet → SSH, "
                "SMTP → SMTPS/STARTTLS, POP3 → POP3S, IMAP → IMAPS, LDAP → LDAPS, "
                "SNMP v1/v2 → SNMPv3, VNC → VNC over SSH tunnel."
            ),
        ))


def _check_credentials_in_traffic(stats: PacketStats, report: AnalysisReport, filter_ips):
    """Report any credentials found in cleartext traffic."""
    creds = stats.potential_credentials
    if filter_ips:
        creds = [c for c in creds if c["src"] in filter_ips or c["dst"] in filter_ips]

    if not creds:
        return

    # Group by type
    by_type: dict[str, list] = {}
    for cred in creds:
        by_type.setdefault(cred["type"], []).append(cred)

    for cred_type, items in by_type.items():
        severity = Severity.CRITICAL if "Password" in cred_type or "Auth" in cred_type else Severity.HIGH
        details = []
        for item in items[:5]:
            sanitized = item["matched_value"]
            # Partially redact the value for the report
            if len(sanitized) > 8:
                sanitized = sanitized[:4] + "****" + sanitized[-2:]
            details.append(f"{item['protocol']}: {item['src']} → {item['dst']} | {sanitized}")

        report.findings.append(Finding(
            title=f"Cleartext {cred_type} Detected",
            severity=severity,
            category="Credentials",
            description=f"{len(items)} instance(s) of '{cred_type}' found transmitted in cleartext.",
            details=details,
            recommendation="Credentials should never be transmitted in cleartext. Use encrypted protocols (TLS/SSL) for all authentication.",
        ))


def _check_sensitive_data(stats: PacketStats, report: AnalysisReport, filter_ips):
    """Report sensitive data patterns found in traffic."""
    patterns = stats.sensitive_patterns
    if filter_ips:
        patterns = [p for p in patterns if p["src"] in filter_ips or p["dst"] in filter_ips]

    if not patterns:
        return

    by_type: dict[str, list] = {}
    for pat in patterns:
        by_type.setdefault(pat["type"], []).append(pat)

    for pat_type, items in by_type.items():
        severity = Severity.CRITICAL if "Private key" in pat_type or "Credit card" in pat_type or "SSN" in pat_type else Severity.HIGH
        report.findings.append(Finding(
            title=f"Sensitive Data in Cleartext: {pat_type}",
            severity=severity,
            category="Data Exposure",
            description=f"{len(items)} instance(s) of '{pat_type}' found in unencrypted network traffic.",
            details=[f"{item['protocol']}: {item['src']} → {item['dst']}" for item in items[:5]],
            recommendation="Sensitive data must be encrypted in transit. Implement TLS for all connections carrying PII or credentials.",
        ))


def _check_unencrypted_email(stats: PacketStats, report: AnalysisReport):
    """Detect unencrypted email protocols."""
    smtp_count = stats.dst_ports.get(25, 0)
    pop3_count = stats.dst_ports.get(110, 0)
    imap_count = stats.dst_ports.get(143, 0)

    if smtp_count + pop3_count + imap_count > 0:
        details = []
        if smtp_count:
            details.append(f"SMTP (port 25): {smtp_count} packets — use SMTPS (465) or STARTTLS (587)")
        if pop3_count:
            details.append(f"POP3 (port 110): {pop3_count} packets — use POP3S (995)")
        if imap_count:
            details.append(f"IMAP (port 143): {imap_count} packets — use IMAPS (993)")

        report.findings.append(Finding(
            title="Unencrypted Email Traffic",
            severity=Severity.HIGH,
            category="Email Security",
            description="Email traffic is being transmitted without encryption, potentially exposing credentials and message content.",
            details=details,
            recommendation="Configure email clients and servers to use TLS-encrypted connections (SMTPS, POP3S, IMAPS).",
        ))


def _check_unencrypted_web(stats: PacketStats, report: AnalysisReport):
    """Detect HTTP traffic that should be HTTPS."""
    http_count = stats.dst_ports.get(80, 0) + stats.dst_ports.get(8080, 0)
    if http_count > 0:
        report.findings.append(Finding(
            title="Unencrypted HTTP Traffic",
            severity=Severity.MEDIUM,
            category="Web Security",
            description=f"{http_count} packets sent over unencrypted HTTP (ports 80/8080).",
            details=["HTTP traffic can be intercepted and modified by attackers on the network path."],
            recommendation="Enforce HTTPS across all web services. Use HSTS headers to prevent downgrade attacks.",
        ))


def _check_unencrypted_auth(stats: PacketStats, report: AnalysisReport):
    """Check for authentication protocols sent unencrypted."""
    ldap_count = stats.dst_ports.get(389, 0)
    if ldap_count > 0:
        report.findings.append(Finding(
            title="Unencrypted LDAP Traffic",
            severity=Severity.HIGH,
            category="Authentication Security",
            description=f"LDAP traffic on port 389 detected ({ldap_count} packets). LDAP binds may expose credentials.",
            details=["Use LDAPS (port 636) or LDAP with STARTTLS instead."],
            recommendation="Migrate all LDAP connections to LDAPS (port 636) to encrypt directory queries and authentication.",
        ))


def _check_dns_security(stats: PacketStats, report: AnalysisReport):
    """Check DNS for security concerns (unencrypted, possible tunneling)."""
    if stats.dns_packets > 0:
        # Check for unusually long DNS queries (possible tunneling)
        long_queries = [q for q in stats.dns_queries if len(q.get("query", "")) > 60]
        if long_queries:
            report.findings.append(Finding(
                title="Unusually Long DNS Queries — Possible DNS Tunneling",
                severity=Severity.HIGH,
                category="DNS Security",
                description=f"{len(long_queries)} DNS queries with unusually long domain names detected (>60 chars).",
                details=[f"Query: {q['query'][:80]}..." for q in long_queries[:5]],
                recommendation="Investigate for DNS tunneling/exfiltration. Consider implementing DNS query length monitoring and DNS-over-HTTPS/TLS.",
            ))

        # General DNS security note
        report.findings.append(Finding(
            title="DNS Traffic is Unencrypted",
            severity=Severity.LOW,
            category="DNS Security",
            description=f"{stats.dns_packets} DNS packets observed in cleartext.",
            details=["Standard DNS (port 53) transmits all queries and responses unencrypted, allowing eavesdropping on browsing activity."],
            recommendation="Consider implementing DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) for privacy.",
        ))


def _check_arp_spoofing(stats: PacketStats, report: AnalysisReport):
    """Check for ARP spoofing indicators."""
    ip_to_macs: dict[str, set] = {}
    for reply in stats.arp_replies:
        ip_to_macs.setdefault(reply["src_ip"], set()).add(reply["src_mac"])

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            report.findings.append(Finding(
                title=f"ARP Spoofing Indicator for {ip}",
                severity=Severity.CRITICAL,
                category="Man-in-the-Middle",
                description=f"IP {ip} is associated with {len(macs)} different MAC addresses, a strong ARP spoofing indicator.",
                details=[f"MAC: {mac}" for mac in macs],
                recommendation="Immediately investigate. Enable Dynamic ARP Inspection (DAI) and consider static ARP entries for critical hosts.",
            ))


def _check_telnet_usage(stats: PacketStats, report: AnalysisReport):
    """Flag Telnet usage."""
    telnet_count = stats.dst_ports.get(23, 0)
    if telnet_count > 0:
        report.findings.append(Finding(
            title="Telnet Usage Detected",
            severity=Severity.CRITICAL,
            category="Cleartext Protocols",
            description=f"Telnet traffic detected ({telnet_count} packets). All data including passwords is transmitted in cleartext.",
            details=["Telnet provides zero encryption. All keystrokes, including passwords, are visible to network eavesdroppers."],
            recommendation="Replace Telnet with SSH immediately. Disable Telnet on all network devices and servers.",
        ))


def _check_ftp_usage(stats: PacketStats, report: AnalysisReport):
    """Flag FTP usage."""
    ftp_count = stats.dst_ports.get(21, 0)
    if ftp_count > 0:
        report.findings.append(Finding(
            title="FTP Usage Detected",
            severity=Severity.HIGH,
            category="Cleartext Protocols",
            description=f"FTP traffic detected ({ftp_count} packets). Credentials and data are transmitted in cleartext.",
            details=["FTP transmits usernames, passwords, and all file data without encryption."],
            recommendation="Replace FTP with SFTP (SSH File Transfer) or SCP. If FTP is required, use FTPS (FTP over TLS).",
        ))


def _check_snmp_usage(stats: PacketStats, report: AnalysisReport):
    """Flag SNMP v1/v2 usage."""
    snmp_count = stats.dst_ports.get(161, 0)
    if snmp_count > 0:
        report.findings.append(Finding(
            title="SNMP Traffic Detected (Likely v1/v2c)",
            severity=Severity.MEDIUM,
            category="Cleartext Protocols",
            description=f"SNMP traffic on port 161 detected ({snmp_count} packets). SNMP v1/v2c sends community strings in cleartext.",
            details=["Community strings (effectively passwords) in SNMP v1/v2c are transmitted without encryption."],
            recommendation="Upgrade to SNMPv3 with authentication and encryption. Restrict SNMP access with ACLs.",
        ))


def _check_suspicious_ports(stats: PacketStats, report: AnalysisReport):
    """Detect traffic on commonly abused ports."""
    suspicious = {
        4444: "Metasploit default handler",
        1234: "Common reverse shell port",
        5555: "Android Debug Bridge",
        9001: "Common C2 port",
        31337: "Back Orifice / elite hacker port",
        12345: "NetBus trojan",
        6667: "IRC (commonly used for botnets)",
        6697: "IRC over TLS (botnet C2)",
    }

    found = []
    for port, desc in suspicious.items():
        count = stats.dst_ports.get(port, 0) + stats.src_ports.get(port, 0)
        if count > 0:
            found.append((port, desc, count))

    if found:
        report.findings.append(Finding(
            title="Traffic on Suspicious/Commonly Abused Ports",
            severity=Severity.MEDIUM,
            category="Anomaly Detection",
            description=f"Traffic detected on {len(found)} port(s) commonly associated with malicious tools.",
            details=[f"Port {port} ({desc}): {count} packets" for port, desc, count in found],
            recommendation="Investigate this traffic to determine if it is legitimate. Block unused suspicious ports at the firewall.",
        ))


def _generate_security_summary(stats: PacketStats, report: AnalysisReport) -> str:
    """Generate a natural-language summary for the security audit."""
    counts = report.count_by_severity()
    total_findings = sum(counts.values())

    lines = []
    lines.append(f"Security audit of {stats.total_packets:,} packets ({stats.total_bytes:,} bytes) over {stats.duration_seconds:.1f}s.")

    # Count cleartext vs encrypted protocols
    encrypted_ports = {443, 465, 587, 636, 993, 995, 8443, 22}
    encrypted_pkts = sum(stats.dst_ports.get(p, 0) for p in encrypted_ports)
    cleartext_pkts = sum(stats.dst_ports.get(p, 0) for p in CLEARTEXT_PROTOCOLS)

    if cleartext_pkts + encrypted_pkts > 0:
        enc_pct = encrypted_pkts / (cleartext_pkts + encrypted_pkts) * 100
        lines.append(f"Encryption coverage: {enc_pct:.0f}% of classified traffic uses encrypted protocols.")

    if total_findings == 0:
        lines.append("No security concerns identified.")
    else:
        parts = []
        if counts.get("CRITICAL", 0):
            parts.append(f"{counts['CRITICAL']} CRITICAL")
        if counts.get("HIGH", 0):
            parts.append(f"{counts['HIGH']} HIGH")
        if counts.get("MEDIUM", 0):
            parts.append(f"{counts['MEDIUM']} MEDIUM")
        if counts.get("LOW", 0):
            parts.append(f"{counts['LOW']} LOW")
        lines.append(f"Found {total_findings} security finding(s): {', '.join(parts)}.")

    if stats.potential_credentials:
        lines.append(f"WARNING: {len(stats.potential_credentials)} credential(s) detected in cleartext traffic.")

    return "\n".join(lines)
