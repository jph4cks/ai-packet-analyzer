# AI Packet Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/version-1.0.0-orange" alt="Version 1.0.0">
</p>

**AI Packet Analyzer** is an intelligent, interactive command-line tool that analyzes network packet captures (`.pcap` / `.pcapng` files) using heuristic AI to provide actionable insights for **connectivity troubleshooting** and **security auditing**.

Instead of manually sifting through thousands of packets in Wireshark, point this tool at a capture file and get a prioritized, severity-ranked report with clear explanations and recommendations — in seconds.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [Interactive Mode](#interactive-mode)
  - [Connectivity Troubleshooting](#connectivity-troubleshooting)
  - [Security Audit](#security-audit)
  - [Filtering by IP or Port](#filtering-by-ip-or-port)
  - [Saving Reports](#saving-reports)
- [How It Works](#how-it-works)
  - [Packet Parsing Engine](#packet-parsing-engine)
  - [AI Analysis Engine](#ai-analysis-engine)
  - [Connectivity Checks](#connectivity-checks)
  - [Security Checks](#security-checks)
- [Example Output](#example-output)
- [CLI Reference](#cli-reference)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Connectivity Troubleshooting
- **TCP Handshake Failure Detection** — Identifies connections that never completed the 3-way handshake (SYN → SYN-ACK → ACK)
- **TCP Reset Analysis** — Detects elevated RST rates indicating refused connections or firewall interference
- **Retransmission Detection** — Finds packet loss and network congestion indicators
- **DNS Failure Analysis** — Identifies NXDOMAIN, SERVFAIL, and REFUSED responses with affected domains
- **ICMP Unreachable Tracking** — Detects Host Unreachable, Network Unreachable, Port Unreachable, and other ICMP error messages
- **Ping Loss Calculation** — Measures ICMP echo request/reply ratios
- **ARP Issue Detection** — Finds unanswered ARP requests (offline hosts) and potential ARP spoofing
- **Traffic Black Holes** — Identifies destinations receiving packets but never responding
- **One-Way Traffic Detection** — Spots asymmetric routing or firewall issues
- **Port Scan Detection** — Alerts when a host connects to an unusually large number of ports
- **Smart Context Narrowing** — When multiple issues are found, prompts for problem description, IPs, and ports to focus the analysis

### Security Audit
- **Cleartext Protocol Detection** — Flags use of HTTP, FTP, Telnet, SMTP, POP3, IMAP, LDAP, SNMP, VNC, and other unencrypted protocols
- **Credential Extraction** — Finds passwords, usernames, API keys, tokens, session IDs, and cookies transmitted in cleartext
- **HTTP Basic Auth Detection** — Identifies Base64-encoded credentials in HTTP Authorization headers
- **Sensitive Data Scanning** — Detects SSN patterns, credit card numbers, email addresses, private keys, and certificates in payloads
- **Email Security** — Flags unencrypted SMTP/POP3/IMAP traffic with specific migration recommendations
- **DNS Security** — Detects possible DNS tunneling (unusually long queries) and unencrypted DNS traffic
- **ARP Spoofing Detection** — Identifies multiple MACs claiming the same IP address
- **Suspicious Port Detection** — Flags traffic on ports commonly associated with malware/C2 (4444, 31337, etc.)
- **Encryption Coverage Metric** — Calculates the percentage of traffic using encrypted vs. cleartext protocols

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface (cli.py)                    │
│         Interactive menus • Argument parsing • I/O           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Packet Parser (packet_parser.py)             │
│   Scapy-based engine • Protocol dissection • Stats extraction │
│   TCP/UDP/ICMP/ARP/DNS analysis • Credential pattern matching │
└──────────────────────────┬──────────────────────────────────┘
                           │  PacketStats
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   AI Engine (ai_engine.py)                    │
│  Heuristic analysis • Connectivity checks • Security checks  │
│  Severity classification • Recommendation generation         │
└──────────────────────────┬──────────────────────────────────┘
                           │  AnalysisReport
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               Report Renderer (report_renderer.py)           │
│     Rich-powered console output • Panels • Tables • Colors   │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- `tshark` (optional, for pcapng support) — `sudo apt install tshark`

### Install with pip (recommended — works on Windows, macOS, Linux)

```bash
pip install git+https://github.com/jph4cks/ai-packet-analyzer.git
```

### Install from source

```bash
# Clone the repository
git clone https://github.com/jph4cks/ai-packet-analyzer.git
cd ai-packet-analyzer

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install .

# Or install in development mode
pip install -e .
```

### Build standalone binary (any platform)

```bash
# Linux / macOS
chmod +x build.sh && ./build.sh

# Windows (PowerShell)
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --name ai-packet-analyzer --paths src `
  --hidden-import ai_packet_analyzer --hidden-import scapy.all `
  --hidden-import rich --clean build_entry.py
```

The output binary will be in the `dist/` folder — a single file, no Python installation required.

### CI/CD Builds (all platforms)

The repository includes a **GitHub Actions workflow** that automatically builds standalone binaries for Linux, Windows, and macOS. Fork the repo and push a version tag (`v*`) to generate all three binaries as release artifacts.

### Install dependencies only

```bash
pip install scapy pyshark rich
```

---

## Quick Start

```bash
# Interactive mode — the tool will ask what type of analysis you want
ai-packet-analyzer capture.pcap

# Or run directly with Python
python -m ai_packet_analyzer.cli capture.pcap

# Quick connectivity troubleshooting
ai-packet-analyzer capture.pcap --mode troubleshoot

# Quick security audit
ai-packet-analyzer capture.pcap --mode security
```

---

## Usage Guide

### Interactive Mode

When you run the tool without specifying a mode, it enters interactive mode:

```
$ ai-packet-analyzer network_capture.pcap

    _    ___   ____            _        _
   / \  |_ _| |  _ \ __ _  ___| | _____| |_
  ...

  Parsing network_capture.pcap...
  Loaded 15,482 packets (12,345,678 bytes, 342.50s)

  What type of analysis would you like to perform?

    [1] Connectivity Troubleshooting
        Diagnose network connectivity issues: failed connections,
        DNS errors, packet loss, routing problems, and more.

    [2] Security Audit
        Find unencrypted traffic, exposed credentials, cleartext
        protocols, and sensitive data in network traffic.

  Select mode [1/2] (1):
```

If the connectivity troubleshooting mode detects multiple issues, it prompts you to optionally narrow the analysis:

```
  Multiple issues detected (8 findings).
  To get a more focused analysis, you can provide additional context.

  Would you like to narrow down the analysis? [Y/n]:
  Describe the problem you're experiencing: Users can't reach the web server
  Enter IP address(es) involved (comma-separated): 192.168.1.10, 10.0.0.1
  Enter port(s) involved (comma-separated): 80, 443
```

### Connectivity Troubleshooting

Run directly from the command line:

```bash
# Basic troubleshooting
ai-packet-analyzer capture.pcap --mode troubleshoot

# With verbose statistics
ai-packet-analyzer capture.pcap --mode troubleshoot --verbose

# Focused on specific IPs and ports
ai-packet-analyzer capture.pcap --mode troubleshoot \
  --ip 192.168.1.10 --ip 10.0.0.1 \
  --port 80 --port 443

# With problem description
ai-packet-analyzer capture.pcap --mode troubleshoot \
  --description "Web server intermittently unreachable from client subnet"
```

### Security Audit

```bash
# Full security audit
ai-packet-analyzer capture.pcap --mode security

# Verbose with detailed statistics
ai-packet-analyzer capture.pcap --mode security --verbose

# Focus on a specific server
ai-packet-analyzer capture.pcap --mode security --ip 10.0.0.25

# Focus on email traffic
ai-packet-analyzer capture.pcap --mode security --port 25 --port 110 --port 143
```

### Filtering by IP or Port

You can combine `--ip` and `--port` flags to narrow the analysis scope:

```bash
# Analyze traffic involving a specific host
ai-packet-analyzer capture.pcap --mode troubleshoot --ip 192.168.1.100

# Multiple IPs
ai-packet-analyzer capture.pcap --mode security --ip 10.0.0.1 --ip 10.0.0.2

# Specific ports
ai-packet-analyzer capture.pcap --mode security --port 21 --port 23 --port 80

# Combined
ai-packet-analyzer capture.pcap --mode troubleshoot --ip 10.0.0.5 --port 443
```

### Saving Reports

Save the report to a text file:

```bash
ai-packet-analyzer capture.pcap --mode security --verbose --output report.txt
```

---

## How It Works

### Packet Parsing Engine

The **Packet Parser** (`packet_parser.py`) uses [Scapy](https://scapy.net/) to dissect every packet in the capture file and extract structured metadata:

| Layer | What's Extracted |
|-------|-----------------|
| **Ethernet/ARP** | ARP requests/replies, MAC addresses, IP-to-MAC mappings |
| **IP** | Source/destination IPs, conversation tracking, byte counts |
| **TCP** | Flags (SYN/ACK/RST/FIN), port numbers, sequence tracking, retransmission detection, stream reconstruction |
| **UDP** | Port numbers, protocol identification |
| **DNS** | Query names, types, response codes (NXDOMAIN, SERVFAIL, etc.), answer records |
| **ICMP** | Type/code classification, unreachable messages, echo request/reply tracking |
| **Payload** | Cleartext protocol content extraction, regex-based credential and sensitive data detection |

**Credential detection** uses 13+ regex patterns to identify:
- FTP/POP3 `USER` and `PASS` commands
- HTTP `Authorization: Basic` and `Bearer` headers
- Passwords, API keys, tokens, secrets in form data
- Session IDs and cookies
- SMTP AUTH commands

**Sensitive data detection** scans for:
- Social Security Number patterns
- Credit card number patterns
- Email addresses
- Private keys and certificates

### AI Analysis Engine

The **AI Engine** (`ai_engine.py`) applies heuristic intelligence to the parsed data, running 20+ specialized checks that evaluate the data against thresholds, correlate multiple signals, and generate prioritized findings.

Each finding includes:
- **Severity** — CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **Title** — Clear, descriptive name
- **Description** — What was detected and why it matters
- **Details** — Supporting data points (counts, IPs, ports, etc.)
- **Recommendation** — Specific, actionable steps to resolve the issue

### Connectivity Checks

| Check | What It Detects | Severity |
|-------|----------------|----------|
| TCP Handshake Failures | SYN sent without SYN-ACK completion | HIGH-CRITICAL |
| TCP Reset Rate | Elevated RST packets / connection rejections | MEDIUM-HIGH |
| TCP Retransmissions | Packet loss / network congestion | MEDIUM-HIGH |
| DNS NXDOMAIN | Non-existent domain resolution failures | MEDIUM-HIGH |
| DNS SERVFAIL | DNS server internal errors | HIGH |
| DNS REFUSED | DNS query access denied | MEDIUM |
| ICMP Unreachable | Host/Network/Port Unreachable messages | MEDIUM-HIGH |
| ICMP Packet Loss | Ping requests without replies | MEDIUM-HIGH |
| ARP Unanswered | Hosts not responding to ARP (offline/wrong VLAN) | MEDIUM-HIGH |
| ARP Spoofing | Multiple MACs claiming same IP | CRITICAL |
| Traffic Black Holes | Destinations with no return traffic | HIGH |
| One-Way Traffic | Asymmetric routing indicators | MEDIUM |
| Network Congestion | Combined retransmissions + resets | MEDIUM |
| Port Scan Patterns | Single host connecting to many ports | INFO |

### Security Checks

| Check | What It Detects | Severity |
|-------|----------------|----------|
| Cleartext Protocols | HTTP, FTP, Telnet, SMTP, POP3, IMAP, LDAP, SNMP, VNC | HIGH |
| Cleartext Credentials | Passwords, usernames, auth tokens in plaintext | CRITICAL-HIGH |
| Sensitive Data Exposure | SSNs, credit cards, emails, private keys | CRITICAL-HIGH |
| Unencrypted Email | SMTP/POP3/IMAP without TLS | HIGH |
| Unencrypted HTTP | Web traffic on port 80/8080 | MEDIUM |
| Unencrypted LDAP | Directory queries on port 389 | HIGH |
| DNS Tunneling | Unusually long DNS query names (>60 chars) | HIGH |
| Unencrypted DNS | Standard DNS on port 53 | LOW |
| ARP Spoofing | Multiple MAC addresses per IP | CRITICAL |
| Telnet Usage | Any traffic on port 23 | CRITICAL |
| FTP Usage | Any traffic on port 21 | HIGH |
| SNMP v1/v2c Usage | Community strings in cleartext | MEDIUM |
| Suspicious Ports | Traffic on known C2/malware ports (4444, 31337, etc.) | MEDIUM |

---

## Example Output

### Security Audit

```
╔══════════════════════════════════════════════════════════════╗
║ AI Packet Analyzer — SECURITY AUDIT                         ║
╚══════════════════════════════════════════════════════════════╝

╭────────────────────────── Summary ───────────────────────────╮
│ Security audit of 60 packets (26,866 bytes) over 9.2s.      │
│ Encryption coverage: 0% of classified traffic uses           │
│ encrypted protocols.                                         │
│ Found 6 security finding(s): 1 CRITICAL, 4 HIGH, 1 LOW.     │
│ WARNING: 6 credential(s) detected in cleartext traffic.      │
╰──────────────────────────────────────────────────────────────╯

╭── [!!!] CRITICAL — Cleartext SMTP Auth Detected ─────────────╮
│ Description: 2 instance(s) of 'SMTP Auth' found transmitted  │
│ in cleartext.                                                 │
│ Category: Credentials                                         │
│                                                               │
│ Details:                                                      │
│   • SMTP: 74.53.140.153 → 10.10.1.4 | AUTH****IN             │
│                                                               │
│ Recommendation: Credentials should never be transmitted in    │
│ cleartext. Use encrypted protocols (TLS/SSL) for all          │
│ authentication.                                               │
╰───────────────────────────────────────────────────────────────╯
```

---

## CLI Reference

```
usage: ai-packet-analyzer [-h] [--mode {troubleshoot,security,interactive}]
                          [--ip IP] [--port PORT] [--description DESCRIPTION]
                          [--verbose] [--max-packets MAX_PACKETS]
                          [--output OUTPUT]
                          [pcap_file]

AI Packet Analyzer — AI-powered pcap analysis

positional arguments:
  pcap_file             Path to the pcap/pcapng file to analyze

options:
  -h, --help            Show this help message and exit
  --mode, -m            Analysis mode: troubleshoot, security, or interactive
  --ip IP               Filter to specific IP address(es) (repeatable)
  --port PORT           Filter to specific port(s) (repeatable)
  --description, -d     Problem description for troubleshooting
  --verbose, -v         Show detailed statistics in the report
  --max-packets N       Maximum number of packets to analyze
  --output, -o FILE     Save report output to a text file
```

---

## Project Structure

```
ai-packet-analyzer/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── requirements.txt                   # Python dependencies
├── setup.py                           # Package configuration
├── pyproject.toml                     # Modern Python packaging config
├── build.sh                           # Build script for standalone binary
├── build_entry.py                     # PyInstaller entry point
├── ai-packet-analyzer.spec            # PyInstaller spec file
├── .github/
│   └── workflows/
│       └── build-release.yml          # CI/CD: builds Linux/Win/Mac binaries
├── src/
│   └── ai_packet_analyzer/
│       ├── __init__.py                # Package init + version
│       ├── cli.py                     # Interactive CLI interface
│       ├── packet_parser.py           # Scapy-based packet parsing engine
│       ├── ai_engine.py               # Heuristic AI analysis engine
│       └── report_renderer.py         # Rich-powered report rendering
└── tests/
    └── pcaps/                         # Sample pcap files for testing
        ├── synthetic_test.pcap        # Synthetic test with various protocols
        ├── dns.cap                    # Real DNS traffic sample
        ├── smtp.pcap                  # Real SMTP traffic sample
        └── telnet-cooked.pcap         # Real Telnet traffic sample
```

---

## Testing

Run the tool against the included sample captures:

```bash
# Test connectivity troubleshooting
python -m ai_packet_analyzer.cli tests/pcaps/synthetic_test.pcap --mode troubleshoot --verbose

# Test security audit
python -m ai_packet_analyzer.cli tests/pcaps/synthetic_test.pcap --mode security --verbose

# Test with real DNS traffic
python -m ai_packet_analyzer.cli tests/pcaps/dns.cap --mode troubleshoot

# Test with real SMTP traffic
python -m ai_packet_analyzer.cli tests/pcaps/smtp.pcap --mode security

# Test with real Telnet traffic
python -m ai_packet_analyzer.cli tests/pcaps/telnet-cooked.pcap --mode security
```

To create your own test captures, use `tcpdump`:

```bash
# Capture all traffic on eth0 for 60 seconds
sudo tcpdump -i eth0 -w test_capture.pcap -c 10000

# Then analyze it
ai-packet-analyzer test_capture.pcap
```

---

## Contributing

Contributions are welcome! Here are some areas where you can help:

1. **New protocol parsers** — Add support for additional protocols (e.g., MQTT, CoAP, gRPC)
2. **New security checks** — Add detection for additional attack patterns
3. **Machine learning integration** — Replace heuristics with trained models for anomaly detection
4. **Output formats** — Add JSON, CSV, or HTML report output
5. **Real-time capture** — Add live capture mode with real-time analysis
6. **PCAPNG support** — Enhanced pcapng features (comments, interface metadata)

### Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/ai-packet-analyzer.git
cd ai-packet-analyzer
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for authorized network analysis and security auditing only. Always ensure you have proper authorization before analyzing network traffic. The credential detection features are designed to help identify security weaknesses — never use this tool to intercept or access unauthorized communications.
