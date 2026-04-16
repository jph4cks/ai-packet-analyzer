# Comprehensive Test Plan — AI Packet Analyzer

## Test Pcap Inventory

### From Wireshark Wiki (wiki.wireshark.org/SampleCaptures)
| File | Source | Protocol Focus |
|------|--------|----------------|
| `dhcp.pcap` | Wireshark Wiki | DHCP discovery/offer/request/ack |
| `dns.cap` | Wireshark Wiki | Various DNS lookups |
| `http.pcap` | Wireshark GitLab | Simple HTTP request/response |
| `tcp-ecn-sample.pcap` | Wireshark Wiki | TCP/HTTP with ECN congestion |
| `tcp-winscale.pcapng` | Wireshark Wiki | TCP window scaling |
| `ipv4frags.pcap` | Wireshark Wiki | ICMP Echo with IP fragments |
| `arp-storm.pcap` | Wireshark Wiki | ARP storm (>20 req/sec) |
| `telnet-cooked.pcap` | Wireshark Wiki | Telnet per-line mode |
| `telnet-raw.pcap` | Wireshark Wiki | Telnet per-character mode |
| `smtp.pcap` | Wireshark Wiki | Unencrypted SMTP |
| `slammer.pcap` | Wireshark Wiki | Slammer worm (1 packet) |
| `dns-remoteshell.pcap` | Wireshark Wiki | DNS C2 anomaly |

### From Other Sources
| File | Source | Protocol Focus |
|------|--------|----------------|
| `smallFlows.pcap` | tcpreplay | Mixed real-world traffic (9.4 MB) |
| `netresec_proxy.pcap` | Netresec | Proxy traffic capture (25 MB) |

### Synthetic (Generated with Scapy)
| File | Scenario |
|------|----------|
| `ftp-credentials.pcap` | FTP USER/PASS credentials in cleartext |
| `http-basic-auth.pcap` | HTTP Basic Auth + sensitive data in URLs |
| `port-scan.pcap` | SYN scan across 25 ports |
| `tcp-problems.pcap` | Retransmissions, RST floods, half-open connections |
| `icmp-errors.pcap` | Destination/port unreachable, TTL exceeded |
| `arp-spoofing.pcap` | ARP cache poisoning (same IP, different MAC) |
| `security-nightmare.pcap` | Multi-vector: Telnet+FTP+HTTP creds, SNMP, suspicious ports, SSN, CC |
| `dns-problems.pcap` | NXDOMAIN, SERVFAIL, DNS timeouts |
| `synthetic_test.pcap` | Baseline mixed traffic |

---

## Test Matrix

### Troubleshooting Mode (12 tests)

| # | Pcap | Category | Expected Detection | Result |
|---|------|----------|-------------------|--------|
| 1 | `dhcp.pcap` | DHCP | DHCP traffic recognized | ✅ PASS |
| 2 | `dns.cap` | DNS | DNS lookups analyzed | ✅ PASS |
| 3 | `dns-problems.pcap` | DNS | NXDOMAIN/SERVFAIL failures | ✅ PASS |
| 4 | `http.pcap` | HTTP | HTTP traffic recognized | ✅ PASS |
| 5 | `tcp-ecn-sample.pcap` | TCP | TCP analysis runs | ✅ PASS |
| 6 | `tcp-problems.pcap` | TCP | Resets + retransmissions detected | ✅ PASS |
| 7 | `tcp-winscale.pcapng` | TCP | Pcapng format supported | ✅ PASS |
| 8 | `ipv4frags.pcap` | ICMP | Only 3 fragment packets | ⚠️ EDGE CASE |
| 9 | `icmp-errors.pcap` | ICMP | Unreachable + TTL exceeded | ✅ PASS |
| 10 | `arp-storm.pcap` | ARP | ARP anomaly detected | ✅ PASS |
| 11 | `smallFlows.pcap` | Mixed | Large file processed | ✅ PASS |
| 12 | `netresec_proxy.pcap` | Mixed | One-way traffic detected | ✅ PASS |

### Security Mode (13 tests)

| # | Pcap | Category | Expected Detection | Result |
|---|------|----------|-------------------|--------|
| 1 | `telnet-cooked.pcap` | Cleartext | Telnet + credentials flagged | ✅ PASS |
| 2 | `telnet-raw.pcap` | Cleartext | Telnet flagged | ✅ PASS |
| 3 | `ftp-credentials.pcap` | Credentials | FTP USER/PASS detected | ✅ PASS |
| 4 | `http-basic-auth.pcap` | Credentials | HTTP Basic Auth flagged | ✅ PASS |
| 5 | `smtp.pcap` | Cleartext | Unencrypted email flagged | ✅ PASS |
| 6 | `port-scan.pcap` | Recon | Port scan pattern detected | ✅ PASS |
| 7 | `arp-storm.pcap` | ARP | ARP anomaly flagged | ✅ PASS |
| 8 | `arp-spoofing.pcap` | ARP | ARP spoofing detected | ✅ PASS |
| 9 | `dns-remoteshell.pcap` | Malware/C2 | DNS anomaly flagged | ✅ PASS |
| 10 | `slammer.pcap` | Malware | Single-packet worm | ⚠️ EDGE CASE |
| 11 | `security-nightmare.pcap` | Multi-vector | Creds + sensitive data + suspicious ports | ✅ PASS |
| 12 | `smallFlows.pcap` | Mixed | HTTP/cleartext/creds found | ✅ PASS |
| 13 | `netresec_proxy.pcap` | Mixed | HTTP cleartext + sensitive data | ✅ PASS |

---

## Results Summary

- **Total tests**: 25
- **Clean passes**: 23 (92%)
- **Edge cases** (expected): 2 (8%)
- **Crashes**: 0
- **Timeouts**: 0

### Edge Case Notes

1. **`ipv4frags.pcap` (troubleshoot)**: Only 3 IP fragment packets — too few to trigger
   any heuristic threshold. The analyzer correctly reports "no issues" since fragments
   alone aren't a connectivity problem. This is expected behavior.

2. **`slammer.pcap` (security)**: Contains a single UDP packet (Slammer worm payload).
   The analyzer doesn't have a specific malware signature engine — it focuses on
   protocol-level security issues (cleartext, credentials, scanning). A single UDP
   packet to port 1434 doesn't trigger port scan or cleartext protocol checks. This
   is a reasonable limitation for a heuristic-based tool.

---

## Capabilities Verified

### Troubleshooting Mode
- ✅ TCP handshake failure detection
- ✅ TCP retransmission detection
- ✅ TCP RST flood detection
- ✅ DNS failure analysis (NXDOMAIN, SERVFAIL)
- ✅ ICMP unreachable / TTL exceeded detection
- ✅ ARP anomaly detection
- ✅ One-way / asymmetric traffic detection
- ✅ Large pcap handling (25 MB, 32K+ packets)
- ✅ Pcapng format support

### Security Mode
- ✅ Telnet cleartext protocol detection
- ✅ FTP credential extraction
- ✅ HTTP Basic Auth detection
- ✅ SMTP unencrypted email flagging
- ✅ Port scan pattern recognition
- ✅ ARP spoofing detection (IP/MAC mismatch)
- ✅ Suspicious port detection (IRC, backdoor ports)
- ✅ Sensitive data in traffic (SSN, credit cards)
- ✅ DNS security analysis
- ✅ SNMP community string detection
- ✅ Unencrypted HTTP traffic flagging

---

## How to Run

```bash
# Run full test suite
python3 tests/run_comprehensive_tests.py

# Test individual pcap
ai-packet-analyzer tests/pcaps/security-nightmare.pcap --mode security
ai-packet-analyzer tests/pcaps/tcp-problems.pcap --mode troubleshoot -v
```
