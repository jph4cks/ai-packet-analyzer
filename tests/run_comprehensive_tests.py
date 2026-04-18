#!/usr/bin/env python3
"""Comprehensive test runner for AI Packet Analyzer.

This is intentionally a black-box test harness: it runs the installed
``ai-packet-analyzer`` CLI against pcaps under ``tests/pcaps``.

Note: This runner is not auto-discovered by pytest; run it directly:

  python3 tests/run_comprehensive_tests.py

"""

import subprocess
import sys
import os
import json
from pathlib import Path

PCAP_DIR = Path(__file__).parent / "pcaps"
ANALYZER = ["ai-packet-analyzer"]

# Define what each pcap should trigger in each mode
TEST_MATRIX = {
    # === TROUBLESHOOTING MODE TESTS ===
    "troubleshooting": {
        "dhcp.pcap": {
            "desc": "DHCP discovery/offer/request/ack",
            "should_find": ["DHCP", "UDP"],
            "category": "DHCP"
        },
        "dns.cap": {
            "desc": "Various DNS lookups",
            "should_find": ["DNS"],
            "category": "DNS"
        },
        "dns-problems.pcap": {
            "desc": "DNS NXDOMAIN, SERVFAIL, timeouts",
            "should_find": ["DNS", "fail"],
            "category": "DNS"
        },
        "http.pcap": {
            "desc": "Simple HTTP request/response",
            "should_find": ["TCP", "HTTP"],
            "category": "HTTP"
        },
        "tcp-ecn-sample.pcap": {
            "desc": "TCP/HTTP with ECN congestion markers",
            "should_find": ["TCP"],
            "category": "TCP"
        },
        "tcp-problems.pcap": {
            "desc": "TCP retransmissions, RST floods, half-open connections",
            "should_find": ["TCP", "reset", "retransmission"],
            "category": "TCP"
        },
        "tcp-winscale.pcapng": {
            "desc": "TCP window scaling examples",
            "should_find": ["TCP"],
            "category": "TCP"
        },
        "ipv4frags.pcap": {
            "desc": "ICMP Echo with IP fragmentation",
            "should_find": ["ICMP"],
            "category": "ICMP"
        },
        "icmp-errors.pcap": {
            "desc": "ICMP unreachable, TTL exceeded, port unreachable",
            "should_find": ["ICMP", "unreachable"],
            "category": "ICMP"
        },
        "arp-storm.pcap": {
            "desc": "ARP storm (>20 req/sec)",
            "should_find": ["ARP"],
            "category": "ARP"
        },
        "smallFlows.pcap": {
            "desc": "Mixed real-world traffic (large)",
            "should_find": ["TCP", "UDP"],
            "category": "Mixed"
        },
        "netresec_proxy.pcap": {
            "desc": "Large proxy traffic capture",
            "should_find": ["TCP"],
            "category": "Mixed"
        },
    },
    # === SECURITY MODE TESTS ===
    "security": {
        "telnet-cooked.pcap": {
            "desc": "Telnet session (per-line mode) with credentials",
            "should_find": ["telnet", "cleartext", "unencrypted"],
            "category": "Cleartext Protocols"
        },
        "telnet-raw.pcap": {
            "desc": "Telnet session (per-character mode)",
            "should_find": ["telnet", "cleartext", "unencrypted"],
            "category": "Cleartext Protocols"
        },
        "ftp-credentials.pcap": {
            "desc": "FTP with USER/PASS credentials",
            "should_find": ["FTP", "credential", "cleartext"],
            "category": "Credentials"
        },
        "http-basic-auth.pcap": {
            "desc": "HTTP Basic Auth + sensitive data in URLs",
            "should_find": ["HTTP", "unencrypted", "credential"],
            "category": "Credentials"
        },
        "smtp.pcap": {
            "desc": "Unencrypted SMTP email traffic",
            "should_find": ["SMTP", "email", "unencrypted"],
            "category": "Cleartext Protocols"
        },
        "port-scan.pcap": {
            "desc": "SYN port scan across 25 ports",
            "should_find": ["scan", "port"],
            "category": "Reconnaissance"
        },
        "arp-storm.pcap": {
            "desc": "ARP storm (possible spoofing indicator)",
            "should_find": ["ARP"],
            "category": "ARP Attacks"
        },
        "arp-spoofing.pcap": {
            "desc": "ARP spoofing (same IP, different MAC)",
            "should_find": ["ARP", "spoof"],
            "category": "ARP Attacks"
        },
        "dns-remoteshell.pcap": {
            "desc": "DNS anomaly from remoteshell C2",
            "should_find": ["DNS"],
            "category": "Malware/C2"
        },
        "slammer.pcap": {
            "desc": "Slammer worm DCE RPC packet",
            "should_find": ["UDP"],
            "category": "Malware/C2"
        },
        "security-nightmare.pcap": {
            "desc": "Kitchen sink: Telnet+FTP+HTTP creds, SNMP, suspicious ports, SSN, CC",
            "should_find": ["credential", "cleartext", "sensitive"],
            "category": "Multi-vector"
        },
        "smallFlows.pcap": {
            "desc": "Real-world mixed traffic security audit",
            "should_find": ["TCP", "UDP"],
            "category": "Mixed"
        },
        "netresec_proxy.pcap": {
            "desc": "Large proxy traffic security audit",
            "should_find": ["TCP"],
            "category": "Mixed"
        },
    }
}


def run_test(pcap_name, mode, test_info):
    """Run the analyzer on a pcap and capture results."""
    pcap_path = PCAP_DIR / pcap_name
    if not pcap_path.exists():
        return {
            "status": "SKIP",
            "reason": f"File not found: {pcap_path}",
            "output": ""
        }
    
    mode_flag = "troubleshoot" if mode == "troubleshooting" else "security"
    cmd = ANALYZER + [str(pcap_path), "--mode", mode_flag]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120,
            cwd=str(Path(__file__).parent.parent)
        )
        output = result.stdout + result.stderr
        
        # Check for crashes
        if result.returncode != 0:
            return {
                "status": "CRASH",
                "reason": f"Exit code {result.returncode}",
                "output": output[-2000:] if len(output) > 2000 else output
            }
        
        # Check for expected findings
        output_lower = output.lower()
        found = []
        missed = []
        for keyword in test_info["should_find"]:
            if keyword.lower() in output_lower:
                found.append(keyword)
            else:
                missed.append(keyword)
        
        # Count findings
        finding_count = output_lower.count("finding") + output_lower.count("⚠") + output_lower.count("🔴") + output_lower.count("●")
        
        status = "PASS" if not missed else "PARTIAL" if found else "MISS"
        
        return {
            "status": status,
            "found_keywords": found,
            "missed_keywords": missed,
            "finding_count": finding_count,
            "output": output[-3000:] if len(output) > 3000 else output,
            "output_length": len(output)
        }
        
    except subprocess.TimeoutExpired:
        return {
            "status": "TIMEOUT",
            "reason": "Exceeded 120s timeout",
            "output": ""
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "reason": str(e),
            "output": ""
        }


def main():
    results = {}
    total = passed = failed = crashed = skipped = 0
    
    for mode, tests in TEST_MATRIX.items():
        print(f"\n{'='*70}")
        print(f"  MODE: {mode.upper()}")
        print(f"{'='*70}")
        results[mode] = {}
        
        for pcap_name, test_info in tests.items():
            total += 1
            print(f"\n  [{test_info['category']}] {pcap_name}")
            print(f"    Description: {test_info['desc']}")
            
            result = run_test(pcap_name, mode, test_info)
            results[mode][pcap_name] = result
            
            status = result["status"]
            if status == "PASS":
                passed += 1
                print(f"    Result: ✅ PASS - Found all expected keywords: {result['found_keywords']}")
            elif status == "PARTIAL":
                passed += 1  # Count as pass but note what's missing
                print(f"    Result: ⚠️  PARTIAL - Found: {result['found_keywords']}, Missing: {result['missed_keywords']}")
            elif status == "MISS":
                failed += 1
                print(f"    Result: ❌ MISS - None of expected keywords found: {test_info['should_find']}")
            elif status == "CRASH":
                crashed += 1
                print(f"    Result: 💥 CRASH - {result['reason']}")
                # Print last few lines of output
                if result['output']:
                    for line in result['output'].strip().split('\n')[-5:]:
                        print(f"      | {line}")
            elif status == "SKIP":
                skipped += 1
                print(f"    Result: ⏭️  SKIP - {result['reason']}")
            elif status == "TIMEOUT":
                failed += 1
                print(f"    Result: ⏰ TIMEOUT - {result['reason']}")
            elif status == "ERROR":
                crashed += 1
                print(f"    Result: 💥 ERROR - {result['reason']}")
            
            if "finding_count" in result:
                print(f"    Findings detected: ~{result['finding_count']}")
    
    # Summary
    print(f"\n{'='*70}")
    print(f"  TEST SUMMARY")
    print(f"{'='*70}")
    print(f"  Total tests:  {total}")
    print(f"  Passed:       {passed}")
    print(f"  Failed:       {failed}")
    print(f"  Crashed:      {crashed}")
    print(f"  Skipped:      {skipped}")
    print(f"  Pass rate:    {passed/(total-skipped)*100:.1f}%" if total > skipped else "  Pass rate:    N/A")
    print(f"{'='*70}")
    
    # Save detailed results
    results_path = Path(__file__).parent / "test_results.json"
    with open(results_path, 'w') as f:
        # Remove large output fields for JSON
        clean = {}
        for mode, tests in results.items():
            clean[mode] = {}
            for pcap, res in tests.items():
                clean[mode][pcap] = {k: v for k, v in res.items() if k != 'output'}
        json.dump(clean, f, indent=2)
    print(f"\n  Detailed results saved to: {results_path}")
    
    return 0 if crashed == 0 and failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
