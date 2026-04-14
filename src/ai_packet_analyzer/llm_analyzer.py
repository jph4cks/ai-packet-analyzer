"""
LLM-Enhanced Analysis Module.

Takes the structured output from the heuristic AI engine and sends it to an LLM
for deeper contextual analysis, correlation of findings, root cause identification,
attack chain analysis, and executive-level summarization.
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field

from .ai_engine import AnalysisReport, Finding, Severity
from .packet_parser import PacketStats
from .llm_providers import LLMConfig, LLMResponse, query_llm


# ─────────────────────────── System Prompts ───────────────────────────

SYSTEM_PROMPT_TROUBLESHOOTING = textwrap.dedent("""\
    You are an expert network engineer and packet analyst. You are analyzing
    a network packet capture (pcap) that has already been processed by an
    automated heuristic engine. You will receive:

    1. Capture statistics (packet counts, protocols, top talkers, etc.)
    2. Heuristic findings (severity-ranked issues already detected)
    3. Optionally, a user-provided problem description

    Your job is to provide ADDITIONAL deep analysis that goes beyond what
    the heuristic engine found. Specifically:

    - Correlate multiple findings to identify a likely ROOT CAUSE
    - Identify patterns the heuristic engine may have missed
    - Provide a prioritized action plan (what to check first, second, etc.)
    - Explain the likely network topology and traffic flow based on the data
    - If the user described a problem, directly address that specific issue
    - Suggest specific diagnostic commands (ping, traceroute, nslookup, etc.)
    - Identify if the issue is likely Layer 2, Layer 3, Layer 4, or application layer

    Format your response in clear markdown with these sections:
    ## Root Cause Analysis
    ## Correlated Findings
    ## Prioritized Action Plan
    ## Additional Observations
    ## Diagnostic Commands

    Be concise but thorough. Reference specific IPs, ports, and packet counts
    from the data when making your analysis.
""")

SYSTEM_PROMPT_SECURITY = textwrap.dedent("""\
    You are a senior cybersecurity analyst and penetration tester performing
    a security audit on captured network traffic. You will receive:

    1. Capture statistics (packet counts, protocols, top talkers, etc.)
    2. Heuristic findings (already-detected security issues)
    3. Details about cleartext traffic, credentials, and sensitive data found

    Your job is to provide ADDITIONAL deep security analysis:

    - Assess the overall security posture based on the traffic patterns
    - Identify potential ATTACK CHAINS (how an attacker could combine findings)
    - Classify findings by compliance frameworks (PCI-DSS, HIPAA, SOC 2, GDPR)
    - Calculate a risk score (Critical/High/Medium/Low) with justification
    - Identify lateral movement opportunities visible in the traffic
    - Flag any indicators of compromise (IoCs) or suspicious behavioral patterns
    - Provide specific remediation steps with priority ordering
    - Identify what sensitive data categories are at risk

    Format your response in clear markdown with these sections:
    ## Security Posture Assessment
    ## Attack Chain Analysis
    ## Compliance Impact
    ## Risk Score & Justification
    ## Remediation Priority List
    ## Indicators of Compromise

    Be specific about what an attacker could do with the exposed data.
    Reference specific protocols, IPs, and credential types found.
""")

SYSTEM_PROMPT_CUSTOM = textwrap.dedent("""\
    You are an expert network and security analyst. You are analyzing
    a network packet capture (pcap) that has been processed by an automated
    heuristic engine. You will receive capture statistics and findings.

    The user has a specific question about this capture. Answer it thoroughly
    using the provided packet analysis data. Reference specific IPs, ports,
    protocols, and packet counts in your answer.

    Format your response in clear, well-structured markdown.
""")


# ─────────────────────────── Data Serialization ───────────────────────────

def _serialize_stats(stats: PacketStats) -> dict:
    """Convert PacketStats to a serializable summary for the LLM context."""
    return {
        "total_packets": stats.total_packets,
        "duration_seconds": round(stats.duration_seconds, 2),
        "total_bytes": stats.total_bytes,
        "protocols": {
            "TCP": stats.tcp_packets,
            "UDP": stats.udp_packets,
            "ICMP": stats.icmp_packets,
            "ARP": stats.arp_packets,
            "DNS": stats.dns_packets,
        },
        "tcp_analysis": {
            "syn_count": stats.tcp_syn_count,
            "syn_ack_count": stats.tcp_syn_ack_count,
            "rst_count": stats.tcp_rst_count,
            "fin_count": stats.tcp_fin_count,
            "retransmissions": stats.tcp_retransmissions,
            "connections_attempted": stats.tcp_connections_attempted,
            "connections_completed": stats.tcp_connections_completed,
            "connections_reset": stats.tcp_connections_reset,
        },
        "unique_source_ips": len(stats.src_ips),
        "unique_destination_ips": len(stats.dst_ips),
        "top_source_ips": dict(stats.src_ips.most_common(15)),
        "top_destination_ips": dict(stats.dst_ips.most_common(15)),
        "top_destination_ports": dict(stats.dst_ports.most_common(20)),
        "application_protocols": dict(stats.protocols_used.most_common(20)),
        "dns_queries": [
            {"query": q["query"], "type": q["type"], "src": q["src"]}
            for q in stats.dns_queries[:30]
        ],
        "dns_errors": [
            {"query": e["query"], "rcode": e["rcode"], "server": e.get("dst", "")}
            for e in stats.dns_errors[:20]
        ],
        "icmp_types": dict(stats.icmp_types),
        "icmp_unreachable": [
            {"src": u["src"], "dst": u["dst"], "code": u["code"]}
            for u in stats.icmp_unreachable[:15]
        ],
        "arp_unanswered_count": len(
            set(r["dst_ip"] for r in stats.arp_requests)
            - set(r["src_ip"] for r in stats.arp_replies)
        ),
        "cleartext_protocols_detected": list(set(
            s["protocol"] for s in stats.cleartext_sessions
        )),
        "credentials_found": [
            {
                "type": c["type"],
                "protocol": c["protocol"],
                "src": c["src"],
                "dst": c["dst"],
                # Partially redact
                "value_preview": c["matched_value"][:6] + "****" if len(c["matched_value"]) > 6 else "****",
            }
            for c in stats.potential_credentials[:20]
        ],
        "sensitive_data_patterns": [
            {"type": p["type"], "protocol": p["protocol"], "src": p["src"], "dst": p["dst"]}
            for p in stats.sensitive_patterns[:15]
        ],
        "top_conversations": [
            {"hosts": list(k), "packets": v}
            for k, v in stats.conversations.most_common(10)
        ],
        "tcp_streams_count": len(stats.tcp_streams),
        "top_streams": [
            {
                "src": s["src"], "dst": s["dst"],
                "sport": s["sport"], "dport": s["dport"],
                "packets": s["packets"], "bytes": s["bytes"],
            }
            for s in sorted(stats.tcp_streams.values(), key=lambda x: -x["packets"])[:10]
        ],
    }


def _serialize_findings(findings: list[Finding]) -> list[dict]:
    """Convert findings to a serializable list for the LLM context."""
    return [
        {
            "severity": f.severity.value,
            "title": f.title,
            "category": f.category,
            "description": f.description,
            "details": f.details,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]


def _build_user_prompt(
    stats: PacketStats,
    report: AnalysisReport,
    mode: str,
    problem_description: str | None = None,
    custom_question: str | None = None,
) -> str:
    """Build the user prompt with all the analysis data."""
    stats_data = _serialize_stats(stats)
    findings_data = _serialize_findings(report.findings)

    parts = []

    parts.append("## Capture Statistics")
    parts.append(f"```json\n{json.dumps(stats_data, indent=2, default=str)}\n```")

    parts.append(f"\n## Heuristic Engine Findings ({len(findings_data)} total)")
    parts.append(f"```json\n{json.dumps(findings_data, indent=2)}\n```")

    parts.append(f"\n## Heuristic Engine Summary")
    parts.append(report.summary)

    if problem_description:
        parts.append(f"\n## User-Reported Problem")
        parts.append(problem_description)

    if custom_question:
        parts.append(f"\n## User Question")
        parts.append(custom_question)
        parts.append("\nPlease answer this specific question using the packet analysis data above.")

    # Add cleartext payload samples for security mode
    if mode == "security" and stats.cleartext_sessions:
        parts.append("\n## Cleartext Traffic Samples (first 10)")
        samples = []
        for session in stats.cleartext_sessions[:10]:
            samples.append({
                "protocol": session["protocol"],
                "src": session["src"],
                "dst": session["dst"],
                "dport": session["dport"],
                "payload_preview": session["payload_preview"][:200],
            })
        parts.append(f"```json\n{json.dumps(samples, indent=2)}\n```")

    return "\n".join(parts)


# ─────────────────────────── Public API ───────────────────────────

@dataclass
class LLMAnalysis:
    """Result of LLM-enhanced analysis."""
    content: str  # Markdown-formatted analysis from the LLM
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None
    success: bool = True


def run_llm_analysis(
    config: LLMConfig,
    stats: PacketStats,
    report: AnalysisReport,
    mode: str = "troubleshooting",
    problem_description: str | None = None,
    custom_question: str | None = None,
) -> LLMAnalysis:
    """
    Run LLM-enhanced analysis on the parsed packet data and heuristic findings.

    Args:
        config: LLM provider configuration.
        stats: Parsed packet statistics.
        report: Heuristic analysis report.
        mode: Analysis mode ("troubleshooting" or "security").
        problem_description: Optional user problem description.
        custom_question: Optional custom follow-up question.

    Returns:
        LLMAnalysis with the model's deep analysis.
    """
    # Select system prompt
    if custom_question:
        system_prompt = SYSTEM_PROMPT_CUSTOM
    elif mode == "security":
        system_prompt = SYSTEM_PROMPT_SECURITY
    else:
        system_prompt = SYSTEM_PROMPT_TROUBLESHOOTING

    # Build user prompt with all data
    user_prompt = _build_user_prompt(
        stats=stats,
        report=report,
        mode=mode,
        problem_description=problem_description,
        custom_question=custom_question,
    )

    # Query the LLM
    response = query_llm(config, system_prompt, user_prompt)

    return LLMAnalysis(
        content=response.content,
        model=response.model,
        provider=response.provider,
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        error=response.error,
        success=response.success,
    )


def run_interactive_followup(
    config: LLMConfig,
    stats: PacketStats,
    report: AnalysisReport,
    mode: str,
    question: str,
    previous_analysis: str | None = None,
) -> LLMAnalysis:
    """
    Run an interactive follow-up question against the same capture data.

    Args:
        config: LLM provider configuration.
        stats: Parsed packet statistics.
        report: Heuristic analysis report.
        mode: Analysis mode.
        question: The follow-up question.
        previous_analysis: Previous LLM analysis for context continuity.

    Returns:
        LLMAnalysis with the model's response.
    """
    system_prompt = textwrap.dedent("""\
        You are an expert network and security analyst in an interactive
        analysis session. You have already analyzed a packet capture and
        provided an initial assessment. The user has a follow-up question.

        Answer it using the capture data provided. Be specific and reference
        actual IPs, ports, protocols, and packet counts from the data.
        Format your response in clear markdown.
    """)

    # Build context with previous analysis included
    user_prompt = _build_user_prompt(
        stats=stats,
        report=report,
        mode=mode,
        custom_question=question,
    )

    if previous_analysis:
        user_prompt = (
            f"## Previous Analysis\n{previous_analysis}\n\n"
            f"---\n\n{user_prompt}"
        )

    response = query_llm(config, system_prompt, user_prompt)

    return LLMAnalysis(
        content=response.content,
        model=response.model,
        provider=response.provider,
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        error=response.error,
        success=response.success,
    )
