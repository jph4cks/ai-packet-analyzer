# Changelog

All notable changes to **AI Packet Analyzer** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-04-26

### Added — Live Capture Mode

- New **live capture** mode lets the analyzer sniff packets directly from a
  network interface in real time, as an alternative to reading a `.pcap` file.
- New `live_capture.py` module with:
  - `LiveCaptureOptions` dataclass for configuring sessions (interface, BPF
    filter, packet count, duration, save-pcap path, promiscuous mode).
  - `capture_live()` function that returns a fully-populated `PacketStats`
    object — the same data model used by `parse_pcap()` — so all downstream
    heuristic and LLM analyzers work unchanged.
  - `check_capture_privileges()` and `list_interfaces()` helpers.
  - `LiveCaptureError` for cleanly surfacing permission and OS errors.
- New `live_ui.py` module: a Rich-powered dashboard that refreshes several
  times per second during capture, showing packet rate, top talkers, protocol
  mix, TCP flag counts, and live security alerts (cleartext sessions,
  potential credentials).
- New CLI flags:
  - `--live` — enable live capture (mutually exclusive with `pcap_file`).
  - `-i / --interface IFACE` — pick the capture interface.
  - `-t / --duration SECONDS` — stop after N seconds.
  - `--packet-count N` — stop after N packets.
  - `-f / --bpf-filter EXPR` — BPF filter (e.g. `"tcp port 80"`).
  - `--save-pcap FILE` — also write captured packets to a pcap file.
  - `--list-interfaces` — list available interfaces and exit.
  - `--no-live-ui` — disable the Rich dashboard for headless / CI usage.
- Graceful `Ctrl+C` handling: stops the sniffer cleanly and still runs
  analysis on whatever was captured so far.
- Cross-platform privilege guidance printed at startup (Linux `CAP_NET_RAW`,
  macOS ChmodBPF, Windows Npcap).

### Tests

- 13 new tests covering the per-packet accumulator, DNS / ARP / ICMP / TCP
  stats, cleartext credential detection on live frames, mocked `AsyncSniffer`
  end-to-end runs, `--save-pcap` output, and error wrapping
  (`PermissionError` / `OSError`).
- All tests run without opening real sockets.

### Documentation

- New "Live Capture Mode" section in the README with privileges table, CLI
  flag reference, examples, and a description of the dashboard.
- New "Live Capture (new in v1.2)" feature list entry.
- README version badge bumped to `1.2.0`.

## [1.1.0] — 2025

### Added

- LLM integration: OpenAI, Anthropic, OpenRouter, Ollama, LM Studio, and any
  OpenAI-compatible local server.
- Interactive Q&A follow-up loop with the LLM after the heuristic report.
- Smoke test suite and comprehensive black-box test harness
  (`tests/run_comprehensive_tests.py`).
- Cross-platform build system and GitHub Actions CI/CD pipeline.

### Changed

- Hardened DNS / LLM error handling (no more silent swallowed exceptions).
- Improved report output rendering.

## [1.0.0] — 2025

### Added

- Initial release with heuristic connectivity troubleshooting and security
  auditing modes for `.pcap` / `.pcapng` files.
- Scapy-based packet parsing engine.
- Rich-powered terminal report renderer.
- IP / port filtering, problem-description narrowing, and verbose mode.
