# Changelog

All notable changes to **AI Packet Analyzer** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.1] — 2026-04-26

### Added — Devin Terminal / direnv Compatibility

- New `env_loader` module that auto-discovers `.envrc` and `.env` files in
  the current working directory and walks up to (but never past) the user's
  home directory — matching [Devin Terminal's recommended](https://docs.devin.ai/onboard-devin/repo-setup#configuring-environment-variables)
  workflow and the way [direnv](https://direnv.net) loads project secrets.
  Files are parsed without invoking a shell (`KEY=value`, `export KEY=value`,
  comments, single/double quotes are supported).
- Existing shell exports always win — the loader will never overwrite a
  variable that's already set, so explicit `export FOO=bar` in your terminal
  takes precedence over `.env` / `.envrc`.
- New `--no-load-env` CLI flag to disable the auto-loader.
- Provider env var **alias support**: a single key set up for Aider,
  Claude Code, Codex, OpenCode, or Devin's `.envrc` Just Works without
  re-exporting. Aliases (in priority order):
  - `OPENAI_API_KEY` → `OPENAI_KEY` → `CHATGPT_API_KEY`
  - `ANTHROPIC_API_KEY` → `CLAUDE_API_KEY` → `ANTHROPIC_KEY`
  - `OPENROUTER_API_KEY` → `OPENROUTER_KEY` → `OR_API_KEY`
- New `LLMConfig.get_api_key_source()` method returns the env var name that
  supplied the key (useful for friendlier logging like `Using API key from
  CLAUDE_API_KEY`).
- `--list-providers` output now lists every accepted alias and shows endpoint
  URLs, plus a note explaining the canonical-first rule.
- `has_devin_terminal_auth()` helper detects a Devin Terminal-configured
  shell (via `WINDSURF_API_KEY` or `~/.config/devin/`). When verbose mode
  is on and no `.envrc`/`.env` is found, the analyzer prints a friendly
  hint pointing the user at the recommended setup.

### Changed

- All API-key error messages now list every accepted alias rather than just
  the canonical name, so the fix is obvious when the user has a key set
  under a non-canonical alias.
- `LLMConfig.get_api_key()` resolution path is documented inline in its
  docstring.

### Tests

- 24 new tests covering `parse_env_file` edge cases (quotes, comments,
  `export` prefix, invalid lines), `discover_env_files` (nearest-first walk,
  hard stop at `$HOME`, multi-level resolution), `load_project_env`
  (precedence, no-overwrite contract), `resolve_api_key` (canonical-first,
  alias fallback, custom aliases), `has_devin_terminal_auth`, and end-to-end
  `LLMConfig.get_api_key()` integration with aliases.
- Total suite: 38 tests, all passing.

### Compatibility

- Fully backward compatible. Existing scripts that set `OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, or `OPENROUTER_API_KEY` continue to work unchanged.
  The `ENV_KEYS` dict in `llm_providers.py` is kept (canonical-only) for
  any external code that imported it.

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
