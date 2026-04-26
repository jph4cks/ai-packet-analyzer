"""Tests for the env_loader (Devin Terminal compatibility) module.

These tests use ``tmp_path`` and ``monkeypatch`` so nothing touches the real
home directory or environment.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ai_packet_analyzer.env_loader import (
    DEVIN_AUTH_ENV_VAR,
    PROVIDER_ENV_ALIASES,
    discover_env_files,
    has_devin_terminal_auth,
    load_project_env,
    parse_env_file,
    resolve_api_key,
)


# ---------------------------------------------------------------------------
# parse_env_file
# ---------------------------------------------------------------------------


def test_parse_env_file_basic_assignments(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text("FOO=bar\nBAZ=qux\n")
    assert parse_env_file(f) == {"FOO": "bar", "BAZ": "qux"}


def test_parse_env_file_export_prefix(tmp_path: Path) -> None:
    f = tmp_path / ".envrc"
    f.write_text("export OPENAI_API_KEY=sk-abc123\nexport CLAUDE_API_KEY=cl-xyz\n")
    assert parse_env_file(f) == {
        "OPENAI_API_KEY": "sk-abc123",
        "CLAUDE_API_KEY": "cl-xyz",
    }


def test_parse_env_file_comments_and_blanks(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text(
        "# top comment\n"
        "\n"
        "FOO=bar  # trailing comment\n"
        "   # indented comment\n"
        "BAZ=value-only\n"
    )
    parsed = parse_env_file(f)
    assert parsed == {"FOO": "bar", "BAZ": "value-only"}


def test_parse_env_file_quoted_values(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    f.write_text(
        'DOUBLE="hello world"\n'
        "SINGLE='spaces and # hashes'\n"
        "RAW=no-quotes\n"
    )
    parsed = parse_env_file(f)
    assert parsed["DOUBLE"] == "hello world"
    assert parsed["SINGLE"] == "spaces and # hashes"
    assert parsed["RAW"] == "no-quotes"


def test_parse_env_file_skips_invalid_lines(tmp_path: Path) -> None:
    f = tmp_path / ".envrc"
    f.write_text(
        "VALID=ok\n"
        "source ./other.sh\n"           # ignored
        "function foo() { echo hi; }\n" # ignored
        "BAD LINE WITHOUT EQUALS\n"      # ignored
    )
    parsed = parse_env_file(f)
    assert parsed == {"VALID": "ok"}


def test_parse_env_file_missing_returns_empty(tmp_path: Path) -> None:
    assert parse_env_file(tmp_path / "does_not_exist") == {}


# ---------------------------------------------------------------------------
# discover_env_files
# ---------------------------------------------------------------------------


def test_discover_env_files_walks_up_to_home(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path
    project = home / "projects" / "demo"
    project.mkdir(parents=True)
    (home / ".envrc").write_text("HOME_LEVEL=1\n")
    (project / ".env").write_text("PROJECT_LEVEL=1\n")

    monkeypatch.setattr(Path, "home", lambda: home)
    found = discover_env_files(project)
    # Nearest first: project/.env then home/.envrc
    rel = [str(p.relative_to(home)) for p in found]
    assert rel == ["projects/demo/.env", ".envrc"]


def test_discover_env_files_stops_at_home(tmp_path: Path, monkeypatch) -> None:
    """We must NOT escape above the user's home directory."""
    home = tmp_path / "user"
    home.mkdir()
    project = home / "code"
    project.mkdir()
    # Put a file ABOVE home — this must not be discovered.
    (tmp_path / ".envrc").write_text("LEAK=should_not_load\n")
    (project / ".env").write_text("OK=1\n")

    monkeypatch.setattr(Path, "home", lambda: home)
    found = discover_env_files(project)
    assert all(home in p.parents or p.parent == home for p in found)
    assert all("LEAK=" not in p.read_text() for p in found)


def test_discover_env_files_no_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    sub = tmp_path / "empty"
    sub.mkdir()
    assert discover_env_files(sub) == []


# ---------------------------------------------------------------------------
# load_project_env
# ---------------------------------------------------------------------------


def test_load_project_env_injects_new_vars(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / ".env").write_text("APA_TEST_NEW=fresh\n")
    monkeypatch.delenv("APA_TEST_NEW", raising=False)

    injected = load_project_env(tmp_path)
    assert injected == {"APA_TEST_NEW": "fresh"}
    assert os.environ["APA_TEST_NEW"] == "fresh"


def test_load_project_env_does_not_overwrite_existing(tmp_path: Path, monkeypatch) -> None:
    """Explicit shell exports must always win over .env files."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / ".env").write_text("APA_TEST_KEEP=from_file\n")
    monkeypatch.setenv("APA_TEST_KEEP", "from_shell")

    injected = load_project_env(tmp_path)
    assert "APA_TEST_KEEP" not in injected
    assert os.environ["APA_TEST_KEEP"] == "from_shell"


def test_load_project_env_nearest_wins(tmp_path: Path, monkeypatch) -> None:
    """When the same key is defined at multiple levels, nearest wins."""
    home = tmp_path
    project = home / "p"
    project.mkdir()
    (home / ".envrc").write_text("APA_TEST_LAYER=from_home\n")
    (project / ".env").write_text("APA_TEST_LAYER=from_project\n")
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.delenv("APA_TEST_LAYER", raising=False)

    load_project_env(project)
    assert os.environ["APA_TEST_LAYER"] == "from_project"


# ---------------------------------------------------------------------------
# resolve_api_key
# ---------------------------------------------------------------------------


def test_resolve_api_key_canonical_first(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "canonical")
    monkeypatch.setenv("CHATGPT_API_KEY", "alias")
    value, name = resolve_api_key("openai")
    assert (value, name) == ("canonical", "OPENAI_API_KEY")


def test_resolve_api_key_falls_back_to_alias(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_KEY", raising=False)
    monkeypatch.setenv("CLAUDE_API_KEY", "claude-key")
    value, name = resolve_api_key("anthropic")
    assert (value, name) == ("claude-key", "CLAUDE_API_KEY")


def test_resolve_api_key_returns_none_when_unset(monkeypatch) -> None:
    for alias in PROVIDER_ENV_ALIASES["openrouter"]:
        monkeypatch.delenv(alias, raising=False)
    assert resolve_api_key("openrouter") == (None, None)


def test_resolve_api_key_extra_aliases_take_precedence(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("MY_CUSTOM_KEY", "custom-value")
    value, name = resolve_api_key("openai", extra_aliases=("MY_CUSTOM_KEY",))
    assert (value, name) == ("custom-value", "MY_CUSTOM_KEY")


def test_resolve_api_key_local_provider_has_no_aliases() -> None:
    assert resolve_api_key("local") == (None, None)


def test_resolve_api_key_unknown_provider() -> None:
    assert resolve_api_key("nonexistent") == (None, None)


# ---------------------------------------------------------------------------
# has_devin_terminal_auth
# ---------------------------------------------------------------------------


def test_has_devin_terminal_auth_via_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv(DEVIN_AUTH_ENV_VAR, "ws-token")
    assert has_devin_terminal_auth() is True


def test_has_devin_terminal_auth_via_config_dir(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv(DEVIN_AUTH_ENV_VAR, raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    (tmp_path / ".config" / "devin").mkdir(parents=True)
    # Force POSIX path on all platforms by resetting os.name
    if os.name == "nt":
        monkeypatch.setenv("APPDATA", str(tmp_path))
        (tmp_path / "devin").mkdir(exist_ok=True)
    assert has_devin_terminal_auth() is True


def test_has_devin_terminal_auth_negative(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv(DEVIN_AUTH_ENV_VAR, raising=False)
    if os.name == "nt":
        monkeypatch.setenv("APPDATA", str(tmp_path))
    assert has_devin_terminal_auth() is False


# ---------------------------------------------------------------------------
# Integration: LLMConfig.get_api_key uses aliases
# ---------------------------------------------------------------------------


def test_llmconfig_uses_alias(monkeypatch) -> None:
    """Setting CLAUDE_API_KEY alone should be enough for Anthropic provider."""
    from ai_packet_analyzer.llm_providers import LLMConfig, LLMProvider

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_KEY", raising=False)
    monkeypatch.setenv("CLAUDE_API_KEY", "cl-test")

    cfg = LLMConfig(provider=LLMProvider.ANTHROPIC)
    assert cfg.get_api_key() == "cl-test"
    assert cfg.get_api_key_source() == "CLAUDE_API_KEY"


def test_llmconfig_explicit_key_wins(monkeypatch) -> None:
    from ai_packet_analyzer.llm_providers import LLMConfig, LLMProvider

    monkeypatch.setenv("OPENAI_API_KEY", "from-env")
    cfg = LLMConfig(provider=LLMProvider.OPENAI, api_key="explicit")
    assert cfg.get_api_key() == "explicit"
    assert cfg.get_api_key_source() is None  # came from explicit, not env


def test_llmconfig_local_returns_none(monkeypatch) -> None:
    from ai_packet_analyzer.llm_providers import LLMConfig, LLMProvider

    monkeypatch.setenv("OPENAI_API_KEY", "should-not-leak")
    cfg = LLMConfig(provider=LLMProvider.LOCAL)
    assert cfg.get_api_key() is None
