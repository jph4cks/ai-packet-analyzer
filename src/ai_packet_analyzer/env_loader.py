"""
Environment loading helpers — Devin Terminal compatible.

Devin for Terminal recommends managing per-project secrets via ``direnv`` and
a ``.envrc`` file at the repository root. Many users also keep a plain
``.env`` file (the convention used by Aider, Codex, OpenCode, etc.).

This module gives the analyzer a small, dependency-free loader that picks up
the same files Devin does **without** requiring direnv to be installed:

* If a ``.envrc`` or ``.env`` file exists at the current working directory
  (or any parent up to the user's home), its ``KEY=VALUE`` and
  ``export KEY=VALUE`` lines are parsed and merged into ``os.environ``.
* Existing environment variables always win — we never overwrite a key that
  the user already exported in their shell.

We also expose :func:`resolve_api_key`, which tries several aliases for the
same provider so that a single ``ANTHROPIC_API_KEY`` (or
``CLAUDE_API_KEY``, ``ANTHROPIC_KEY``, etc.) Just Works regardless of which
upstream tool put it there.

Reference:

* `Devin docs — Configuring Environment Variables`__
* `Devin Terminal — Extensibility`__

__ https://docs.devin.ai/onboard-devin/repo-setup#configuring-environment-variables
__ https://cli.devin.ai/docs/extensibility
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Provider alias table
# ---------------------------------------------------------------------------
#
# When the user asks for, say, ``--llm anthropic`` we look up the API key by
# walking each candidate env var in order. The first non-empty match wins.
#
# This mirrors the conventions used by Aider, OpenCode, Codex, Claude Code,
# and Devin's own ``.envrc`` examples — so a key set up for any of those
# tools is automatically reused.

PROVIDER_ENV_ALIASES: dict[str, tuple[str, ...]] = {
    "openai": (
        "OPENAI_API_KEY",       # Canonical (OpenAI, Aider, Codex, Devin secrets)
        "OPENAI_KEY",
        "CHATGPT_API_KEY",
    ),
    "anthropic": (
        "ANTHROPIC_API_KEY",    # Canonical (Anthropic, Claude Code, Aider)
        "CLAUDE_API_KEY",
        "ANTHROPIC_KEY",
    ),
    "openrouter": (
        "OPENROUTER_API_KEY",   # Canonical
        "OPENROUTER_KEY",
        "OR_API_KEY",
    ),
    "local": (),                # Local / Ollama / LM Studio — usually no key
}

# Devin Terminal uses WINDSURF_API_KEY for its own auth. We don't try to use
# that as a model key, but expose the constant so callers can detect a
# Devin-authenticated environment.
DEVIN_AUTH_ENV_VAR = "WINDSURF_API_KEY"


# ---------------------------------------------------------------------------
# .env / .envrc loader
# ---------------------------------------------------------------------------

# Match `KEY=VALUE` and `export KEY=VALUE`, ignoring comments and blank lines.
# We deliberately keep this simple — full direnv semantics (functions, source,
# command substitution) are out of scope. This matches the subset Devin's docs
# show in their `.envrc` examples.
_ASSIGNMENT_RE = re.compile(
    r"""
    ^\s*
    (?:export\s+)?           # optional `export`
    ([A-Za-z_][A-Za-z0-9_]*) # key
    \s*=\s*
    (.*?)                    # value (greedy stripped below)
    \s*$
    """,
    re.VERBOSE,
)


def _strip_inline_comment(value: str) -> str:
    """Strip a trailing ``# comment`` from an unquoted value."""
    # Don't strip inside quotes — shlex handles that for us when we re-parse.
    if value.startswith(("'", '"')):
        return value
    if " #" in value:
        return value.split(" #", 1)[0].rstrip()
    return value


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse ``.env`` / ``.envrc`` style files into a ``dict``.

    Supports:

    * Blank lines and ``#`` comments
    * ``KEY=value``
    * ``export KEY=value`` (Devin / direnv style)
    * Single- and double-quoted values (handled by :mod:`shlex`)

    Unsupported (silently skipped):

    * Shell expansions like ``$OTHER_VAR``
    * ``source ...`` directives
    * Multi-line values

    Args:
        path: File to parse.

    Returns:
        Mapping of variable names to string values. Empty if the file does
        not exist or cannot be read.
    """
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ASSIGNMENT_RE.match(line)
        if not match:
            continue
        key, value = match.group(1), _strip_inline_comment(match.group(2))
        # shlex handles quoted strings ("foo bar", 'baz') and escapes.
        try:
            tokens = shlex.split(value, posix=True)
            value = tokens[0] if tokens else ""
        except ValueError:
            # Unbalanced quotes — fall back to the raw value sans surrounding
            # whitespace.
            value = value.strip().strip("'\"")
        out[key] = value
    return out


def discover_env_files(start: Path | None = None) -> list[Path]:
    """Walk from *start* up to the user home looking for ``.envrc`` / ``.env``.

    Returns the matching paths in nearest-first order. We stop at the user's
    home directory to avoid accidentally loading variables from a parent of
    home (which would be a privacy footgun on multi-tenant systems).

    Args:
        start: Directory to start from. Defaults to the current working
            directory.

    Returns:
        List of files (zero or more), nearest first.
    """
    start = (start or Path.cwd()).resolve()
    home = Path.home().resolve()
    found: list[Path] = []
    seen: set[Path] = set()

    current = start
    while True:
        for name in (".envrc", ".env"):
            candidate = current / name
            if candidate.is_file() and candidate not in seen:
                found.append(candidate)
                seen.add(candidate)
        if current == home or current.parent == current:
            break
        # Don't escape above home.
        if home not in current.parents:
            break
        current = current.parent
    return found


def load_project_env(start: Path | None = None) -> dict[str, str]:
    """Load ``.envrc`` / ``.env`` from the project tree into ``os.environ``.

    This is intentionally conservative:

    * Only ``KEY=VALUE`` style lines are honored (no shell execution).
    * Variables already set in ``os.environ`` are **never** overwritten —
      explicit shell exports always win.
    * Files closer to the start directory take precedence over higher ones.

    Args:
        start: Directory to start the upward search from. Defaults to CWD.

    Returns:
        Dict of variables that were actually injected into ``os.environ``
        (i.e. excluding ones that were already set). Useful for logging or
        tests.
    """
    files = discover_env_files(start)
    injected: dict[str, str] = {}
    # ``files`` is nearest-first. We walk in that order and skip keys already
    # set — so the nearest file (and any explicit shell exports) win.
    for path in files:
        for key, value in parse_env_file(path).items():
            if key in os.environ:
                continue
            os.environ[key] = value
            injected[key] = value
    return injected


# ---------------------------------------------------------------------------
# Provider key resolver
# ---------------------------------------------------------------------------


def resolve_api_key(provider: str, *, extra_aliases: Iterable[str] = ()) -> tuple[str | None, str | None]:
    """Return ``(api_key, env_var_name)`` for a provider, or ``(None, None)``.

    The lookup walks :data:`PROVIDER_ENV_ALIASES` in order so a single
    canonical export works for the analyzer, Aider, Claude Code, Codex,
    OpenCode, and Devin's recommended ``.envrc`` setup.

    Args:
        provider: Provider name (``"openai"``, ``"anthropic"``, etc.).
        extra_aliases: Additional env vars to check before the defaults.
            Useful when a downstream tool wants to add a custom alias.

    Returns:
        ``(value, name)`` of the first non-empty environment variable, or
        ``(None, None)`` if none of the candidates is set.
    """
    candidates = list(extra_aliases) + list(
        PROVIDER_ENV_ALIASES.get(provider.lower(), ())
    )
    for name in candidates:
        value = os.environ.get(name)
        if value:
            return value, name
    return None, None


def has_devin_terminal_auth() -> bool:
    """Return True if the current shell is set up for Devin Terminal.

    This is purely informational — Devin Terminal's auth token (stored in
    ``WINDSURF_API_KEY`` or in ``~/.config/devin/``) does **not** grant
    access to model APIs. We expose this so the CLI can print a friendly
    hint when the user appears to be on a Devin-configured machine.
    """
    if os.environ.get(DEVIN_AUTH_ENV_VAR):
        return True
    config_dir = (
        Path(os.environ.get("APPDATA", "")) / "devin"
        if os.name == "nt"
        else Path.home() / ".config" / "devin"
    )
    return config_dir.is_dir()


__all__ = [
    "DEVIN_AUTH_ENV_VAR",
    "PROVIDER_ENV_ALIASES",
    "discover_env_files",
    "has_devin_terminal_auth",
    "load_project_env",
    "parse_env_file",
    "resolve_api_key",
]
