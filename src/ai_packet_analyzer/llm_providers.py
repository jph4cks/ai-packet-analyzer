"""
LLM Provider Abstraction Layer.

Supports OpenAI, Anthropic, OpenRouter, and local LLMs (Ollama/LM Studio)
using only stdlib (urllib) — no extra dependencies required.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OPENROUTER = "openrouter"
    LOCAL = "local"       # Ollama, LM Studio, llama.cpp, vLLM, etc.


# Default models per provider
DEFAULT_MODELS = {
    LLMProvider.OPENAI: "gpt-4o",
    LLMProvider.ANTHROPIC: "claude-sonnet-4-20250514",
    LLMProvider.OPENROUTER: "anthropic/claude-sonnet-4",
    LLMProvider.LOCAL: "llama3",
}

# API endpoints
PROVIDER_ENDPOINTS = {
    LLMProvider.OPENAI: "https://api.openai.com/v1/chat/completions",
    LLMProvider.ANTHROPIC: "https://api.anthropic.com/v1/messages",
    LLMProvider.OPENROUTER: "https://openrouter.ai/api/v1/chat/completions",
    LLMProvider.LOCAL: "http://localhost:11434/api/chat",  # Ollama default
}

# Environment variable names for API keys
ENV_KEYS = {
    LLMProvider.OPENAI: "OPENAI_API_KEY",
    LLMProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
    LLMProvider.OPENROUTER: "OPENROUTER_API_KEY",
    LLMProvider.LOCAL: None,  # No key needed
}


@dataclass
class LLMConfig:
    """Configuration for the LLM provider."""
    provider: LLMProvider = LLMProvider.OPENAI
    api_key: str | None = None
    model: str | None = None
    base_url: str | None = None  # Override endpoint (for local LLMs or proxies)
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: int = 120

    def get_model(self) -> str:
        """Get the model name, falling back to the provider default."""
        return self.model or DEFAULT_MODELS[self.provider]

    def get_endpoint(self) -> str:
        """Get the API endpoint URL."""
        if self.base_url:
            return self.base_url
        return PROVIDER_ENDPOINTS[self.provider]

    def get_api_key(self) -> str | None:
        """Get the API key from config or environment."""
        if self.api_key:
            return self.api_key
        env_var = ENV_KEYS.get(self.provider)
        if env_var:
            return os.environ.get(env_var)
        return None

    @classmethod
    def from_args(
        cls,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMConfig:
        """Create config from CLI arguments."""
        if provider is None:
            provider = "openai"

        # Map string to enum
        provider_map = {
            "openai": LLMProvider.OPENAI,
            "chatgpt": LLMProvider.OPENAI,
            "anthropic": LLMProvider.ANTHROPIC,
            "claude": LLMProvider.ANTHROPIC,
            "openrouter": LLMProvider.OPENROUTER,
            "local": LLMProvider.LOCAL,
            "ollama": LLMProvider.LOCAL,
            "lmstudio": LLMProvider.LOCAL,
        }

        llm_provider = provider_map.get(provider.lower())
        if llm_provider is None:
            raise ValueError(
                f"Unknown provider: '{provider}'. "
                f"Supported: {', '.join(provider_map.keys())}"
            )

        # Auto-detect local LLM endpoint
        if llm_provider == LLMProvider.LOCAL and base_url is None:
            base_url = _detect_local_endpoint()

        return cls(
            provider=llm_provider,
            api_key=api_key,
            model=model,
            base_url=base_url,
            temperature=temperature,
            max_tokens=max_tokens,
        )


@dataclass
class LLMResponse:
    """Response from an LLM API call."""
    content: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    error: str | None = None
    success: bool = True


def query_llm(config: LLMConfig, system_prompt: str, user_prompt: str) -> LLMResponse:
    """
    Send a query to the configured LLM provider and return the response.

    All providers are accessed via HTTP — no SDK dependencies needed.

    Args:
        config: LLM configuration.
        system_prompt: System instruction prompt.
        user_prompt: The user's analysis query.

    Returns:
        LLMResponse with the model's output.
    """
    provider = config.provider
    try:
        if provider == LLMProvider.ANTHROPIC:
            return _query_anthropic(config, system_prompt, user_prompt)
        elif provider == LLMProvider.LOCAL:
            return _query_local(config, system_prompt, user_prompt)
        else:
            # OpenAI and OpenRouter both use the OpenAI-compatible API
            return _query_openai_compatible(config, system_prompt, user_prompt)
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8", errors="ignore")[:500]
        except Exception as read_err:
            error_body = f"<unable to read HTTP error body: {read_err}>"
        return LLMResponse(
            content="",
            model=config.get_model(),
            provider=provider.value,
            error=f"HTTP {e.code}: {e.reason}. {error_body}",
            success=False,
        )
    except urllib.error.URLError as e:
        return LLMResponse(
            content="",
            model=config.get_model(),
            provider=provider.value,
            error=f"Connection error: {e.reason}. Is the API endpoint reachable?",
            success=False,
        )
    except Exception as e:
        return LLMResponse(
            content="",
            model=config.get_model(),
            provider=provider.value,
            error=f"Unexpected error: {str(e)}",
            success=False,
        )


def _query_openai_compatible(config: LLMConfig, system_prompt: str, user_prompt: str) -> LLMResponse:
    """Query OpenAI or OpenRouter (both use OpenAI-compatible API)."""
    api_key = config.get_api_key()
    if not api_key:
        env_var = ENV_KEYS.get(config.provider, "API_KEY")
        return LLMResponse(
            content="",
            model=config.get_model(),
            provider=config.provider.value,
            error=f"No API key found. Set --llm-api-key or the {env_var} environment variable.",
            success=False,
        )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    # OpenRouter requires additional headers
    if config.provider == LLMProvider.OPENROUTER:
        headers["HTTP-Referer"] = "https://github.com/jph4cks/ai-packet-analyzer"
        headers["X-Title"] = "AI Packet Analyzer"

    payload = {
        "model": config.get_model(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        config.get_endpoint(),
        data=data,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=config.timeout) as resp:
        result = json.loads(resp.read().decode("utf-8"))

    content = result["choices"][0]["message"]["content"]
    usage = result.get("usage", {})

    return LLMResponse(
        content=content,
        model=result.get("model", config.get_model()),
        provider=config.provider.value,
        input_tokens=usage.get("prompt_tokens", 0),
        output_tokens=usage.get("completion_tokens", 0),
    )


def _query_anthropic(config: LLMConfig, system_prompt: str, user_prompt: str) -> LLMResponse:
    """Query the Anthropic Messages API."""
    api_key = config.get_api_key()
    if not api_key:
        return LLMResponse(
            content="",
            model=config.get_model(),
            provider="anthropic",
            error="No API key found. Set --llm-api-key or the ANTHROPIC_API_KEY environment variable.",
            success=False,
        )

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    payload = {
        "model": config.get_model(),
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": user_prompt},
        ],
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        config.get_endpoint(),
        data=data,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=config.timeout) as resp:
        result = json.loads(resp.read().decode("utf-8"))

    # Extract text from content blocks
    content_blocks = result.get("content", [])
    content = "\n".join(
        block.get("text", "") for block in content_blocks if block.get("type") == "text"
    )

    usage = result.get("usage", {})

    return LLMResponse(
        content=content,
        model=result.get("model", config.get_model()),
        provider="anthropic",
        input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0),
    )


def _query_local(config: LLMConfig, system_prompt: str, user_prompt: str) -> LLMResponse:
    """
    Query a local LLM server.

    Supports:
    - Ollama (default: http://localhost:11434/api/chat)
    - LM Studio (http://localhost:1234/v1/chat/completions)
    - llama.cpp server (http://localhost:8080/v1/chat/completions)
    - vLLM (http://localhost:8000/v1/chat/completions)
    - Any OpenAI-compatible local server
    """
    endpoint = config.get_endpoint()

    # Detect if this is an Ollama-style endpoint or OpenAI-compatible
    is_ollama = "/api/chat" in endpoint or "/api/generate" in endpoint

    if is_ollama:
        return _query_ollama(config, system_prompt, user_prompt)
    else:
        # Treat as OpenAI-compatible (LM Studio, llama.cpp, vLLM, etc.)
        # No API key needed for local servers
        local_config = LLMConfig(
            provider=LLMProvider.LOCAL,
            api_key=config.api_key or "not-needed",
            model=config.get_model(),
            base_url=endpoint,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=config.timeout,
        )
        return _query_openai_compatible(local_config, system_prompt, user_prompt)


def _query_ollama(config: LLMConfig, system_prompt: str, user_prompt: str) -> LLMResponse:
    """Query an Ollama server."""
    payload = {
        "model": config.get_model(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": config.temperature,
            "num_predict": config.max_tokens,
        },
    }

    headers = {"Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        config.get_endpoint(),
        data=data,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=config.timeout) as resp:
        result = json.loads(resp.read().decode("utf-8"))

    content = result.get("message", {}).get("content", "")
    eval_count = result.get("eval_count", 0)
    prompt_eval_count = result.get("prompt_eval_count", 0)

    return LLMResponse(
        content=content,
        model=result.get("model", config.get_model()),
        provider="local/ollama",
        input_tokens=prompt_eval_count,
        output_tokens=eval_count,
    )


def _detect_local_endpoint() -> str:
    """Try to auto-detect which local LLM server is running."""
    candidates = [
        ("http://localhost:11434/api/chat", "Ollama"),
        ("http://localhost:1234/v1/chat/completions", "LM Studio"),
        ("http://localhost:8080/v1/chat/completions", "llama.cpp"),
        ("http://localhost:8000/v1/chat/completions", "vLLM"),
    ]

    for url, name in candidates:
        try:
            # Quick health check — try to connect
            base = url.rsplit("/", 2)[0]
            health_req = urllib.request.Request(base, method="GET")
            urllib.request.urlopen(health_req, timeout=2)
            return url
        except Exception:
            continue

    # Default to Ollama
    return "http://localhost:11434/api/chat"


def validate_config(config: LLMConfig) -> tuple[bool, str]:
    """
    Validate an LLM configuration before use.

    Returns:
        (is_valid, error_message)
    """
    if config.provider != LLMProvider.LOCAL:
        api_key = config.get_api_key()
        if not api_key:
            env_var = ENV_KEYS.get(config.provider, "API_KEY")
            return False, (
                f"No API key for {config.provider.value}. "
                f"Set --llm-api-key or the {env_var} environment variable."
            )

    return True, ""


def list_providers() -> str:
    """Return a formatted string listing all supported providers."""
    lines = []
    lines.append("Supported LLM Providers:")
    lines.append("")
    lines.append("  Provider     │ Default Model              │ Env Variable          │ Endpoint")
    lines.append("  ─────────────┼────────────────────────────┼───────────────────────┼─────────────────────────────")
    for provider in LLMProvider:
        model = DEFAULT_MODELS[provider]
        env = ENV_KEYS.get(provider, "—") or "— (none needed)"
        endpoint = PROVIDER_ENDPOINTS[provider]
        lines.append(f"  {provider.value:<12} │ {model:<26} │ {env:<21} │ {endpoint}")
    lines.append("")
    lines.append("  Aliases: chatgpt → openai, claude → anthropic, ollama/lmstudio → local")
    return "\n".join(lines)
