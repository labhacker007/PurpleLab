"""Unified LLM completion client.

Provides a single async interface for text completion across all supported
providers. For the main agentic loop (which needs native tool_use), the
orchestrator uses provider-specific clients directly. This client is for
all utility functions (log generation, threat intel, rule analysis, etc.)
that just need text completions.

Provider routing:
  - Anthropic → anthropic SDK
  - OpenAI    → openai SDK
  - Google    → openai SDK with Google's OpenAI-compatible base URL
  - Ollama    → openai SDK with local base URL
  - Azure     → openai SDK with Azure endpoint
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from backend.llm.config import ModelConfig
from backend.llm.providers import LLMProvider

logger = logging.getLogger(__name__)

# Google Gemini OpenAI-compatible endpoint
_GOOGLE_OPENAI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai/"

# Default Ollama base URL
_OLLAMA_DEFAULT_BASE = "http://localhost:11434/v1"


@dataclass
class CompletionResponse:
    """Normalized completion response."""
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    provider: str = ""
    finish_reason: str = "stop"

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class UnifiedCompletionClient:
    """Async completion client that routes to the correct provider SDK.

    Use for text-only completions (no tool use). The result is always a
    plain string so callers don't need to know which provider is active.
    """

    def __init__(self, config: ModelConfig) -> None:
        self._config = config

    async def complete(
        self,
        messages: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        json_mode: bool = False,
    ) -> CompletionResponse:
        """Run a completion and return normalised text.

        Args:
            messages: Chat messages in OpenAI format
                      ([{"role": "user", "content": "..."}]).
            system: Optional system prompt injected at the start.
            max_tokens: Override config max_tokens.
            temperature: Override config temperature.
            json_mode: Ask the model to return valid JSON.

        Returns:
            CompletionResponse with text + token counts.
        """
        cfg = self._config
        mt = max_tokens or cfg.max_tokens
        temp = temperature if temperature is not None else cfg.temperature

        if cfg.provider == LLMProvider.ANTHROPIC:
            return await self._complete_anthropic(messages, system, mt, temp, json_mode)
        else:
            # OpenAI SDK works for OpenAI, Google (OpenAI-compat), and Ollama
            return await self._complete_openai_compat(
                messages, system, mt, temp, json_mode
            )

    async def complete_json(
        self, messages: list[dict[str, Any]], system: str | None = None
    ) -> dict[str, Any]:
        """Convenience: complete + parse JSON. Returns {} on parse failure."""
        import json
        resp = await self.complete(messages, system=system, json_mode=True)
        try:
            text = resp.text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()
            return json.loads(text)
        except Exception as exc:
            logger.warning("JSON parse failed from %s: %s", self._config.model_id, exc)
            return {}

    # ------------------------------------------------------------------
    # Provider implementations
    # ------------------------------------------------------------------

    async def _complete_anthropic(
        self,
        messages: list[dict[str, Any]],
        system: str | None,
        max_tokens: int,
        temperature: float,
        json_mode: bool,
    ) -> CompletionResponse:
        from anthropic import AsyncAnthropic

        api_key = self._config.api_key_override or self._get_env_key("ANTHROPIC_API_KEY")
        client = AsyncAnthropic(api_key=api_key)

        kwargs: dict[str, Any] = {
            "model": self._config.model_id,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if json_mode:
            kwargs["system"] = (
                (system or "") + "\n\nReturn ONLY valid JSON. No markdown fences, no explanation."
            ).strip()

        try:
            resp = await client.messages.create(**kwargs)
            text = resp.content[0].text if resp.content else ""
            return CompletionResponse(
                text=text,
                input_tokens=resp.usage.input_tokens,
                output_tokens=resp.usage.output_tokens,
                model=self._config.model_id,
                provider=LLMProvider.ANTHROPIC,
                finish_reason=resp.stop_reason or "stop",
            )
        except Exception as exc:
            logger.error("Anthropic completion failed: %s", exc)
            raise

    async def _complete_openai_compat(
        self,
        messages: list[dict[str, Any]],
        system: str | None,
        max_tokens: int,
        temperature: float,
        json_mode: bool,
    ) -> CompletionResponse:
        from openai import AsyncOpenAI

        base_url, api_key = self._resolve_openai_endpoint()
        client = AsyncOpenAI(api_key=api_key, base_url=base_url)

        # Inject system message
        full_messages = list(messages)
        sys_text = system or ""
        if json_mode:
            sys_text = (sys_text + "\n\nReturn ONLY valid JSON.").strip()
        if sys_text:
            full_messages = [{"role": "system", "content": sys_text}] + full_messages

        kwargs: dict[str, Any] = {
            "model": self._config.model_id,
            "messages": full_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if json_mode and self._config.provider not in (LLMProvider.OLLAMA,):
            kwargs["response_format"] = {"type": "json_object"}

        try:
            resp = await client.chat.completions.create(**kwargs)
            text = resp.choices[0].message.content or ""
            usage = resp.usage
            return CompletionResponse(
                text=text,
                input_tokens=usage.prompt_tokens if usage else 0,
                output_tokens=usage.completion_tokens if usage else 0,
                model=self._config.model_id,
                provider=self._config.provider,
                finish_reason=resp.choices[0].finish_reason or "stop",
            )
        except Exception as exc:
            logger.error(
                "OpenAI-compat completion failed (provider=%s model=%s): %s",
                self._config.provider, self._config.model_id, exc,
            )
            raise

    def _resolve_openai_endpoint(self) -> tuple[str, str]:
        """Return (base_url, api_key) for the configured provider."""
        provider = self._config.provider

        if provider == LLMProvider.OPENAI:
            return (
                "https://api.openai.com/v1",
                self._config.api_key_override or self._get_env_key("OPENAI_API_KEY"),
            )

        if provider == LLMProvider.GOOGLE:
            return (
                _GOOGLE_OPENAI_BASE,
                self._config.api_key_override or self._get_env_key("GOOGLE_API_KEY"),
            )

        if provider == LLMProvider.OLLAMA:
            base = self._config.base_url or _OLLAMA_DEFAULT_BASE
            # Ollama doesn't need a real key but the SDK requires one
            return base, "ollama"

        if provider == LLMProvider.AZURE_OPENAI:
            base = self._config.base_url or self._get_env_key("AZURE_OPENAI_ENDPOINT")
            return (
                base,
                self._config.api_key_override or self._get_env_key("AZURE_OPENAI_API_KEY"),
            )

        raise ValueError(f"Unsupported provider for OpenAI-compat: {provider}")

    @staticmethod
    def _get_env_key(env_var: str) -> str:
        import os
        return os.environ.get(env_var, "")


# ---------------------------------------------------------------------------
# Connectivity test helper
# ---------------------------------------------------------------------------

async def test_model_connection(config: ModelConfig) -> dict[str, Any]:
    """Send a minimal ping to verify a model configuration works.

    Returns: { ok: bool, latency_ms: float, error?: str, model: str }
    """
    import time
    t0 = time.monotonic()
    try:
        client = UnifiedCompletionClient(config)
        resp = await client.complete(
            messages=[{"role": "user", "content": "Reply with: OK"}],
            max_tokens=10,
            temperature=0.0,
        )
        latency_ms = (time.monotonic() - t0) * 1000
        return {
            "ok": True,
            "latency_ms": round(latency_ms, 1),
            "model": config.model_id,
            "provider": config.provider,
            "response_preview": resp.text[:50],
        }
    except Exception as exc:
        latency_ms = (time.monotonic() - t0) * 1000
        return {
            "ok": False,
            "latency_ms": round(latency_ms, 1),
            "model": config.model_id,
            "provider": config.provider,
            "error": str(exc),
        }
