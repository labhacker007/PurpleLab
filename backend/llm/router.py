"""LLM Function Router — selects the right model for each function.

Config priority (highest first):
  1. DB-stored admin config (per-function override)
  2. Environment variable defaults (PURPLELAB_LLM_* env vars)
  3. Code defaults derived from available API keys

All configs are cached in memory (TTL: 5 minutes) to avoid DB round-trips
on every LLM call. Cache is invalidated when admin updates a config.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from backend.llm.config import (
    LLMFunction,
    ModelConfig,
    FunctionModelConfig,
    FUNCTION_METADATA,
    DEFAULT_FUNCTION_CONFIGS,
    default_config,
)
from backend.llm.providers import LLMProvider

logger = logging.getLogger(__name__)

_CACHE_TTL = 300  # 5 minutes


class LLMRouter:
    """Routes LLM function calls to the configured provider/model.

    Exposes:
      - get_config(fn)       → ModelConfig for a function
      - get_client(fn)       → UnifiedCompletionClient ready to use
      - complete(fn, msgs)   → shortcut for get_client(fn).complete(...)
      - set_config(fn, cfg)  → update in-memory + DB config
      - list_configs()       → all function configs (for admin UI)
    """

    def __init__(self) -> None:
        self._cache: dict[str, tuple[ModelConfig, float]] = {}
        self._db_available = False
        self._db_checked = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_config(self, function: LLMFunction | str) -> ModelConfig:
        """Return the active ModelConfig for a function (sync, cache-first)."""
        fn = function.value if isinstance(function, LLMFunction) else function

        cached = self._cache.get(fn)
        if cached and (time.monotonic() - cached[1]) < _CACHE_TTL:
            return cached[0]

        # Build from env/defaults synchronously (DB lookup happens async separately)
        cfg = self._env_config(fn) or self._default_config(fn)
        self._cache[fn] = (cfg, time.monotonic())
        return cfg

    async def get_config_async(self, function: LLMFunction | str) -> ModelConfig:
        """Return ModelConfig — checks DB first (async)."""
        fn = function.value if isinstance(function, LLMFunction) else function

        # Check memory cache
        cached = self._cache.get(fn)
        if cached and (time.monotonic() - cached[1]) < _CACHE_TTL:
            return cached[0]

        # Try DB
        db_cfg = await self._load_from_db(fn)
        if db_cfg:
            self._cache[fn] = (db_cfg, time.monotonic())
            return db_cfg

        # Fall back to env/defaults
        cfg = self._env_config(fn) or self._default_config(fn)
        self._cache[fn] = (cfg, time.monotonic())
        return cfg

    def get_client(self, function: LLMFunction | str) -> "UnifiedCompletionClient":
        """Return a ready-to-use UnifiedCompletionClient for a function."""
        from backend.llm.client import UnifiedCompletionClient
        cfg = self.get_config(function)
        return UnifiedCompletionClient(cfg)

    async def get_client_async(self, function: LLMFunction | str) -> "UnifiedCompletionClient":
        """Async version — loads DB config before returning client."""
        from backend.llm.client import UnifiedCompletionClient
        cfg = await self.get_config_async(function)
        return UnifiedCompletionClient(cfg)

    async def complete(
        self,
        function: LLMFunction | str,
        messages: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        json_mode: bool = False,
    ) -> str:
        """Convenience: route to correct model and return text only."""
        client = await self.get_client_async(function)
        resp = await client.complete(
            messages=messages,
            system=system,
            max_tokens=max_tokens,
            temperature=temperature,
            json_mode=json_mode,
        )
        return resp.text

    async def set_config(
        self,
        function: LLMFunction | str,
        config: ModelConfig,
        fallback: ModelConfig | None = None,
    ) -> FunctionModelConfig:
        """Store a new config for a function (DB + cache invalidate)."""
        fn = function.value if isinstance(function, LLMFunction) else function

        # Persist to DB
        await self._save_to_db(fn, config, fallback)

        # Invalidate cache
        self._cache.pop(fn, None)
        logger.info("LLM config updated for function=%s provider=%s model=%s",
                    fn, config.provider, config.model_id)

        return FunctionModelConfig(
            function_name=fn,
            config=config,
            fallback_config=fallback,
            updated_at=_now_iso(),
        )

    async def list_configs(self) -> list[FunctionModelConfig]:
        """Return configs for all known functions (for admin UI)."""
        result = []
        for fn in LLMFunction:
            cfg = await self.get_config_async(fn)
            result.append(FunctionModelConfig(
                function_name=fn.value,
                config=cfg,
                updated_at="",
            ))
        return result

    def invalidate_cache(self, function: LLMFunction | str | None = None) -> None:
        """Flush cache entry (or all if function is None)."""
        if function is None:
            self._cache.clear()
        else:
            fn = function.value if isinstance(function, LLMFunction) else function
            self._cache.pop(fn, None)

    # ------------------------------------------------------------------
    # Agent-loop helper: returns the Anthropic client for tool-use loops
    # ------------------------------------------------------------------

    def get_anthropic_client(self, function: LLMFunction = LLMFunction.AGENT_CHAT):
        """Return configured Anthropic AsyncClient.

        If the configured model is not Anthropic, returns None and the
        caller should fall back to the OpenAI-compat path.
        """
        cfg = self.get_config(function)
        if cfg.provider != LLMProvider.ANTHROPIC:
            return None, cfg
        try:
            from anthropic import AsyncAnthropic
            api_key = cfg.api_key_override or os.environ.get("ANTHROPIC_API_KEY", "")
            return AsyncAnthropic(api_key=api_key), cfg
        except ImportError:
            return None, cfg

    def get_openai_client(self, function: LLMFunction = LLMFunction.AGENT_CHAT):
        """Return configured OpenAI AsyncClient for non-Anthropic providers."""
        from openai import AsyncOpenAI
        from backend.llm.client import _GOOGLE_OPENAI_BASE, _OLLAMA_DEFAULT_BASE

        cfg = self.get_config(function)
        provider = cfg.provider
        api_key = cfg.api_key_override

        if provider == LLMProvider.OPENAI:
            base_url = "https://api.openai.com/v1"
            api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        elif provider == LLMProvider.GOOGLE:
            base_url = _GOOGLE_OPENAI_BASE
            api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")
        elif provider == LLMProvider.OLLAMA:
            base_url = cfg.base_url or _OLLAMA_DEFAULT_BASE
            api_key = "ollama"
        elif provider == LLMProvider.AZURE_OPENAI:
            base_url = cfg.base_url or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
            api_key = api_key or os.environ.get("AZURE_OPENAI_API_KEY", "")
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        return AsyncOpenAI(api_key=api_key, base_url=base_url), cfg

    # ------------------------------------------------------------------
    # DB persistence (graceful degradation when DB unavailable)
    # ------------------------------------------------------------------

    async def _load_from_db(self, function_name: str) -> ModelConfig | None:
        """Try to load config from DB. Returns None on any failure."""
        try:
            from backend.db.session import async_session
            from sqlalchemy import select, text

            async with async_session() as session:
                # Use raw text to avoid hard dep on ModelFunctionConfig model during init
                result = await session.execute(
                    text(
                        "SELECT provider, model_id, temperature, max_tokens, "
                        "base_url, api_key_override, extra_params FROM model_function_configs "
                        "WHERE function_name = :fn AND is_active = true LIMIT 1"
                    ),
                    {"fn": function_name},
                )
                row = result.fetchone()
                if row:
                    import json
                    return ModelConfig(
                        provider=row[0],
                        model_id=row[1],
                        temperature=float(row[2]),
                        max_tokens=int(row[3]),
                        base_url=row[4] or "",
                        api_key_override=row[5] or "",
                        extra_params=json.loads(row[6]) if row[6] else {},
                    )
        except Exception as exc:
            # DB not ready yet (e.g. first startup) — silently fall back
            if not self._db_checked:
                logger.debug("DB not available for model config lookup: %s", exc)
        return None

    async def _save_to_db(
        self,
        function_name: str,
        config: ModelConfig,
        fallback: ModelConfig | None,
    ) -> None:
        """Upsert model config to DB."""
        try:
            import json
            from backend.db.session import async_session
            from sqlalchemy import text

            fallback_json = json.dumps(fallback.to_dict()) if fallback else None
            extra_json = json.dumps(config.extra_params) if config.extra_params else "{}"

            async with async_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO model_function_configs
                            (function_name, provider, model_id, temperature,
                             max_tokens, base_url, api_key_override, extra_params,
                             fallback_config_json, is_active, updated_at)
                        VALUES
                            (:fn, :provider, :model_id, :temperature,
                             :max_tokens, :base_url, :api_key_override, :extra_params,
                             :fallback_json, true, NOW())
                        ON CONFLICT (function_name) DO UPDATE SET
                            provider = EXCLUDED.provider,
                            model_id = EXCLUDED.model_id,
                            temperature = EXCLUDED.temperature,
                            max_tokens = EXCLUDED.max_tokens,
                            base_url = EXCLUDED.base_url,
                            api_key_override = EXCLUDED.api_key_override,
                            extra_params = EXCLUDED.extra_params,
                            fallback_config_json = EXCLUDED.fallback_config_json,
                            is_active = EXCLUDED.is_active,
                            updated_at = NOW()
                    """),
                    {
                        "fn": function_name,
                        "provider": config.provider,
                        "model_id": config.model_id,
                        "temperature": config.temperature,
                        "max_tokens": config.max_tokens,
                        "base_url": config.base_url,
                        "api_key_override": config.api_key_override,
                        "extra_params": extra_json,
                        "fallback_json": fallback_json,
                    },
                )
                await session.commit()
        except Exception as exc:
            logger.error("Failed to save model config to DB: %s", exc)

    # ------------------------------------------------------------------
    # Env-var and default config helpers
    # ------------------------------------------------------------------

    def _env_config(self, function_name: str) -> ModelConfig | None:
        """Read PURPLELAB_LLM_{FUNCTION}_{FIELD} env vars."""
        prefix = f"PURPLELAB_LLM_{function_name.upper()}_"
        provider = os.environ.get(f"{prefix}PROVIDER")
        model_id = os.environ.get(f"{prefix}MODEL")
        if not provider or not model_id:
            return None
        return ModelConfig(
            provider=provider,
            model_id=model_id,
            temperature=float(os.environ.get(f"{prefix}TEMPERATURE", "0.3")),
            max_tokens=int(os.environ.get(f"{prefix}MAX_TOKENS", "4096")),
            base_url=os.environ.get(f"{prefix}BASE_URL", ""),
            api_key_override=os.environ.get(f"{prefix}API_KEY", ""),
        )

    def _default_config(self, function_name: str) -> ModelConfig:
        """Build default config from available API keys."""
        try:
            from backend.config import settings
            try:
                fn = LLMFunction(function_name)
            except ValueError:
                fn = LLMFunction.AGENT_CHAT
            return default_config(fn, settings)
        except Exception:
            # Absolute fallback
            return ModelConfig(
                provider=LLMProvider.ANTHROPIC,
                model_id="claude-sonnet-4-6",
            )


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_router: LLMRouter | None = None


def get_router() -> LLMRouter:
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router
