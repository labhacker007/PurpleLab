"""Semantic LLM response cache backed by Redis.

Two-tier caching strategy:
  1. Exact hash cache: SHA-256 of (function + full prompt) → instant hit, zero compute
  2. Semantic cache: embed prompt → cosine similarity search → fuzzy hit (optional)

Semantic cache uses sentence-transformers/all-MiniLM-L6-v2 if available (free, CPU,
~80MB). Falls back to exact-hash-only if not installed.

Cache keys:
  llm:exact:{sha256}        → cached response string (TTL per function)
  llm:sem:idx:{fn}          → Redis hash of {key → JSON embedding vector}
  llm:sem:{key}             → cached response string

TTL policy (per LLMFunction volume):
  high volume (LOG_GENERATION): 4 hours
  medium volume (THREAT_INTEL, RULE_ANALYSIS, SIGMA_TRANSLATION): 24 hours
  low volume (AGENT_CHAT, ATTACK_CHAIN_PLAN): no cache (dynamic/streaming)
  HITL_REVIEW: 1 hour (volume=low → mapped to 3600)
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from backend.llm.config import LLMFunction, FUNCTION_METADATA

logger = logging.getLogger(__name__)

# Semantic similarity threshold — prompts with cosine similarity above this
# are considered "the same question" and will return the cached response.
_SIMILARITY_THRESHOLD = 0.93

# Maximum number of semantic index entries per function before eviction.
_MAX_SEM_ENTRIES = 1000

# Functions that must never be cached (dynamic / streaming).
_NO_CACHE_FUNCTIONS = {LLMFunction.AGENT_CHAT, LLMFunction.ATTACK_CHAIN_PLAN}


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two equal-length vectors."""
    try:
        import numpy as np
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))
    except ImportError:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x ** 2 for x in a) ** 0.5
        norm_b = sum(x ** 2 for x in b) ** 0.5
        return dot / (norm_a * norm_b) if norm_a and norm_b else 0.0


class LLMCache:
    """Two-tier semantic + exact response cache.

    All Redis operations are wrapped in try/except so that any Redis failure
    is transparent — callers always proceed to the real LLM if the cache is
    unavailable.
    """

    def __init__(self, redis_client: Any = None) -> None:
        self._redis = redis_client
        self._encoder: Any = None         # sentence-transformers model (lazy-loaded)
        self._use_semantic: bool | None = None  # None = not yet attempted

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(
        self,
        fn: LLMFunction,
        messages: list[dict],
        system: str = "",
    ) -> str | None:
        """Check cache. Returns cached response string or None on miss."""
        if self._redis is None:
            return None
        if fn in _NO_CACHE_FUNCTIONS:
            return None

        key = self._cache_key(fn, messages, system)
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")

        # -- 1. Exact hash cache ------------------------------------------
        try:
            cached = await self._redis.get(f"llm:exact:{key}")
            if cached is not None:
                logger.debug("LLM cache HIT (exact) fn=%s", fn.value)
                await self._incr_stat("hits", date_str)
                return cached
        except Exception as exc:
            logger.debug("LLM exact-cache GET error: %s", exc)

        # -- 2. Semantic cache --------------------------------------------
        self._try_load_encoder()
        if self._use_semantic:
            prompt_text = self._messages_to_text(messages, system)
            try:
                sem_result = await self._semantic_get(fn, prompt_text)
                if sem_result is not None:
                    await self._incr_stat("hits", date_str)
                    return sem_result
            except Exception as exc:
                logger.debug("LLM semantic-cache GET error: %s", exc)

        await self._incr_stat("misses", date_str)
        return None

    async def set(
        self,
        fn: LLMFunction,
        messages: list[dict],
        system: str,
        response: str,
    ) -> None:
        """Store response in cache (exact hash + optional semantic index)."""
        if self._redis is None:
            return
        if fn in _NO_CACHE_FUNCTIONS:
            return

        ttl = self._get_ttl(fn)
        if ttl is None:
            return

        key = self._cache_key(fn, messages, system)

        # -- 1. Exact hash cache ------------------------------------------
        try:
            await self._redis.set(f"llm:exact:{key}", response, ex=ttl)
        except Exception as exc:
            logger.debug("LLM exact-cache SET error: %s", exc)

        # -- 2. Semantic index --------------------------------------------
        self._try_load_encoder()
        if self._use_semantic:
            prompt_text = self._messages_to_text(messages, system)
            try:
                await self._semantic_set(fn, prompt_text, key, response)
            except Exception as exc:
                logger.debug("LLM semantic-cache SET error: %s", exc)

    # ------------------------------------------------------------------
    # Key / TTL helpers
    # ------------------------------------------------------------------

    def _cache_key(
        self,
        fn: LLMFunction,
        messages: list[dict],
        system: str,
    ) -> str:
        """SHA-256 hash of function + messages + system prompt."""
        content = json.dumps(
            {"fn": fn.value, "messages": messages, "system": system},
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_ttl(self, fn: LLMFunction) -> int | None:
        """Return TTL in seconds, or None to skip caching entirely."""
        if fn in _NO_CACHE_FUNCTIONS:
            return None

        meta = FUNCTION_METADATA.get(fn.value, {})
        volume = meta.get("volume", "medium")

        return {
            "high": 4 * 3600,       # 4 h — LOG_GENERATION
            "medium": 24 * 3600,    # 24 h — THREAT_INTEL, RULE_ANALYSIS, SIGMA_TRANSLATION
            "low": 3600,            # 1 h — HITL_REVIEW, SCORING_ASSIST
        }.get(volume, 3600)

    # ------------------------------------------------------------------
    # Encoder helpers
    # ------------------------------------------------------------------

    def _try_load_encoder(self) -> None:
        """Lazy-load sentence-transformers. Silently skip if not installed."""
        if self._use_semantic is not None:
            # Already attempted (True = loaded, False = not available)
            return
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import]
            self._encoder = SentenceTransformer("all-MiniLM-L6-v2")
            self._use_semantic = True
            logger.info("LLM semantic cache enabled (all-MiniLM-L6-v2)")
        except ImportError:
            self._use_semantic = False
            logger.debug(
                "sentence-transformers not installed — LLM cache running in exact-hash-only mode"
            )
        except Exception as exc:
            self._use_semantic = False
            logger.warning("Failed to load sentence-transformers encoder: %s", exc)

    def _embed(self, text: str) -> list[float]:
        """Return embedding vector for text. Assumes encoder is loaded."""
        vec = self._encoder.encode(text, convert_to_numpy=True)
        # Ensure plain Python list so it serialises cleanly to JSON
        return vec.tolist()

    # ------------------------------------------------------------------
    # Semantic cache internals
    # ------------------------------------------------------------------

    async def _semantic_get(
        self,
        fn: LLMFunction,
        prompt_text: str,
    ) -> str | None:
        """Search Redis semantic index for a similar cached prompt.

        Returns the cached response if cosine similarity > threshold, else None.
        """
        idx_key = f"llm:sem:idx:{fn.value}"

        # Load all stored embeddings for this function
        try:
            raw_index: dict[str, str] = await self._redis.hgetall(idx_key)
        except Exception as exc:
            logger.debug("LLM sem idx HGETALL error: %s", exc)
            return None

        if not raw_index:
            return None

        query_vec = self._embed(prompt_text)

        best_key: str | None = None
        best_score = -1.0

        for cache_key, vec_json in raw_index.items():
            try:
                stored_vec: list[float] = json.loads(vec_json)
                score = _cosine_similarity(query_vec, stored_vec)
                if score > best_score:
                    best_score = score
                    best_key = cache_key
            except Exception:
                continue  # corrupt entry — skip

        if best_key is not None and best_score >= _SIMILARITY_THRESHOLD:
            try:
                response = await self._redis.get(f"llm:sem:{best_key}")
                if response is not None:
                    logger.debug(
                        "LLM cache HIT (semantic) fn=%s similarity=%.3f",
                        fn.value,
                        best_score,
                    )
                    return response
            except Exception as exc:
                logger.debug("LLM sem response GET error: %s", exc)

        return None

    async def _semantic_set(
        self,
        fn: LLMFunction,
        prompt_text: str,
        cache_key: str,
        response: str,
    ) -> None:
        """Store embedding vector in semantic index and response in its own key."""
        idx_key = f"llm:sem:idx:{fn.value}"
        response_key = f"llm:sem:{cache_key}"
        ttl = self._get_ttl(fn)

        # Enforce max index size (evict oldest entry on overflow)
        try:
            current_size = await self._redis.hlen(idx_key)
            if current_size >= _MAX_SEM_ENTRIES:
                # Fetch all keys and remove the first one (oldest by insertion order in Redis 7+)
                existing_keys: list[str] = await self._redis.hkeys(idx_key)
                if existing_keys:
                    evict_key = existing_keys[0]
                    await self._redis.hdel(idx_key, evict_key)
                    await self._redis.delete(f"llm:sem:{evict_key}")
                    logger.debug(
                        "LLM sem cache evicted entry for fn=%s (index at capacity)",
                        fn.value,
                    )
        except Exception as exc:
            logger.debug("LLM sem eviction error: %s", exc)

        vec = self._embed(prompt_text)
        vec_json = json.dumps(vec)

        try:
            await self._redis.hset(idx_key, cache_key, vec_json)
            await self._redis.set(response_key, response, ex=ttl)
            # The index itself should live at least as long as the longest TTL
            if ttl:
                await self._redis.expire(idx_key, ttl)
        except Exception as exc:
            logger.debug("LLM sem SET error: %s", exc)

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    async def _incr_stat(self, kind: str, date_str: str) -> None:
        """Increment hit/miss counter in Redis. Silently swallows errors."""
        if self._redis is None:
            return
        try:
            stat_key = f"llm:stats:{kind}:{date_str}"
            await self._redis.incr(stat_key)
            await self._redis.expire(stat_key, 86400 * 2)  # keep 2 days
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Text helpers
    # ------------------------------------------------------------------

    def _messages_to_text(self, messages: list[dict], system: str) -> str:
        """Flatten messages to a single string for embedding."""
        parts: list[str] = []
        if system:
            parts.append(f"SYSTEM: {system}")
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if isinstance(content, list):  # handle Anthropic content blocks
                content = " ".join(
                    c.get("text", "") for c in content if isinstance(c, dict)
                )
            parts.append(f"{role.upper()}: {content}")
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_cache: LLMCache | None = None


def get_llm_cache(redis_client: Any = None) -> LLMCache:
    """Return the global LLMCache instance, creating it if necessary.

    Pass redis_client on first call (from startup) to wire in Redis.
    Subsequent calls with redis_client=None will return the existing instance.
    """
    global _cache
    if _cache is None:
        _cache = LLMCache(redis_client)
    elif redis_client is not None and _cache._redis is None:
        # Late-wire Redis (e.g. Redis connected after cache was first accessed)
        _cache._redis = redis_client
    return _cache
