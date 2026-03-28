"""Embedding generation for knowledge base documents.

Supports multiple embedding providers with automatic fallback:
- OpenAI text-embedding-3-small (primary, if API key available)
- Sentence-transformers all-MiniLM-L6-v2 (local fallback)
- ChromaDB default embedding function (last resort)
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency imports with graceful fallback
# ---------------------------------------------------------------------------

_openai_available = False
_sentence_transformers_available = False

try:
    import openai as _openai_mod

    _openai_available = True
except ImportError:
    pass

try:
    from sentence_transformers import SentenceTransformer as _SentenceTransformer

    _sentence_transformers_available = True
except ImportError:
    pass


class EmbeddingProvider:
    """Generates text embeddings using the best available provider.

    Parameters
    ----------
    provider : str
        One of ``"auto"``, ``"openai"``, ``"local"``, ``"default"``.
        ``"auto"`` tries OpenAI first, then local sentence-transformers,
        then falls back to a simple hash-based placeholder.
    openai_api_key : str | None
        Optional explicit OpenAI API key.  When *None* the library will
        read ``OPENAI_API_KEY`` from the environment automatically.
    model : str
        OpenAI model name (only used when provider is ``"openai"``).
    """

    def __init__(
        self,
        provider: str = "auto",
        openai_api_key: str | None = None,
        model: str = "text-embedding-3-small",
    ) -> None:
        self._provider = provider
        self._model = model
        self._openai_client: Any = None
        self._local_model: Any = None
        self._dimension: int = 384  # default for MiniLM

        self._resolve_provider(openai_api_key)

    # ------------------------------------------------------------------
    # Provider resolution
    # ------------------------------------------------------------------

    def _resolve_provider(self, openai_api_key: str | None) -> None:
        """Determine which embedding backend to use."""
        if self._provider in ("auto", "openai"):
            if _openai_available:
                try:
                    kwargs: dict[str, Any] = {}
                    if openai_api_key:
                        kwargs["api_key"] = openai_api_key
                    self._openai_client = _openai_mod.OpenAI(**kwargs)
                    self._provider = "openai"
                    self._dimension = 1536
                    logger.info("EmbeddingProvider: using OpenAI %s", self._model)
                    return
                except Exception as exc:
                    logger.warning("OpenAI init failed (%s), trying fallback", exc)

        if self._provider in ("auto", "local"):
            if _sentence_transformers_available:
                try:
                    self._local_model = _SentenceTransformer("all-MiniLM-L6-v2")
                    self._provider = "local"
                    self._dimension = 384
                    logger.info("EmbeddingProvider: using local sentence-transformers")
                    return
                except Exception as exc:
                    logger.warning("Sentence-transformers init failed (%s), using default", exc)

        # Ultimate fallback: deterministic hash-based pseudo-embeddings.
        # Good enough for development / testing without GPU or API key.
        self._provider = "default"
        self._dimension = 384
        logger.info("EmbeddingProvider: using default hash-based embeddings (dev only)")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def dimension(self) -> int:
        """Return the dimensionality of generated embeddings."""
        return self._dimension

    def embed(self, text: str) -> list[float]:
        """Generate an embedding vector for *text*."""
        if self._provider == "openai":
            return self._embed_openai(text)
        if self._provider == "local":
            return self._embed_local(text)
        return self._embed_hash(text)

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a batch of texts."""
        if self._provider == "openai":
            return self._embed_openai_batch(texts)
        if self._provider == "local":
            return self._embed_local_batch(texts)
        return [self._embed_hash(t) for t in texts]

    # ------------------------------------------------------------------
    # Async wrappers (delegate to sync in a thread)
    # ------------------------------------------------------------------

    async def aembed(self, text: str) -> list[float]:
        return await asyncio.to_thread(self.embed, text)

    async def aembed_batch(self, texts: list[str]) -> list[list[float]]:
        return await asyncio.to_thread(self.embed_batch, texts)

    # ------------------------------------------------------------------
    # OpenAI backend
    # ------------------------------------------------------------------

    def _embed_openai(self, text: str) -> list[float]:
        resp = self._openai_client.embeddings.create(input=[text], model=self._model)
        return resp.data[0].embedding

    def _embed_openai_batch(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        # OpenAI supports up to 2048 inputs per call; chunk if needed.
        all_embeddings: list[list[float]] = []
        chunk_size = 2048
        for i in range(0, len(texts), chunk_size):
            chunk = texts[i : i + chunk_size]
            resp = self._openai_client.embeddings.create(input=chunk, model=self._model)
            all_embeddings.extend([d.embedding for d in resp.data])
        return all_embeddings

    # ------------------------------------------------------------------
    # Local sentence-transformers backend
    # ------------------------------------------------------------------

    def _embed_local(self, text: str) -> list[float]:
        vec = self._local_model.encode(text, convert_to_numpy=True)
        return vec.tolist()

    def _embed_local_batch(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        vecs = self._local_model.encode(texts, convert_to_numpy=True, batch_size=64)
        return [v.tolist() for v in vecs]

    # ------------------------------------------------------------------
    # Hash-based fallback (deterministic, no external deps)
    # ------------------------------------------------------------------

    def _embed_hash(self, text: str) -> list[float]:
        """Create a deterministic pseudo-embedding from a SHA-256 hash.

        This is NOT semantically meaningful — it is a stand-in so that the
        rest of the pipeline works without any ML dependencies installed.
        """
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        # Expand hash to fill dimension (384 floats from 64 hex chars)
        values: list[float] = []
        for i in range(self._dimension):
            byte_idx = i % 32
            byte_val = int(digest[byte_idx * 2 : byte_idx * 2 + 2], 16)
            # Normalise to [-1, 1] range with some variation per position
            val = ((byte_val + i) % 256) / 128.0 - 1.0
            values.append(val)
        return values


# ---------------------------------------------------------------------------
# Module-level convenience (backward-compatible with old EmbeddingService name)
# ---------------------------------------------------------------------------

class EmbeddingService(EmbeddingProvider):
    """Alias kept for backward compatibility with existing imports."""

    async def embed(self, text: str) -> list[float]:  # type: ignore[override]
        """Async embed (matches original stub signature)."""
        return await self.aembed(text)

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:  # type: ignore[override]
        """Async batch embed (matches original stub signature)."""
        return await self.aembed_batch(texts)
