"""Unified knowledge store interface.

Combines vector-based semantic search (ChromaDB) with structured
metadata for a single, ergonomic API used by the rest of the app.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from backend.knowledge.vector_store import VectorStore

logger = logging.getLogger(__name__)

# Namespace → ChromaDB collection mapping
_NAMESPACE_COLLECTION: dict[str, str] = {
    "threat_actors": "threat_actors",
    "detection_rules": "detection_rules",
    "log_schemas": "log_schemas",
    "siem_configs": "siem_configs",
    "research_notes": "research_notes",
    # Allow arbitrary namespaces too — they map to themselves
}


class KnowledgeStore:
    """Unified interface combining vector DB and structured storage.

    Every knowledge entry is stored as a document in ChromaDB with its
    text content (auto-embedded) and arbitrary metadata.
    """

    def __init__(self, vector_store: VectorStore) -> None:
        self.vector = vector_store

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collection_for(namespace: str) -> str:
        return _NAMESPACE_COLLECTION.get(namespace, namespace)

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    async def store_knowledge(
        self,
        namespace: str,
        key: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store a knowledge entry with vector embedding."""
        meta = dict(metadata) if metadata else {}
        meta.setdefault("namespace", namespace)
        meta.setdefault("key", key)
        meta["indexed_at"] = datetime.now(timezone.utc).isoformat()

        collection = self._collection_for(namespace)
        await self.vector.add(collection=collection, id=key, text=content, metadata=meta)
        logger.debug("Stored knowledge: %s/%s (%d chars)", namespace, key, len(content))

    async def search_knowledge(
        self,
        namespace: str,
        query: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Semantic search across the knowledge base within *namespace*."""
        collection = self._collection_for(namespace)
        results = await self.vector.search(collection=collection, query=query, top_k=top_k)
        return results

    async def get_knowledge(
        self,
        namespace: str,
        key: str,
    ) -> dict[str, Any] | None:
        """Get a specific knowledge entry by key."""
        collection = self._collection_for(namespace)
        return await self.vector.get(collection=collection, id=key)

    async def delete_knowledge(self, namespace: str, key: str) -> None:
        """Delete a knowledge entry."""
        collection = self._collection_for(namespace)
        await self.vector.delete(collection=collection, id=key)
        logger.debug("Deleted knowledge: %s/%s", namespace, key)

    # ------------------------------------------------------------------
    # Unified search (backward-compatible with original stub)
    # ------------------------------------------------------------------

    async def search(
        self,
        query: str,
        top_k: int = 10,
        source_filter: str = "",
    ) -> list[dict[str, Any]]:
        """Search the knowledge base, optionally filtering by source/namespace.

        If *source_filter* is provided, search only that collection.
        Otherwise search across all known collections and merge results.
        """
        if source_filter:
            return await self.search_knowledge(source_filter, query, top_k)

        # Search all collections and merge
        all_results: list[dict[str, Any]] = []
        collections = await self.vector.list_collections()
        for col_name in collections:
            results = await self.vector.search(collection=col_name, query=query, top_k=top_k)
            for r in results:
                r.setdefault("collection", col_name)
            all_results.extend(results)

        # Sort by distance (lower is better) if available
        all_results.sort(key=lambda r: r.get("distance", float("inf")))
        return all_results[:top_k]

    async def index_document(
        self,
        content: str,
        metadata: dict[str, Any] | None = None,
        source: str = "custom",
    ) -> str:
        """Index a document into the knowledge base (backward-compatible)."""
        import uuid

        key = str(uuid.uuid4())
        namespace = source if source else "research_notes"
        await self.store_knowledge(namespace, key, content, metadata)
        return key

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict[str, Any]:
        """Get knowledge base statistics."""
        collections = await self.vector.list_collections()
        sources: dict[str, int] = {}
        total = 0
        for col_name in collections:
            count = await self.vector.count(col_name)
            sources[col_name] = count
            total += count
        return {
            "total_documents": total,
            "sources": sources,
            "collections": collections,
        }
