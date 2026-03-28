"""ChromaDB vector store wrapper.

Provides async-safe access to ChromaDB for semantic search across
multiple collections (threat_actors, detection_rules, log_schemas,
siem_configs, research_notes).
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: chromadb
# ---------------------------------------------------------------------------
_chromadb_available = False
try:
    import chromadb as _chromadb
    from chromadb.config import Settings as _ChromaSettings

    _chromadb_available = True
except ImportError:
    pass

# Well-known collections
COLLECTIONS = [
    "threat_actors",
    "detection_rules",
    "log_schemas",
    "siem_configs",
    "research_notes",
]


class VectorStore:
    """ChromaDB wrapper for vector storage and retrieval.

    All public methods are ``async``; internally they delegate to the
    synchronous ChromaDB client via :func:`asyncio.to_thread`.

    When ChromaDB is not installed, the store operates in an in-memory
    fallback mode backed by plain Python dicts (no real vector search —
    useful for development / testing only).
    """

    def __init__(self, persist_dir: str = "./data/chroma") -> None:
        self.persist_dir = persist_dir
        self._client: Any = None
        self._fallback: dict[str, dict[str, dict[str, Any]]] = {}  # collection -> id -> doc

        if _chromadb_available:
            try:
                os.makedirs(persist_dir, exist_ok=True)
                self._client = _chromadb.PersistentClient(
                    path=persist_dir,
                    settings=_ChromaSettings(anonymized_telemetry=False),
                )
                logger.info("VectorStore: ChromaDB initialised at %s", persist_dir)
            except Exception as exc:
                logger.warning("ChromaDB init failed (%s), using in-memory fallback", exc)
        else:
            logger.info("VectorStore: chromadb not installed, using in-memory fallback")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_collection(self, name: str) -> Any:
        """Get or create a ChromaDB collection (sync)."""
        assert self._client is not None
        return self._client.get_or_create_collection(name=name)

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def add(
        self,
        collection: str,
        id: str,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a single document to *collection* with auto-embedding."""
        if self._client is not None:
            await asyncio.to_thread(self._add_sync, collection, id, text, metadata)
        else:
            # Fallback
            col = self._fallback.setdefault(collection, {})
            col[id] = {"id": id, "text": text, "metadata": metadata or {}}

    def _add_sync(
        self, collection: str, doc_id: str, text: str, metadata: dict[str, Any] | None
    ) -> None:
        col = self._get_collection(collection)
        clean_meta = self._sanitise_metadata(metadata)
        col.upsert(ids=[doc_id], documents=[text], metadatas=[clean_meta] if clean_meta else None)

    async def add_documents(
        self,
        collection_name: str,
        documents: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
    ) -> None:
        """Batch-add documents (preserves original stub signature)."""
        if ids is None:
            ids = [str(uuid.uuid4()) for _ in documents]
        if self._client is not None:
            await asyncio.to_thread(
                self._add_documents_sync, collection_name, documents, metadatas, ids
            )
        else:
            col = self._fallback.setdefault(collection_name, {})
            for i, doc_id in enumerate(ids):
                col[doc_id] = {
                    "id": doc_id,
                    "text": documents[i],
                    "metadata": (metadatas[i] if metadatas else {}),
                }

    def _add_documents_sync(
        self,
        collection_name: str,
        documents: list[str],
        metadatas: list[dict[str, Any]] | None,
        ids: list[str],
    ) -> None:
        col = self._get_collection(collection_name)
        clean_metas = None
        if metadatas:
            clean_metas = [self._sanitise_metadata(m) for m in metadatas]
        # ChromaDB recommends batches <= 5461
        batch = 5000
        for i in range(0, len(documents), batch):
            col.upsert(
                ids=ids[i : i + batch],
                documents=documents[i : i + batch],
                metadatas=clean_metas[i : i + batch] if clean_metas else None,
            )

    async def search(
        self,
        collection: str,
        query: str,
        top_k: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Semantic search in *collection*."""
        if self._client is not None:
            return await asyncio.to_thread(self._search_sync, collection, query, top_k, where)
        # Fallback: naive substring search
        return self._search_fallback(collection, query, top_k)

    # Alias to keep backward compatibility with original stub
    async def query(
        self,
        collection_name: str,
        query_text: str,
        top_k: int = 10,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Alias for :meth:`search` (matches original stub)."""
        return await self.search(collection_name, query_text, top_k, where)

    def _search_sync(
        self, collection: str, query: str, top_k: int, where: dict[str, Any] | None
    ) -> list[dict[str, Any]]:
        col = self._get_collection(collection)
        kwargs: dict[str, Any] = {"query_texts": [query], "n_results": top_k}
        if where:
            kwargs["where"] = where
        try:
            results = col.query(**kwargs)
        except Exception as exc:
            logger.error("ChromaDB query error: %s", exc)
            return []
        out: list[dict[str, Any]] = []
        if results and results.get("ids"):
            for i, doc_id in enumerate(results["ids"][0]):
                entry: dict[str, Any] = {"id": doc_id}
                if results.get("documents"):
                    entry["text"] = results["documents"][0][i]
                if results.get("metadatas"):
                    entry["metadata"] = results["metadatas"][0][i]
                if results.get("distances"):
                    entry["distance"] = results["distances"][0][i]
                out.append(entry)
        return out

    def _search_fallback(self, collection: str, query: str, top_k: int) -> list[dict[str, Any]]:
        """Very basic substring match for when ChromaDB is unavailable."""
        col = self._fallback.get(collection, {})
        query_lower = query.lower()
        scored: list[tuple[int, dict[str, Any]]] = []
        for doc in col.values():
            text = doc.get("text", "")
            score = text.lower().count(query_lower)
            if score > 0 or not query_lower:
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:top_k]]

    async def get(self, collection: str, id: str) -> dict[str, Any] | None:
        """Get a specific document by ID."""
        if self._client is not None:
            return await asyncio.to_thread(self._get_sync, collection, id)
        col = self._fallback.get(collection, {})
        return col.get(id)

    def _get_sync(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        col = self._get_collection(collection)
        try:
            result = col.get(ids=[doc_id])
        except Exception:
            return None
        if result and result["ids"]:
            entry: dict[str, Any] = {"id": result["ids"][0]}
            if result.get("documents"):
                entry["text"] = result["documents"][0]
            if result.get("metadatas"):
                entry["metadata"] = result["metadatas"][0]
            return entry
        return None

    async def delete(self, collection: str, id: str) -> None:
        """Delete a document by ID."""
        if self._client is not None:
            await asyncio.to_thread(self._delete_sync, collection, id)
        else:
            col = self._fallback.get(collection, {})
            col.pop(id, None)

    def _delete_sync(self, collection: str, doc_id: str) -> None:
        col = self._get_collection(collection)
        col.delete(ids=[doc_id])

    async def list_collections(self) -> list[str]:
        """List all collection names."""
        if self._client is not None:
            return await asyncio.to_thread(self._list_collections_sync)
        return list(self._fallback.keys())

    def _list_collections_sync(self) -> list[str]:
        collections = self._client.list_collections()
        return [c.name for c in collections]

    async def count(self, collection: str) -> int:
        """Count documents in *collection*."""
        if self._client is not None:
            return await asyncio.to_thread(self._count_sync, collection)
        return len(self._fallback.get(collection, {}))

    def _count_sync(self, collection: str) -> int:
        col = self._get_collection(collection)
        return col.count()

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitise_metadata(meta: dict[str, Any] | None) -> dict[str, Any]:
        """ChromaDB metadata values must be str, int, float, or bool.
        Convert or drop anything else."""
        if not meta:
            return {}
        clean: dict[str, Any] = {}
        for k, v in meta.items():
            if isinstance(v, (str, int, float, bool)):
                clean[k] = v
            elif isinstance(v, list):
                clean[k] = ", ".join(str(x) for x in v)
            elif v is None:
                continue
            else:
                clean[k] = str(v)
        return clean
