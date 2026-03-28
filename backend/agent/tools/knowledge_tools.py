"""Knowledge base tools for the agent orchestrator.

Provides tools for searching, storing, and managing knowledge in
the ChromaDB-backed knowledge store.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


def register_tools(registry: ToolRegistry) -> None:
    """Register all knowledge base tools."""

    registry.register(
        name="search_knowledge_base",
        description=(
            "Semantic search across the knowledge base powered by ChromaDB. "
            "Searches within a specific namespace (collection) and returns "
            "the most relevant results with their content and metadata."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query (natural language or keywords).",
                },
                "namespace": {
                    "type": "string",
                    "description": (
                        "The namespace/collection to search in. "
                        "Common namespaces: 'threat_actors', 'detection_rules', "
                        "'log_schemas', 'siem_configs', 'research_notes'."
                    ),
                    "default": "research_notes",
                },
                "top_k": {
                    "type": "integer",
                    "description": "Maximum number of results to return.",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
        handler=_search_knowledge_base,
    )

    registry.register(
        name="save_to_knowledge_base",
        description=(
            "Store a piece of knowledge in the knowledge base. The content "
            "is auto-embedded for semantic search. Use this to save research "
            "findings, analysis results, or any other information for later retrieval."
        ),
        parameters={
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": (
                        "The namespace/collection to store in. "
                        "Common namespaces: 'threat_actors', 'detection_rules', "
                        "'log_schemas', 'siem_configs', 'research_notes'."
                    ),
                },
                "key": {
                    "type": "string",
                    "description": (
                        "A unique key for this entry (used for updates/retrieval). "
                        "Use descriptive, slug-style keys like 'apt29-research-2024'."
                    ),
                },
                "content": {
                    "type": "string",
                    "description": "The text content to store and embed.",
                },
                "metadata": {
                    "type": "object",
                    "description": (
                        "Optional metadata dict to attach to the entry. "
                        "Values must be strings, numbers, or booleans."
                    ),
                    "default": {},
                },
            },
            "required": ["namespace", "key", "content"],
        },
        handler=_save_to_knowledge_base,
    )

    registry.register(
        name="list_knowledge_namespaces",
        description=(
            "List all available namespaces (collections) in the knowledge base "
            "along with document counts and statistics."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_list_knowledge_namespaces,
    )


def _build_knowledge_store() -> Any:
    """Lazily construct a KnowledgeStore."""
    from backend.knowledge.vector_store import VectorStore
    from backend.knowledge.store import KnowledgeStore

    vector_store = VectorStore()
    return KnowledgeStore(vector_store)


async def _search_knowledge_base(
    query: str, namespace: str = "research_notes", top_k: int = 5
) -> dict[str, Any]:
    """Search the knowledge base semantically."""
    try:
        store = _build_knowledge_store()
        results = await store.search_knowledge(namespace, query, top_k=top_k)

        entries = []
        for r in results:
            entry: dict[str, Any] = {
                "id": r.get("id", ""),
                "text": r.get("text", ""),
                "metadata": r.get("metadata", {}),
            }
            if "distance" in r:
                entry["relevance_distance"] = r["distance"]
            entries.append(entry)

        return {
            "status": "success",
            "query": query,
            "namespace": namespace,
            "count": len(entries),
            "results": entries,
        }
    except Exception as exc:
        logger.exception("search_knowledge_base failed")
        return {"error": f"Failed to search knowledge base: {exc}"}


async def _save_to_knowledge_base(
    namespace: str, key: str, content: str, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Store knowledge in the knowledge base."""
    try:
        store = _build_knowledge_store()
        await store.store_knowledge(namespace, key, content, metadata=metadata)
        return {
            "status": "success",
            "namespace": namespace,
            "key": key,
            "content_length": len(content),
            "message": f"Successfully stored entry '{key}' in namespace '{namespace}'.",
        }
    except Exception as exc:
        logger.exception("save_to_knowledge_base failed")
        return {"error": f"Failed to save to knowledge base: {exc}"}


async def _list_knowledge_namespaces() -> dict[str, Any]:
    """List all namespaces in the knowledge base."""
    try:
        store = _build_knowledge_store()
        stats = await store.get_stats()
        return {
            "status": "success",
            "total_documents": stats.get("total_documents", 0),
            "namespaces": [
                {"name": name, "document_count": count}
                for name, count in stats.get("sources", {}).items()
            ],
            "well_known_namespaces": [
                {"name": "threat_actors", "purpose": "Threat actor profiles and intelligence"},
                {"name": "detection_rules", "purpose": "Detection rule metadata and MITRE mappings"},
                {"name": "log_schemas", "purpose": "Log source field schemas"},
                {"name": "siem_configs", "purpose": "SIEM connection configurations"},
                {"name": "research_notes", "purpose": "Research findings and analysis notes"},
            ],
        }
    except Exception as exc:
        logger.exception("list_knowledge_namespaces failed")
        return {"error": f"Failed to list knowledge namespaces: {exc}"}
