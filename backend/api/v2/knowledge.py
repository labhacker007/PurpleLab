"""Knowledge base search endpoints for v2 API.

Provides semantic search over indexed security knowledge:
MITRE ATT&CK, detection rules, threat reports, and custom documents.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from backend.dependencies import get_knowledge_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class IndexDocumentRequest(BaseModel):
    content: str
    source: str = "custom"
    metadata: dict[str, Any] | None = None


class IndexDocumentResponse(BaseModel):
    id: str
    status: str = "indexed"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/search")
async def search_knowledge(
    q: str = Query(..., description="Search query"),
    top_k: int = Query(10, ge=1, le=50),
    source_filter: str = Query("", description="Filter by source: mitre, sigma, custom, threat_actors, detection_rules, etc."),
    knowledge=Depends(get_knowledge_store),
):
    """Semantic search across the knowledge base.

    Uses vector embeddings (ChromaDB) to find relevant documents
    matching the query.
    """
    try:
        results = await knowledge.search(query=q, top_k=top_k, source_filter=source_filter)
        return {"query": q, "results": results, "total": len(results)}
    except Exception as exc:
        logger.error("Knowledge search failed: %s", exc)
        return {"query": q, "results": [], "total": 0, "error": str(exc)}


@router.post("/index", response_model=IndexDocumentResponse)
async def index_document(
    req: IndexDocumentRequest,
    knowledge=Depends(get_knowledge_store),
):
    """Index a new document into the knowledge base."""
    try:
        doc_id = await knowledge.index_document(
            content=req.content,
            metadata=req.metadata,
            source=req.source,
        )
        return IndexDocumentResponse(id=doc_id, status="indexed")
    except Exception as exc:
        logger.error("Knowledge indexing failed: %s", exc)
        return IndexDocumentResponse(id="", status=f"error: {exc}")


@router.get("/stats")
async def knowledge_stats(
    knowledge=Depends(get_knowledge_store),
):
    """Get knowledge base statistics."""
    try:
        stats = await knowledge.get_stats()
        return stats
    except Exception as exc:
        logger.error("Knowledge stats failed: %s", exc)
        return {
            "total_documents": 0,
            "sources": {},
            "error": str(exc),
        }
