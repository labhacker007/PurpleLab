"""Knowledge base CRUD and semantic search endpoints for v2 API.

Documents (procedures, playbooks, runbooks, techniques, custom) are stored in
Postgres and indexed into ChromaDB for semantic retrieval during simulations
and rule generation.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from backend.auth.dependencies import get_current_active_user
from backend.config import settings
from backend.db import models
from backend.db.session import async_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/knowledge", tags=["knowledge"])

# ---------------------------------------------------------------------------
# ChromaDB helpers — wrapped so failures never break the DB layer
# ---------------------------------------------------------------------------

_chroma_client = None
_chroma_collection = None

CHROMA_COLLECTION = "purplelab_knowledge"


def _get_chroma_collection():
    """Lazily initialise the ChromaDB persistent client and collection."""
    global _chroma_client, _chroma_collection
    if _chroma_collection is not None:
        return _chroma_collection
    try:
        import chromadb
        _chroma_client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
        _chroma_collection = _chroma_client.get_or_create_collection(
            name=CHROMA_COLLECTION,
            metadata={"hnsw:space": "cosine"},
        )
        return _chroma_collection
    except Exception as exc:
        logger.warning("ChromaDB init failed: %s", exc)
        return None


async def _embed_document(doc_id: str, content: str, metadata: dict) -> bool:
    """Add / update a document embedding in ChromaDB. Returns True on success."""
    try:
        collection = _get_chroma_collection()
        if collection is None:
            return False
        # ChromaDB's default embedding function (sentence-transformers) is used
        # when no embeddings are supplied explicitly.
        collection.upsert(
            ids=[doc_id],
            documents=[content],
            metadatas=[metadata],
        )
        return True
    except Exception as exc:
        logger.warning("ChromaDB embed failed for %s: %s", doc_id, exc)
        return False


async def _delete_from_chroma(doc_id: str) -> None:
    """Remove a document from ChromaDB; silently ignores errors."""
    try:
        collection = _get_chroma_collection()
        if collection is None:
            return
        collection.delete(ids=[doc_id])
    except Exception as exc:
        logger.warning("ChromaDB delete failed for %s: %s", doc_id, exc)


# ---------------------------------------------------------------------------
# Background embedding task
# ---------------------------------------------------------------------------

async def _background_embed(doc_id: str) -> None:
    """Fetch document from DB, embed it, update embedding_status."""
    async with async_session() as db:
        try:
            result = await db.execute(
                select(models.KnowledgeDocument).where(models.KnowledgeDocument.id == uuid.UUID(doc_id))
            )
            doc = result.scalar_one_or_none()
            if doc is None:
                return

            metadata = {
                "title": doc.title,
                "doc_type": doc.doc_type,
                "tags": ",".join(doc.tags or []),
            }
            success = await _embed_document(doc_id, doc.content, metadata)

            doc.embedding_status = "indexed" if success else "failed"
            doc.updated_at = datetime.utcnow()
            await db.commit()
        except Exception as exc:
            logger.error("Background embed error for %s: %s", doc_id, exc)
            try:
                result = await db.execute(
                    select(models.KnowledgeDocument).where(
                        models.KnowledgeDocument.id == uuid.UUID(doc_id)
                    )
                )
                doc = result.scalar_one_or_none()
                if doc:
                    doc.embedding_status = "failed"
                    await db.commit()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class DocumentListItem(BaseModel):
    id: str
    title: str
    doc_type: str
    tags: list[str]
    created_at: str
    embedding_status: str


class DocumentDetail(BaseModel):
    id: str
    title: str
    content: str
    doc_type: str
    tags: list[str]
    source_url: Optional[str]
    created_by: Optional[str]
    created_at: str
    updated_at: str
    embedding_status: str


class CreateDocumentRequest(BaseModel):
    title: str
    content: str
    doc_type: str = "custom"
    tags: list[str] = Field(default_factory=list)
    source_url: Optional[str] = None


class UpdateDocumentRequest(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    doc_type: Optional[str] = None
    tags: Optional[list[str]] = None
    source_url: Optional[str] = None


class SemanticSearchRequest(BaseModel):
    query: str
    limit: int = Field(default=10, ge=1, le=50)
    doc_type: Optional[str] = None


class SemanticSearchResult(BaseModel):
    id: str
    title: str
    doc_type: str
    similarity_score: float
    excerpt: str


class ImportURLRequest(BaseModel):
    url: str
    title: Optional[str] = None


class KnowledgeStats(BaseModel):
    total_docs: int
    indexed_docs: int
    pending_docs: int
    doc_types: dict[str, int]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _doc_to_list_item(doc: models.KnowledgeDocument) -> DocumentListItem:
    return DocumentListItem(
        id=str(doc.id),
        title=doc.title,
        doc_type=doc.doc_type,
        tags=doc.tags or [],
        created_at=doc.created_at.isoformat(),
        embedding_status=doc.embedding_status,
    )


def _doc_to_detail(doc: models.KnowledgeDocument) -> DocumentDetail:
    return DocumentDetail(
        id=str(doc.id),
        title=doc.title,
        content=doc.content,
        doc_type=doc.doc_type,
        tags=doc.tags or [],
        source_url=doc.source_url,
        created_by=doc.created_by,
        created_at=doc.created_at.isoformat(),
        updated_at=doc.updated_at.isoformat(),
        embedding_status=doc.embedding_status,
    )


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=KnowledgeStats)
async def knowledge_stats(
    current_user: models.User = Depends(get_current_active_user),
):
    """Return aggregate counts for the knowledge base."""
    async with async_session() as db:
        total_result = await db.execute(select(func.count()).select_from(models.KnowledgeDocument))
        total = total_result.scalar_one()

        indexed_result = await db.execute(
            select(func.count()).select_from(models.KnowledgeDocument).where(
                models.KnowledgeDocument.embedding_status == "indexed"
            )
        )
        indexed = indexed_result.scalar_one()

        pending_result = await db.execute(
            select(func.count()).select_from(models.KnowledgeDocument).where(
                models.KnowledgeDocument.embedding_status == "pending"
            )
        )
        pending = pending_result.scalar_one()

        type_results = await db.execute(
            select(models.KnowledgeDocument.doc_type, func.count().label("cnt"))
            .group_by(models.KnowledgeDocument.doc_type)
        )
        doc_types = {row.doc_type: row.cnt for row in type_results}

        return KnowledgeStats(
            total_docs=total,
            indexed_docs=indexed,
            pending_docs=pending,
            doc_types=doc_types,
        )


@router.get("", response_model=list[DocumentListItem])
async def list_documents(
    doc_type: Optional[str] = Query(None, description="Filter by doc_type"),
    search: Optional[str] = Query(None, description="ilike search on title + content"),
    limit: int = Query(50, ge=1, le=200),
    current_user: models.User = Depends(get_current_active_user),
):
    """List knowledge documents with optional type/search filtering."""
    async with async_session() as db:
        stmt = select(models.KnowledgeDocument).order_by(
            models.KnowledgeDocument.updated_at.desc()
        )
        if doc_type:
            stmt = stmt.where(models.KnowledgeDocument.doc_type == doc_type)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    models.KnowledgeDocument.title.ilike(pattern),
                    models.KnowledgeDocument.content.ilike(pattern),
                )
            )
        stmt = stmt.limit(limit)
        result = await db.execute(stmt)
        docs = result.scalars().all()
        return [_doc_to_list_item(d) for d in docs]


@router.post("", response_model=DocumentDetail, status_code=status.HTTP_201_CREATED)
async def create_document(
    req: CreateDocumentRequest,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_active_user),
):
    """Create a new knowledge document and queue it for embedding."""
    async with async_session() as db:
        doc = models.KnowledgeDocument(
            title=req.title,
            content=req.content,
            doc_type=req.doc_type,
            tags=req.tags,
            source_url=req.source_url,
            created_by=current_user.email,
            embedding_status="pending",
        )
        db.add(doc)
        await db.commit()
        await db.refresh(doc)
        doc_id = str(doc.id)

    background_tasks.add_task(_background_embed, doc_id)
    # Re-fetch from fresh session to return
    async with async_session() as db:
        result = await db.execute(
            select(models.KnowledgeDocument).where(models.KnowledgeDocument.id == uuid.UUID(doc_id))
        )
        doc = result.scalar_one()
        return _doc_to_detail(doc)


@router.get("/search", response_model=list[SemanticSearchResult])
async def semantic_search_get(
    q: str = Query(..., description="Semantic search query"),
    limit: int = Query(10, ge=1, le=50),
    doc_type: Optional[str] = Query(None),
    current_user: models.User = Depends(get_current_active_user),
):
    """Semantic search via GET (for simple clients)."""
    return await _do_semantic_search(q, limit, doc_type)


@router.post("/search", response_model=list[SemanticSearchResult])
async def semantic_search(
    req: SemanticSearchRequest,
    current_user: models.User = Depends(get_current_active_user),
):
    """Semantic search over the knowledge base using ChromaDB embeddings."""
    return await _do_semantic_search(req.query, req.limit, req.doc_type)


async def _do_semantic_search(
    query: str, limit: int, doc_type: Optional[str]
) -> list[SemanticSearchResult]:
    try:
        collection = _get_chroma_collection()
        if collection is None:
            raise ValueError("ChromaDB not available")

        where: dict | None = {"doc_type": doc_type} if doc_type else None
        chroma_result = collection.query(
            query_texts=[query],
            n_results=min(limit, max(1, collection.count())),
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        ids = chroma_result.get("ids", [[]])[0]
        distances = chroma_result.get("distances", [[]])[0]
        metadatas = chroma_result.get("metadatas", [[]])[0]
        documents = chroma_result.get("documents", [[]])[0]

        results: list[SemanticSearchResult] = []
        for i, doc_id in enumerate(ids):
            dist = distances[i] if i < len(distances) else 1.0
            # cosine distance → similarity score (0-1)
            score = round(max(0.0, 1.0 - float(dist)), 4)
            meta = metadatas[i] if i < len(metadatas) else {}
            raw_doc = documents[i] if i < len(documents) else ""
            excerpt = raw_doc[:300] + ("..." if len(raw_doc) > 300 else "")
            results.append(SemanticSearchResult(
                id=doc_id,
                title=meta.get("title", "Untitled"),
                doc_type=meta.get("doc_type", "custom"),
                similarity_score=score,
                excerpt=excerpt,
            ))
        return results

    except Exception as exc:
        logger.warning("Semantic search failed, falling back to keyword: %s", exc)
        # Graceful fallback: keyword search in Postgres
        async with async_session() as db:
            pattern = f"%{query}%"
            stmt = select(models.KnowledgeDocument).where(
                or_(
                    models.KnowledgeDocument.title.ilike(pattern),
                    models.KnowledgeDocument.content.ilike(pattern),
                )
            ).limit(limit)
            if doc_type:
                stmt = stmt.where(models.KnowledgeDocument.doc_type == doc_type)
            result = await db.execute(stmt)
            docs = result.scalars().all()
            return [
                SemanticSearchResult(
                    id=str(d.id),
                    title=d.title,
                    doc_type=d.doc_type,
                    similarity_score=0.0,
                    excerpt=(d.content[:300] + "...") if len(d.content) > 300 else d.content,
                )
                for d in docs
            ]


@router.post("/import-url", response_model=DocumentDetail, status_code=status.HTTP_201_CREATED)
async def import_url(
    req: ImportURLRequest,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_active_user),
):
    """Fetch a URL, strip HTML, and create a knowledge document from it."""
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(req.url, headers={"User-Agent": "PurpleLab/2.0"})
            resp.raise_for_status()
            raw = resp.text
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {exc}")

    content = _strip_html(raw)
    title = req.title or req.url

    async with async_session() as db:
        doc = models.KnowledgeDocument(
            title=title,
            content=content,
            doc_type="custom",
            tags=[],
            source_url=req.url,
            created_by=current_user.email,
            embedding_status="pending",
        )
        db.add(doc)
        await db.commit()
        await db.refresh(doc)
        doc_id = str(doc.id)

    background_tasks.add_task(_background_embed, doc_id)
    async with async_session() as db:
        result = await db.execute(
            select(models.KnowledgeDocument).where(models.KnowledgeDocument.id == uuid.UUID(doc_id))
        )
        doc = result.scalar_one()
        return _doc_to_detail(doc)


@router.get("/{doc_id}", response_model=DocumentDetail)
async def get_document(
    doc_id: str,
    current_user: models.User = Depends(get_current_active_user),
):
    """Retrieve a single knowledge document including full content."""
    async with async_session() as db:
        try:
            uid = uuid.UUID(doc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid document ID")
        result = await db.execute(
            select(models.KnowledgeDocument).where(models.KnowledgeDocument.id == uid)
        )
        doc = result.scalar_one_or_none()
        if doc is None:
            raise HTTPException(status_code=404, detail="Document not found")
        return _doc_to_detail(doc)


@router.put("/{doc_id}", response_model=DocumentDetail)
async def update_document(
    doc_id: str,
    req: UpdateDocumentRequest,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_active_user),
):
    """Update a knowledge document. Content changes reset embedding_status to pending."""
    async with async_session() as db:
        try:
            uid = uuid.UUID(doc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid document ID")
        result = await db.execute(
            select(models.KnowledgeDocument).where(models.KnowledgeDocument.id == uid)
        )
        doc = result.scalar_one_or_none()
        if doc is None:
            raise HTTPException(status_code=404, detail="Document not found")

        content_changed = False
        if req.title is not None:
            doc.title = req.title
        if req.content is not None and req.content != doc.content:
            doc.content = req.content
            content_changed = True
        if req.doc_type is not None:
            doc.doc_type = req.doc_type
        if req.tags is not None:
            doc.tags = req.tags
        if req.source_url is not None:
            doc.source_url = req.source_url

        if content_changed:
            doc.embedding_status = "pending"

        doc.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(doc)

    if content_changed:
        background_tasks.add_task(_background_embed, doc_id)

    async with async_session() as db:
        result = await db.execute(
            select(models.KnowledgeDocument).where(models.KnowledgeDocument.id == uid)
        )
        doc = result.scalar_one()
        return _doc_to_detail(doc)


@router.delete("/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    doc_id: str,
    current_user: models.User = Depends(get_current_active_user),
):
    """Delete a knowledge document from the DB and remove its ChromaDB embedding."""
    async with async_session() as db:
        try:
            uid = uuid.UUID(doc_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid document ID")
        result = await db.execute(
            select(models.KnowledgeDocument).where(models.KnowledgeDocument.id == uid)
        )
        doc = result.scalar_one_or_none()
        if doc is None:
            raise HTTPException(status_code=404, detail="Document not found")
        await db.delete(doc)
        await db.commit()

    await _delete_from_chroma(doc_id)
