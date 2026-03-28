"""FastAPI dependency injection providers.

These are used with Depends() in route handlers to inject database sessions,
Redis connections, settings, and other shared resources.

Singletons are initialised lazily on first request and reused across the
application lifetime.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import AsyncGenerator

from backend.config import Settings, settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


async def get_settings() -> Settings:
    """Return application settings."""
    return settings


# ---------------------------------------------------------------------------
# Database (placeholder — not yet wired up)
# ---------------------------------------------------------------------------


async def get_db():
    """Yield an async SQLAlchemy session.

    TODO: Wire up once db/session.py async_session factory is initialized.
    """
    raise NotImplementedError("Database session not yet configured")


# ---------------------------------------------------------------------------
# Redis (placeholder — not yet wired up)
# ---------------------------------------------------------------------------


async def get_redis():
    """Yield a Redis connection.

    TODO: Wire up once redis client is initialized at startup.
    """
    raise NotImplementedError("Redis connection not yet configured")


# ---------------------------------------------------------------------------
# Knowledge base singletons
# ---------------------------------------------------------------------------

_vector_store_instance = None
_knowledge_store_instance = None


def _get_vector_store():
    """Create or return the singleton VectorStore."""
    global _vector_store_instance
    if _vector_store_instance is None:
        from backend.knowledge.vector_store import VectorStore

        _vector_store_instance = VectorStore(persist_dir=settings.CHROMA_PERSIST_DIR)
        logger.info("VectorStore singleton initialised (persist_dir=%s)", settings.CHROMA_PERSIST_DIR)
    return _vector_store_instance


def _get_knowledge_store():
    """Create or return the singleton KnowledgeStore."""
    global _knowledge_store_instance
    if _knowledge_store_instance is None:
        from backend.knowledge.store import KnowledgeStore

        _knowledge_store_instance = KnowledgeStore(vector_store=_get_vector_store())
        logger.info("KnowledgeStore singleton initialised")
    return _knowledge_store_instance


async def get_knowledge_store():
    """FastAPI dependency: return the KnowledgeStore singleton."""
    return _get_knowledge_store()


# ---------------------------------------------------------------------------
# MITRE ATT&CK service
# ---------------------------------------------------------------------------

_mitre_source_instance = None
_mitre_service_instance = None


def _get_mitre_source():
    global _mitre_source_instance
    if _mitre_source_instance is None:
        from backend.threat_intel.sources.mitre_attack import MITREAttackSource

        _mitre_source_instance = MITREAttackSource()
        logger.info("MITREAttackSource singleton initialised")
    return _mitre_source_instance


def _get_mitre_service():
    global _mitre_service_instance
    if _mitre_service_instance is None:
        from backend.threat_intel.mitre_service import MITREService

        _mitre_service_instance = MITREService(
            knowledge_store=_get_knowledge_store(),
            mitre_source=_get_mitre_source(),
        )
        logger.info("MITREService singleton initialised")
    return _mitre_service_instance


async def get_mitre_service():
    """FastAPI dependency: return the MITREService singleton."""
    return _get_mitre_service()


# ---------------------------------------------------------------------------
# Actor service
# ---------------------------------------------------------------------------

_actor_service_instance = None


def _get_actor_service():
    global _actor_service_instance
    if _actor_service_instance is None:
        from backend.threat_intel.actor_service import ActorService

        _actor_service_instance = ActorService(
            knowledge_store=_get_knowledge_store(),
            mitre_service=_get_mitre_service(),
        )
        logger.info("ActorService singleton initialised")
    return _actor_service_instance


async def get_actor_service():
    """FastAPI dependency: return the ActorService singleton."""
    return _get_actor_service()


# ---------------------------------------------------------------------------
# Threat researcher
# ---------------------------------------------------------------------------

_researcher_instance = None


def _get_threat_researcher():
    global _researcher_instance
    if _researcher_instance is None:
        from backend.threat_intel.research import ThreatResearcher
        from backend.threat_intel.sources.web_search import WebSearchSource

        _researcher_instance = ThreatResearcher(
            mitre_source=_get_mitre_source(),
            web_source=WebSearchSource(),
            knowledge=_get_knowledge_store(),
        )
        logger.info("ThreatResearcher singleton initialised")
    return _researcher_instance


async def get_threat_researcher():
    """FastAPI dependency: return the ThreatResearcher singleton."""
    return _get_threat_researcher()
