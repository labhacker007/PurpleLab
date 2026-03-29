"""Dashboard metrics API — v2.

Single endpoint that returns all KPIs needed for the PurpleLab dashboard.
Uses get_optional_user so it works during development without authentication.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from backend.auth.dependencies import get_optional_user
from backend.db import models
from backend.db.session import async_session

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/metrics")
async def get_metrics(current_user: models.User | None = Depends(get_optional_user)):
    """Return all KPIs needed for the PurpleLab dashboard.

    Each metric is fetched independently; if a query fails the field returns
    its zero/null default rather than crashing the whole response.
    """
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    result: dict = {
        "active_sessions": 0,
        "total_sessions_today": 0,
        "events_generated_today": 0,
        "rules_count": 0,
        "rules_enabled": 0,
        "des_score": None,
        "pending_hitl": 0,
        "siem_connections": 0,
        "siem_connected": 0,
        "threat_actors_count": 0,
        "knowledge_entries_count": 0,
        "joti_connected": False,
        "recent_activity": [],
        "coverage_by_tactic": {},
        "pipeline_runs_today": 0,
        "model_provider": None,
    }

    async with async_session() as db:
        # active_sessions
        try:
            result["active_sessions"] = await db.scalar(
                select(func.count()).select_from(models.SimulationSession).where(
                    models.SimulationSession.status == "running"
                )
            ) or 0
        except Exception:
            pass

        # total_sessions_today
        try:
            result["total_sessions_today"] = await db.scalar(
                select(func.count()).select_from(models.SimulationSession).where(
                    models.SimulationSession.created_at >= today_start
                )
            ) or 0
        except Exception:
            pass

        # events_generated_today
        try:
            result["events_generated_today"] = await db.scalar(
                select(func.count()).select_from(models.GeneratedEvent).where(
                    models.GeneratedEvent.created_at >= today_start
                )
            ) or 0
        except Exception:
            pass

        # rules_count
        try:
            result["rules_count"] = await db.scalar(
                select(func.count()).select_from(models.ImportedRule)
            ) or 0
        except Exception:
            pass

        # rules_enabled  — column is named "enabled" on ImportedRule
        try:
            result["rules_enabled"] = await db.scalar(
                select(func.count()).select_from(models.ImportedRule).where(
                    models.ImportedRule.enabled == True  # noqa: E712
                )
            ) or 0
        except Exception:
            pass

        # pending_hitl
        try:
            result["pending_hitl"] = await db.scalar(
                select(func.count()).select_from(models.HITLApprovalRequest).where(
                    models.HITLApprovalRequest.status == "pending"
                )
            ) or 0
        except Exception:
            pass

        # siem_connections / siem_connected
        try:
            result["siem_connections"] = await db.scalar(
                select(func.count()).select_from(models.SIEMConnection)
            ) or 0
        except Exception:
            pass

        try:
            result["siem_connected"] = await db.scalar(
                select(func.count()).select_from(models.SIEMConnection).where(
                    models.SIEMConnection.is_connected == True  # noqa: E712
                )
            ) or 0
        except Exception:
            pass

        # threat_actors_count
        try:
            result["threat_actors_count"] = await db.scalar(
                select(func.count()).select_from(models.ThreatActor)
            ) or 0
        except Exception:
            pass

        # knowledge_entries_count  — model is KnowledgeEntry if it exists
        try:
            from backend.db import models as m
            if hasattr(m, "KnowledgeEntry"):
                result["knowledge_entries_count"] = await db.scalar(
                    select(func.count()).select_from(m.KnowledgeEntry)
                ) or 0
        except Exception:
            pass

        # recent_activity — last 10 GeneratedEvents
        try:
            rows = await db.execute(
                select(models.GeneratedEvent)
                .order_by(models.GeneratedEvent.created_at.desc())
                .limit(10)
            )
            events = rows.scalars().all()
            result["recent_activity"] = [
                {
                    "id": str(e.id),
                    "source_type": e.product_type,
                    "technique_id": None,  # GeneratedEvent has no technique_id column
                    "severity": e.severity,
                    "created_at": e.created_at.isoformat(),
                }
                for e in events
            ]
        except Exception:
            pass

    # joti_connected — check if JOTI_BASE_URL is configured
    try:
        from backend.config import settings
        result["joti_connected"] = bool(settings.JOTI_BASE_URL)
    except Exception:
        pass

    # model_provider — current AGENT_CHAT provider from LLM router
    try:
        from backend.llm.router import get_router as get_llm_router
        from backend.llm.config import LLMFunction
        llm_router = get_llm_router()
        cfg = llm_router.get_config(LLMFunction.AGENT_CHAT)
        result["model_provider"] = cfg.provider if cfg else None
    except Exception:
        pass

    return result
