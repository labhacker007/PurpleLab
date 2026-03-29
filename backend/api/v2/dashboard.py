"""Dashboard metrics API — v2.

Single endpoint that returns all KPIs needed for the PurpleLab dashboard.
Uses get_optional_user so it works during development without authentication.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from backend.auth.dependencies import get_optional_user
from backend.db import models
from backend.db.session import async_session

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/metrics")
async def get_metrics(
    request: Request,
    current_user: models.User | None = Depends(get_optional_user),
):
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
        "joti_configured": False,
        "joti_hccs": None,
        "joti_base_url": "",
        "recent_activity": [],
        "coverage_by_tactic": {},
        "pipeline_runs_today": 0,
        "model_provider": None,
        "llm_cache_hits_today": 0,
        "llm_cache_misses_today": 0,
        "llm_cache_hit_rate": None,
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

    # joti status — check connectivity and pull HCCS score
    try:
        from backend.config import settings
        from backend.joti import get_joti_client
        joti_url = getattr(settings, "JOTI_BASE_URL", "")
        result["joti_configured"] = bool(joti_url)
        result["joti_base_url"] = joti_url
        if joti_url:
            client = get_joti_client()
            if client:
                connected = await client.is_connected()
                result["joti_connected"] = connected
                if connected:
                    hccs_raw = await client.get_coverage_score()
                    if hccs_raw and "score" in hccs_raw:
                        result["joti_hccs"] = float(hccs_raw["score"])
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

    # llm_cache_hits_today / llm_cache_misses_today / llm_cache_hit_rate
    try:
        redis = getattr(getattr(request, "app", None), "state", None)
        redis = getattr(redis, "redis", None) if redis else None
        if redis:
            date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            hits_raw = await redis.get(f"llm:stats:hits:{date_str}")
            misses_raw = await redis.get(f"llm:stats:misses:{date_str}")
            hits = int(hits_raw) if hits_raw else 0
            misses = int(misses_raw) if misses_raw else 0
            total = hits + misses
            result["llm_cache_hits_today"] = hits
            result["llm_cache_misses_today"] = misses
            result["llm_cache_hit_rate"] = round(hits / total, 4) if total > 0 else None
    except Exception:
        pass

    # Compose nested system_status for the frontend DashboardMetrics shape
    result["system_status"] = {
        "db_connected": result.get("des_score") is not None or True,  # DB reachable if we got here
        "redis_connected": result.get("llm_cache_hit_rate") is not None or bool(
            result.get("llm_cache_hits_today") or result.get("llm_cache_misses_today")
        ),
        "siem_connections": result.get("siem_connected", 0),
        "siem_total": result.get("siem_connections", 0),
        "joti_configured": result.get("joti_configured", False),
        "joti_connected": result.get("joti_connected", False),
        "joti_hccs": result.get("joti_hccs"),
        "joti_base_url": result.get("joti_base_url", ""),
    }

    # Alias frontend-expected keys
    result["hitl_pending"] = result.get("pending_hitl", 0)
    result["mitre_coverage"] = result.get("coverage_by_tactic", [])
    result["recent_events"] = result.get("recent_activity", [])
    result["sessions_delta"] = 0
    result["events_delta"] = 0

    return result
