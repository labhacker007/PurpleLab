"""V2 API — agentic endpoints for chat, detection, threat intel, and more."""
from __future__ import annotations

from fastapi import APIRouter, Request
from sqlalchemy import text

from backend.api.v2.chat import router as chat_router
from backend.api.v2.sessions import router as sessions_router
from backend.api.v2.rules import router as rules_router
from backend.api.v2.threat_intel import router as threat_intel_router
from backend.api.v2.siem import router as siem_router
from backend.api.v2.environments import router as environments_router
from backend.api.v2.log_sources import router as log_sources_router
from backend.api.v2.knowledge import router as knowledge_router
from backend.api.v2.model_config import router as model_config_router
from backend.api.v2.hitl import router as hitl_router
from backend.api.v2.auth import router as auth_router
from backend.api.v2.dashboard import router as dashboard_router
from backend.api.v2.admin import router as admin_router
from backend.api.v2.pipeline import router as pipeline_router
from backend.api.v2.scoring import router as scoring_router
from backend.api.v2.use_cases import router as use_cases_router
from backend.api.v2.reports import router as reports_router
from backend.joti.webhook import router as joti_webhook_router

v2_router = APIRouter(prefix="/v2", tags=["v2"])


@v2_router.get("/health")
async def health_check(request: Request):
    """Component-level health check for the v2 API."""
    redis_ok = False
    db_ok = False
    try:
        await request.app.state.redis.ping()
        redis_ok = True
    except Exception:
        pass
    try:
        from backend.db.session import async_session
        async with async_session() as s:
            await s.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    return {
        "status": "ok" if (redis_ok and db_ok) else "degraded",
        "database": "ok" if db_ok else "error",
        "redis": "ok" if redis_ok else "error",
        "version": "2.0.0",
    }


v2_router.include_router(chat_router)
v2_router.include_router(sessions_router)
v2_router.include_router(rules_router)
v2_router.include_router(threat_intel_router)
v2_router.include_router(siem_router)
v2_router.include_router(environments_router)
v2_router.include_router(log_sources_router)
v2_router.include_router(knowledge_router)
v2_router.include_router(model_config_router)
v2_router.include_router(hitl_router)
v2_router.include_router(auth_router)
v2_router.include_router(dashboard_router)
v2_router.include_router(admin_router)
v2_router.include_router(pipeline_router)
v2_router.include_router(scoring_router)
v2_router.include_router(use_cases_router)
v2_router.include_router(reports_router)
v2_router.include_router(joti_webhook_router)
