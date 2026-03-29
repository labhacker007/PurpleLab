"""V2 API — agentic endpoints for chat, detection, threat intel, and more."""
from __future__ import annotations

from fastapi import APIRouter

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

v2_router = APIRouter(prefix="/v2", tags=["v2"])

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
