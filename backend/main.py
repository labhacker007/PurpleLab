"""PurpleLab — FastAPI backend serving simulation engine + static frontend."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.config import settings
from backend.core.exceptions import PurpleLabError
from backend.api.legacy import router as legacy_router
from backend.api.v2 import v2_router
from backend.api.vendor.crowdstrike import router as crowdstrike_router
from backend.api.vendor.splunk import router as splunk_router
from backend.api.vendor.defender import router as defender_router
from backend.api.vendor.qradar import router as qradar_router
from backend.api.vendor.xsiam import router as xsiam_router
from backend.api.vendor.carbonblack import router as carbonblack_router
from backend.api.vendor.okta import router as okta_router
from backend.api.vendor.entra_id import router as entra_router
from backend.api.vendor.elastic import router as elastic_router
from backend.api.vendor.sentinelone import router as sentinelone_router
from backend.api.vendor.panorama import router as panorama_router
from backend.api.vendor.servicenow import router as servicenow_router
from backend.api.vendor.jira import router as jira_router
from backend.api.vendor.tenable import router as tenable_router
from backend.api.vendor.wiz import router as wiz_router
from backend.api.vendor.qualys import router as qualys_router
from backend.api.v2.sim_siem import router as sim_siem_router
from backend.api.v2.tabletop import router as tabletop_router

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    version="2.0.0",
    description="Universal Security Product Simulator — Agentic Platform",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if not settings.DEBUG else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# ── Exception Handlers ───────────────────────────────────────────────────────

@app.exception_handler(PurpleLabError)
async def purplelab_error_handler(request: Request, exc: PurpleLabError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status_code": exc.status_code},
    )


# ── Routers ──────────────────────────────────────────────────────────────────

app.include_router(legacy_router, prefix="/api")
app.include_router(v2_router, prefix="/api")

# Vendor API emulation — each mimics a real vendor's REST API
app.include_router(crowdstrike_router)
app.include_router(splunk_router)
app.include_router(defender_router)
app.include_router(qradar_router)
app.include_router(xsiam_router)
app.include_router(carbonblack_router)
app.include_router(okta_router)
app.include_router(entra_router)
app.include_router(elastic_router)
app.include_router(sentinelone_router)
app.include_router(panorama_router)
app.include_router(servicenow_router)
app.include_router(jira_router)
app.include_router(tenable_router)
app.include_router(wiz_router)
app.include_router(qualys_router)

# Simulation SIEM + Tabletop
app.include_router(sim_siem_router)
app.include_router(tabletop_router)


# ── Startup / Shutdown ───────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup() -> None:
    logger.info("PurpleLab v2 starting up (model=%s)", settings.DEFAULT_MODEL)

    # 1. Initialize database (create tables if not exist)
    try:
        from backend.db.session import init_db
        await init_db()
        logger.info("Database initialized")
    except Exception as exc:
        logger.warning("Database init failed (will retry on first request): %s", exc)

    # 2. Initialize Redis connection pool
    try:
        import redis.asyncio as aioredis
        app.state.redis = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            max_connections=20,
        )
        await app.state.redis.ping()
        logger.info("Redis connected: %s", settings.REDIS_URL)
    except Exception as exc:
        app.state.redis = None
        logger.warning("Redis unavailable (in-memory fallback active): %s", exc)

    # Wire Redis client into the dependency injection layer
    try:
        from backend.dependencies import set_redis_client
        set_redis_client(app.state.redis)
    except Exception as exc:
        logger.warning("Could not wire Redis into dependencies: %s", exc)

    # 3. Seed log source schemas into ChromaDB (idempotent)
    try:
        from backend.log_sources.schema_registry import get_registry
        from backend.knowledge.store import KnowledgeStore
        registry = get_registry()
        store = KnowledgeStore()
        seeded = await registry.seed_knowledge_base(store)
        if seeded:
            logger.info("Seeded %d log schemas into ChromaDB", seeded)
    except Exception as exc:
        logger.warning("Schema seeding skipped: %s", exc)

    # 4. Pre-warm agent tool registry
    try:
        from backend.agent.orchestrator import get_orchestrator
        get_orchestrator()
        logger.info("Agent orchestrator ready")
    except Exception as exc:
        logger.warning("Agent orchestrator pre-warm failed: %s", exc)

    # 5. Initialize LLM router (loads defaults, no DB yet — lazy DB on first use)
    try:
        from backend.llm.router import get_router
        router = get_router()
        logger.info("LLM router ready")
    except Exception as exc:
        logger.warning("LLM router init failed: %s", exc)

    # 5a. Wire Redis into LLM router for response caching
    try:
        from backend.llm.router import get_router
        llm_router = get_router()
        if hasattr(app.state, "redis") and app.state.redis:
            llm_router.set_redis(app.state.redis)
            logger.info("LLM cache wired to Redis")
    except Exception as exc:
        logger.warning("LLM cache wiring failed: %s", exc)

    # 6. Start pipeline scheduler
    try:
        from backend.pipeline.scheduler import get_scheduler
        sched = await get_scheduler()
        await sched.start()
        logger.info("Pipeline scheduler started")
    except Exception as exc:
        logger.warning("Pipeline scheduler start failed: %s", exc)

    # 7. Seed built-in use cases
    try:
        from backend.use_cases.service import UseCaseService
        svc = UseCaseService()
        seeded = await svc.seed_builtin_use_cases()
        if seeded:
            logger.info("Seeded %d built-in use cases", seeded)
    except Exception as exc:
        logger.warning("Use case seeding skipped: %s", exc)

    # 7b. Seed identity Sigma rules from use case library
    try:
        from backend.use_cases.service import UseCaseService
        svc = UseCaseService()
        sigma_seeded = await svc.seed_identity_sigma_rules()
        if sigma_seeded:
            logger.info("Seeded %d identity Sigma rules into library", sigma_seeded)
    except Exception as exc:
        logger.warning("Identity Sigma rule seeding skipped: %s", exc)

    # 8. Auto-create superadmin if FIRST_SUPERADMIN_EMAIL is set
    if settings.FIRST_SUPERADMIN_EMAIL and settings.FIRST_SUPERADMIN_PASSWORD:
        try:
            from backend.auth.security import hash_password
            from backend.db.session import async_session
            from backend.db import models
            from sqlalchemy import select
            async with async_session() as db:
                existing = await db.scalar(select(models.User).where(models.User.email == settings.FIRST_SUPERADMIN_EMAIL))
                if not existing:
                    user = models.User(
                        email=settings.FIRST_SUPERADMIN_EMAIL,
                        hashed_password=hash_password(settings.FIRST_SUPERADMIN_PASSWORD),
                        full_name="Super Admin",
                        role="admin",
                        is_superadmin=True,
                        is_active=True,
                    )
                    db.add(user)
                    await db.commit()
                    logger.info("Created superadmin: %s", settings.FIRST_SUPERADMIN_EMAIL)
        except Exception as exc:
            logger.warning("Superadmin auto-create failed: %s", exc)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    logger.info("PurpleLab v2 shutting down")

    try:
        from backend.pipeline.scheduler import get_scheduler
        sched = await get_scheduler()
        sched.stop()
    except Exception:
        pass

    try:
        from backend.db.session import close_db
        await close_db()
    except Exception:
        pass

    try:
        if hasattr(app.state, "redis") and app.state.redis:
            await app.state.redis.aclose()
    except Exception:
        pass


# ── Health check ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    from backend.config import settings
    redis_ok = False
    db_ok = False
    try:
        if hasattr(app.state, "redis") and app.state.redis:
            await app.state.redis.ping()
            redis_ok = True
    except Exception:
        pass
    try:
        from backend.db.session import async_session
        from sqlalchemy import text
        async with async_session() as s:
            await s.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    return {
        "status": "ok",
        "db": "ok" if db_ok else "unavailable",
        "redis": "ok" if redis_ok else "unavailable",
        "version": "2.0.0",
    }


# ── Serve Frontend ────────────────────────────────────────────────────────────

@app.get("/")
def serve_index():
    import os
    if os.path.exists("frontend/index.html"):
        return FileResponse("frontend/index.html")
    return JSONResponse({"message": "PurpleLab API v2", "docs": "/api/docs"})


try:
    app.mount("/static", StaticFiles(directory="frontend"), name="static")
except Exception:
    pass
