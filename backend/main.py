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


@app.on_event("shutdown")
async def on_shutdown() -> None:
    logger.info("PurpleLab v2 shutting down")

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
