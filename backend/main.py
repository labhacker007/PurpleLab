"""Joti Sim — FastAPI backend serving simulation engine + static frontend.

Mounts legacy v1 routes at /api/ and new v2 routes at /api/v2/.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.config import settings
from backend.core.exceptions import JotiSimError
from backend.api.legacy import router as legacy_router
from backend.api.v2 import v2_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title=settings.APP_NAME,
    version="2.0.0",
    description="Universal Security Product Simulator — Agentic Platform",
)

# ── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if not settings.DEBUG else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Exception Handlers ───────────────────────────────────────────────────────

@app.exception_handler(JotiSimError)
async def jotisim_error_handler(request: Request, exc: JotiSimError):
    """Handle all JotiSimError subclasses with consistent JSON responses."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status_code": exc.status_code},
    )


# ── Routers ──────────────────────────────────────────────────────────────────

# Legacy v1 API (backward compatible)
app.include_router(legacy_router, prefix="/api")

# New v2 API
app.include_router(v2_router, prefix="/api")


# ── Startup / Shutdown ───────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup():
    """Initialize database connection pool and other resources.

    TODO: Call db.session.init_db() for development auto-migration.
    TODO: Initialize Redis connection pool.
    TODO: Register agent tools.
    """
    logging.getLogger(__name__).info("Joti Sim v2 starting up")


@app.on_event("shutdown")
async def on_shutdown():
    """Clean up database connections and background tasks.

    TODO: Call db.session.close_db().
    TODO: Close Redis connections.
    TODO: Shut down all running simulation schedulers.
    """
    logging.getLogger(__name__).info("Joti Sim v2 shutting down")


# ── Serve Frontend ────────────────────────────────────────────────────────────

@app.get("/")
def serve_index():
    return FileResponse("frontend/index.html")


try:
    app.mount("/static", StaticFiles(directory="frontend"), name="static")
except Exception:
    pass  # Frontend not built yet
