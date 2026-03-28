"""Simulation Engine — manages sessions, schedules events, dispatches webhooks.

A "session" is a running simulation with N configured products sending events
to a target platform. Sessions can be started, stopped, paused, and monitored.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from pydantic import BaseModel, Field

from backend.generators.base import BaseGenerator, GeneratorConfig

log = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────────────────────

class ProductNode(BaseModel):
    """A product on the simulation canvas."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    product_type: str              # "splunk", "crowdstrike", etc.
    label: str = ""                # Display name
    x: float = 0                   # Canvas position
    y: float = 0
    config: GeneratorConfig        # Generator configuration
    connected_to: Optional[str] = None  # Target node ID


class TargetNode(BaseModel):
    """A target platform (e.g., Joti) on the canvas."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    label: str = "Joti Platform"
    base_url: str = "http://localhost:8000"
    webhook_path: str = "/api/alerts/ingest/{token}"
    x: float = 500
    y: float = 300


class SessionConfig(BaseModel):
    """Full session configuration — products + target + connections."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = "Untitled Session"
    products: list[ProductNode] = Field(default_factory=list)
    targets: list[TargetNode] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EventLog(BaseModel):
    """Record of a sent event."""
    timestamp: str
    session_id: str
    product_type: str
    product_label: str
    severity: str
    title: str
    target_url: str
    status_code: int
    success: bool


# ── Engine ────────────────────────────────────────────────────────────────────

class SimulationEngine:
    """Manages simulation sessions — create, start, stop, monitor."""

    def __init__(self):
        self.sessions: dict[str, SessionConfig] = {}
        self.running: dict[str, bool] = {}
        self.schedulers: dict[str, AsyncIOScheduler] = {}
        self.generators: dict[str, dict[str, BaseGenerator]] = {}  # session_id → {product_id → generator}
        self.event_log: list[EventLog] = []  # Last N events for UI
        self.stats: dict[str, dict] = {}  # session_id → {events_sent, errors, etc.}
        self._http = httpx.AsyncClient(timeout=10.0)

    # ── Session CRUD ──────────────────────────────────────────────────────

    def create_session(self, config: SessionConfig) -> SessionConfig:
        self.sessions[config.session_id] = config
        self.running[config.session_id] = False
        self.stats[config.session_id] = {"events_sent": 0, "errors": 0, "last_event_at": None}
        return config

    def get_session(self, session_id: str) -> Optional[SessionConfig]:
        return self.sessions.get(session_id)

    def list_sessions(self) -> list[dict]:
        return [
            {
                "session_id": s.session_id,
                "name": s.name,
                "products": len(s.products),
                "targets": len(s.targets),
                "running": self.running.get(s.session_id, False),
                "stats": self.stats.get(s.session_id, {}),
            }
            for s in self.sessions.values()
        ]

    def update_session(self, session_id: str, config: SessionConfig) -> Optional[SessionConfig]:
        if session_id not in self.sessions:
            return None
        was_running = self.running.get(session_id, False)
        if was_running:
            self.stop_session(session_id)
        config.session_id = session_id
        self.sessions[session_id] = config
        if was_running:
            self.start_session(session_id)
        return config

    def delete_session(self, session_id: str) -> bool:
        if session_id in self.running and self.running[session_id]:
            self.stop_session(session_id)
        self.sessions.pop(session_id, None)
        self.running.pop(session_id, None)
        self.stats.pop(session_id, None)
        return True

    # ── Start / Stop ──────────────────────────────────────────────────────

    def start_session(self, session_id: str) -> bool:
        session = self.sessions.get(session_id)
        if not session:
            return False

        from backend.generators import GENERATOR_REGISTRY

        # Create generators for each product
        gens = {}
        for product in session.products:
            gen_cls = GENERATOR_REGISTRY.get(product.product_type)
            if gen_cls:
                gens[product.id] = gen_cls(product.config)

        self.generators[session_id] = gens

        # Create scheduler
        scheduler = AsyncIOScheduler()
        for product in session.products:
            if not product.config.enabled:
                continue
            interval = 60.0 / max(product.config.events_per_minute, 0.1)
            scheduler.add_job(
                self._send_event,
                "interval",
                seconds=interval,
                args=[session_id, product],
                id=f"{session_id}_{product.id}",
                replace_existing=True,
            )

        scheduler.start()
        self.schedulers[session_id] = scheduler
        self.running[session_id] = True
        log.info("session_started id=%s products=%d", session_id, len(gens))
        return True

    def stop_session(self, session_id: str) -> bool:
        scheduler = self.schedulers.pop(session_id, None)
        if scheduler:
            scheduler.shutdown(wait=False)
        self.generators.pop(session_id, None)
        self.running[session_id] = False
        log.info("session_stopped id=%s", session_id)
        return True

    # ── Event Generation & Dispatch ───────────────────────────────────────

    async def _send_event(self, session_id: str, product: ProductNode):
        """Generate one event and send it to the target."""
        gen = self.generators.get(session_id, {}).get(product.id)
        if not gen:
            return

        event = gen.generate()
        severity = event.get("urgency") or event.get("result", {}).get("severity") or \
                   event.get("event", {}).get("SeverityName", "").lower() or "medium"
        title = event.get("message") or event.get("search_name") or \
                event.get("event", {}).get("DetectDescription") or str(event.get("eventType", ""))

        # Find target
        session = self.sessions.get(session_id)
        target_url = product.config.target_url
        if not target_url and session and session.targets:
            t = session.targets[0]
            token = product.config.webhook_token or "sim-token"
            target_url = f"{t.base_url}{t.webhook_path.replace('{token}', token)}"

        status_code = 0
        success = False
        try:
            resp = await self._http.post(target_url, json=event, timeout=5.0)
            status_code = resp.status_code
            success = 200 <= resp.status_code < 300
        except Exception as e:
            log.debug("send_failed session=%s product=%s error=%s", session_id, product.id, e)
            self.stats[session_id]["errors"] = self.stats.get(session_id, {}).get("errors", 0) + 1

        self.stats[session_id]["events_sent"] = self.stats.get(session_id, {}).get("events_sent", 0) + 1
        self.stats[session_id]["last_event_at"] = self._now_iso()

        log_entry = EventLog(
            timestamp=self._now_iso(),
            session_id=session_id,
            product_type=product.product_type,
            product_label=product.label or product.product_type,
            severity=str(severity),
            title=str(title)[:200],
            target_url=target_url,
            status_code=status_code,
            success=success,
        )
        self.event_log.append(log_entry)
        if len(self.event_log) > 500:
            self.event_log = self.event_log[-500:]

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Event Log ─────────────────────────────────────────────────────────

    def get_event_log(self, session_id: Optional[str] = None, limit: int = 50) -> list[dict]:
        logs = self.event_log
        if session_id:
            logs = [l for l in logs if l.session_id == session_id]
        return [l.model_dump() for l in logs[-limit:]]

    # ── Generate preview (no send) ────────────────────────────────────────

    def preview_event(self, product_type: str) -> dict:
        from backend.generators import GENERATOR_REGISTRY
        gen_cls = GENERATOR_REGISTRY.get(product_type)
        if not gen_cls:
            return {"error": f"Unknown product: {product_type}"}
        config = GeneratorConfig(product_type=product_type, target_url="preview://")
        gen = gen_cls(config)
        return gen.generate()


# Singleton
engine = SimulationEngine()
