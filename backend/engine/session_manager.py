"""Session manager — refactored from engine.py.

Handles CRUD operations for simulation sessions and coordinates
with the scheduler and dispatcher for event generation.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from backend.engine.generators import GENERATOR_REGISTRY
from backend.engine.generators.base import BaseGenerator, GeneratorConfig

log = logging.getLogger(__name__)


class SessionManager:
    """Manages the lifecycle of simulation sessions.

    TODO: Migrate from in-memory dict to database-backed storage
    using backend.db.models.SimulationSession.
    """

    def __init__(self) -> None:
        self.sessions: dict[str, Any] = {}
        self.generators: dict[str, dict[str, BaseGenerator]] = {}
        self.stats: dict[str, dict[str, Any]] = {}

    def create_session(self, config: Any) -> Any:
        """Create a new simulation session."""
        self.sessions[config.session_id] = config
        self.stats[config.session_id] = {
            "events_sent": 0,
            "errors": 0,
            "last_event_at": None,
        }
        return config

    def get_session(self, session_id: str) -> Optional[Any]:
        """Retrieve a session by ID."""
        return self.sessions.get(session_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all sessions with summary info."""
        return [
            {
                "session_id": s.session_id,
                "name": s.name,
                "products": len(s.products),
                "targets": len(s.targets),
                "stats": self.stats.get(s.session_id, {}),
            }
            for s in self.sessions.values()
        ]

    def update_session(self, session_id: str, config: Any) -> Optional[Any]:
        """Update an existing session's configuration."""
        if session_id not in self.sessions:
            return None
        config.session_id = session_id
        self.sessions[session_id] = config
        return config

    def delete_session(self, session_id: str) -> bool:
        """Remove a session entirely."""
        self.sessions.pop(session_id, None)
        self.generators.pop(session_id, None)
        self.stats.pop(session_id, None)
        return True

    def build_generators(self, session_id: str) -> dict[str, BaseGenerator]:
        """Instantiate generators for all products in a session."""
        session = self.sessions.get(session_id)
        if not session:
            return {}
        gens: dict[str, BaseGenerator] = {}
        for product in session.products:
            gen_cls = GENERATOR_REGISTRY.get(product.product_type)
            if gen_cls:
                gens[product.id] = gen_cls(product.config)
        self.generators[session_id] = gens
        return gens
