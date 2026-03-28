"""Threat actor service — CRUD, enrichment, and research for threat actor profiles.

Combines MITRE ATT&CK group data with the knowledge base for
persistent, searchable threat actor profiles.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.knowledge.store import KnowledgeStore
from backend.threat_intel.mitre_service import MITREService

logger = logging.getLogger(__name__)

_NAMESPACE = "threat_actors"


class ActorService:
    """Manages threat actor profiles.

    Stores actors in the knowledge base (vector DB) for semantic search
    and enriches them with MITRE ATT&CK data.
    """

    def __init__(
        self,
        knowledge_store: KnowledgeStore | None = None,
        mitre_service: MITREService | None = None,
    ) -> None:
        self.knowledge = knowledge_store
        self.mitre = mitre_service

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def get_actor(self, actor_id: str) -> dict[str, Any] | None:
        """Get a threat actor profile by ID or name."""
        if not self.knowledge:
            return None

        # Try direct key lookup
        entry = await self.knowledge.get_knowledge(_NAMESPACE, actor_id)
        if entry:
            return self._entry_to_actor(entry)

        # Try searching by name
        results = await self.knowledge.search_knowledge(_NAMESPACE, actor_id, top_k=1)
        if results:
            return self._entry_to_actor(results[0])

        # Try MITRE ATT&CK groups
        if self.mitre:
            group = await self.mitre.get_group(actor_id)
            if group:
                return self._group_to_actor(group)

        return None

    async def list_actors(self, search: str = "") -> list[dict[str, Any]]:
        """List all known threat actors, optionally filtered by search query."""
        actors: list[dict[str, Any]] = []

        if self.knowledge:
            if search:
                results = await self.knowledge.search_knowledge(_NAMESPACE, search, top_k=50)
            else:
                # List all — search with a broad query
                results = await self.knowledge.search_knowledge(_NAMESPACE, "threat actor group", top_k=100)
            for r in results:
                actor = self._entry_to_actor(r)
                if actor:
                    actors.append(actor)

        return actors

    async def create_actor(self, data: dict[str, Any]) -> dict[str, Any]:
        """Create a new threat actor profile."""
        return await self.create_or_update_actor(data)

    async def create_or_update_actor(self, actor: dict[str, Any]) -> dict[str, Any]:
        """Create or update a threat actor profile in the knowledge base."""
        if not self.knowledge:
            return actor

        name = actor.get("name", "")
        actor_id = actor.get("id") or actor.get("actor_id") or f"actor-{_slug(name)}"

        # Build searchable text
        parts = [name]
        if actor.get("aliases"):
            parts.append(f"Aliases: {', '.join(actor['aliases'])}")
        if actor.get("description"):
            parts.append(actor["description"])
        if actor.get("ttps"):
            ttp_text = ", ".join(
                t.get("technique_id", "") + " " + t.get("name", "")
                for t in actor["ttps"]
            )
            parts.append(f"TTPs: {ttp_text}")
        content = "\n\n".join(parts)

        metadata: dict[str, Any] = {
            "type": "threat_actor",
            "name": name,
            "actor_id": actor_id,
            "aliases": ", ".join(actor.get("aliases", [])),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        await self.knowledge.store_knowledge(_NAMESPACE, actor_id, content, metadata)

        actor["id"] = actor_id
        return actor

    async def delete_actor(self, actor_id: str) -> None:
        """Delete a threat actor profile."""
        if self.knowledge:
            await self.knowledge.delete_knowledge(_NAMESPACE, actor_id)

    # ------------------------------------------------------------------
    # Enrichment & research
    # ------------------------------------------------------------------

    async def enrich_actor(self, actor_id: str) -> dict[str, Any]:
        """Enrich an actor with MITRE ATT&CK data."""
        actor = await self.get_actor(actor_id)
        if not actor:
            return {"error": f"Actor '{actor_id}' not found"}

        if self.mitre:
            ttps = await self.get_actor_ttps(actor.get("name", actor_id))
            actor["ttps"] = ttps
            actor["enriched_at"] = datetime.now(timezone.utc).isoformat()

            # Persist enriched profile
            await self.create_or_update_actor(actor)

        return actor

    async def research_actor(self, name: str) -> dict[str, Any]:
        """Research a threat actor using available sources.

        1. Check knowledge base cache
        2. Search MITRE ATT&CK groups
        3. Build structured profile with TTPs
        4. Store in knowledge base
        """
        # 1. Check cache
        if self.knowledge:
            cached = await self.get_actor(name)
            if cached and cached.get("ttps"):
                return cached

        # 2. MITRE ATT&CK
        actor: dict[str, Any] = {
            "name": name,
            "aliases": [],
            "description": "",
            "ttps": [],
            "mitre_group": None,
            "sources": [],
        }

        if self.mitre:
            group = await self.mitre.get_group(name)
            if group:
                actor["name"] = group["name"]
                actor["aliases"] = group.get("aliases", [])
                actor["description"] = group.get("description", "")
                actor["mitre_group"] = group
                actor["sources"].append("mitre_attack")

                # 3. Get TTPs
                techniques = await self.mitre.get_actor_techniques(name)
                actor["ttps"] = [
                    {
                        "technique_id": t["technique_id"],
                        "name": t["name"],
                        "tactics": t.get("tactics", []),
                        "description": t.get("description", "")[:500],
                    }
                    for t in techniques
                ]

        actor["researched_at"] = datetime.now(timezone.utc).isoformat()

        # 4. Store in knowledge base
        if self.knowledge:
            await self.create_or_update_actor(actor)

        return actor

    async def get_actor_ttps(self, name: str) -> list[dict[str, Any]]:
        """Get TTPs for a threat actor, enriched with technique details."""
        if not self.mitre:
            return []

        techniques = await self.mitre.get_actor_techniques(name)
        return [
            {
                "technique_id": t["technique_id"],
                "name": t["name"],
                "tactics": t.get("tactics", []),
                "platforms": t.get("platforms", []),
                "description": t.get("description", "")[:500],
                "detection": t.get("detection", "")[:500],
                "url": t.get("url", ""),
            }
            for t in techniques
        ]

    async def search_actors(self, query: str) -> list[dict[str, Any]]:
        """Semantic search for threat actors."""
        results: list[dict[str, Any]] = []

        # Search knowledge base
        if self.knowledge:
            kb_results = await self.knowledge.search_knowledge(_NAMESPACE, query, top_k=10)
            for r in kb_results:
                actor = self._entry_to_actor(r)
                if actor:
                    results.append(actor)

        # Also search MITRE groups if we have few results
        if self.mitre and len(results) < 5:
            groups = await self.mitre.get_all_groups()
            query_lower = query.lower()
            for g in groups:
                text = f"{g['name']} {' '.join(g.get('aliases', []))} {g.get('description', '')}".lower()
                if query_lower in text:
                    actor = self._group_to_actor(g)
                    # Avoid duplicates
                    if not any(r.get("name") == actor.get("name") for r in results):
                        results.append(actor)
                        if len(results) >= 10:
                            break

        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _entry_to_actor(entry: dict[str, Any]) -> dict[str, Any] | None:
        """Convert a knowledge store entry to an actor dict."""
        if not entry:
            return None
        meta = entry.get("metadata", {})
        return {
            "id": meta.get("actor_id", entry.get("id", "")),
            "name": meta.get("name", ""),
            "aliases": [a.strip() for a in meta.get("aliases", "").split(",") if a.strip()],
            "description": entry.get("text", ""),
            "type": meta.get("type", "threat_actor"),
        }

    @staticmethod
    def _group_to_actor(group: dict[str, Any]) -> dict[str, Any]:
        """Convert a MITRE ATT&CK group dict to an actor dict."""
        return {
            "id": group.get("group_id", ""),
            "name": group.get("name", ""),
            "aliases": group.get("aliases", []),
            "description": group.get("description", ""),
            "type": "mitre_group",
            "url": group.get("url", ""),
        }


def _slug(name: str) -> str:
    """Create a URL-safe slug from a name."""
    import re
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
