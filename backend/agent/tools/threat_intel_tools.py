"""Threat intelligence tools for the agent orchestrator.

Provides tools for researching threat actors, searching MITRE ATT&CK
techniques, and listing known threat actors.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


def register_tools(registry: ToolRegistry) -> None:
    """Register all threat intelligence tools."""

    registry.register(
        name="research_threat_actor",
        description=(
            "Research a threat actor by name. Returns a structured profile "
            "including aliases, description, MITRE ATT&CK TTPs, and sources. "
            "Checks the knowledge base cache first, then queries MITRE ATT&CK data."
        ),
        parameters={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The threat actor name (e.g., 'APT29', 'Lazarus Group').",
                },
            },
            "required": ["name"],
        },
        handler=_research_threat_actor,
    )

    registry.register(
        name="search_mitre_technique",
        description=(
            "Search MITRE ATT&CK techniques by keyword or technique ID. "
            "Returns matching techniques with their IDs, names, tactics, "
            "and descriptions."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Search query — a technique ID like 'T1059.001' or "
                        "a keyword like 'credential dumping'."
                    ),
                },
            },
            "required": ["query"],
        },
        handler=_search_mitre_technique,
    )

    registry.register(
        name="list_threat_actors",
        description=(
            "List known threat actors from the knowledge base and MITRE ATT&CK. "
            "Optionally filter by a search query."
        ),
        parameters={
            "type": "object",
            "properties": {
                "search": {
                    "type": "string",
                    "description": "Optional search filter for actor names or aliases.",
                    "default": "",
                },
            },
            "required": [],
        },
        handler=_list_threat_actors,
    )

    registry.register(
        name="get_threat_actor_ttps",
        description=(
            "Get the MITRE ATT&CK TTPs (Tactics, Techniques, and Procedures) "
            "associated with a specific threat actor. Returns technique IDs, "
            "names, tactics, platforms, and detection guidance."
        ),
        parameters={
            "type": "object",
            "properties": {
                "actor_name": {
                    "type": "string",
                    "description": "The threat actor name (e.g., 'APT29', 'FIN7').",
                },
            },
            "required": ["actor_name"],
        },
        handler=_get_threat_actor_ttps,
    )


def _build_actor_service() -> Any:
    """Lazily construct an ActorService with default dependencies."""
    from backend.knowledge.vector_store import VectorStore
    from backend.knowledge.store import KnowledgeStore
    from backend.threat_intel.mitre_service import MITREService
    from backend.threat_intel.actor_service import ActorService

    vector_store = VectorStore()
    knowledge_store = KnowledgeStore(vector_store)
    mitre_service = MITREService(knowledge_store=knowledge_store)
    return ActorService(knowledge_store=knowledge_store, mitre_service=mitre_service)


def _build_mitre_service() -> Any:
    """Lazily construct a MITREService with default dependencies."""
    from backend.knowledge.vector_store import VectorStore
    from backend.knowledge.store import KnowledgeStore
    from backend.threat_intel.mitre_service import MITREService

    vector_store = VectorStore()
    knowledge_store = KnowledgeStore(vector_store)
    return MITREService(knowledge_store=knowledge_store)


async def _research_threat_actor(name: str) -> dict[str, Any]:
    """Research a threat actor and return a structured profile."""
    try:
        service = _build_actor_service()
        result = await service.research_actor(name)
        # Ensure the result is JSON-safe (truncate very long descriptions)
        if result.get("ttps"):
            for ttp in result["ttps"]:
                if isinstance(ttp.get("description"), str) and len(ttp["description"]) > 500:
                    ttp["description"] = ttp["description"][:500] + "..."
        return {
            "status": "success",
            "actor": result,
        }
    except Exception as exc:
        logger.exception("research_threat_actor failed for '%s'", name)
        return {"error": f"Failed to research threat actor '{name}': {exc}"}


async def _search_mitre_technique(query: str) -> dict[str, Any]:
    """Search MITRE ATT&CK techniques."""
    try:
        service = _build_mitre_service()
        techniques = await service.search_techniques(query)
        # Return a summary-friendly format
        results = [
            {
                "technique_id": t.get("technique_id", ""),
                "name": t.get("name", ""),
                "tactics": t.get("tactics", []),
                "platforms": t.get("platforms", []),
                "description": (t.get("description", "") or "")[:300],
                "url": t.get("url", ""),
            }
            for t in techniques
        ]
        return {
            "status": "success",
            "query": query,
            "count": len(results),
            "techniques": results,
        }
    except Exception as exc:
        logger.exception("search_mitre_technique failed for '%s'", query)
        return {"error": f"Failed to search MITRE techniques: {exc}"}


async def _list_threat_actors(search: str = "") -> dict[str, Any]:
    """List known threat actors."""
    try:
        service = _build_actor_service()
        actors = await service.list_actors(search=search)
        # Also pull MITRE groups for a more complete listing
        if not actors:
            mitre = _build_mitre_service()
            groups = await mitre.get_all_groups()
            if search:
                search_lower = search.lower()
                groups = [
                    g for g in groups
                    if search_lower in g.get("name", "").lower()
                    or any(search_lower in a.lower() for a in g.get("aliases", []))
                ]
            actors = [
                {
                    "id": g.get("group_id", ""),
                    "name": g.get("name", ""),
                    "aliases": g.get("aliases", []),
                    "description": (g.get("description", "") or "")[:200],
                }
                for g in groups[:50]
            ]
        return {
            "status": "success",
            "count": len(actors),
            "actors": actors,
        }
    except Exception as exc:
        logger.exception("list_threat_actors failed")
        return {"error": f"Failed to list threat actors: {exc}"}


async def _get_threat_actor_ttps(actor_name: str) -> dict[str, Any]:
    """Get TTPs for a threat actor."""
    try:
        service = _build_actor_service()
        ttps = await service.get_actor_ttps(actor_name)
        return {
            "status": "success",
            "actor_name": actor_name,
            "ttp_count": len(ttps),
            "ttps": ttps,
        }
    except Exception as exc:
        logger.exception("get_threat_actor_ttps failed for '%s'", actor_name)
        return {"error": f"Failed to get TTPs for '{actor_name}': {exc}"}
