"""Log generation tools for the agent orchestrator.

Uses the AgenticLogGenerator — reads schemas from the SchemaRegistry (ChromaDB),
calls Claude to produce events dynamically, caches templates in Redis/memory.
Never uses hardcoded event templates.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


def register_tools(registry: ToolRegistry) -> None:
    """Register all log generation tools."""

    registry.register(
        name="generate_attack_logs",
        description=(
            "Generate synthetic log events containing attack indicators for a "
            "specific MITRE ATT&CK technique. Uses the agentic log generator — "
            "reads vendor schemas from ChromaDB, generates realistic events via "
            "Claude, and caches templates so repeated calls are fast. "
            "Use list_log_sources to see available source IDs."
        ),
        parameters={
            "type": "object",
            "properties": {
                "source_id": {
                    "type": "string",
                    "description": (
                        "Log source ID from the schema registry "
                        "(e.g. 'windows_sysmon', 'aws_cloudtrail', 'kubernetes_audit'). "
                        "Use list_log_sources to enumerate all options."
                    ),
                },
                "technique_id": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique ID (e.g. 'T1059.001').",
                },
                "count": {
                    "type": "integer",
                    "description": "Number of attack events to generate (1-100).",
                    "default": 10,
                },
                "snr_ratio": {
                    "type": "number",
                    "description": (
                        "Signal-to-noise ratio (0.0–1.0). "
                        "1.0 = all attack events. 0.2 = 20% attack + 80% benign noise. "
                        "Default 1.0."
                    ),
                    "default": 1.0,
                },
                "force_refresh": {
                    "type": "boolean",
                    "description": (
                        "Bypass the template cache and ask Claude to generate fresh events. "
                        "Use when you want new variation or after a schema update."
                    ),
                    "default": False,
                },
            },
            "required": ["source_id", "technique_id"],
        },
        handler=_generate_attack_logs,
    )

    registry.register(
        name="generate_benign_logs",
        description=(
            "Generate realistic benign/normal log events from a log source. "
            "Useful for creating noise context around attack simulations. "
            "Events are Claude-generated from the schema, cached for reuse."
        ),
        parameters={
            "type": "object",
            "properties": {
                "source_id": {
                    "type": "string",
                    "description": "Log source ID (e.g. 'windows_security', 'dns').",
                },
                "count": {
                    "type": "integer",
                    "description": "Number of benign events to generate (1-200).",
                    "default": 20,
                },
                "force_refresh": {
                    "type": "boolean",
                    "description": "Bypass cache and regenerate.",
                    "default": False,
                },
            },
            "required": ["source_id"],
        },
        handler=_generate_benign_logs,
    )

    registry.register(
        name="list_log_sources",
        description=(
            "List all log sources registered in the schema registry with their "
            "vendor, product, MITRE technique mappings, and SIEM integration details. "
            "Use this before generate_attack_logs to find valid source_id values."
        ),
        parameters={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": (
                        "Filter by category: endpoint|cloud|network|identity|"
                        "email|container|cdn|posture. Omit for all sources."
                    ),
                },
            },
            "required": [],
        },
        handler=_list_log_sources,
    )

    registry.register(
        name="invalidate_log_source_cache",
        description=(
            "Flush cached log templates for a source. Use after a schema update "
            "so the next generate call fetches fresh templates from Claude."
        ),
        parameters={
            "type": "object",
            "properties": {
                "source_id": {
                    "type": "string",
                    "description": "Source ID whose cached templates to flush.",
                },
            },
            "required": ["source_id"],
        },
        handler=_invalidate_cache,
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def _generate_attack_logs(
    source_id: str,
    technique_id: str,
    count: int = 10,
    snr_ratio: float = 1.0,
    force_refresh: bool = False,
) -> dict[str, Any]:
    count = max(1, min(count, 100))
    snr_ratio = max(0.0, min(1.0, snr_ratio))
    try:
        from backend.log_sources.agentic_generator import get_generator
        gen = get_generator()
        result = await gen.generate(
            source_id=source_id,
            technique_id=technique_id,
            count=count,
            snr_ratio=snr_ratio,
            force_refresh=force_refresh,
        )
        return result
    except Exception as exc:
        logger.exception("generate_attack_logs failed")
        return {"error": f"Generation failed: {exc}", "events": []}


async def _generate_benign_logs(
    source_id: str,
    count: int = 20,
    force_refresh: bool = False,
) -> dict[str, Any]:
    count = max(1, min(count, 200))
    try:
        from backend.log_sources.agentic_generator import get_generator
        gen = get_generator()
        result = await gen.generate_benign(
            source_id=source_id,
            count=count,
            force_refresh=force_refresh,
        )
        return result
    except Exception as exc:
        logger.exception("generate_benign_logs failed")
        return {"error": f"Generation failed: {exc}", "events": []}


async def _list_log_sources(category: str | None = None) -> dict[str, Any]:
    try:
        from backend.log_sources.agentic_generator import get_generator
        gen = get_generator()
        sources = await gen.list_sources()
        if category:
            sources = [s for s in sources if s["category"] == category]
        return {
            "status": "success",
            "count": len(sources),
            "sources": sources,
        }
    except Exception as exc:
        logger.exception("list_log_sources failed")
        return {"error": f"Failed: {exc}"}


async def _invalidate_cache(source_id: str) -> dict[str, Any]:
    try:
        from backend.log_sources.agentic_generator import get_generator
        gen = get_generator()
        flushed = await gen.invalidate_source(source_id)
        return {
            "status": "success",
            "source_id": source_id,
            "templates_flushed": flushed,
            "message": f"Flushed {flushed} cached templates for '{source_id}'.",
        }
    except Exception as exc:
        logger.exception("invalidate_log_source_cache failed")
        return {"error": f"Failed: {exc}"}
