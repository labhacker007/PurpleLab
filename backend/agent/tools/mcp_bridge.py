"""MCP Bridge — exposes all MCP server tools to the chat agent.

Every tool registered in backend/mcp/server.py becomes available to the
AgentOrchestrator automatically via this bridge. New MCP tools are picked
up at startup with no extra wiring.

Schema normalisation:
  MCP tools use "inputSchema" (camelCase, JSON Schema root object).
  Anthropic tool_use format uses "input_schema" (snake_case).
  The bridge translates on import so both surfaces stay consistent.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


def _normalise_schema(mcp_tool: dict[str, Any]) -> dict[str, Any]:
    """Convert MCP inputSchema to Anthropic input_schema format."""
    schema = mcp_tool.get("inputSchema") or mcp_tool.get("input_schema", {})
    if not schema:
        schema = {"type": "object", "properties": {}}
    # Ensure required top-level fields
    if "type" not in schema:
        schema = {"type": "object", "properties": {}, **schema}
    return schema


def register_tools(registry: ToolRegistry) -> None:
    """Register every MCP tool into the agent ToolRegistry.

    Skips tools already registered (native agent tools take precedence).
    Called from agent/tools/__init__.py after native tool modules.
    """
    try:
        from backend.mcp.server import TOOLS, _call_tool
    except Exception as exc:
        logger.warning("mcp_bridge_import_failed: %s — chat agent will not have MCP tools", exc)
        return

    bridged = 0
    skipped = 0
    for tool in TOOLS:
        name = tool.get("name", "")
        if not name:
            continue

        # Native agent tools take precedence — don't override them
        if registry.get(name) is not None:
            skipped += 1
            continue

        schema = _normalise_schema(tool)
        description = tool.get("description", f"MCP tool: {name}")

        # Capture name in closure to avoid late-binding bug
        def _make_handler(tool_name: str):
            async def _handler(**kwargs: Any) -> Any:
                return await _call_tool(tool_name, kwargs)
            _handler.__name__ = tool_name
            return _handler

        registry.register(
            name=name,
            description=description,
            parameters=schema,
            handler=_make_handler(name),
        )
        bridged += 1

    logger.info("mcp_bridge_ready bridged=%d skipped_native=%d total_mcp=%d",
                bridged, skipped, len(TOOLS))
