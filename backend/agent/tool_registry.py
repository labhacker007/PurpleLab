"""Tool registry — registers and manages callable tools for the agent.

Tools are Python functions decorated with metadata that the LLM can
invoke during the agentic loop. The registry converts them to the
format expected by Claude's tool_use API.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

log = logging.getLogger(__name__)


class ToolDefinition:
    """Metadata for a registered tool."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: Callable,
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters  # JSON Schema for input
        self.handler = handler

    def to_anthropic_format(self) -> dict[str, Any]:
        """Convert to the format expected by Claude's tool_use API."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


class ToolRegistry:
    """Registry of tools available to the agent.

    TODO: Register tools from backend/agent/tools/ directory.
    TODO: Add tool categories (simulation, detection, threat_intel, etc.).
    TODO: Implement tool permission scoping per environment.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: Callable,
    ) -> None:
        """Register a new tool."""
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            handler=handler,
        )
        log.info("tool_registered name=%s", name)

    def get(self, name: str) -> ToolDefinition | None:
        """Look up a tool by name."""
        return self._tools.get(name)

    async def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        """Execute a registered tool by name.

        Args:
            name: The tool name.
            arguments: The tool input arguments.

        Returns:
            The tool's return value.

        Raises:
            KeyError: If the tool is not registered.
        """
        tool = self._tools.get(name)
        if not tool:
            raise KeyError(f"Tool '{name}' is not registered")
        log.info("tool_executing name=%s", name)
        result = tool.handler(**arguments)
        # Support both sync and async handlers
        import asyncio
        if asyncio.iscoroutine(result):
            result = await result
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        """List all registered tools in Anthropic API format."""
        return [t.to_anthropic_format() for t in self._tools.values()]

    @property
    def tool_count(self) -> int:
        return len(self._tools)
