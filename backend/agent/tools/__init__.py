"""Agent tools — callable functions available to the LLM during conversation.

Each sub-module registers domain-specific tools with the ToolRegistry.
Call ``register_all_tools(registry)`` at startup to make all tools
available to the agent orchestrator.
"""
from __future__ import annotations

from backend.agent.tool_registry import ToolRegistry


def register_all_tools(registry: ToolRegistry) -> None:
    """Register every tool from every tool module.

    This is the single entry point called at application startup.
    Each module's ``register_tools`` function adds its tools to the
    shared registry.
    """
    from backend.agent.tools import threat_intel_tools
    from backend.agent.tools import rule_tools
    from backend.agent.tools import log_tools
    from backend.agent.tools import siem_tools
    from backend.agent.tools import knowledge_tools
    from backend.agent.tools import simulation_tools
    from backend.agent.tools import sigma_tools
    from backend.agent.tools import hitl_tools

    threat_intel_tools.register_tools(registry)
    rule_tools.register_tools(registry)
    log_tools.register_tools(registry)
    siem_tools.register_tools(registry)
    knowledge_tools.register_tools(registry)
    simulation_tools.register_tools(registry)
    sigma_tools.register_tools(registry)
    hitl_tools.register_tools(registry)
