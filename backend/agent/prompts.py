"""System prompt templates for the agent.

These prompts define the agent's persona, capabilities, and behavior
when interacting with users through the chat interface.
"""
from __future__ import annotations

from typing import Any, Optional


# ── Base Identity ───────────────────────────────────────────────────────────

_BASE_IDENTITY = """\
You are PurpleLab, an expert cybersecurity simulation assistant. You help security teams:

1. **Simulate attacks**: Generate realistic security events matching real vendor formats (Splunk, CrowdStrike, Sentinel, etc.)
2. **Test detection rules**: Evaluate detection rules against simulated attack data to measure coverage
3. **Research threats**: Look up threat actors, MITRE ATT&CK techniques, and TTPs
4. **Build environments**: Configure simulated SOC environments with specific SIEM platforms and log sources
5. **Analyze coverage**: Map detection rules to MITRE ATT&CK and identify gaps

When users ask you to do something, use your tools to accomplish it. Be specific and actionable.
Always explain what you're doing and why."""

# ── Tool Description Block ──────────────────────────────────────────────────

_TOOLS_SECTION = """
## Available Tools

You have access to the following tools:
{tool_descriptions}

Use these tools whenever the user's request requires data retrieval, simulation,
or any action that goes beyond pure conversation. Call tools with the correct
parameter schema. You may call multiple tools in sequence if needed."""

# ── Environment Context Block ───────────────────────────────────────────────

_ENVIRONMENT_SECTION = """
## Current Environment

{environment_context}"""

# ── RAG Context Block ──────────────────────────────────────────────────────

_RAG_SECTION = """
## Relevant Knowledge Base Context

The following information was retrieved from the knowledge base and may be
relevant to the current conversation:

{rag_context}"""

# ── Legacy compat (kept for any code that imports SYSTEM_PROMPT directly) ──

SYSTEM_PROMPT = _BASE_IDENTITY + """

Current environment: {environment_context}
"""


# ── Tool Result Prompt ──────────────────────────────────────────────────────

TOOL_RESULT_PROMPT = """\
The tool '{tool_name}' returned the following result:

{result}

Use this information to continue helping the user. If the result indicates an error,
explain what went wrong and suggest alternatives."""


# ── Conversation Summary Prompt ─────────────────────────────────────────────

CONVERSATION_SUMMARY_PROMPT = """\
Summarize the following conversation in 2-3 sentences,
focusing on what was accomplished and any pending tasks:

{conversation}"""


# ── Builder ─────────────────────────────────────────────────────────────────

def build_system_prompt(
    environment_context: Optional[str] = None,
    available_tools: Optional[list[dict[str, Any]]] = None,
    rag_context: Optional[str] = None,
) -> str:
    """Dynamically assemble the system prompt from component sections.

    Args:
        environment_context: Description of the active simulation environment
            (SIEM type, log sources, etc.). ``None`` means no environment.
        available_tools: List of tool definitions (Anthropic format) to
            describe in the prompt so the model knows what it can call.
        rag_context: Pre-retrieved knowledge-base snippets to inject.

    Returns:
        A fully assembled system prompt string.
    """
    sections: list[str] = [_BASE_IDENTITY]

    # Tools section
    if available_tools:
        descriptions: list[str] = []
        for tool in available_tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            descriptions.append(f"- **{name}**: {desc}")
        tool_block = _TOOLS_SECTION.format(
            tool_descriptions="\n".join(descriptions)
        )
        sections.append(tool_block)

    # Environment section
    if environment_context:
        sections.append(
            _ENVIRONMENT_SECTION.format(environment_context=environment_context)
        )

    # RAG section
    if rag_context:
        sections.append(
            _RAG_SECTION.format(rag_context=rag_context)
        )

    return "\n".join(sections)
