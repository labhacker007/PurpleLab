"""Agent orchestrator — coordinates LLM calls with tool execution.

The orchestrator implements the agentic loop:
1. Receive user message
2. Send to LLM with system prompt + conversation history + available tools
3. If LLM returns tool calls, execute them and feed results back
4. Repeat until LLM returns a final text response
5. Stream all intermediate steps to the client via SSE
"""
from __future__ import annotations

import logging
from typing import Any, AsyncIterator

log = logging.getLogger(__name__)


class AgentOrchestrator:
    """Coordinates the agentic conversation loop.

    TODO: Initialize Anthropic client with ANTHROPIC_API_KEY from settings.
    TODO: Implement the tool-use loop with Claude's tool_use API.
    TODO: Support streaming responses via SSE.
    TODO: Add conversation context management (sliding window, summarization).
    TODO: Implement error recovery and retry logic.
    TODO: Add token usage tracking and rate limiting.
    """

    def __init__(self) -> None:
        # TODO: Initialize LLM client
        # from anthropic import AsyncAnthropic
        # from backend.config import settings
        # self.client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        # self.tool_registry = ToolRegistry()
        # self.conversation_manager = ConversationManager()
        pass

    async def run(
        self,
        message: str,
        conversation_id: str | None = None,
        environment_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Execute the agentic loop and yield SSE chunks.

        Args:
            message: The user's input message.
            conversation_id: Optional existing conversation to continue.
            environment_id: Optional environment context for the agent.
            context: Additional context (active rules, SIEM config, etc.).

        Yields:
            Dicts with type/content/metadata for SSE streaming.

        TODO: Implement full agentic loop.
        """
        yield {
            "type": "text",
            "content": "Agent orchestrator is not yet implemented.",
        }
        yield {"type": "done"}
