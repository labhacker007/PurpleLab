"""Agent orchestrator — coordinates LLM calls with tool execution.

The orchestrator implements the agentic loop:
1. Receive user message
2. Send to LLM with system prompt + conversation history + available tools
3. If LLM returns tool calls, execute them and feed results back
4. Repeat until LLM returns a final text response
5. Stream all intermediate steps to the client via SSE
"""
from __future__ import annotations

import json
import logging
import traceback
from typing import Any, AsyncIterator, Optional

log = logging.getLogger(__name__)

# Attempt to import anthropic — degrade gracefully if not installed.
try:
    from anthropic import AsyncAnthropic
except ImportError:
    AsyncAnthropic = None  # type: ignore[assignment, misc]
    log.warning(
        "anthropic SDK is not installed — AgentOrchestrator will not function. "
        "Install with: pip install anthropic"
    )

from backend.config import settings
from backend.agent.tool_registry import ToolRegistry
from backend.agent.conversation import ConversationManager
from backend.agent.prompts import build_system_prompt

# Maximum number of tool-use round-trips before forcing a text reply.
_MAX_TOOL_ROUNDS = 15


class AgentOrchestrator:
    """Coordinates the agentic conversation loop.

    One orchestrator instance is shared across requests (singleton pattern
    managed by ``get_orchestrator``). It holds the Anthropic client,
    tool registry, and conversation manager.
    """

    def __init__(self) -> None:
        if AsyncAnthropic is None:
            raise RuntimeError(
                "anthropic SDK is not installed. "
                "Install with: pip install anthropic"
            )
        self.client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.tool_registry = ToolRegistry()
        self.conversation_manager = ConversationManager()
        self.register_default_tools()

    # ── Tool Registration ───────────────────────────────────────────────────

    def register_default_tools(self) -> None:
        """Import and register built-in tools from the tools/ directory."""
        try:
            from backend.agent.tools import register_all_tools
            register_all_tools(self.tool_registry)
        except Exception:
            log.warning("tools_load_error", exc_info=True)

        log.info("tool_registry_ready count=%d", self.tool_registry.tool_count)

    # ── Agentic Loop ────────────────────────────────────────────────────────

    async def run(
        self,
        message: str,
        conversation_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Execute the agentic loop and yield SSE-ready dicts.

        Args:
            message: The user's input message.
            conversation_id: Optional existing conversation to continue.
            environment_id: Optional environment context for the agent.
            context: Additional context (active rules, SIEM config, etc.).

        Yields:
            Dicts with ``type`` / ``content`` / ``metadata`` keys.
        """
        context = context or {}

        try:
            # Resolve conversation
            conv_id = await self.conversation_manager.get_or_create(conversation_id)

            # Yield the conversation id so the frontend knows which conversation this is
            yield {
                "type": "conversation_id",
                "content": conv_id,
                "metadata": {},
            }

            # Store the user message
            await self.conversation_manager.add_message(conv_id, "user", message)

            # Trim to budget before building the messages array
            await self.conversation_manager.trim_to_budget(conv_id)

            # Build system prompt
            env_context = context.get("environment", None)
            if environment_id:
                env_context = env_context or f"Environment ID: {environment_id}"
            rag_context = context.get("rag_context", None)
            system_prompt = build_system_prompt(
                environment_context=env_context,
                available_tools=self.tool_registry.list_tools() or None,
                rag_context=rag_context,
            )

            # Build messages array from conversation history
            api_messages = await self.conversation_manager.get_anthropic_messages(conv_id)

            # Prepare tools
            tools = self.tool_registry.list_tools()

            # ── Agentic loop ────────────────────────────────────────────────
            for _round in range(_MAX_TOOL_ROUNDS):
                try:
                    response = await self.client.messages.create(
                        model=settings.DEFAULT_MODEL,
                        max_tokens=4096,
                        system=system_prompt,
                        messages=api_messages,
                        tools=tools if tools else [],
                    )
                except Exception as api_err:
                    log.error("anthropic_api_error: %s", api_err, exc_info=True)
                    yield {
                        "type": "error",
                        "content": f"LLM API error: {api_err}",
                        "metadata": {},
                    }
                    yield {"type": "done", "content": "", "metadata": {}}
                    return

                # Process response content blocks
                text_parts: list[str] = []
                tool_use_blocks: list[dict[str, Any]] = []

                for block in response.content:
                    if block.type == "text":
                        text_parts.append(block.text)
                        yield {
                            "type": "text",
                            "content": block.text,
                            "metadata": {},
                        }
                    elif block.type == "tool_use":
                        tool_use_blocks.append({
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })
                        yield {
                            "type": "tool_call",
                            "content": "",
                            "metadata": {
                                "tool_name": block.name,
                                "arguments": block.input,
                                "tool_use_id": block.id,
                            },
                        }

                # If no tool calls, we're done — this is the final response.
                if response.stop_reason != "tool_use" or not tool_use_blocks:
                    # Store the assistant's final text reply
                    combined_text = "\n".join(text_parts) if text_parts else ""
                    await self.conversation_manager.add_message(
                        conv_id, "assistant", combined_text
                    )
                    break

                # ── Execute tools and feed results back ─────────────────────

                # Store the assistant message with tool calls
                combined_text = "\n".join(text_parts) if text_parts else ""
                await self.conversation_manager.add_message(
                    conv_id,
                    "assistant",
                    combined_text,
                    tool_calls=tool_use_blocks,
                )

                # Build the assistant content blocks for the API
                assistant_content: list[dict[str, Any]] = []
                if combined_text:
                    assistant_content.append({"type": "text", "text": combined_text})
                for tc in tool_use_blocks:
                    assistant_content.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc["input"],
                    })
                api_messages.append({"role": "assistant", "content": assistant_content})

                # Execute each tool and collect results
                tool_result_blocks: list[dict[str, Any]] = []
                for tc in tool_use_blocks:
                    tool_name = tc["name"]
                    tool_args = tc["input"]
                    tool_use_id = tc["id"]

                    try:
                        result = await self.tool_registry.execute(tool_name, tool_args)
                        result_str = (
                            json.dumps(result, default=str)
                            if not isinstance(result, str)
                            else result
                        )
                    except KeyError:
                        result_str = f"Error: Tool '{tool_name}' is not registered."
                        log.warning("tool_not_found name=%s", tool_name)
                    except Exception as tool_err:
                        result_str = f"Error executing tool '{tool_name}': {tool_err}"
                        log.error(
                            "tool_execution_error name=%s error=%s",
                            tool_name,
                            tool_err,
                            exc_info=True,
                        )

                    yield {
                        "type": "tool_result",
                        "content": "",
                        "metadata": {
                            "tool_name": tool_name,
                            "result": result_str,
                            "tool_use_id": tool_use_id,
                        },
                    }

                    tool_result_blocks.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": result_str,
                    })

                # Append tool results as a user message (Anthropic API format)
                api_messages.append({"role": "user", "content": tool_result_blocks})

                # Store tool results in conversation
                await self.conversation_manager.add_message(
                    conv_id,
                    "user",
                    "",
                    tool_results=[
                        {"tool_use_id": tr["tool_use_id"], "content": tr["content"]}
                        for tr in tool_result_blocks
                    ],
                )

            else:
                # Exhausted max rounds
                yield {
                    "type": "text",
                    "content": (
                        "I've reached the maximum number of tool calls for this turn. "
                        "Here's what I have so far — please let me know if you'd like "
                        "me to continue."
                    ),
                    "metadata": {},
                }

        except Exception as exc:
            log.error("orchestrator_error: %s", exc, exc_info=True)
            yield {
                "type": "error",
                "content": f"Internal error: {exc}",
                "metadata": {"traceback": traceback.format_exc()},
            }

        # Always emit done
        yield {"type": "done", "content": "", "metadata": {}}


# ── Singleton / Dependency Injection ────────────────────────────────────────

_orchestrator_instance: Optional[AgentOrchestrator] = None


def get_orchestrator() -> AgentOrchestrator:
    """Return the shared AgentOrchestrator singleton.

    Lazily initialises on first call so that import-time errors
    (e.g. missing API key) are deferred until the endpoint is hit.
    """
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = AgentOrchestrator()
    return _orchestrator_instance
