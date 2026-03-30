"""Agent orchestrator — coordinates LLM calls with tool execution.

Supports all configured LLM providers via the LLM Router:
  - Anthropic Claude (native tool_use format)
  - OpenAI GPT (function_calling format)
  - Google Gemini (OpenAI-compatible endpoint)
  - Ollama local models (OpenAI-compatible)

The provider is selected by admin configuration per function (AGENT_CHAT).
The agentic loop adapts its API call format to match the active provider.
"""
from __future__ import annotations

import json
import logging
import traceback
import uuid
from typing import Any, AsyncIterator, Optional

log = logging.getLogger(__name__)

_MAX_TOOL_ROUNDS = 15


class AgentOrchestrator:
    """Coordinates the agentic conversation loop across any LLM provider."""

    def __init__(self) -> None:
        from backend.agent.tool_registry import ToolRegistry
        from backend.agent.conversation import ConversationManager
        self.tool_registry = ToolRegistry()
        self.conversation_manager = ConversationManager()
        self._register_tools()

    def _register_tools(self) -> None:
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
        """Execute agentic loop and yield SSE-ready dicts.

        Automatically selects the right API format based on the configured
        AGENT_CHAT model provider.
        """
        context = context or {}

        try:
            from backend.llm.router import get_router
            from backend.llm.providers import LLMProvider
            from backend.llm.config import LLMFunction
            from backend.agent.prompts import build_system_prompt

            router = get_router()
            cfg = await router.get_config_async(LLMFunction.AGENT_CHAT)

            conv_id = await self.conversation_manager.get_or_create(conversation_id)
            yield {"type": "conversation_id", "content": conv_id, "metadata": {}}

            await self.conversation_manager.add_message(conv_id, "user", message)
            await self.conversation_manager.trim_to_budget(conv_id)

            env_context = context.get("environment", None)
            if environment_id:
                env_context = env_context or f"Environment ID: {environment_id}"
            # For OpenAI-compat providers (including Ollama), tools are passed via API
            # params, not in the system prompt — keeps prompt small for local models.
            include_tools_in_prompt = cfg.provider == LLMProvider.ANTHROPIC
            system_prompt = build_system_prompt(
                environment_context=env_context,
                available_tools=self.tool_registry.list_tools() if include_tools_in_prompt else None,
                rag_context=context.get("rag_context", None),
            )

            # Route to correct provider loop
            if cfg.provider == LLMProvider.ANTHROPIC:
                gen = self._run_anthropic(conv_id, system_prompt, cfg)
            else:
                gen = self._run_openai_compat(conv_id, system_prompt, cfg)

            async for event in gen:
                yield event

        except Exception as exc:
            log.error("orchestrator_error: %s", exc, exc_info=True)
            yield {
                "type": "error",
                "content": f"Internal error: {exc}",
                "metadata": {"traceback": traceback.format_exc()},
            }

        yield {"type": "done", "content": "", "metadata": {}}

    # ── Anthropic path ──────────────────────────────────────────────────────

    async def _run_anthropic(
        self,
        conv_id: str,
        system_prompt: str,
        cfg: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        from anthropic import AsyncAnthropic
        import os

        api_key = cfg.api_key_override or os.environ.get("ANTHROPIC_API_KEY", "")
        client = AsyncAnthropic(api_key=api_key)
        tools = self.tool_registry.list_tools()
        api_messages = await self.conversation_manager.get_anthropic_messages(conv_id)

        for _round in range(_MAX_TOOL_ROUNDS):
            try:
                response = await client.messages.create(
                    model=cfg.model_id,
                    max_tokens=cfg.max_tokens,
                    temperature=cfg.temperature,
                    system=system_prompt,
                    messages=api_messages,
                    tools=tools if tools else [],
                )
            except Exception as api_err:
                log.error("anthropic_api_error: %s", api_err, exc_info=True)
                yield {"type": "error", "content": f"LLM API error: {api_err}", "metadata": {}}
                return

            text_parts: list[str] = []
            tool_use_blocks: list[dict[str, Any]] = []

            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                    yield {"type": "text", "content": block.text, "metadata": {}}
                elif block.type == "tool_use":
                    tool_use_blocks.append({"id": block.id, "name": block.name, "input": block.input})
                    yield {
                        "type": "tool_call",
                        "content": "",
                        "metadata": {"tool_name": block.name, "arguments": block.input, "tool_use_id": block.id},
                    }

            if response.stop_reason != "tool_use" or not tool_use_blocks:
                combined = "\n".join(text_parts)
                await self.conversation_manager.add_message(conv_id, "assistant", combined)
                break

            combined = "\n".join(text_parts)
            await self.conversation_manager.add_message(conv_id, "assistant", combined, tool_calls=tool_use_blocks)

            assistant_content: list[dict] = []
            if combined:
                assistant_content.append({"type": "text", "text": combined})
            for tc in tool_use_blocks:
                assistant_content.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["input"]})
            api_messages.append({"role": "assistant", "content": assistant_content})

            tool_result_blocks = await self._execute_tools(tool_use_blocks)
            for tr in tool_result_blocks:
                yield {
                    "type": "tool_result",
                    "content": "",
                    "metadata": {"tool_name": tr["_name"], "result": tr["content"], "tool_use_id": tr["tool_use_id"]},
                }

            api_messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tr["tool_use_id"], "content": tr["content"]}
                for tr in tool_result_blocks
            ]})
            await self.conversation_manager.add_message(conv_id, "user", "", tool_results=[
                {"tool_use_id": tr["tool_use_id"], "content": tr["content"]} for tr in tool_result_blocks
            ])
        else:
            yield {
                "type": "text",
                "content": "I've reached the maximum number of tool calls for this turn. Please let me know if you'd like me to continue.",
                "metadata": {},
            }

    # ── OpenAI-compatible path (OpenAI, Gemini, Ollama) ────────────────────

    async def _run_openai_compat(
        self,
        conv_id: str,
        system_prompt: str,
        cfg: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        from openai import AsyncOpenAI
        from backend.llm.providers import LLMProvider
        from backend.llm.client import _GOOGLE_OPENAI_BASE, _OLLAMA_DEFAULT_BASE
        import os

        # Resolve endpoint
        provider = cfg.provider
        if provider == LLMProvider.OPENAI:
            base_url = "https://api.openai.com/v1"
            api_key = cfg.api_key_override or os.environ.get("OPENAI_API_KEY", "sk-placeholder")
        elif provider == LLMProvider.GOOGLE:
            base_url = _GOOGLE_OPENAI_BASE
            api_key = cfg.api_key_override or os.environ.get("GOOGLE_API_KEY", "placeholder")
        elif provider == LLMProvider.OLLAMA:
            raw_url = cfg.base_url or _OLLAMA_DEFAULT_BASE
            # Ensure /v1 suffix for OpenAI-compatible endpoint
            base_url = raw_url.rstrip("/")
            if not base_url.endswith("/v1"):
                base_url = base_url + "/v1"
            api_key = "ollama"
        else:
            base_url = cfg.base_url or "https://api.openai.com/v1"
            api_key = cfg.api_key_override or os.environ.get("AZURE_OPENAI_API_KEY", "")

        client = AsyncOpenAI(api_key=api_key, base_url=base_url)

        # Convert tools to OpenAI function format
        # Skip tools for Ollama — most local models don't support tool calling via the API
        if provider == LLMProvider.OLLAMA:
            openai_tools = []
        else:
            openai_tools = _tools_to_openai_format(self.tool_registry.list_tools())

        # Build messages from conversation history (OpenAI format)
        api_messages = [{"role": "system", "content": system_prompt}]
        api_messages += await self.conversation_manager.get_openai_messages(conv_id)

        # Track whether this model supports tools (some Ollama models don't)
        _tools_supported = True

        for _round in range(_MAX_TOOL_ROUNDS):
            try:
                kwargs: dict[str, Any] = {
                    "model": cfg.model_id,
                    "messages": api_messages,
                    "max_tokens": cfg.max_tokens,
                    "temperature": cfg.temperature,
                }
                if openai_tools and _tools_supported:
                    kwargs["tools"] = openai_tools
                    kwargs["tool_choice"] = "auto"

                response = await client.chat.completions.create(**kwargs)
            except Exception as api_err:
                err_str = str(api_err)
                # If the model doesn't support tools, retry without them
                if "does not support tools" in err_str and _tools_supported:
                    log.warning("Model %s does not support tools, retrying without", cfg.model_id)
                    _tools_supported = False
                    kwargs.pop("tools", None)
                    kwargs.pop("tool_choice", None)
                    try:
                        response = await client.chat.completions.create(**kwargs)
                    except Exception as retry_err:
                        log.error("openai_api_retry_error: %s", retry_err, exc_info=True)
                        yield {"type": "error", "content": f"LLM API error: {retry_err}", "metadata": {}}
                        return
                else:
                    log.error("openai_api_error: %s", api_err, exc_info=True)
                    yield {"type": "error", "content": f"LLM API error: {api_err}", "metadata": {}}
                    return

            choice = response.choices[0]
            msg = choice.message
            text = msg.content or ""
            tool_calls = msg.tool_calls or []

            if text:
                yield {"type": "text", "content": text, "metadata": {}}

            for tc in tool_calls:
                yield {
                    "type": "tool_call",
                    "content": "",
                    "metadata": {
                        "tool_name": tc.function.name,
                        "arguments": json.loads(tc.function.arguments or "{}"),
                        "tool_use_id": tc.id,
                    },
                }

            if choice.finish_reason != "tool_calls" or not tool_calls:
                await self.conversation_manager.add_message(conv_id, "assistant", text)
                break

            # Execute tools
            await self.conversation_manager.add_message(conv_id, "assistant", text,
                tool_calls=[{"id": tc.id, "name": tc.function.name,
                              "input": json.loads(tc.function.arguments or "{}")}
                             for tc in tool_calls])

            # Append assistant message with tool_calls to api_messages
            api_messages.append({
                "role": "assistant",
                "content": text or None,
                "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ],
            })

            # Execute and append results
            for tc in tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                    result = await self.tool_registry.execute(tc.function.name, args)
                    result_str = json.dumps(result, default=str) if not isinstance(result, str) else result
                except Exception as e:
                    result_str = f"Error: {e}"

                yield {
                    "type": "tool_result",
                    "content": "",
                    "metadata": {"tool_name": tc.function.name, "result": result_str, "tool_use_id": tc.id},
                }
                api_messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_str,
                })
        else:
            yield {
                "type": "text",
                "content": "Maximum tool call rounds reached.",
                "metadata": {},
            }

    # ── Tool execution ──────────────────────────────────────────────────────

    async def _execute_tools(
        self, tool_use_blocks: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        results = []
        for tc in tool_use_blocks:
            try:
                result = await self.tool_registry.execute(tc["name"], tc["input"])
                result_str = json.dumps(result, default=str) if not isinstance(result, str) else result
            except KeyError:
                result_str = f"Error: Tool '{tc['name']}' not registered."
            except Exception as e:
                result_str = f"Error: {e}"
                log.error("tool_error name=%s: %s", tc["name"], e, exc_info=True)
            results.append({"tool_use_id": tc["id"], "content": result_str, "_name": tc["name"]})
        return results


# ── Helpers ──────────────────────────────────────────────────────────────────

def _tools_to_openai_format(anthropic_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert Anthropic tool definitions to OpenAI function_calling format."""
    openai_tools = []
    for tool in anthropic_tools:
        openai_tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
            },
        })
    return openai_tools


# ── Singleton ─────────────────────────────────────────────────────────────────

_orchestrator_instance: Optional[AgentOrchestrator] = None


def get_orchestrator() -> AgentOrchestrator:
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = AgentOrchestrator()
    return _orchestrator_instance
