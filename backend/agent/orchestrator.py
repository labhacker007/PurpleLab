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

import asyncio
import json
import logging
import traceback
import uuid
from typing import Any, AsyncIterator, Optional

log = logging.getLogger(__name__)

_MAX_TOOL_ROUNDS = 10
# Keep conversation history under this many tokens to stay within TPM limits
_HISTORY_TOKEN_BUDGET = 18_000
# 429 retry config
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 2.0


class AgentOrchestrator:
    """Coordinates the agentic conversation loop across any LLM provider."""

    def __init__(self) -> None:
        from backend.agent.tool_registry import ToolRegistry
        from backend.agent.conversation import ConversationManager
        self.tool_registry = ToolRegistry()
        self.conversation_manager = ConversationManager()
        self._register_tools()
        self._guardrail_cache: dict[str, Any] = {}
        self._guardrail_cache_ts: float = 0.0

    async def _get_chat_guardrail(self) -> dict[str, Any]:
        """Return the AGENT_CHAT guardrail config, cached for 5 minutes."""
        import time
        now = time.monotonic()
        if now - self._guardrail_cache_ts < 300 and self._guardrail_cache:
            return self._guardrail_cache
        try:
            from backend.db.session import async_session
            from backend.db.models import AIGuardrailConfig
            from sqlalchemy import select as sa_select
            async with async_session() as db:
                row = await db.scalar(
                    sa_select(AIGuardrailConfig).where(
                        AIGuardrailConfig.function_name == "AGENT_CHAT"
                    )
                )
            if row:
                self._guardrail_cache = {
                    "max_input_tokens": row.max_input_tokens,
                    "max_output_tokens": row.max_output_tokens,
                    "rate_limit_per_minute": row.rate_limit_per_minute,
                    "enabled": row.enabled,
                }
        except Exception as e:
            log.debug("guardrail_cache_miss: %s", e)
        self._guardrail_cache_ts = now
        return self._guardrail_cache

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

            # Load sticky context to seed get_or_create with existing goal
            goal_hint = context.get("goal")
            conv_id = await self.conversation_manager.get_or_create(
                conversation_id, goal=goal_hint
            )
            yield {"type": "conversation_id", "content": conv_id, "metadata": {}}

            await self.conversation_manager.add_message(conv_id, "user", message)
            # Use admin-configured context budget (falls back to class default)
            guardrail = await self._get_chat_guardrail()
            history_budget = guardrail.get("max_input_tokens") or _HISTORY_TOKEN_BUDGET
            await self.conversation_manager.trim_to_budget(conv_id, budget=history_budget)

            # Load sticky context for this conversation
            sticky = await self.conversation_manager.get_context(conv_id)
            # Merge request-level context over sticky (request wins)
            merged_context = {**sticky, **context}

            env_context = merged_context.get("environment")
            if not env_context and environment_id:
                env_context = f"Environment ID: {environment_id}"
            elif not env_context and merged_context.get("environment_name"):
                env_context = merged_context["environment_name"]

            system_prompt = build_system_prompt(
                environment_context=env_context,
                rag_context=merged_context.get("rag_context"),
                context_state=sticky,
            )

            # Set ContextVar so save_context tool can access conv_id + manager
            try:
                from backend.agent.tools.context_tools import set_conversation_context
                set_conversation_context(conv_id, self.conversation_manager)
            except Exception:
                pass

            # Route to correct provider loop
            if cfg.provider == LLMProvider.ANTHROPIC:
                gen = self._run_anthropic(conv_id, system_prompt, cfg)
            else:
                gen = self._run_openai_compat(conv_id, system_prompt, cfg)

            async for event in gen:
                yield event

            # Emit the updated sticky context so the frontend can refresh the context bar
            updated_ctx = await self.conversation_manager.get_context(conv_id)
            if updated_ctx:
                yield {"type": "context_state", "content": "", "metadata": updated_ctx}

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
            response = None
            last_err: Exception | None = None
            for _attempt in range(_MAX_RETRIES + 1):
                try:
                    response = await client.messages.create(
                        model=cfg.model_id,
                        max_tokens=cfg.max_tokens,
                        temperature=cfg.temperature,
                        system=system_prompt,
                        messages=api_messages,
                        tools=tools if tools else [],
                    )
                    break
                except Exception as api_err:
                    err_str = str(api_err)
                    last_err = api_err
                    is_rate_limit = "429" in err_str or "rate_limit" in err_str.lower()
                    is_overload = "overloaded" in err_str.lower() or "529" in err_str
                    if (is_rate_limit or is_overload) and _attempt < _MAX_RETRIES:
                        wait = _RETRY_BASE_DELAY * (2 ** _attempt)
                        log.warning("anthropic_rate_limit attempt=%d waiting=%.1fs", _attempt + 1, wait)
                        yield {"type": "text", "content": f"\n*Rate limited — retrying in {int(wait)}s...*\n", "metadata": {}}
                        await asyncio.sleep(wait)
                        continue
                    log.error("anthropic_api_error: %s", api_err, exc_info=True)
                    yield {"type": "error", "content": f"LLM API error: {api_err}", "metadata": {}}
                    return
            if response is None:
                yield {"type": "error", "content": f"LLM API error after retries: {last_err}", "metadata": {}}
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

            tool_result_blocks = await self._execute_tools(tool_use_blocks, conv_id=conv_id)
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
        self,
        tool_use_blocks: list[dict[str, Any]],
        conv_id: str | None = None,
    ) -> list[dict[str, Any]]:
        results = []
        for tc in tool_use_blocks:
            try:
                result = await self.tool_registry.execute(tc["name"], tc["input"])
                # Auto-extract context patch if the tool returns one
                if conv_id and isinstance(result, dict):
                    patch = result.pop("_context_patch", None)
                    if patch:
                        await self.conversation_manager.update_context(conv_id, patch)
                    else:
                        # Auto-detect well-known fields even without explicit _context_patch
                        inferred = _infer_context_patch(tc["name"], result)
                        if inferred:
                            await self.conversation_manager.update_context(conv_id, inferred)
                result_str = json.dumps(result, default=str) if not isinstance(result, str) else result
            except KeyError:
                result_str = f"Error: Tool '{tc['name']}' not registered."
            except Exception as e:
                result_str = f"Error: {e}"
                log.error("tool_error name=%s: %s", tc["name"], e, exc_info=True)
            results.append({"tool_use_id": tc["id"], "content": result_str, "_name": tc["name"]})
        return results


# ── Helpers ──────────────────────────────────────────────────────────────────

def _infer_context_patch(tool_name: str, result: dict[str, Any]) -> dict[str, Any] | None:
    """Infer context_state updates from tool results without explicit _context_patch.

    Keeps the agent's context bar up to date automatically as it uses tools.
    """
    if result.get("status") != "success":
        return None
    data = result.get("data", result)
    patch: dict[str, Any] = {}

    # Environment tools
    if tool_name in ("create_environment", "get_environment", "configure_environment"):
        if data.get("id"):
            patch["environment_id"] = str(data["id"])
        if data.get("name"):
            patch["environment_name"] = data["name"]

    # Session tools
    if tool_name in ("get_session", "run_scenario"):
        sid = data.get("id") or data.get("session_id")
        if sid:
            patch["active_session_id"] = str(sid)
            patch.setdefault("working_set", {})
            patch["working_set"]["session_ids"] = [str(sid)]

    # Sigma / rule tools
    if tool_name in ("import_sigma_rule", "search_sigma_library"):
        rule_ids = []
        if isinstance(data, list):
            rule_ids = [str(r.get("id")) for r in data if r.get("id")]
        elif data.get("id"):
            rule_ids = [str(data["id"])]
        if rule_ids:
            patch.setdefault("working_set", {})
            patch["working_set"]["rule_ids"] = rule_ids

    # Use-case tools
    if tool_name in ("create_use_case", "run_use_case", "get_use_case_coverage"):
        uc_id = data.get("id")
        if uc_id:
            patch.setdefault("working_set", {})
            patch["working_set"]["use_case_ids"] = [str(uc_id)]

    # Track last tool used
    if patch or tool_name:
        patch["last_tool"] = tool_name

    return patch if patch else None


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
