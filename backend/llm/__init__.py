"""PurpleLab LLM Router — multi-provider, per-function model configuration.

Every function (chat, log generation, threat intel, etc.) can be configured
by an admin to use any supported LLM provider and model. Configs are stored
in the database with in-memory caching so routing decisions are fast.

Supported providers:
  - Anthropic   — Claude (claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5)
  - OpenAI      — GPT-4o, GPT-4o-mini, o1, o3-mini
  - Google      — Gemini 2.0 Flash, 1.5 Pro (via OpenAI-compat endpoint)
  - Ollama      — Any local model (llama3.2, mistral, qwen2.5, deepseek-r1, …)
  - Azure OpenAI — GPT-4o via Azure endpoint

Usage::

    from backend.llm import get_router, LLMFunction

    router = get_router()

    # Simple text completion (for log generation, threat intel, etc.)
    text = await router.complete(LLMFunction.LOG_GENERATION, messages=[
        {"role": "user", "content": "Generate 5 sysmon events for T1059.001"}
    ])

    # Full chat client for the agentic loop (returns provider-specific client)
    client = router.get_chat_client(LLMFunction.AGENT_CHAT)
    # client.provider tells you which SDK to use
"""
from backend.llm.providers import LLMProvider, ModelCatalog, PROVIDER_DISPLAY_NAMES
from backend.llm.config import LLMFunction, ModelConfig, FunctionModelConfig
from backend.llm.router import LLMRouter, get_router
from backend.llm.client import UnifiedCompletionClient

__all__ = [
    "LLMProvider",
    "ModelCatalog",
    "PROVIDER_DISPLAY_NAMES",
    "LLMFunction",
    "ModelConfig",
    "FunctionModelConfig",
    "LLMRouter",
    "get_router",
    "UnifiedCompletionClient",
]
