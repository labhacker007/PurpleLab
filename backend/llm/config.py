"""LLM function configuration models.

Defines which functions can have per-model configuration and the
data models for storing/retrieving those configs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LLMFunction(str, Enum):
    """All system functions that route through an LLM.

    Each function can be independently configured to use a different
    provider/model. This allows cost/capability trade-offs per workload:
    - Use a fast cheap model (Haiku, GPT-4o-mini) for high-volume log generation
    - Use the frontier model (Opus, GPT-4o) for complex threat intel research
    - Use a local Ollama model for air-gapped/sensitive environments
    """
    AGENT_CHAT = "AGENT_CHAT"
    """Main agentic conversation loop — needs tool calling + streaming."""

    LOG_GENERATION = "LOG_GENERATION"
    """Agentic log event generation from schema templates."""

    THREAT_INTEL = "THREAT_INTEL"
    """Threat actor and technique research and analysis."""

    RULE_ANALYSIS = "RULE_ANALYSIS"
    """Detection rule parsing, quality review, Sigma translation."""

    EMBEDDING = "EMBEDDING"
    """Knowledge base vector embeddings (not all providers support this)."""

    SCORING_ASSIST = "SCORING_ASSIST"
    """DES/IHDS score explanation and improvement suggestions."""

    ATTACK_CHAIN_PLAN = "ATTACK_CHAIN_PLAN"
    """Attack chain sequencing and TTP selection."""

    SIGMA_TRANSLATION = "SIGMA_TRANSLATION"
    """Sigma rule translation to SPL/KQL/ES|QL/YARA-L."""

    HITL_REVIEW = "HITL_REVIEW"
    """Human-in-the-loop decision summarization and suggestions."""


# Human-readable metadata for the admin UI
FUNCTION_METADATA: dict[str, dict[str, Any]] = {
    LLMFunction.AGENT_CHAT: {
        "display_name": "Agent Chat",
        "description": "Main agentic conversation loop with tool calling and streaming.",
        "needs_tools": True,
        "needs_streaming": True,
        "volume": "low",
        "recommended_tags": ["balanced", "frontier"],
    },
    LLMFunction.LOG_GENERATION: {
        "display_name": "Log Generation",
        "description": "Generate realistic synthetic log events from vendor schemas.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "high",
        "recommended_tags": ["fast", "cheap"],
    },
    LLMFunction.THREAT_INTEL: {
        "display_name": "Threat Intelligence",
        "description": "Research threat actors, TTPs, and MITRE techniques.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "medium",
        "recommended_tags": ["balanced", "reasoning"],
    },
    LLMFunction.RULE_ANALYSIS: {
        "display_name": "Rule Analysis",
        "description": "Parse, review, and improve detection rules.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "medium",
        "recommended_tags": ["balanced", "code"],
    },
    LLMFunction.EMBEDDING: {
        "display_name": "Embeddings",
        "description": "Knowledge base vector embeddings for semantic search.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "high",
        "recommended_tags": ["fast"],
        "note": "Not all providers support embeddings.",
    },
    LLMFunction.SCORING_ASSIST: {
        "display_name": "Scoring Assistant",
        "description": "Explain DES/IHDS scores and suggest improvements.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "low",
        "recommended_tags": ["reasoning", "balanced"],
    },
    LLMFunction.ATTACK_CHAIN_PLAN: {
        "display_name": "Attack Chain Planning",
        "description": "Plan attack chain sequences from threat actor profiles.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "low",
        "recommended_tags": ["reasoning", "frontier"],
    },
    LLMFunction.SIGMA_TRANSLATION: {
        "display_name": "Sigma Translation",
        "description": "Translate Sigma rules to SPL, KQL, ES|QL, YARA-L.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "medium",
        "recommended_tags": ["code", "balanced"],
    },
    LLMFunction.HITL_REVIEW: {
        "display_name": "HITL Review",
        "description": "Summarise pending approvals and suggest decisions.",
        "needs_tools": False,
        "needs_streaming": False,
        "volume": "low",
        "recommended_tags": ["balanced"],
    },
}


@dataclass
class ModelConfig:
    """Configuration for a specific LLM function."""
    provider: str                         # LLMProvider value
    model_id: str                         # e.g. "claude-sonnet-4-6"
    temperature: float = 0.3
    max_tokens: int = 4096
    base_url: str = ""                    # Required for Ollama; optional for Azure
    api_key_override: str = ""            # Explicit key; empty = read from env
    extra_params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "base_url": self.base_url,
            "has_api_key_override": bool(self.api_key_override),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ModelConfig":
        return cls(
            provider=d["provider"],
            model_id=d["model_id"],
            temperature=float(d.get("temperature", 0.3)),
            max_tokens=int(d.get("max_tokens", 4096)),
            base_url=d.get("base_url", ""),
            api_key_override=d.get("api_key_override", ""),
            extra_params=d.get("extra_params", {}),
        )


@dataclass
class FunctionModelConfig:
    """Full config entry for a function including fallback."""
    function_name: str
    config: ModelConfig
    fallback_config: ModelConfig | None = None
    is_active: bool = True
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        meta = FUNCTION_METADATA.get(self.function_name, {})
        return {
            "function_name": self.function_name,
            "display_name": meta.get("display_name", self.function_name),
            "description": meta.get("description", ""),
            "needs_tools": meta.get("needs_tools", False),
            "volume": meta.get("volume", "medium"),
            "config": self.config.to_dict(),
            "fallback_config": self.fallback_config.to_dict() if self.fallback_config else None,
            "is_active": self.is_active,
            "updated_at": self.updated_at,
        }


# ---------------------------------------------------------------------------
# Default configurations
# These are used when no DB config exists for a function.
# ---------------------------------------------------------------------------

def default_config(function: LLMFunction, settings: Any) -> ModelConfig:
    """Return the default ModelConfig for a function based on app settings."""
    from backend.llm.providers import LLMProvider

    # Determine provider from primary API key availability
    if getattr(settings, "ANTHROPIC_API_KEY", ""):
        provider = LLMProvider.ANTHROPIC
    elif getattr(settings, "OPENAI_API_KEY", ""):
        provider = LLMProvider.OPENAI
    else:
        provider = LLMProvider.OLLAMA

    # Model selection: cheap/fast models for high-volume, frontier for complex tasks
    if provider == LLMProvider.ANTHROPIC:
        high_volume_model = "claude-haiku-4-5-20251001"
        balanced_model = "claude-sonnet-4-6"
        frontier_model = "claude-sonnet-4-6"
    elif provider == LLMProvider.OPENAI:
        high_volume_model = "gpt-4o-mini"
        balanced_model = "gpt-4o-mini"
        frontier_model = "gpt-4o"
    else:
        high_volume_model = "llama3.2"
        balanced_model = "llama3.2"
        frontier_model = "llama3.1:70b"

    meta = FUNCTION_METADATA.get(function.value, {})
    volume = meta.get("volume", "medium")

    if volume == "high":
        model = high_volume_model
        temperature = 0.5
    elif volume == "low":
        model = frontier_model
        temperature = 0.2
    else:
        model = balanced_model
        temperature = 0.3

    # Ollama needs base URL
    base_url = ""
    if provider == LLMProvider.OLLAMA:
        base_url = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434")

    return ModelConfig(
        provider=provider,
        model_id=model,
        temperature=temperature,
        max_tokens=4096,
        base_url=base_url,
    )


DEFAULT_FUNCTION_CONFIGS: dict[LLMFunction, dict[str, Any]] = {
    # Chat needs the best tool-calling model
    LLMFunction.AGENT_CHAT: {
        "temperature": 0.2, "max_tokens": 4096, "volume": "low"
    },
    # Log gen: high-volume, use cheap model
    LLMFunction.LOG_GENERATION: {
        "temperature": 0.7, "max_tokens": 4096, "volume": "high"
    },
    # Threat intel: needs depth
    LLMFunction.THREAT_INTEL: {
        "temperature": 0.1, "max_tokens": 8192, "volume": "medium"
    },
    # Rule analysis: needs precision
    LLMFunction.RULE_ANALYSIS: {
        "temperature": 0.1, "max_tokens": 4096, "volume": "medium"
    },
    # Sigma translation: code-like, low temp
    LLMFunction.SIGMA_TRANSLATION: {
        "temperature": 0.1, "max_tokens": 2048, "volume": "medium"
    },
}
