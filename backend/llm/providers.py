"""LLM provider definitions and model catalogs.

Contains:
  - LLMProvider enum
  - ModelCatalog: known models per provider with capabilities/cost metadata
  - PROVIDER_DISPLAY_NAMES: human-readable labels for the UI
"""
from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from typing import Any


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    OLLAMA = "ollama"
    AZURE_OPENAI = "azure_openai"


PROVIDER_DISPLAY_NAMES: dict[str, str] = {
    LLMProvider.ANTHROPIC: "Anthropic (Claude)",
    LLMProvider.OPENAI: "OpenAI",
    LLMProvider.GOOGLE: "Google Gemini",
    LLMProvider.OLLAMA: "Ollama (Local)",
    LLMProvider.AZURE_OPENAI: "Azure OpenAI",
}


@dataclass
class ModelSpec:
    """Metadata for a single model."""
    model_id: str
    display_name: str
    context_window: int         # tokens
    max_output_tokens: int
    supports_tools: bool = True
    supports_vision: bool = False
    supports_streaming: bool = True
    cost_per_1k_input: float = 0.0   # USD
    cost_per_1k_output: float = 0.0  # USD
    is_reasoning: bool = False        # o1/o3 style chain-of-thought models
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "display_name": self.display_name,
            "context_window": self.context_window,
            "max_output_tokens": self.max_output_tokens,
            "supports_tools": self.supports_tools,
            "supports_vision": self.supports_vision,
            "supports_streaming": self.supports_streaming,
            "cost_per_1k_input": self.cost_per_1k_input,
            "cost_per_1k_output": self.cost_per_1k_output,
            "is_reasoning": self.is_reasoning,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# Model Catalogs
# ---------------------------------------------------------------------------

ANTHROPIC_MODELS: list[ModelSpec] = [
    ModelSpec(
        model_id="claude-opus-4-6",
        display_name="Claude Opus 4.6",
        context_window=200_000,
        max_output_tokens=8192,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.015,
        cost_per_1k_output=0.075,
        tags=["frontier", "most-capable", "reasoning"],
    ),
    ModelSpec(
        model_id="claude-sonnet-4-6",
        display_name="Claude Sonnet 4.6",
        context_window=200_000,
        max_output_tokens=8192,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
        tags=["balanced", "recommended", "fast"],
    ),
    ModelSpec(
        model_id="claude-haiku-4-5-20251001",
        display_name="Claude Haiku 4.5",
        context_window=200_000,
        max_output_tokens=4096,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.0008,
        cost_per_1k_output=0.004,
        tags=["fast", "cheap", "high-volume"],
    ),
]

OPENAI_MODELS: list[ModelSpec] = [
    ModelSpec(
        model_id="gpt-4o",
        display_name="GPT-4o",
        context_window=128_000,
        max_output_tokens=16_384,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.005,
        cost_per_1k_output=0.015,
        tags=["frontier", "balanced"],
    ),
    ModelSpec(
        model_id="gpt-4o-mini",
        display_name="GPT-4o Mini",
        context_window=128_000,
        max_output_tokens=16_384,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006,
        tags=["fast", "cheap"],
    ),
    ModelSpec(
        model_id="o1",
        display_name="o1",
        context_window=200_000,
        max_output_tokens=100_000,
        supports_tools=True,
        supports_vision=False,
        cost_per_1k_input=0.015,
        cost_per_1k_output=0.06,
        is_reasoning=True,
        tags=["reasoning", "complex-tasks"],
    ),
    ModelSpec(
        model_id="o3-mini",
        display_name="o3-mini",
        context_window=200_000,
        max_output_tokens=65_536,
        supports_tools=True,
        supports_vision=False,
        cost_per_1k_input=0.0011,
        cost_per_1k_output=0.0044,
        is_reasoning=True,
        tags=["reasoning", "fast"],
    ),
]

GOOGLE_MODELS: list[ModelSpec] = [
    ModelSpec(
        model_id="gemini-2.0-flash",
        display_name="Gemini 2.0 Flash",
        context_window=1_000_000,
        max_output_tokens=8192,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.0001,
        cost_per_1k_output=0.0004,
        tags=["fast", "long-context", "cheap"],
    ),
    ModelSpec(
        model_id="gemini-1.5-pro",
        display_name="Gemini 1.5 Pro",
        context_window=2_000_000,
        max_output_tokens=8192,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.00125,
        cost_per_1k_output=0.005,
        tags=["long-context", "frontier"],
    ),
    ModelSpec(
        model_id="gemini-1.5-flash",
        display_name="Gemini 1.5 Flash",
        context_window=1_000_000,
        max_output_tokens=8192,
        supports_tools=True,
        supports_vision=True,
        cost_per_1k_input=0.000075,
        cost_per_1k_output=0.0003,
        tags=["fast", "cheap"],
    ),
]

# Ollama models: user-defined (these are common defaults)
OLLAMA_MODELS: list[ModelSpec] = [
    ModelSpec(
        model_id="llama3.2",
        display_name="Llama 3.2 (3B)",
        context_window=128_000,
        max_output_tokens=4096,
        supports_tools=True,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        tags=["local", "fast", "small"],
    ),
    ModelSpec(
        model_id="llama3.1:70b",
        display_name="Llama 3.1 70B",
        context_window=128_000,
        max_output_tokens=4096,
        supports_tools=True,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        tags=["local", "large", "capable"],
    ),
    ModelSpec(
        model_id="mistral",
        display_name="Mistral 7B",
        context_window=32_000,
        max_output_tokens=4096,
        supports_tools=False,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        tags=["local", "fast"],
    ),
    ModelSpec(
        model_id="qwen2.5",
        display_name="Qwen 2.5 (7B)",
        context_window=128_000,
        max_output_tokens=8192,
        supports_tools=True,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        tags=["local", "code", "tools"],
    ),
    ModelSpec(
        model_id="qwen2.5:32b",
        display_name="Qwen 2.5 32B",
        context_window=128_000,
        max_output_tokens=8192,
        supports_tools=True,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        tags=["local", "large", "code"],
    ),
    ModelSpec(
        model_id="phi4",
        display_name="Phi-4 (14B)",
        context_window=16_000,
        max_output_tokens=4096,
        supports_tools=True,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        tags=["local", "microsoft", "reasoning"],
    ),
    ModelSpec(
        model_id="deepseek-r1",
        display_name="DeepSeek R1",
        context_window=64_000,
        max_output_tokens=8192,
        supports_tools=False,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        is_reasoning=True,
        tags=["local", "reasoning", "large"],
    ),
    ModelSpec(
        model_id="codellama",
        display_name="Code Llama",
        context_window=16_000,
        max_output_tokens=4096,
        supports_tools=False,
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        tags=["local", "code"],
    ),
]


class ModelCatalog:
    """Registry of all known models per provider."""

    _catalog: dict[str, list[ModelSpec]] = {
        LLMProvider.ANTHROPIC: ANTHROPIC_MODELS,
        LLMProvider.OPENAI: OPENAI_MODELS,
        LLMProvider.GOOGLE: GOOGLE_MODELS,
        LLMProvider.OLLAMA: OLLAMA_MODELS,
        LLMProvider.AZURE_OPENAI: OPENAI_MODELS,  # Same models, different endpoint
    }

    @classmethod
    def get_models(cls, provider: str) -> list[ModelSpec]:
        return cls._catalog.get(provider, [])

    @classmethod
    def get_model(cls, provider: str, model_id: str) -> ModelSpec | None:
        for m in cls.get_models(provider):
            if m.model_id == model_id:
                return m
        return None

    @classmethod
    def all_models_dict(cls) -> dict[str, list[dict]]:
        return {
            provider: [m.to_dict() for m in models]
            for provider, models in cls._catalog.items()
        }

    @classmethod
    def get_default_model(cls, provider: str) -> str:
        """Return the recommended default model for each provider."""
        defaults = {
            LLMProvider.ANTHROPIC: "claude-sonnet-4-6",
            LLMProvider.OPENAI: "gpt-4o-mini",
            LLMProvider.GOOGLE: "gemini-2.0-flash",
            LLMProvider.OLLAMA: "llama3.2",
            LLMProvider.AZURE_OPENAI: "gpt-4o",
        }
        return defaults.get(provider, "")
