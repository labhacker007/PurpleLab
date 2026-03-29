"""Model configuration admin API.

Allows admins and engineers to configure which LLM provider + model
is used for each platform function:
  - AGENT_CHAT, LOG_GENERATION, THREAT_INTEL, RULE_ANALYSIS
  - EMBEDDING, SCORING_ASSIST, ATTACK_CHAIN_PLAN, SIGMA_TRANSLATION, HITL_REVIEW

Changes take effect immediately (cache invalidated on save).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/model-config", tags=["model-config"])


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class ModelConfigRequest(BaseModel):
    provider: str = Field(..., description="LLM provider: anthropic|openai|google|ollama|azure_openai")
    model_id: str = Field(..., description="Model identifier (e.g. 'claude-sonnet-4-6', 'gpt-4o')")
    temperature: float = Field(0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(4096, ge=128, le=128000)
    base_url: str = Field("", description="Base URL — required for Ollama, optional for Azure")
    api_key_override: str = Field("", description="Explicit API key (leave empty to use env var)")
    fallback_provider: str | None = Field(None, description="Fallback provider if primary fails")
    fallback_model_id: str | None = Field(None, description="Fallback model ID")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
async def list_all_configs():
    """List current model configuration for all functions."""
    from backend.llm.router import get_router
    from backend.llm.config import FUNCTION_METADATA
    from backend.llm.providers import ModelCatalog

    router_inst = get_router()
    configs = await router_inst.list_configs()

    return {
        "configs": [c.to_dict() for c in configs],
        "providers": {
            p: {
                "display_name": name,
                "models": [m.to_dict() for m in ModelCatalog.get_models(p)],
            }
            for p, name in _get_provider_display_names().items()
        },
    }


@router.get("/providers")
async def list_providers():
    """List all supported providers with their model catalogs."""
    from backend.llm.providers import ModelCatalog, PROVIDER_DISPLAY_NAMES
    return {
        "providers": [
            {
                "provider": p,
                "display_name": PROVIDER_DISPLAY_NAMES.get(p, p),
                "models": [m.to_dict() for m in ModelCatalog.get_models(p)],
                "requires_api_key": p not in ("ollama",),
                "env_var": _provider_env_var(p),
            }
            for p in ["anthropic", "openai", "google", "ollama", "azure_openai"]
        ]
    }


@router.get("/{function_name}")
async def get_function_config(function_name: str):
    """Get model configuration for a specific function."""
    from backend.llm.router import get_router
    from backend.llm.config import LLMFunction, FUNCTION_METADATA

    try:
        fn = LLMFunction(function_name)
    except ValueError:
        valid = [f.value for f in LLMFunction]
        raise HTTPException(400, detail=f"Unknown function '{function_name}'. Valid: {valid}")

    router_inst = get_router()
    cfg = await router_inst.get_config_async(fn)
    meta = FUNCTION_METADATA.get(fn.value, {})

    return {
        "function_name": fn.value,
        "display_name": meta.get("display_name", fn.value),
        "description": meta.get("description", ""),
        "needs_tools": meta.get("needs_tools", False),
        "volume": meta.get("volume", "medium"),
        "config": cfg.to_dict(),
    }


@router.put("/{function_name}")
async def update_function_config(function_name: str, req: ModelConfigRequest):
    """Update model configuration for a function.

    Takes effect immediately — cache is invalidated on save.
    """
    from backend.llm.router import get_router
    from backend.llm.config import LLMFunction, ModelConfig
    from backend.llm.providers import LLMProvider, ModelCatalog

    try:
        fn = LLMFunction(function_name)
    except ValueError:
        valid = [f.value for f in LLMFunction]
        raise HTTPException(400, detail=f"Unknown function. Valid: {valid}")

    # Validate provider
    try:
        provider = LLMProvider(req.provider)
    except ValueError:
        raise HTTPException(400, detail=f"Unknown provider '{req.provider}'")

    # Build config
    config = ModelConfig(
        provider=req.provider,
        model_id=req.model_id,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
        base_url=req.base_url,
        api_key_override=req.api_key_override,
    )

    # Optional fallback
    fallback = None
    if req.fallback_provider and req.fallback_model_id:
        fallback = ModelConfig(
            provider=req.fallback_provider,
            model_id=req.fallback_model_id,
        )

    router_inst = get_router()
    result = await router_inst.set_config(fn, config, fallback)
    return result.to_dict()


@router.post("/{function_name}/test")
async def test_function_config(function_name: str):
    """Send a test ping to the configured model and return latency/status."""
    from backend.llm.router import get_router
    from backend.llm.config import LLMFunction
    from backend.llm.client import test_model_connection

    try:
        fn = LLMFunction(function_name)
    except ValueError:
        raise HTTPException(400, detail=f"Unknown function '{function_name}'")

    router_inst = get_router()
    cfg = await router_inst.get_config_async(fn)
    result = await test_model_connection(cfg)
    return result


@router.post("/test-all")
async def test_all_configs():
    """Test connectivity for all configured functions in parallel."""
    import asyncio
    from backend.llm.router import get_router
    from backend.llm.config import LLMFunction
    from backend.llm.client import test_model_connection

    router_inst = get_router()

    async def test_one(fn: LLMFunction):
        cfg = await router_inst.get_config_async(fn)
        result = await test_model_connection(cfg)
        return fn.value, result

    tasks = [test_one(fn) for fn in LLMFunction]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    return {
        fn: (result if not isinstance(result, Exception) else {"ok": False, "error": str(result)})
        for fn, result in results
    }


@router.post("/reset-defaults")
async def reset_to_defaults():
    """Reset all function configs to system defaults (clears DB overrides)."""
    from backend.llm.router import get_router
    router_inst = get_router()
    router_inst.invalidate_cache()
    return {"status": "ok", "message": "Cache cleared — defaults will reload on next request."}


@router.get("/ollama/models")
async def list_ollama_models(base_url: str = "http://localhost:11434"):
    """Query a running Ollama instance for available local models."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [
                {
                    "model_id": m["name"],
                    "display_name": m["name"],
                    "size_gb": round(m.get("size", 0) / 1e9, 1),
                    "modified_at": m.get("modified_at", ""),
                }
                for m in data.get("models", [])
            ]
            return {"available": True, "base_url": base_url, "models": models}
    except Exception as exc:
        return {
            "available": False,
            "base_url": base_url,
            "error": str(exc),
            "models": [],
            "hint": "Install Ollama from https://ollama.ai and run 'ollama serve'",
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_provider_display_names() -> dict[str, str]:
    from backend.llm.providers import PROVIDER_DISPLAY_NAMES
    return {str(k): v for k, v in PROVIDER_DISPLAY_NAMES.items()}


def _provider_env_var(provider: str) -> str:
    env_vars = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "google": "GOOGLE_API_KEY",
        "ollama": None,
        "azure_openai": "AZURE_OPENAI_API_KEY",
    }
    return env_vars.get(provider, "")
