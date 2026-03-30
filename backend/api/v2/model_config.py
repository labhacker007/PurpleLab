"""Model configuration admin API.

Allows admins and engineers to configure which LLM provider + model
is used for each platform function:
  - AGENT_CHAT, LOG_GENERATION, THREAT_INTEL, RULE_ANALYSIS
  - EMBEDDING, SCORING_ASSIST, ATTACK_CHAIN_PLAN, SIGMA_TRANSLATION, HITL_REVIEW

Also manages provider API keys and local model discovery (Ollama).
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


class ApiKeyRequest(BaseModel):
    provider: str
    api_key: str


class OllamaPullRequest(BaseModel):
    model: str


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
    """List all supported providers with their model catalogs and key status."""
    from backend.llm.providers import ModelCatalog, PROVIDER_DISPLAY_NAMES
    from backend.config import settings

    # Check which providers have keys configured
    env_keys = {
        "anthropic": bool(getattr(settings, "ANTHROPIC_API_KEY", "")),
        "openai": bool(getattr(settings, "OPENAI_API_KEY", "")),
        "google": bool(getattr(settings, "GOOGLE_API_KEY", "")),
        "azure_openai": bool(getattr(settings, "AZURE_OPENAI_API_KEY", "")),
        "ollama": True,  # Always available
    }

    # Also check DB-stored keys
    db_keys = await _get_db_key_providers()

    return {
        "providers": [
            {
                "provider": p,
                "display_name": PROVIDER_DISPLAY_NAMES.get(p, p),
                "models": [m.to_dict() for m in ModelCatalog.get_models(p)],
                "requires_api_key": p not in ("ollama",),
                "env_var": _provider_env_var(p),
                "has_env_key": env_keys.get(p, False),
                "has_db_key": p in db_keys,
                "configured": env_keys.get(p, False) or p in db_keys,
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
    """Update model configuration for a function. Takes effect immediately."""
    from backend.llm.router import get_router
    from backend.llm.config import LLMFunction, ModelConfig
    from backend.llm.providers import LLMProvider, ModelCatalog

    try:
        fn = LLMFunction(function_name)
    except ValueError:
        valid = [f.value for f in LLMFunction]
        raise HTTPException(400, detail=f"Unknown function. Valid: {valid}")

    try:
        provider = LLMProvider(req.provider)
    except ValueError:
        raise HTTPException(400, detail=f"Unknown provider '{req.provider}'")

    config = ModelConfig(
        provider=req.provider,
        model_id=req.model_id,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
        base_url=req.base_url,
        api_key_override=req.api_key_override,
    )

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


# ---------------------------------------------------------------------------
# Provider API Key Management
# ---------------------------------------------------------------------------

@router.get("/api-keys/status")
async def get_api_key_status():
    """Return which providers have API keys configured (env or DB)."""
    from backend.config import settings

    env_status = {
        "anthropic": {"configured": bool(getattr(settings, "ANTHROPIC_API_KEY", "")), "source": "env"},
        "openai": {"configured": bool(getattr(settings, "OPENAI_API_KEY", "")), "source": "env"},
        "google": {"configured": bool(getattr(settings, "GOOGLE_API_KEY", "")), "source": "env"},
        "azure_openai": {"configured": bool(getattr(settings, "AZURE_OPENAI_API_KEY", "")), "source": "env"},
        "ollama": {"configured": True, "source": "local"},
    }

    # Check DB-stored keys
    db_keys = await _get_db_key_providers()
    for provider in db_keys:
        if provider in env_status:
            env_status[provider] = {"configured": True, "source": "database"}
        else:
            env_status[provider] = {"configured": True, "source": "database"}

    return env_status


@router.put("/api-keys")
async def save_api_key(req: ApiKeyRequest):
    """Save or update a provider API key in the database."""
    from backend.db.session import async_session
    from backend.db.models import ProviderApiKey
    from sqlalchemy import select

    if not req.api_key or len(req.api_key) < 5:
        raise HTTPException(400, detail="API key too short")

    async with async_session() as db:
        existing = await db.scalar(
            select(ProviderApiKey).where(ProviderApiKey.provider == req.provider)
        )
        if existing:
            existing.encrypted_key = req.api_key  # TODO: encrypt with Fernet
            existing.source = "ui"
        else:
            db.add(ProviderApiKey(
                provider=req.provider,
                encrypted_key=req.api_key,
                source="ui",
            ))
        await db.commit()

    return {"ok": True, "provider": req.provider}


@router.delete("/api-keys/{provider}")
async def delete_api_key(provider: str):
    """Remove a provider API key from the database."""
    from backend.db.session import async_session
    from backend.db.models import ProviderApiKey
    from sqlalchemy import select, delete

    async with async_session() as db:
        await db.execute(
            delete(ProviderApiKey).where(ProviderApiKey.provider == provider)
        )
        await db.commit()

    return {"ok": True, "provider": provider}


# ---------------------------------------------------------------------------
# Ollama Management
# ---------------------------------------------------------------------------

@router.get("/ollama/models")
async def list_ollama_models(base_url: str | None = None):
    """Query a running Ollama instance for available local models."""
    import httpx
    from backend.config import settings

    url = base_url or getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [
                {
                    "model_id": m["name"],
                    "display_name": m["name"],
                    "size_gb": round(m.get("size", 0) / 1e9, 1),
                    "modified_at": m.get("modified_at", ""),
                    "family": m.get("details", {}).get("family", ""),
                    "parameter_size": m.get("details", {}).get("parameter_size", ""),
                    "quantization": m.get("details", {}).get("quantization_level", ""),
                }
                for m in data.get("models", [])
            ]
            return {"available": True, "base_url": url, "models": models}
    except Exception as exc:
        return {
            "available": False,
            "base_url": url,
            "error": str(exc),
            "models": [],
            "hint": "Install Ollama from https://ollama.ai and run 'ollama serve'",
        }


@router.post("/ollama/pull")
async def pull_ollama_model(req: OllamaPullRequest):
    """Pull (download) an Ollama model. This may take several minutes."""
    import httpx
    from backend.config import settings

    url = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434")

    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            resp = await client.post(f"{url}/api/pull", json={"name": req.model, "stream": False})
            resp.raise_for_status()
            return {"ok": True, "message": f"Model '{req.model}' pulled successfully."}
    except httpx.TimeoutException:
        return {"ok": False, "message": f"Pull timed out — '{req.model}' may still be downloading. Check Ollama logs."}
    except Exception as exc:
        raise HTTPException(500, detail=f"Failed to pull model: {exc}")


@router.get("/ollama/recommended")
async def get_recommended_ollama_models():
    """Return recommended Ollama models for security use cases."""
    return {
        "recommended": [
            {"model": "llama3.2", "size": "3B", "use_case": "Fast general-purpose, log generation, chat", "vram_gb": 4,
             "tags": ["general", "fast", "chat", "log-generation"]},
            {"model": "llama3", "size": "8B", "use_case": "Balanced quality/speed for threat intel and rule analysis", "vram_gb": 6,
             "tags": ["general", "balanced", "threat-intel", "rules"]},
            {"model": "mistral", "size": "7B", "use_case": "Fast instruction following, Sigma translation", "vram_gb": 6,
             "tags": ["general", "fast", "sigma", "translation"]},
            {"model": "deepseek-r1:14b", "size": "14B", "use_case": "Complex reasoning — attack chain planning, scoring", "vram_gb": 10,
             "tags": ["reasoning", "attack-chain", "scoring", "analysis"]},
            {"model": "deepseek-r1:32b", "size": "32B", "use_case": "Best local reasoning model for complex analysis", "vram_gb": 20,
             "tags": ["reasoning", "complex", "analysis", "frontier"]},
            {"model": "codellama", "size": "7B", "use_case": "Code-specific — rule analysis, Sigma writing, detection logic", "vram_gb": 6,
             "tags": ["code", "sigma", "rules", "detection"]},
            {"model": "qwen2.5-coder", "size": "7B", "use_case": "Strong code generation — KQL, SPL, YARA rules", "vram_gb": 6,
             "tags": ["code", "rules", "kql", "spl", "yara"]},
            {"model": "phi4", "size": "14B", "use_case": "Microsoft reasoning model — scoring, review, HITL summaries", "vram_gb": 10,
             "tags": ["reasoning", "scoring", "review", "microsoft"]},
            {"model": "gemma2", "size": "9B", "use_case": "Google's efficient model — good for log analysis and classification", "vram_gb": 7,
             "tags": ["general", "classification", "log-analysis", "google"]},
            {"model": "nomic-embed-text", "size": "137M", "use_case": "Local embeddings — semantic search without API calls", "vram_gb": 1,
             "tags": ["embedding", "search", "vectors", "lightweight"]},
            {"model": "mxbai-embed-large", "size": "335M", "use_case": "High-quality local embeddings for knowledge base", "vram_gb": 1,
             "tags": ["embedding", "search", "vectors", "quality"]},
            {"model": "llama-guard3", "size": "8B", "use_case": "Content safety classifier — validate AI agent outputs", "vram_gb": 6,
             "tags": ["safety", "classifier", "guardrails", "security"]},
        ],
        "security_specialized": [
            # ── Cybersecurity NLP Models (HuggingFace) ──
            {"model": "jackfan.us.kg/ehsanaghaei/SecureBERT", "name": "SecureBERT",
             "description": "Pre-trained on cybersecurity corpus (APT reports, CVEs, MITRE). Best for security-specific NER and classification.",
             "type": "huggingface", "size": "110M", "domain": "Security NLP",
             "use_cases": ["IOC extraction", "Threat classification", "Malware text analysis", "APT report parsing"]},
            {"model": "jackfan.us.kg/jackaduma/SecBERT", "name": "SecBERT",
             "description": "BERT fine-tuned on security text from threat reports, advisories, and vulnerability databases.",
             "type": "huggingface", "size": "110M", "domain": "Security NLP",
             "use_cases": ["CVE parsing", "Advisory classification", "Security text understanding"]},
            {"model": "jackfan.us.kg/CyberPeace-Institute/SecureBERT-NER", "name": "SecureBERT-NER",
             "description": "Named entity recognition for cybersecurity text — extracts IOCs, malware names, threat actors.",
             "type": "huggingface", "size": "110M", "domain": "NER",
             "use_cases": ["IOC extraction", "Entity recognition", "Threat report parsing"]},

            # ── Malware & Threat Analysis ──
            {"model": "jackfan.us.kg/MalwareBERT/MalBERT", "name": "MalBERT",
             "description": "BERT model specialized for malware detection from API call sequences and binary analysis text.",
             "type": "huggingface", "size": "110M", "domain": "Malware Analysis",
             "use_cases": ["Malware family classification", "API call sequence analysis", "Binary analysis"]},
            {"model": "jackfan.us.kg/Microsoft/codebert-base", "name": "CodeBERT",
             "description": "Microsoft's code understanding model — useful for analyzing detection rules, scripts, and exploit code.",
             "type": "huggingface", "size": "125M", "domain": "Code Analysis",
             "use_cases": ["Rule syntax analysis", "Script review", "Code similarity detection"]},

            # ── Log & Anomaly Detection ──
            {"model": "jackfan.us.kg/LogPAI/LogBERT", "name": "LogBERT",
             "description": "Pre-trained on system logs for anomaly detection — identifies unusual patterns in log sequences.",
             "type": "huggingface", "size": "110M", "domain": "Log Analysis",
             "use_cases": ["Log anomaly detection", "System log parsing", "Event sequence analysis"]},
            {"model": "jackfan.us.kg/allenai/scibert_scivocab_uncased", "name": "SciBERT",
             "description": "Scientific text model — useful for parsing CVE descriptions, research papers, and technical advisories.",
             "type": "huggingface", "size": "110M", "domain": "Technical Text",
             "use_cases": ["CVE description parsing", "Technical advisory analysis", "Vulnerability classification"]},

            # ── Phishing & Social Engineering ──
            {"model": "jackfan.us.kg/ealvaradob/bert-finetuned-phishing", "name": "PhishBERT",
             "description": "BERT fine-tuned for phishing email and URL detection — classifies suspicious content.",
             "type": "huggingface", "size": "110M", "domain": "Phishing Detection",
             "use_cases": ["Phishing email detection", "URL classification", "Social engineering analysis"]},

            # ── Vulnerability & CVE ──
            {"model": "jackfan.us.kg/CIRCL/vulnerability-scores", "name": "VulnScorer",
             "description": "Predicts CVSS scores and severity from vulnerability descriptions — automates CVE triage.",
             "type": "huggingface", "size": "110M", "domain": "Vulnerability Assessment",
             "use_cases": ["CVSS score prediction", "CVE triage", "Vulnerability prioritization"]},
            {"model": "jackfan.us.kg/dslim/bert-base-NER", "name": "BERT-NER (base)",
             "description": "General NER model — useful as a foundation for extracting IPs, domains, hashes from unstructured text.",
             "type": "huggingface", "size": "110M", "domain": "Entity Extraction",
             "use_cases": ["IP/domain extraction", "Hash extraction", "General NER for security text"]},

            # ── Embedding Models for Security RAG ──
            {"model": "jackfan.us.kg/BAAI/bge-large-en-v1.5", "name": "BGE-Large",
             "description": "Top-tier embedding model — excellent for building security knowledge base RAG pipelines.",
             "type": "huggingface", "size": "335M", "domain": "Embeddings",
             "use_cases": ["Security KB search", "Threat intel RAG", "Semantic rule matching"]},
            {"model": "jackfan.us.kg/sentence-transformers/all-MiniLM-L6-v2", "name": "MiniLM-L6",
             "description": "Lightweight sentence embeddings — fast local alternative for vector search.",
             "type": "huggingface", "size": "22M", "domain": "Embeddings",
             "use_cases": ["Fast semantic search", "IOC similarity", "Alert deduplication"]},

            # ── Ollama Security-Relevant Models ──
            {"model": "llama-guard3", "name": "Llama Guard 3",
             "description": "Meta's content safety model — validates AI agent outputs, detects prompt injection and unsafe content.",
             "type": "ollama", "size": "8B", "domain": "AI Safety",
             "use_cases": ["Agent output validation", "Prompt injection detection", "Content safety guardrails"]},
            {"model": "granite3-dense:8b", "name": "IBM Granite 3.0",
             "description": "IBM's enterprise model — strong on structured data, logs, and compliance text.",
             "type": "ollama", "size": "8B", "domain": "Enterprise",
             "use_cases": ["Compliance analysis", "Structured log parsing", "Policy generation"]},
        ],
    }


@router.get("/ollama/search")
async def search_ollama_models(q: str = ""):
    """Search the local recommended catalog and Ollama library by keyword.

    Searches model names, descriptions, tags, and use cases.
    """
    import httpx

    if not q or len(q) < 2:
        return {"query": q, "results": [], "hint": "Enter at least 2 characters to search"}

    query = q.lower()
    results = []

    # 1. Search local recommended catalog
    recs = (await get_recommended_ollama_models())
    for model in recs.get("recommended", []):
        score = 0
        searchable = f"{model['model']} {model['use_case']} {' '.join(model.get('tags', []))}".lower()
        if query in searchable:
            score = 10 if query in model["model"].lower() else 5
            results.append({**model, "source": "recommended", "relevance": score})

    for model in recs.get("security_specialized", []):
        searchable = f"{model['name']} {model['description']} {' '.join(model.get('use_cases', []))} {model.get('domain', '')}".lower()
        if query in searchable:
            score = 10 if query in model["name"].lower() else 5
            results.append({**model, "source": "security_specialized", "relevance": score})

    # 2. Search Ollama library (ollama.com/search)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"https://ollama.com/search?q={q}", headers={"Accept": "application/json"})
            if resp.status_code == 200:
                # Ollama search returns HTML, parse model names from it
                import re
                html = resp.text
                # Extract model names from href="/library/modelname" patterns
                model_links = re.findall(r'href="/library/([^"]+)"', html)
                seen = set()
                for name in model_links[:20]:
                    if name not in seen:
                        seen.add(name)
                        # Extract description if available
                        desc_match = re.search(rf'{name}.*?<p[^>]*>(.*?)</p>', html, re.DOTALL)
                        desc = desc_match.group(1).strip()[:200] if desc_match else ""
                        desc = re.sub(r'<[^>]+>', '', desc).strip()
                        results.append({
                            "model": name,
                            "name": name,
                            "description": desc or f"Ollama model: {name}",
                            "source": "ollama_library",
                            "type": "ollama",
                            "relevance": 3,
                        })
    except Exception:
        pass  # Ollama library search is best-effort

    # Sort by relevance
    results.sort(key=lambda x: x.get("relevance", 0), reverse=True)

    return {"query": q, "results": results[:30], "total": len(results)}


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
        "ollama": "",
        "azure_openai": "AZURE_OPENAI_API_KEY",
    }
    return env_vars.get(provider, "")


async def _get_db_key_providers() -> set[str]:
    """Return set of provider names that have API keys stored in the DB."""
    try:
        from backend.db.session import async_session
        from backend.db.models import ProviderApiKey
        from sqlalchemy import select

        async with async_session() as db:
            result = await db.execute(select(ProviderApiKey.provider))
            return {row[0] for row in result.fetchall()}
    except Exception:
        return set()
