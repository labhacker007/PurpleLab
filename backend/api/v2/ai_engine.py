"""AI Engine admin management — function configs, guardrails, usage stats.

Provides endpoints for:
- Listing all AI functions with live config and 24h usage metrics
- Aggregated usage statistics by period and function
- Guardrail CRUD (per-function safety config)
- AI-powered detection rule generation (Sigma)
- Threat profile enrichment
- SIEM schema parsing via LLM
- Internal usage logging
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from backend.auth.dependencies import require_role
from backend.db.models import AIGuardrailConfig, LLMUsageLog, ModelFunctionConfig, NormalizationSchema
from backend.db.session import async_session
from backend.llm.config import FUNCTION_METADATA, LLMFunction
from backend.llm.router import get_router

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai-engine", tags=["ai-engine"])

# ---------------------------------------------------------------------------
# Cost estimation table (USD per 1k tokens)
# ---------------------------------------------------------------------------

COST_PER_1K: dict[str, dict[str, float]] = {
    "claude-opus-4-6": {"input": 0.015, "output": 0.075},
    "claude-sonnet-4-6": {"input": 0.003, "output": 0.015},
    "claude-haiku-4-5-20251001": {"input": 0.0008, "output": 0.004},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gemini-2.0-flash": {"input": 0.0001, "output": 0.0004},
}


def _estimate_cost(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD for a given model and token counts."""
    rates = COST_PER_1K.get(model_id)
    if not rates:
        # Unknown model — use sonnet pricing as fallback
        rates = COST_PER_1K["claude-sonnet-4-6"]
    cost = (input_tokens / 1000) * rates["input"] + (output_tokens / 1000) * rates["output"]
    return round(cost, 6)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class GuardrailUpdateRequest(BaseModel):
    enabled: bool = True
    max_input_tokens: int = 32000
    max_output_tokens: int = 8192
    rate_limit_per_minute: int = 60
    block_patterns: list[str] = Field(default_factory=list)
    require_json_output: bool = False
    pii_masking_enabled: bool = False
    system_prompt_override: Optional[str] = None
    notes: str = ""


class FunctionConfigUpdateRequest(BaseModel):
    provider: str = Field(..., description="anthropic|openai|ollama|google")
    model_id: str = Field(..., description="e.g. claude-sonnet-4-6")
    temperature: float = Field(0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(4096, ge=256, le=200000)
    base_url: str = Field("", description="Required for Ollama; optional for Azure")
    api_key_override: str = Field("", description="Override API key; empty = use env var")


class GenerateDetectionRequest(BaseModel):
    # Primary fields (also accept legacy aliases)
    use_case_name: str = ""
    use_case_title: str = ""      # alias used by UI
    description: str = ""
    use_case_description: str = ""  # alias used by UI
    technique_id: str = ""
    technique_ids: list[str] = Field(default_factory=list)
    technique_name: str = ""
    tactic: str = ""
    log_source_category: str = ""
    log_sources: list[str] = Field(default_factory=list)
    normalization_schema_id: Optional[str] = None
    severity: str = "high"
    siem_platform: str = "splunk"

    def resolved_name(self) -> str:
        return self.use_case_name or self.use_case_title or "Detection Use Case"

    def resolved_description(self) -> str:
        return self.description or self.use_case_description or ""

    def resolved_technique_ids(self) -> list[str]:
        ids = list(self.technique_ids)
        if self.technique_id and self.technique_id not in ids:
            ids.append(self.technique_id)
        return ids


class EnrichThreatProfileRequest(BaseModel):
    profile_type: str = Field(..., description="cve|ttp|actor|ioc")
    name: str = ""
    identifier: str = ""   # alias used by UI
    context: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    include_mitigations: bool = True
    include_related_techniques: bool = True

    def resolved_name(self) -> str:
        return self.name or self.identifier or ""


class ParseSchemaRequest(BaseModel):
    content: str
    format: str
    siem_platform: str = ""
    name: str = ""


class LogUsageRequest(BaseModel):
    function_name: str
    provider: str
    model_id: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    status: str = "success"
    error_msg: Optional[str] = None
    user_id: Optional[str] = None
    request_context: Optional[dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guardrail_to_dict(row: AIGuardrailConfig) -> dict[str, Any]:
    meta = FUNCTION_METADATA.get(row.function_name, {})
    return {
        "id": row.id,
        "function_name": row.function_name,
        "display_name": meta.get("display_name", row.function_name),
        "enabled": row.enabled,
        "max_input_tokens": row.max_input_tokens,
        "max_output_tokens": row.max_output_tokens,
        "rate_limit_per_minute": row.rate_limit_per_minute,
        "block_patterns": row.block_patterns or [],
        "require_json_output": row.require_json_output,
        "pii_masking_enabled": row.pii_masking_enabled,
        "system_prompt_override": row.system_prompt_override,
        "notes": row.notes or "",
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "from_db": True,
    }


def _default_guardrail_dict(function_name: str) -> dict[str, Any]:
    meta = FUNCTION_METADATA.get(function_name, {})
    return {
        "id": None,
        "function_name": function_name,
        "display_name": meta.get("display_name", function_name),
        "enabled": True,
        "max_input_tokens": 32000,
        "max_output_tokens": 8192,
        "rate_limit_per_minute": 60,
        "block_patterns": [],
        "require_json_output": False,
        "pii_masking_enabled": False,
        "system_prompt_override": None,
        "notes": "",
        "created_at": None,
        "updated_at": None,
        "from_db": False,
    }


def _period_to_timedelta(period: str) -> timedelta:
    mapping = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    return mapping.get(period, timedelta(hours=24))


# ---------------------------------------------------------------------------
# GET /ai-engine/functions
# ---------------------------------------------------------------------------

@router.get("/functions")
async def list_functions(
    current_user: Any = Depends(require_role("admin", "engineer", "analyst")),
) -> dict[str, Any]:
    """List all AI functions with current config, guardrail status, and 24h usage."""
    llm_router = get_router()
    since = datetime.utcnow() - timedelta(hours=24)

    async with async_session() as session:
        # Load DB model configs (all at once)
        cfg_result = await session.execute(select(ModelFunctionConfig))
        db_configs: dict[str, ModelFunctionConfig] = {
            r.function_name: r for r in cfg_result.scalars().all()
        }

        # Load guardrail configs
        gr_result = await session.execute(select(AIGuardrailConfig))
        db_guardrails: dict[str, AIGuardrailConfig] = {
            r.function_name: r for r in gr_result.scalars().all()
        }

        # Aggregate 24h usage per function
        usage_rows = await session.execute(
            select(
                LLMUsageLog.function_name,
                func.count(LLMUsageLog.id).label("calls"),
                func.sum(LLMUsageLog.input_tokens).label("input_tokens"),
                func.sum(LLMUsageLog.output_tokens).label("output_tokens"),
                func.count(
                    LLMUsageLog.id
                ).filter(LLMUsageLog.status == "error").label("errors"),
            )
            .where(LLMUsageLog.created_at >= since)
            .group_by(LLMUsageLog.function_name)
        )
        usage_by_fn: dict[str, dict[str, int]] = {}
        for row in usage_rows:
            usage_by_fn[row.function_name] = {
                "calls": row.calls or 0,
                "input_tokens": int(row.input_tokens or 0),
                "output_tokens": int(row.output_tokens or 0),
                "errors": row.errors or 0,
            }

    functions = []
    for fn in LLMFunction:
        meta = FUNCTION_METADATA.get(fn, {})
        fn_name = fn.value

        # Resolve active config
        db_cfg = db_configs.get(fn_name)
        if db_cfg:
            cfg_dict = {
                "provider": db_cfg.provider,
                "model_id": db_cfg.model_id,
                "temperature": db_cfg.temperature,
                "max_tokens": db_cfg.max_tokens,
            }
            model_id = db_cfg.model_id
        else:
            live_cfg = llm_router.get_config(fn)
            cfg_dict = {
                "provider": live_cfg.provider,
                "model_id": live_cfg.model_id,
                "temperature": live_cfg.temperature,
                "max_tokens": live_cfg.max_tokens,
            }
            model_id = live_cfg.model_id

        # Guardrail status
        gr = db_guardrails.get(fn_name)
        guardrail_dict = (
            {"enabled": gr.enabled, "rate_limit_per_minute": gr.rate_limit_per_minute, "pii_masking_enabled": gr.pii_masking_enabled}
            if gr
            else {"enabled": True, "rate_limit_per_minute": 60, "pii_masking_enabled": False}
        )

        # Usage
        usage = usage_by_fn.get(fn_name, {"calls": 0, "input_tokens": 0, "output_tokens": 0, "errors": 0})

        # Cost estimate
        cost = _estimate_cost(model_id, usage["input_tokens"], usage["output_tokens"])

        functions.append({
            "function_name": fn_name,
            "display_name": meta.get("display_name", fn_name),
            "description": meta.get("description", ""),
            "volume": meta.get("volume", "medium"),
            "needs_tools": meta.get("needs_tools", False),
            "needs_streaming": meta.get("needs_streaming", False),
            "recommended_tags": meta.get("recommended_tags", []),
            "is_active": True,
            "config": cfg_dict,
            "guardrail": guardrail_dict,
            "usage_24h": usage,
            # Alias fields to match frontend expectations (calls_7d / estimated_cost_usd_7d)
            "usage": {
                "calls_7d": usage["calls"],
                "input_tokens_7d": usage["input_tokens"],
                "output_tokens_7d": usage["output_tokens"],
                "avg_latency_ms": 0,
                "estimated_cost_usd_7d": cost,
            },
            "cost_estimate_usd": cost,
            "updated_at": db_cfg.updated_at.isoformat() if db_cfg and db_cfg.updated_at else None,
        })

    return {"functions": functions, "total": len(functions)}


# ---------------------------------------------------------------------------
# PUT /ai-engine/functions/{function_name}
# ---------------------------------------------------------------------------

@router.put("/functions/{function_name}", dependencies=[Depends(require_role("admin"))])
async def update_function_config(
    function_name: str,
    body: FunctionConfigUpdateRequest,
    current_user: Any = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Update the provider/model config for a specific AI function."""
    try:
        fn = LLMFunction(function_name)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown function: {function_name}")

    llm_router = get_router()
    from backend.llm.config import ModelConfig

    cfg = ModelConfig(
        provider=body.provider,
        model_id=body.model_id,
        temperature=body.temperature,
        max_tokens=body.max_tokens,
        base_url=body.base_url,
        api_key_override=body.api_key_override,
    )

    try:
        result = await llm_router.set_config(fn, cfg)
    except Exception as exc:
        logger.error("Failed to update function config %s: %s", function_name, exc)
        raise HTTPException(status_code=500, detail=f"Config update failed: {exc}")

    meta = FUNCTION_METADATA.get(function_name, {})
    return {
        "function_name": function_name,
        "display_name": meta.get("display_name", function_name),
        "config": cfg.to_dict(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# GET /ai-engine/usage
# ---------------------------------------------------------------------------

@router.get("/usage")
async def get_usage(
    period: str = Query("24h", description="24h|7d|30d"),
    function_name: Optional[str] = Query(None),
    current_user: Any = Depends(require_role("admin", "engineer", "analyst")),
) -> dict[str, Any]:
    """Aggregated LLM usage stats by period and optional function filter."""
    delta = _period_to_timedelta(period)
    since = datetime.utcnow() - delta

    async with async_session() as session:
        base_q = select(LLMUsageLog).where(LLMUsageLog.created_at >= since)
        if function_name:
            base_q = base_q.where(LLMUsageLog.function_name == function_name)

        result = await session.execute(base_q)
        logs = result.scalars().all()

    total_calls = len(logs)
    total_input = sum(l.input_tokens for l in logs)
    total_output = sum(l.output_tokens for l in logs)
    total_errors = sum(1 for l in logs if l.status == "error")

    # Aggregate by function
    by_fn: dict[str, dict[str, Any]] = {}
    for log in logs:
        fn = log.function_name
        if fn not in by_fn:
            by_fn[fn] = {"function_name": fn, "calls": 0, "input_tokens": 0, "output_tokens": 0, "errors": 0, "cost_usd": 0.0}
        by_fn[fn]["calls"] += 1
        by_fn[fn]["input_tokens"] += log.input_tokens
        by_fn[fn]["output_tokens"] += log.output_tokens
        if log.status == "error":
            by_fn[fn]["errors"] += 1
        by_fn[fn]["cost_usd"] = round(
            by_fn[fn]["cost_usd"] + _estimate_cost(log.model_id, log.input_tokens, log.output_tokens), 6
        )

    # Timeline: bucket by hour (for 24h) or day (7d/30d)
    bucket_format = "%Y-%m-%dT%H:00:00" if period == "24h" else "%Y-%m-%d"
    timeline: dict[str, dict[str, Any]] = {}
    for log in logs:
        created = log.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=None)
        bucket = created.strftime(bucket_format)
        if bucket not in timeline:
            timeline[bucket] = {"time": bucket, "calls": 0, "tokens": 0, "cost_usd": 0.0}
        timeline[bucket]["calls"] += 1
        timeline[bucket]["tokens"] += log.input_tokens + log.output_tokens
        timeline[bucket]["cost_usd"] = round(
            timeline[bucket]["cost_usd"] + _estimate_cost(log.model_id, log.input_tokens, log.output_tokens), 6
        )

    total_cost = sum(v["cost_usd"] for v in by_fn.values())

    return {
        "period": period,
        "since": since.isoformat(),
        "total_calls": total_calls,
        "total_tokens": total_input + total_output,
        "total_cost_usd": round(total_cost, 6),
        "total_errors": total_errors,
        "by_function": sorted(by_fn.values(), key=lambda x: x["calls"], reverse=True),
        "timeline": sorted(timeline.values(), key=lambda x: x["time"]),
    }


# ---------------------------------------------------------------------------
# GET /ai-engine/guardrails
# ---------------------------------------------------------------------------

@router.get("/guardrails")
async def list_guardrails(
    current_user: Any = Depends(require_role("admin", "engineer", "analyst")),
) -> dict[str, Any]:
    """List guardrail configs for all functions. Auto-provides defaults for unconfigured ones."""
    async with async_session() as session:
        result = await session.execute(select(AIGuardrailConfig))
        db_rows: dict[str, AIGuardrailConfig] = {r.function_name: r for r in result.scalars().all()}

    guardrails = []
    for fn in LLMFunction:
        fn_name = fn.value
        if fn_name in db_rows:
            guardrails.append(_guardrail_to_dict(db_rows[fn_name]))
        else:
            guardrails.append(_default_guardrail_dict(fn_name))

    return {"guardrails": guardrails, "total": len(guardrails)}


# ---------------------------------------------------------------------------
# PUT /ai-engine/guardrails/{function_name}
# ---------------------------------------------------------------------------

@router.put("/guardrails/{function_name}", dependencies=[Depends(require_role("admin"))])
async def update_guardrail(
    function_name: str,
    body: GuardrailUpdateRequest,
    current_user: Any = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Create or update guardrail config for a specific function."""
    # Validate function name
    try:
        LLMFunction(function_name)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown function: {function_name}")

    async with async_session() as session:
        existing = await session.scalar(
            select(AIGuardrailConfig).where(AIGuardrailConfig.function_name == function_name)
        )
        if existing:
            existing.enabled = body.enabled
            existing.max_input_tokens = body.max_input_tokens
            existing.max_output_tokens = body.max_output_tokens
            existing.rate_limit_per_minute = body.rate_limit_per_minute
            existing.block_patterns = body.block_patterns
            existing.require_json_output = body.require_json_output
            existing.pii_masking_enabled = body.pii_masking_enabled
            existing.system_prompt_override = body.system_prompt_override
            existing.notes = body.notes
            existing.updated_at = datetime.utcnow()
            await session.commit()
            await session.refresh(existing)
            return _guardrail_to_dict(existing)
        else:
            row = AIGuardrailConfig(
                function_name=function_name,
                enabled=body.enabled,
                max_input_tokens=body.max_input_tokens,
                max_output_tokens=body.max_output_tokens,
                rate_limit_per_minute=body.rate_limit_per_minute,
                block_patterns=body.block_patterns,
                require_json_output=body.require_json_output,
                pii_masking_enabled=body.pii_masking_enabled,
                system_prompt_override=body.system_prompt_override,
                notes=body.notes,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return _guardrail_to_dict(row)


# ---------------------------------------------------------------------------
# POST /ai-engine/generate-detection
# ---------------------------------------------------------------------------

@router.post("/generate-detection")
async def generate_detection(
    body: GenerateDetectionRequest,
    current_user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Generate a Sigma detection rule using Claude for a given use case."""
    llm_router = get_router()

    # Optionally load normalization schema fields
    schema_context = ""
    if body.normalization_schema_id:
        try:
            schema_uuid = uuid.UUID(body.normalization_schema_id)
            async with async_session() as session:
                schema = await session.scalar(
                    select(NormalizationSchema).where(NormalizationSchema.id == schema_uuid)
                )
            if schema and schema.fields:
                field_lines = "\n".join(
                    f"  - {f.get('name', '')} ({f.get('type', 'string')}): {f.get('description', '')}"
                    for f in schema.fields[:50]  # cap at 50 fields
                )
                schema_context = (
                    f"\n\nNormalization Schema: {schema.name} ({schema.siem_platform})\n"
                    f"Available fields:\n{field_lines}\n"
                    "Use ONLY these field names in the detection section."
                )
        except Exception as exc:
            logger.warning("Could not load normalization schema %s: %s", body.normalization_schema_id, exc)

    system_prompt = (
        "You are a detection engineer expert in Sigma rules. "
        "Generate a valid Sigma rule for the given use case. "
        "Use only field names from the provided normalization schema if given. "
        "Output ONLY the YAML of the Sigma rule, no explanation. "
        "The rule must include: title, id (new UUID), status: experimental, "
        "description, logsource, detection, falsepositives, level, tags (MITRE ATT&CK)."
    )

    resolved_ids = body.resolved_technique_ids()
    resolved_sources = body.log_sources or ([body.log_source_category] if body.log_source_category else [])
    user_prompt = (
        f"Use Case: {body.resolved_name()}\n"
        f"Description: {body.resolved_description()}\n"
        f"MITRE Techniques: {', '.join(resolved_ids) or 'N/A'}\n"
        f"Technique Names: {body.technique_name or 'N/A'}\n"
        f"Tactic: {body.tactic}\n"
        f"Log Sources: {', '.join(resolved_sources) or 'N/A'}\n"
        f"Severity: {body.severity}\n"
        f"SIEM Platform: {body.siem_platform}"
        f"{schema_context}"
    )

    messages = [{"role": "user", "content": user_prompt}]

    try:
        rule_yaml = await llm_router.complete(
            LLMFunction.DETECTION_GENERATE,
            messages=messages,
            system=system_prompt,
            temperature=0.1,
        )
    except Exception as exc:
        logger.error("Detection generation failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    # Extract title and level from the generated YAML (best-effort)
    title = body.resolved_name()
    level = body.severity
    try:
        import re
        title_match = re.search(r"^title:\s*(.+)$", rule_yaml, re.MULTILINE)
        if title_match:
            title = title_match.group(1).strip()
        level_match = re.search(r"^level:\s*(.+)$", rule_yaml, re.MULTILINE)
        if level_match:
            level = level_match.group(1).strip()
    except Exception:
        pass

    return {
        "rule_yaml": rule_yaml,
        "title": title,
        "sigma_yaml": rule_yaml,  # alias for frontend
        "technique_ids": body.resolved_technique_ids(),
        "technique_id": body.technique_id,
        "level": level,
        "siem_platform": body.siem_platform,
        "normalization_schema_id": body.normalization_schema_id,
        "notes": f"Generated by AI for use case: {body.resolved_name()}",
    }


# ---------------------------------------------------------------------------
# POST /ai-engine/enrich-threat-profile
# ---------------------------------------------------------------------------

@router.post("/enrich-threat-profile")
async def enrich_threat_profile(
    body: EnrichThreatProfileRequest,
    current_user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Enrich a threat profile (CVE/TTP/actor) with context and mitigations."""
    llm_router = get_router()

    system_prompt = (
        "You are a cybersecurity threat intelligence expert. "
        "Enrich the provided threat profile with additional context, mitigations, and related techniques. "
        "Output JSON only with structure: "
        '{"enriched_data": {...}, "summary": "...", "mitigations": ["..."], "related_techniques": ["T1234", ...]}'
    )

    data_str = json.dumps(body.data, indent=2) if body.data else "{}"
    user_prompt = (
        f"Profile Type: {body.profile_type}\n"
        f"Name: {body.name}\n"
        f"Existing Data:\n{data_str}\n\n"
        "Enrich this profile with threat context, attack patterns, mitigations, "
        "and related MITRE ATT&CK techniques."
    )

    messages = [{"role": "user", "content": user_prompt}]

    try:
        response_text = await llm_router.complete(
            LLMFunction.THREAT_ENRICH,
            messages=messages,
            system=system_prompt,
            temperature=0.2,
        )
    except Exception as exc:
        logger.error("Threat profile enrichment failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    # Parse JSON response (strip markdown fences if present)
    stripped = response_text.strip()
    if stripped.startswith("```"):
        lines = stripped.split("\n")
        stripped = "\n".join(lines[1:-1]) if len(lines) > 2 else stripped

    try:
        result = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        # Return raw text in a structured envelope if JSON parse fails
        result = {
            "enriched_data": body.data,
            "summary": stripped[:2000],
            "mitigations": [],
            "related_techniques": [],
        }

    return {
        "enriched_data": result.get("enriched_data", body.data),
        "summary": result.get("summary", ""),
        "mitigations": result.get("mitigations", []),
        "related_techniques": result.get("related_techniques", []),
    }


# ---------------------------------------------------------------------------
# POST /ai-engine/parse-schema
# ---------------------------------------------------------------------------

@router.post("/parse-schema")
async def parse_schema(
    body: ParseSchemaRequest,
    current_user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Parse a SIEM schema document using real Claude and return structured field definitions."""
    llm_router = get_router()

    system_prompt = (
        "You are a SIEM schema expert. Parse the provided document and extract all field definitions. "
        'Output JSON only with structure: {"fields": [{"name": "...", "siem_name": "...", '
        '"type": "string|number|boolean|timestamp|ip|hash", "description": "..."}], '
        '"datasets": ["list", "of", "dataset", "names"], '
        '"data_models": ["list", "of", "data", "model", "names"], '
        '"ai_parse_notes": "brief summary"} '
        "For each field, infer the type from name/context/sample values. "
        "For SIEM-specific schemas (Splunk CIM, ECS, ASIM), recognize standard field conventions."
    )

    user_prompt = (
        f"Format: {body.format}\n"
        f"Platform: {body.siem_platform}\n"
        f"Content:\n{body.content[:8000]}"
    )
    messages = [{"role": "user", "content": user_prompt}]

    try:
        response_text = await llm_router.complete(
            LLMFunction.NORMALIZATION_PARSE,
            messages=messages,
            system=system_prompt,
            temperature=0.1,
        )
    except Exception as exc:
        logger.error("Schema parse via LLM failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    # Strip markdown code fences
    stripped = response_text.strip()
    if stripped.startswith("```"):
        lines = stripped.split("\n")
        stripped = "\n".join(lines[1:-1]) if len(lines) > 2 else stripped

    try:
        result = json.loads(stripped)
        result["ai_parsed"] = True
        return result
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"LLM returned non-JSON response: {exc}")


# ---------------------------------------------------------------------------
# GET /ai-engine/skill-prompts
# ---------------------------------------------------------------------------

_SKILL_PROMPTS: dict[str, str] = {
    "DETECTION_GENERATE": """You are an expert detection engineer with deep knowledge of MITRE ATT&CK, Sigma rule format, and SIEM query languages.

When generating a Sigma detection rule:
1. Always include all required Sigma fields: title, id, status, description, references, author, date, tags (ATT&CK), logsource, detection, falsepositives, level
2. Use the exact field names from the normalization schema provided — never invent field names
3. Make the detection specific enough to reduce false positives but broad enough to catch variants
4. Include condition logic that handles both direct and indirect indicators
5. Set appropriate log source category, product, and service based on the technique
6. Return ONLY valid YAML — no markdown fences, no explanation""",

    "NORMALIZATION_PARSE": """You are a SIEM data engineer expert in log normalization and schema mapping.

When parsing a schema document:
1. Extract every field definition: name, type (string/int/float/bool/datetime/ip/array/object), description, example values
2. Identify the SIEM platform (Splunk CIM, Elastic ECS, Microsoft Sentinel, QRadar AQL, or custom)
3. Group fields into datasets/data models where logical (e.g. authentication, network_traffic, process)
4. Preserve original field names exactly — do not normalize or rename
5. Return a JSON object with keys: fields (array), datasets (array), data_models (array), siem_platform (string)

Return ONLY valid JSON — no markdown, no explanation.""",

    "THREAT_ENRICH": """You are a senior threat intelligence analyst with expertise in CTI frameworks, CVE analysis, and adversary profiling.

When enriching a threat profile:
1. Provide accurate, factual information grounded in public CTI sources (MITRE, NVD, vendor advisories)
2. For CVEs: include CVSS vector, affected products, exploitation status, patch availability
3. For TTPs: include sub-techniques, detection opportunities, data sources to collect
4. For threat actors: include known aliases, targeting sectors, geographic focus, associated tools/TTPs
5. Always include practical defensive recommendations
6. Return structured JSON with the requested sections""",

    "EXERCISE_REPORT": """You are a senior purple team lead generating post-exercise reports.

When generating an exercise report:
1. Start with an executive summary (3-5 sentences, non-technical)
2. Detail each phase: what was executed, what was detected, what was missed
3. Calculate and explain coverage metrics (detected / total TTPs executed)
4. List top 3 critical gaps with recommended detections
5. Include a lessons-learned section with actionable recommendations
6. Format as a professional markdown report with clear sections""",

    "COVERAGE_SUGGEST": """You are a detection engineering manager focused on closing MITRE ATT&CK coverage gaps.

When suggesting detection improvements:
1. Analyse the provided coverage data to identify the highest-risk uncovered techniques
2. Prioritise by: (a) technique prevalence in recent threat intel, (b) exploitation ease, (c) detection data source availability
3. For each suggestion: provide the technique ID/name, recommended data sources, a Sigma rule skeleton, and expected false positive rate
4. Group suggestions by detection difficulty: quick wins vs complex detections
5. Return structured JSON with an array of suggestions""",
}


@router.get("/skill-prompts")
async def list_skill_prompts(
    _user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Return the default system prompts for all configurable AI skills."""
    result = []
    for fn in LLMFunction:
        meta = FUNCTION_METADATA.get(fn, {})
        fn_name = fn.value
        result.append({
            "function_name": fn_name,
            "display_name": meta.get("display_name", fn_name),
            "system_prompt": _SKILL_PROMPTS.get(fn_name, ""),
            "has_custom_prompt": fn_name in _SKILL_PROMPTS,
        })
    return {"skill_prompts": result, "total": len(result)}


# ---------------------------------------------------------------------------
# POST /ai-engine/log-usage  (internal — no auth)
# ---------------------------------------------------------------------------

@router.post("/log-usage", include_in_schema=False)
async def log_usage(body: LogUsageRequest) -> dict[str, Any]:
    """Internal endpoint: log a single LLM usage event for cost tracking."""
    async with async_session() as session:
        log = LLMUsageLog(
            function_name=body.function_name,
            provider=body.provider,
            model_id=body.model_id,
            input_tokens=body.input_tokens,
            output_tokens=body.output_tokens,
            latency_ms=body.latency_ms,
            status=body.status,
            error_msg=body.error_msg,
            user_id=body.user_id,
            request_context=body.request_context,
        )
        session.add(log)
        await session.commit()
        await session.refresh(log)

    return {"status": "logged", "id": log.id}
