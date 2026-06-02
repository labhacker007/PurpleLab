"""Data normalization schema management REST API.

Manages SIEM field-mapping schemas with full version history. Includes both
a real LLM-powered parser (via NORMALIZATION_PARSE function) and a heuristic
fallback parser for JSON, CSV, and YAML content.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from backend.auth.dependencies import require_role
from backend.db.models import NormalizationSchema, NormalizationSchemaVersion
from backend.db.session import async_session
from backend.llm.config import LLMFunction
from backend.llm.router import get_router

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/normalization", tags=["normalization"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class SchemaCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    version_label: str = Field(..., max_length=100)
    siem_platform: str = Field(..., description="splunk|elastic|sentinel|qradar|sumo|custom")
    description: str = ""
    fields: list[dict[str, Any]] = Field(default_factory=list)
    datasets: list[Any] = Field(default_factory=list)
    data_models: list[Any] = Field(default_factory=list)
    source_file_name: str | None = None
    source_format: str | None = None


class SchemaUpdateRequest(BaseModel):
    name: str | None = None
    version_label: str | None = None
    description: str | None = None
    fields: list[dict[str, Any]] | None = None
    datasets: list[Any] | None = None
    data_models: list[Any] | None = None


class ParseAIRequest(BaseModel):
    content: str
    format: str = Field(..., description="json|csv|yaml|tsv|pdf")
    siem_platform: str = ""
    name: str = ""


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------

def _schema_to_dict(s: NormalizationSchema, include_versions: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(s.id),
        "name": s.name,
        "version_label": s.version_label,
        "siem_platform": s.siem_platform,
        "description": s.description,
        "fields": s.fields,
        "datasets": s.datasets,
        "data_models": s.data_models,
        "ai_parsed": s.ai_parsed,
        "ai_parse_notes": s.ai_parse_notes,
        "source_file_name": s.source_file_name,
        "source_format": s.source_format,
        "created_by": s.created_by,
        "created_at": s.created_at.isoformat(),
        "updated_at": s.updated_at.isoformat(),
    }
    if include_versions and hasattr(s, "versions"):
        out["versions"] = [_version_to_dict(v) for v in s.versions]
    return out


def _version_to_dict(v: NormalizationSchemaVersion) -> dict[str, Any]:
    return {
        "id": str(v.id),
        "schema_id": str(v.schema_id),
        "version_num": v.version_num,
        "version_label": v.version_label,
        "fields_snapshot": v.fields_snapshot,
        "datasets_snapshot": v.datasets_snapshot,
        "data_models_snapshot": v.data_models_snapshot,
        "change_summary": v.change_summary,
        "created_by": v.created_by,
        "created_at": v.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Heuristic parser helpers
# ---------------------------------------------------------------------------

def _infer_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    # Try numeric coercion for string values
    if isinstance(value, str):
        try:
            int(value)
            return "integer"
        except ValueError:
            pass
        try:
            float(value)
            return "float"
        except ValueError:
            pass
    return "string"


def _extract_yaml_keys(obj: Any, prefix: str = "") -> list[dict[str, Any]]:
    """Recursively extract keys and inferred types from a parsed YAML/dict object."""
    fields: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                fields.append({"name": full_key, "type": "object", "description": ""})
                fields.extend(_extract_yaml_keys(value, prefix=full_key))
            else:
                fields.append({"name": full_key, "type": _infer_type(value), "description": ""})
    return fields


def _parse_content(content: str, fmt: str) -> dict[str, Any]:
    """Heuristic parser for JSON, CSV, TSV, and YAML content.

    Returns a dict with fields, datasets, data_models, and ai_parse_notes.
    """
    fmt_lower = fmt.lower().strip()

    if fmt_lower == "pdf":
        return {
            "fields": [],
            "datasets": [],
            "data_models": [],
            "ai_parse_notes": "PDF parsing requires AI integration — paste the content as text instead",
        }

    if fmt_lower == "json":
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            return {
                "fields": [],
                "datasets": [],
                "data_models": [],
                "ai_parse_notes": f"JSON parse error: {exc}",
            }

        if isinstance(parsed, list) and parsed:
            # Use first object for schema inference
            obj = parsed[0] if isinstance(parsed[0], dict) else {}
        elif isinstance(parsed, dict):
            obj = parsed
        else:
            obj = {}

        fields = [
            {"name": key, "type": _infer_type(value), "description": ""}
            for key, value in obj.items()
        ]
        return {
            "fields": fields,
            "datasets": [],
            "data_models": [],
            "ai_parse_notes": f"Extracted {len(fields)} top-level field(s) from JSON",
        }

    if fmt_lower in ("csv", "tsv"):
        delimiter = "\t" if fmt_lower == "tsv" else ","
        try:
            reader = csv.reader(io.StringIO(content), delimiter=delimiter)
            rows = list(reader)
        except Exception as exc:
            return {
                "fields": [],
                "datasets": [],
                "data_models": [],
                "ai_parse_notes": f"CSV parse error: {exc}",
            }

        if not rows:
            return {"fields": [], "datasets": [], "data_models": [], "ai_parse_notes": "Empty content"}

        headers = [h.strip() for h in rows[0]]
        sample_row = rows[1] if len(rows) > 1 else []

        fields = []
        for i, header in enumerate(headers):
            sample_value = sample_row[i] if i < len(sample_row) else ""
            fields.append({
                "name": header,
                "type": _infer_type(sample_value),
                "description": "",
            })

        return {
            "fields": fields,
            "datasets": [],
            "data_models": [],
            "ai_parse_notes": f"Extracted {len(fields)} field(s) from {fmt_lower.upper()} header row",
        }

    if fmt_lower == "yaml":
        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            return {
                "fields": [],
                "datasets": [],
                "data_models": [],
                "ai_parse_notes": f"YAML parse error: {exc}",
            }

        fields = _extract_yaml_keys(parsed)
        return {
            "fields": fields,
            "datasets": [],
            "data_models": [],
            "ai_parse_notes": f"Extracted {len(fields)} field(s) from YAML (recursive key traversal)",
        }

    # Unknown format — attempt JSON fallback
    return {
        "fields": [],
        "datasets": [],
        "data_models": [],
        "ai_parse_notes": f"Unsupported format '{fmt}'. Supported: json, csv, tsv, yaml, pdf",
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_schemas(
    siem_platform: str | None = Query(None, description="Filter by SIEM platform"),
) -> dict[str, Any]:
    """List all normalization schemas, optionally filtered by SIEM platform."""
    async with async_session() as session:
        q = select(NormalizationSchema).order_by(NormalizationSchema.name)
        if siem_platform:
            q = q.where(NormalizationSchema.siem_platform == siem_platform)
        result = await session.execute(q)
        schemas = result.scalars().all()

    return {"schemas": [_schema_to_dict(s) for s in schemas], "total": len(schemas)}


@router.post("", dependencies=[Depends(require_role("admin", "engineer"))])
async def create_schema(
    body: SchemaCreateRequest,
    current_user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Create a new normalization schema. Automatically creates version 1 snapshot."""
    async with async_session() as session:
        schema = NormalizationSchema(
            name=body.name,
            version_label=body.version_label,
            siem_platform=body.siem_platform,
            description=body.description,
            fields=body.fields,
            datasets=body.datasets,
            data_models=body.data_models,
            source_file_name=body.source_file_name,
            source_format=body.source_format,
            created_by=current_user.email,
        )
        session.add(schema)
        await session.flush()  # Populate schema.id before creating version

        version = NormalizationSchemaVersion(
            schema_id=schema.id,
            version_num=1,
            version_label=body.version_label,
            fields_snapshot=body.fields,
            datasets_snapshot=body.datasets,
            data_models_snapshot=body.data_models,
            change_summary="Initial version",
            created_by=current_user.email,
        )
        session.add(version)
        await session.commit()
        await session.refresh(schema)

    return _schema_to_dict(schema)


@router.get("/{schema_id}")
async def get_schema(schema_id: uuid.UUID) -> dict[str, Any]:
    """Get a schema with its version list."""
    async with async_session() as session:
        schema = await session.scalar(
            select(NormalizationSchema).where(NormalizationSchema.id == schema_id)
        )
        if not schema:
            raise HTTPException(status_code=404, detail=f"Schema {schema_id} not found")

        result = await session.execute(
            select(NormalizationSchemaVersion)
            .where(NormalizationSchemaVersion.schema_id == schema_id)
            .order_by(NormalizationSchemaVersion.version_num.desc())
        )
        versions = result.scalars().all()

    out = _schema_to_dict(schema)
    out["versions"] = [_version_to_dict(v) for v in versions]
    return out


@router.put("/{schema_id}", dependencies=[Depends(require_role("admin", "engineer"))])
async def update_schema(
    schema_id: uuid.UUID,
    body: SchemaUpdateRequest,
    current_user: Any = Depends(require_role("admin", "engineer")),
) -> dict[str, Any]:
    """Update a normalization schema and create a new version snapshot automatically."""
    async with async_session() as session:
        schema = await session.scalar(
            select(NormalizationSchema).where(NormalizationSchema.id == schema_id)
        )
        if not schema:
            raise HTTPException(status_code=404, detail=f"Schema {schema_id} not found")

        updates = body.model_dump(exclude_none=True)
        for field, value in updates.items():
            setattr(schema, field, value)

        from datetime import datetime
        schema.updated_at = datetime.utcnow()

        # Determine new version number
        max_ver_result = await session.scalar(
            select(func.max(NormalizationSchemaVersion.version_num)).where(
                NormalizationSchemaVersion.schema_id == schema_id
            )
        )
        next_version_num = (max_ver_result or 0) + 1

        version = NormalizationSchemaVersion(
            schema_id=schema_id,
            version_num=next_version_num,
            version_label=schema.version_label,
            fields_snapshot=schema.fields,
            datasets_snapshot=schema.datasets,
            data_models_snapshot=schema.data_models,
            change_summary=f"Updated to version {next_version_num}",
            created_by=current_user.email,
        )
        session.add(version)
        await session.commit()
        await session.refresh(schema)

    return _schema_to_dict(schema)


@router.delete("/{schema_id}", dependencies=[Depends(require_role("admin", "engineer"))])
async def delete_schema(schema_id: uuid.UUID) -> dict[str, Any]:
    """Delete a normalization schema and all its version snapshots."""
    async with async_session() as session:
        schema = await session.scalar(
            select(NormalizationSchema).where(NormalizationSchema.id == schema_id)
        )
        if not schema:
            raise HTTPException(status_code=404, detail=f"Schema {schema_id} not found")

        await session.delete(schema)
        await session.commit()

    return {"status": "deleted", "id": str(schema_id)}


@router.get("/{schema_id}/versions")
async def list_versions(schema_id: uuid.UUID) -> dict[str, Any]:
    """List all version snapshots for a normalization schema."""
    async with async_session() as session:
        schema = await session.scalar(
            select(NormalizationSchema).where(NormalizationSchema.id == schema_id)
        )
        if not schema:
            raise HTTPException(status_code=404, detail=f"Schema {schema_id} not found")

        result = await session.execute(
            select(NormalizationSchemaVersion)
            .where(NormalizationSchemaVersion.schema_id == schema_id)
            .order_by(NormalizationSchemaVersion.version_num.desc())
        )
        versions = result.scalars().all()

    return {"schema_id": str(schema_id), "versions": [_version_to_dict(v) for v in versions], "total": len(versions)}


@router.get("/{schema_id}/versions/{version_id}")
async def get_version(schema_id: uuid.UUID, version_id: uuid.UUID) -> dict[str, Any]:
    """Get a specific version snapshot of a normalization schema."""
    async with async_session() as session:
        version = await session.scalar(
            select(NormalizationSchemaVersion).where(
                NormalizationSchemaVersion.id == version_id,
                NormalizationSchemaVersion.schema_id == schema_id,
            )
        )
    if not version:
        raise HTTPException(
            status_code=404,
            detail=f"Version {version_id} not found for schema {schema_id}",
        )
    return _version_to_dict(version)


@router.post("/parse-ai", dependencies=[Depends(require_role("admin", "engineer"))])
async def parse_ai(body: ParseAIRequest) -> dict[str, Any]:
    """Parse schema content using real Claude (NORMALIZATION_PARSE function).

    Attempts an LLM-powered extraction of structured field definitions from
    the supplied content. Falls back to the heuristic deterministic parser
    if the LLM is not configured, unavailable, or returns invalid JSON.
    """
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
    messages = [
        {
            "role": "user",
            "content": (
                f"Format: {body.format}\n"
                f"Platform: {body.siem_platform}\n"
                f"Content:\n{body.content[:8000]}"
            ),
        }
    ]

    try:
        response_text = await llm_router.complete(
            LLMFunction.NORMALIZATION_PARSE,
            messages=messages,
            system=system_prompt,
            temperature=0.1,
        )

        # Strip markdown code fences if present
        stripped = response_text.strip()
        if stripped.startswith("```"):
            lines = stripped.split("\n")
            stripped = "\n".join(lines[1:-1]) if len(lines) > 2 else stripped

        result = json.loads(stripped)
        result["ai_parsed"] = True
        return result

    except Exception as exc:
        logger.warning(
            "LLM schema parse failed for format=%s, falling back to heuristic: %s",
            body.format,
            exc,
        )
        fallback = _parse_content(body.content, body.format)
        fallback["ai_parsed"] = False
        return fallback
