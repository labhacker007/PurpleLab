"""SIEM connection management API — v2.

Endpoints:
    GET    /siem/connections
    POST   /siem/connections
    GET    /siem/connections/{id}
    PUT    /siem/connections/{id}
    DELETE /siem/connections/{id}
    POST   /siem/connections/{id}/test
    POST   /siem/connections/{id}/sync-rules
    POST   /siem/connections/{id}/push-logs
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.schemas import SIEMConnectionCreate, SIEMConnectionResponse, StatusResponse
from backend.db.models import ImportedRule, SIEMConnection
from backend.db.session import async_session
from backend.siem_integration.connector_factory import UnsupportedSIEMTypeError, get_connector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/siem", tags=["siem"])

# Connection test timeout — SIEM must respond within this many seconds.
_TEST_TIMEOUT_SECS = 15.0
# Push-logs timeout
_PUSH_TIMEOUT_SECS = 30.0
# Sync-rules timeout (fetching all rules can be slow)
_SYNC_TIMEOUT_SECS = 60.0


# ── Extra request/response schemas ───────────────────────────────────────────

class SIEMConnectionUpdate(BaseModel):
    """Partial update for a SIEM connection.  All fields optional."""
    name: Optional[str] = None
    base_url: Optional[str] = None
    credentials: Optional[dict[str, str]] = None
    settings: Optional[dict[str, Any]] = None


class TestConnectionResponse(BaseModel):
    id: str
    connected: bool
    latency_ms: float = 0.0
    version: str = ""
    error: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


class SyncRulesResponse(BaseModel):
    id: str
    rules_synced: int = 0
    rules_skipped: int = 0
    errors: list[str] = Field(default_factory=list)


class PushLogsRequest(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)
    source_id: str = "generic"


class PushLogsResponse(BaseModel):
    id: str
    events_sent: int = 0
    errors: list[str] = Field(default_factory=list)


# ── DB session dependency ──────────────────────────────────────────────────────

async def get_db() -> AsyncSession:  # type: ignore[return]
    async with async_session() as session:
        yield session


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_connection_id(raw: str) -> uuid.UUID:
    """Parse and validate a connection ID string, raising 422 on bad format."""
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail=f"Invalid UUID: '{raw}'")


def _encrypt_credentials(creds: dict) -> str:
    """JSON-encode then Fernet-encrypt a credentials dict.

    Raises HTTPException 400 if ENCRYPTION_KEY is not configured.
    """
    try:
        from backend.core.security import encrypt_value
        return encrypt_value(json.dumps(creds))
    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "ENCRYPTION_KEY is not configured. "
                "Generate a key with: "
                "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' "
                "and set it as the ENCRYPTION_KEY environment variable."
            ),
        ) from exc


def _decrypt_credentials(encrypted: str) -> dict:
    """Fernet-decrypt and JSON-decode a credentials blob.

    Raises HTTPException 400 if ENCRYPTION_KEY is not configured,
    or 500 if the stored ciphertext is corrupt.
    """
    try:
        from backend.core.security import decrypt_value
        return json.loads(decrypt_value(encrypted))
    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail="ENCRYPTION_KEY is not configured — cannot decrypt stored credentials.",
        ) from exc
    except Exception as exc:
        logger.error("Credential decryption failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="Failed to decrypt stored credentials. The encryption key may have changed.",
        ) from exc


def _to_response(conn: SIEMConnection) -> dict[str, Any]:
    """Serialize a SIEMConnection ORM record to a dict, redacting credentials."""
    return {
        "id": str(conn.id),
        "name": conn.name,
        "siem_type": conn.siem_type,
        "base_url": conn.base_url,
        "connected": conn.is_connected,
        "last_sync_at": conn.last_sync_at.isoformat() if conn.last_sync_at else None,
        "created_at": conn.created_at.isoformat() if conn.created_at else None,
        "settings": conn.settings or {},
        "environment_id": str(conn.environment_id) if conn.environment_id else None,
    }


async def _fetch_connection_or_404(db: AsyncSession, conn_uuid: uuid.UUID) -> SIEMConnection:
    """Fetch a SIEMConnection by UUID, raising 404 if not found."""
    result = await db.execute(
        select(SIEMConnection).where(SIEMConnection.id == conn_uuid)
    )
    conn = result.scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=404, detail=f"SIEM connection '{conn_uuid}' not found.")
    return conn


async def _run_test_connection(conn: SIEMConnection, creds: dict) -> dict[str, Any]:
    """Instantiate the connector and call test_connection() with a timeout.

    Returns a dict with keys: healthy, latency_ms, version, error, details.
    Never raises — all errors are captured and returned as ``error``.
    """
    try:
        connector = get_connector(conn, creds)
    except UnsupportedSIEMTypeError as exc:
        return {"healthy": False, "latency_ms": 0.0, "version": "", "error": str(exc), "details": {}}

    t0 = time.monotonic()
    try:
        async with asyncio.timeout(_TEST_TIMEOUT_SECS):
            async with connector as c:
                info = await c.test_connection()
    except TimeoutError:
        return {
            "healthy": False,
            "latency_ms": (time.monotonic() - t0) * 1000,
            "version": "",
            "error": f"Connection timed out after {_TEST_TIMEOUT_SECS}s.",
            "details": {},
        }
    except Exception as exc:
        logger.warning("test_connection error for %s: %s", conn.siem_type, exc)
        return {
            "healthy": False,
            "latency_ms": (time.monotonic() - t0) * 1000,
            "version": "",
            "error": str(exc),
            "details": {},
        }

    latency_ms = (time.monotonic() - t0) * 1000
    version = (
        info.get("version")
        or info.get("cluster_name")
        or info.get("workspace_name")
        or ""
    )
    return {
        "healthy": info.get("healthy", False),
        "latency_ms": round(latency_ms, 2),
        "version": str(version),
        "error": info.get("error"),
        "details": {k: v for k, v in info.items() if k not in ("healthy", "error")},
    }


# ── Rule parsing helpers ───────────────────────────────────────────────────────

def _severity_from_rule(raw: dict[str, Any], default: str = "medium") -> str:
    """Extract and normalize a severity string from a raw rule dict."""
    raw_sev = (
        raw.get("severity")
        or raw.get("alert.severity")
        or default
    )
    mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    return mapping.get(str(raw_sev).lower(), default)


def _parse_splunk_rules(
    raw_rules: list[dict[str, Any]],
    environment_id: uuid.UUID | None,
) -> tuple[list[ImportedRule], int]:
    """Convert Splunk saved searches to ImportedRule records.

    Returns (rules_to_add, rules_skipped).
    Skips entries with an empty search query.
    """
    to_add: list[ImportedRule] = []
    skipped = 0
    for rule in raw_rules:
        spl = (rule.get("search") or "").strip()
        name = (rule.get("name") or "").strip()
        if not spl or not name:
            skipped += 1
            continue
        to_add.append(
            ImportedRule(
                name=name,
                description=rule.get("description") or "",
                language="spl",
                source_query=spl,
                severity=_severity_from_rule(rule),
                source="siem",
                environment_id=environment_id,
                metadata_={
                    "cron_schedule": rule.get("cron_schedule", ""),
                    "is_scheduled": rule.get("is_scheduled", False),
                    "alert_type": rule.get("alert_type", ""),
                    "updated": rule.get("updated", ""),
                    "disabled": rule.get("disabled", False),
                },
            )
        )
    return to_add, skipped


def _parse_elastic_rules(
    raw_rules: list[dict[str, Any]],
    environment_id: uuid.UUID | None,
) -> tuple[list[ImportedRule], int]:
    """Convert Kibana detection rules to ImportedRule records.

    Returns (rules_to_add, rules_skipped).
    Skips entries with no query.
    """
    to_add: list[ImportedRule] = []
    skipped = 0
    for rule in raw_rules:
        query = (rule.get("query") or "").strip()
        name = (rule.get("name") or "").strip()
        if not name:
            skipped += 1
            continue
        # Determine query language — default KQL for "query" type rules
        rule_type = rule.get("type", "query")
        language = "esql" if rule_type == "esql" else "kql"
        to_add.append(
            ImportedRule(
                name=name,
                description="",
                language=language,
                source_query=query,
                severity=_severity_from_rule(rule),
                source="siem",
                environment_id=environment_id,
                metadata_={
                    "rule_id": rule.get("rule_id", ""),
                    "type": rule_type,
                    "risk_score": rule.get("risk_score", 0),
                    "enabled": rule.get("enabled", True),
                    "tags": rule.get("tags", []),
                    "updated_at": rule.get("updated_at", ""),
                },
            )
        )
    return to_add, skipped


def _parse_sentinel_rules(
    raw_rules: list[dict[str, Any]],
    environment_id: uuid.UUID | None,
) -> tuple[list[ImportedRule], int]:
    """Convert Sentinel analytic rules to ImportedRule records.

    Returns (rules_to_add, rules_skipped).
    Skips entries with no query.
    """
    to_add: list[ImportedRule] = []
    skipped = 0
    for rule in raw_rules:
        query = (rule.get("query") or "").strip()
        name = (rule.get("display_name") or rule.get("name") or "").strip()
        if not name:
            skipped += 1
            continue
        # Sentinel rules can be Scheduled (KQL) or other kinds (Fusion, MicrosoftSecurityIncidentCreation, etc.)
        kind = rule.get("kind", "Scheduled")
        language = "kql" if kind == "Scheduled" else kind.lower()
        severity_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "low"}
        severity = severity_map.get(rule.get("severity", ""), "medium")
        tactics = rule.get("tactics") or []
        to_add.append(
            ImportedRule(
                name=name,
                description="",
                language=language,
                source_query=query,
                severity=severity,
                source="siem",
                environment_id=environment_id,
                mitre_techniques={"tactics": tactics, "techniques": rule.get("techniques", [])},
                metadata_={
                    "name": rule.get("name", ""),
                    "kind": kind,
                    "enabled": rule.get("enabled", False),
                    "query_period": rule.get("query_period", ""),
                    "query_frequency": rule.get("query_frequency", ""),
                    "trigger_operator": rule.get("trigger_operator", ""),
                    "trigger_threshold": rule.get("trigger_threshold", 0),
                },
            )
        )
    return to_add, skipped


# ── Normalizer dispatch ────────────────────────────────────────────────────────

def _normalize_events(events: list[dict], siem_type: str, source_id: str) -> list[dict]:
    """Normalize events to the schema appropriate for the target SIEM.

    - Elastic  → ECS (Elastic Common Schema)
    - Splunk   → CIM (Splunk Common Information Model)
    - Sentinel → ASIM (Advanced SIEM Information Model)
    """
    siem = siem_type.lower()
    if siem == "elastic":
        from backend.siem_integration.data_models.ecs import to_ecs
        return [to_ecs(evt, source_id) for evt in events]
    if siem == "splunk":
        from backend.siem_integration.data_models.cim import to_cim
        return [to_cim(evt, source_id) for evt in events]
    if siem == "sentinel":
        from backend.siem_integration.data_models.asim import to_asim
        return [to_asim(evt, source_id) for evt in events]
    # Unknown SIEM type — pass through raw
    return events


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/connections", response_model=None)
async def list_connections(db: AsyncSession = Depends(get_db)) -> dict:
    """Return all SIEM connections with credentials redacted."""
    result = await db.execute(select(SIEMConnection))
    connections = result.scalars().all()
    return {
        "connections": [_to_response(c) for c in connections],
        "total": len(connections),
    }


@router.post("/connections", status_code=201, response_model=None)
async def create_connection(
    request: SIEMConnectionCreate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Register a new SIEM connection.

    Encrypts credentials using Fernet before storage, then runs an
    auto-test to populate is_connected.

    Returns 400 if ENCRYPTION_KEY is not set.
    """
    # Validate siem_type early so we don't persist garbage
    siem_type = (request.siem_type or "").lower().strip()
    if siem_type not in {"splunk", "elastic", "sentinel"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported siem_type '{siem_type}'. Must be one of: splunk, elastic, sentinel.",
        )

    # Resolve environment_id
    env_uuid: uuid.UUID | None = None
    if getattr(request, "environment_id", None):
        env_uuid = _parse_connection_id(request.environment_id)  # type: ignore[arg-type]

    # Encrypt credentials — raises 400 if key not set
    encrypted = _encrypt_credentials(request.credentials)

    conn = SIEMConnection(
        name=request.name,
        siem_type=siem_type,
        base_url=request.base_url,
        encrypted_credentials=encrypted,
        settings=request.settings or {},
        is_connected=False,
        environment_id=env_uuid,
    )
    db.add(conn)
    await db.flush()  # populate conn.id before the test

    # Auto-test connectivity
    test_result = await _run_test_connection(conn, request.credentials)
    conn.is_connected = test_result["healthy"]
    if test_result["healthy"]:
        conn.last_sync_at = datetime.utcnow()

    await db.commit()
    await db.refresh(conn)

    response = _to_response(conn)
    response["test_result"] = {
        "connected": test_result["healthy"],
        "latency_ms": test_result["latency_ms"],
        "version": test_result["version"],
        "error": test_result.get("error"),
    }
    return response


@router.get("/connections/{connection_id}", response_model=None)
async def get_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fetch a single SIEM connection by ID (credentials redacted)."""
    conn_uuid = _parse_connection_id(connection_id)
    conn = await _fetch_connection_or_404(db, conn_uuid)
    return _to_response(conn)


@router.put("/connections/{connection_id}", response_model=None)
async def update_connection(
    connection_id: str,
    request: SIEMConnectionUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update a SIEM connection.

    Re-encrypts credentials if the credentials field is provided.
    Re-tests connectivity if base_url or credentials changed.
    """
    conn_uuid = _parse_connection_id(connection_id)
    conn = await _fetch_connection_or_404(db, conn_uuid)

    creds_changed = request.credentials is not None
    url_changed = request.base_url is not None and request.base_url != conn.base_url

    if request.name is not None:
        conn.name = request.name
    if request.base_url is not None:
        conn.base_url = request.base_url
    if request.settings is not None:
        conn.settings = request.settings

    if creds_changed:
        conn.encrypted_credentials = _encrypt_credentials(request.credentials)  # type: ignore[arg-type]

    # Re-test if connectivity-sensitive fields changed
    retest = creds_changed or url_changed
    if retest:
        # Determine which credentials to use for the live test
        if creds_changed:
            live_creds = request.credentials
        else:
            live_creds = _decrypt_credentials(conn.encrypted_credentials)

        test_result = await _run_test_connection(conn, live_creds)  # type: ignore[arg-type]
        conn.is_connected = test_result["healthy"]
        if test_result["healthy"]:
            conn.last_sync_at = datetime.utcnow()
    else:
        test_result = None

    await db.commit()
    await db.refresh(conn)

    response = _to_response(conn)
    if test_result is not None:
        response["test_result"] = {
            "connected": test_result["healthy"],
            "latency_ms": test_result["latency_ms"],
            "version": test_result["version"],
            "error": test_result.get("error"),
        }
    return response


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
) -> StatusResponse:
    """Permanently delete a SIEM connection."""
    conn_uuid = _parse_connection_id(connection_id)
    conn = await _fetch_connection_or_404(db, conn_uuid)
    await db.delete(conn)
    await db.commit()
    return StatusResponse(status="deleted", message=f"Connection '{connection_id}' deleted.")


@router.post("/connections/{connection_id}/test", response_model=TestConnectionResponse)
async def test_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
) -> TestConnectionResponse:
    """Test live connectivity to a SIEM platform.

    Decrypts stored credentials, instantiates the connector, and calls
    test_connection() with a 15-second timeout.  Updates is_connected and
    last_sync_at in the DB regardless of outcome.

    Returns 503 if the SIEM is unreachable (does not crash).
    """
    conn_uuid = _parse_connection_id(connection_id)
    conn = await _fetch_connection_or_404(db, conn_uuid)
    creds = _decrypt_credentials(conn.encrypted_credentials)

    result = await _run_test_connection(conn, creds)

    # Persist updated status
    conn.is_connected = result["healthy"]
    conn.last_sync_at = datetime.utcnow()
    await db.commit()

    response = TestConnectionResponse(
        id=connection_id,
        connected=result["healthy"],
        latency_ms=result["latency_ms"],
        version=result["version"],
        error=result.get("error"),
        details=result.get("details", {}),
    )

    if not result["healthy"]:
        # Use 503 so callers can distinguish "found but unreachable" from 404
        raise HTTPException(
            status_code=503,
            detail={
                "id": connection_id,
                "connected": False,
                "latency_ms": result["latency_ms"],
                "version": result["version"],
                "error": result.get("error"),
                "details": result.get("details", {}),
            },
        )

    return response


@router.post("/connections/{connection_id}/sync-rules", response_model=SyncRulesResponse)
async def sync_rules(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
) -> SyncRulesResponse:
    """Pull detection rules from a connected SIEM and store them as ImportedRule records.

    - Splunk   : fetches saved searches → parses SPL → ImportedRule (language="spl")
    - Elastic  : fetches Kibana detection rules → parses KQL/EQL → ImportedRule
    - Sentinel : fetches analytic rules → parses KQL → ImportedRule

    Returns a summary with rules_synced, rules_skipped, and any errors.
    Existing rules with the same (name, language, environment_id) are skipped
    to avoid duplicates; they can be updated in a future endpoint.
    """
    conn_uuid = _parse_connection_id(connection_id)
    conn = await _fetch_connection_or_404(db, conn_uuid)
    creds = _decrypt_credentials(conn.encrypted_credentials)

    errors: list[str] = []
    raw_rules: list[dict[str, Any]] = []

    try:
        connector = get_connector(conn, creds)
    except UnsupportedSIEMTypeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Fetch raw rules from the SIEM
    try:
        async with asyncio.timeout(_SYNC_TIMEOUT_SECS):
            async with connector as c:
                raw_rules = await c.pull_rules()
    except TimeoutError:
        errors.append(f"Rule sync timed out after {_SYNC_TIMEOUT_SECS}s.")
        return SyncRulesResponse(
            id=connection_id,
            rules_synced=0,
            rules_skipped=0,
            errors=errors,
        )
    except Exception as exc:
        logger.error("sync_rules fetch failed for %s: %s", connection_id, exc)
        raise HTTPException(
            status_code=503,
            detail=f"Could not fetch rules from SIEM: {exc}",
        ) from exc

    # Parse into ImportedRule records
    siem_type = conn.siem_type.lower()
    env_id = conn.environment_id

    if siem_type == "splunk":
        to_add, skipped = _parse_splunk_rules(raw_rules, env_id)
    elif siem_type == "elastic":
        to_add, skipped = _parse_elastic_rules(raw_rules, env_id)
    elif siem_type == "sentinel":
        to_add, skipped = _parse_sentinel_rules(raw_rules, env_id)
    else:
        raise HTTPException(status_code=400, detail=f"No rule parser for siem_type '{siem_type}'.")

    # Deduplicate against existing rules in the DB (same name + language + env)
    if to_add:
        existing_result = await db.execute(
            select(ImportedRule.name, ImportedRule.language, ImportedRule.environment_id)
            .where(ImportedRule.environment_id == env_id)
        )
        existing_keys = {(row.name, row.language) for row in existing_result}
        new_rules = []
        for rule in to_add:
            if (rule.name, rule.language) in existing_keys:
                skipped += 1
            else:
                new_rules.append(rule)
        to_add = new_rules

    synced = 0
    add_errors: list[str] = []
    for rule in to_add:
        try:
            db.add(rule)
            synced += 1
        except Exception as exc:
            add_errors.append(f"Failed to stage rule '{rule.name}': {exc}")

    if synced:
        try:
            await db.commit()
            # Update last_sync_at
            conn.last_sync_at = datetime.utcnow()
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.error("sync_rules commit failed: %s", exc)
            errors.append(f"DB commit failed: {exc}")
            synced = 0

    errors.extend(add_errors)

    return SyncRulesResponse(
        id=connection_id,
        rules_synced=synced,
        rules_skipped=skipped,
        errors=errors,
    )


@router.post("/connections/{connection_id}/push-logs", response_model=PushLogsResponse)
async def push_logs(
    connection_id: str,
    request: PushLogsRequest,
    db: AsyncSession = Depends(get_db),
) -> PushLogsResponse:
    """Push events to a connected SIEM after normalizing to its native schema.

    Normalization:
    - Elastic  → ECS (Elastic Common Schema)
    - Splunk   → CIM (Splunk Common Information Model)
    - Sentinel → ASIM (Advanced SIEM Information Model)

    Returns 503 if the SIEM is unreachable.
    """
    conn_uuid = _parse_connection_id(connection_id)
    conn = await _fetch_connection_or_404(db, conn_uuid)
    creds = _decrypt_credentials(conn.encrypted_credentials)

    if not request.events:
        return PushLogsResponse(id=connection_id, events_sent=0, errors=[])

    errors: list[str] = []

    # Normalize events to the target schema
    try:
        normalized = _normalize_events(request.events, conn.siem_type, request.source_id)
    except Exception as exc:
        logger.error("Event normalization failed for %s: %s", connection_id, exc)
        errors.append(f"Normalization error: {exc}")
        normalized = request.events  # fall back to raw events

    # Instantiate connector and push
    try:
        connector = get_connector(conn, creds)
    except UnsupportedSIEMTypeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    events_sent = 0
    try:
        async with asyncio.timeout(_PUSH_TIMEOUT_SECS):
            async with connector as c:
                sent = await c.send_events(normalized)
                events_sent = sent
    except TimeoutError:
        errors.append(f"Push timed out after {_PUSH_TIMEOUT_SECS}s.")
        raise HTTPException(
            status_code=503,
            detail={
                "id": connection_id,
                "events_sent": events_sent,
                "errors": errors,
            },
        )
    except Exception as exc:
        logger.error("push_logs send failed for %s: %s", connection_id, exc)
        raise HTTPException(
            status_code=503,
            detail={
                "id": connection_id,
                "events_sent": events_sent,
                "errors": [str(exc)],
            },
        ) from exc

    if events_sent < len(normalized):
        errors.append(
            f"Partial delivery: {events_sent}/{len(normalized)} events accepted by SIEM."
        )

    return PushLogsResponse(
        id=connection_id,
        events_sent=events_sent,
        errors=errors,
    )
