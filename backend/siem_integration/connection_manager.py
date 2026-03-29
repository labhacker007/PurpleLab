"""SIEM ConnectionManager — service layer for SIEM connection lifecycle.

Provides database-backed storage, Fernet credential encryption, and
dispatching to concrete connector classes for test/push operations.

Usage::

    from backend.siem_integration.connection_manager import ConnectionManager

    mgr = ConnectionManager()

    # Create
    conn = await mgr.create_connection(
        name="prod-splunk",
        siem_type="splunk",
        config_dict={
            "base_url": "https://splunk.corp:8089",
            "hec_url": "https://splunk.corp:8088",
            "hec_token": "abc123",
            "username": "admin",
            "password": "changeme",
            "environment_id": "<uuid-str>",   # optional
        },
    )

    # Test
    result = await mgr.test_connection(conn["id"])
    # {"success": True, "message": "...", "latency_ms": 42}

    # Push logs
    count = await mgr.push_logs(conn["id"], [{"event": "login", ...}])

    # Push a rule
    await mgr.push_rule(conn["id"], rule_text="...", rule_name="My Rule")
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.models import SIEMConnection
from backend.db.session import async_session
from backend.siem_integration.connectors import CONNECTOR_REGISTRY

logger = logging.getLogger(__name__)

# ── Supported siem_type values ────────────────────────────────────────────────

_SUPPORTED_TYPES: frozenset[str] = frozenset(CONNECTOR_REGISTRY.keys())

# ── Credential helpers ────────────────────────────────────────────────────────


def _get_fernet():  # type: ignore[return]
    """Return a lazy Fernet instance (raises ValueError if key not configured)."""
    key = settings.ENCRYPTION_KEY
    if not key:
        raise ValueError(
            "ENCRYPTION_KEY is not set. Generate one with: "
            "python -c 'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())'"
        )
    from cryptography.fernet import Fernet

    return Fernet(key.encode() if isinstance(key, str) else key)


def _encrypt(data: dict[str, Any]) -> str:
    """JSON-serialize *data* then Fernet-encrypt it. Returns base64 ciphertext."""
    f = _get_fernet()
    return f.encrypt(json.dumps(data).encode()).decode()


def _decrypt(ciphertext: str) -> dict[str, Any]:
    """Fernet-decrypt *ciphertext* and JSON-parse it. Returns credentials dict."""
    f = _get_fernet()
    return json.loads(f.decrypt(ciphertext.encode()).decode())


# ── Serialisation helpers ─────────────────────────────────────────────────────

_MASKED = "***"


def _to_dict(conn: SIEMConnection, *, include_creds: bool = False) -> dict[str, Any]:
    """Serialize a SIEMConnection ORM row to a plain dict.

    Credentials are masked unless *include_creds* is True.
    """
    creds: dict[str, Any] = {}
    if include_creds and conn.encrypted_credentials:
        try:
            creds = _decrypt(conn.encrypted_credentials)
        except Exception as exc:
            logger.error("Failed to decrypt credentials for %s: %s", conn.id, exc)
            creds = {}
    elif conn.encrypted_credentials:
        # Return masked placeholder keys so callers know which fields exist
        try:
            raw_keys = list(_decrypt(conn.encrypted_credentials).keys())
            creds = {k: _MASKED for k in raw_keys}
        except Exception:
            creds = {}

    return {
        "id": str(conn.id),
        "name": conn.name,
        "siem_type": conn.siem_type,
        "base_url": conn.base_url,
        "is_connected": conn.is_connected,
        "last_sync_at": conn.last_sync_at.isoformat() if conn.last_sync_at else None,
        "created_at": conn.created_at.isoformat() if conn.created_at else None,
        "settings": conn.settings or {},
        "environment_id": str(conn.environment_id) if conn.environment_id else None,
        "credentials": creds,
    }


# ── ConnectionManager ─────────────────────────────────────────────────────────


class ConnectionManager:
    """Manages SIEM platform connections with DB persistence and credential encryption.

    All methods open a new async DB session internally, so the manager is safe to
    use as a singleton or instantiated per-request.
    """

    # ── Internal DB helpers ───────────────────────────────────────────────────

    async def _get_session(self) -> AsyncSession:  # type: ignore[return]
        """Not used directly — callers should use ``async with async_session()``."""

    async def _fetch_or_raise(
        self,
        db: AsyncSession,
        connection_id: str,
    ) -> SIEMConnection:
        """Fetch a SIEMConnection row by ID, raising ValueError if not found."""
        try:
            conn_uuid = uuid.UUID(connection_id)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"Invalid connection_id '{connection_id}'.") from exc

        result = await db.execute(
            select(SIEMConnection).where(SIEMConnection.id == conn_uuid)
        )
        conn = result.scalar_one_or_none()
        if conn is None:
            raise ValueError(f"SIEM connection '{connection_id}' not found.")
        return conn

    # ── Public API ────────────────────────────────────────────────────────────

    async def create_connection(
        self,
        name: str,
        siem_type: str,
        config_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate, encrypt, and persist a new SIEM connection.

        Args:
            name:        Human-readable connection name.
            siem_type:   One of "splunk", "elastic", "sentinel", "microsoft_sentinel".
            config_dict: Connection configuration including credentials and settings.
                         Required key: "base_url".
                         Optional:     "environment_id", "settings", plus any
                                       credential keys for the chosen connector.

        Returns:
            Serialized connection dict (credentials masked).

        Raises:
            ValueError: If siem_type is unsupported or base_url is missing.
        """
        siem_type = siem_type.lower().strip()
        if siem_type not in _SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported siem_type '{siem_type}'. "
                f"Supported values: {sorted(_SUPPORTED_TYPES)}."
            )

        base_url: str = config_dict.get("base_url", "").strip()
        if not base_url:
            raise ValueError("config_dict must include a non-empty 'base_url'.")

        # Separate out non-credential keys
        settings_data: dict[str, Any] = config_dict.get("settings") or {}
        env_id_raw: str | None = config_dict.get("environment_id")
        env_uuid: uuid.UUID | None = None
        if env_id_raw:
            try:
                env_uuid = uuid.UUID(env_id_raw)
            except (ValueError, AttributeError) as exc:
                raise ValueError(
                    f"Invalid environment_id '{env_id_raw}'."
                ) from exc

        # Everything else is treated as credentials
        skip_keys = {"base_url", "settings", "environment_id"}
        credentials: dict[str, Any] = {
            k: v for k, v in config_dict.items() if k not in skip_keys
        }
        # Also fold base_url in so connectors can use it directly
        credentials["base_url"] = base_url

        encrypted = _encrypt(credentials)

        async with async_session() as db:
            conn = SIEMConnection(
                name=name,
                siem_type=siem_type,
                base_url=base_url,
                encrypted_credentials=encrypted,
                settings=settings_data,
                is_connected=False,
                environment_id=env_uuid,
            )
            db.add(conn)
            await db.commit()
            await db.refresh(conn)
            return _to_dict(conn)

    async def get_connection(self, connection_id: str) -> dict[str, Any]:
        """Fetch a single connection by ID with decrypted credentials.

        Args:
            connection_id: UUID string.

        Returns:
            Serialized connection dict with decrypted credentials.

        Raises:
            ValueError: If not found or invalid ID.
        """
        async with async_session() as db:
            conn = await self._fetch_or_raise(db, connection_id)
            return _to_dict(conn, include_creds=True)

    async def list_connections(self) -> list[dict[str, Any]]:
        """Return all SIEM connections with credentials masked.

        Returns:
            List of serialized connection dicts.
        """
        async with async_session() as db:
            result = await db.execute(select(SIEMConnection))
            connections = result.scalars().all()
            return [_to_dict(c) for c in connections]

    async def test_connection(self, connection_id: str) -> dict[str, Any]:
        """Test live connectivity to the SIEM platform.

        Decrypts stored credentials, instantiates the appropriate connector,
        and calls ``connector.test()`` with a 10-second timeout.

        Updates ``is_connected`` in the DB based on the result.

        Args:
            connection_id: UUID string.

        Returns:
            {"success": bool, "message": str, "latency_ms": int, **extra}

        Never raises — all errors are captured and returned in the dict.
        """
        try:
            async with async_session() as db:
                conn = await self._fetch_or_raise(db, connection_id)
                try:
                    creds = _decrypt(conn.encrypted_credentials)
                except Exception as exc:
                    return {
                        "success": False,
                        "message": f"Credential decryption failed: {exc}",
                        "latency_ms": 0,
                    }

                siem_type = conn.siem_type.lower()
                connector_cls = CONNECTOR_REGISTRY.get(siem_type)
                if connector_cls is None:
                    return {
                        "success": False,
                        "message": f"No connector for siem_type '{siem_type}'.",
                        "latency_ms": 0,
                    }

                try:
                    import asyncio

                    async with connector_cls(creds) as connector:
                        result = await asyncio.wait_for(connector.test(), timeout=10.0)
                except asyncio.TimeoutError:
                    result = {
                        "success": False,
                        "message": "Connection timed out after 10 seconds.",
                        "latency_ms": 10_000,
                    }
                except Exception as exc:
                    logger.warning(
                        "ConnectionManager.test_connection error for %s: %s",
                        connection_id,
                        exc,
                    )
                    result = {"success": False, "message": str(exc), "latency_ms": 0}

                # Persist connectivity status
                conn.is_connected = result.get("success", False)
                await db.commit()

                return result
        except ValueError:
            raise
        except Exception as exc:
            logger.error("ConnectionManager.test_connection unexpected error: %s", exc)
            return {"success": False, "message": str(exc), "latency_ms": 0}

    async def push_logs(
        self,
        connection_id: str,
        logs: list[dict[str, Any]],
    ) -> int:
        """Push log events to the SIEM platform.

        Args:
            connection_id: UUID string.
            logs:          List of log event dicts.

        Returns:
            Number of events accepted by the SIEM.

        Never raises — returns 0 on error and logs the exception.
        """
        if not logs:
            return 0

        try:
            async with async_session() as db:
                conn = await self._fetch_or_raise(db, connection_id)
                try:
                    creds = _decrypt(conn.encrypted_credentials)
                except Exception as exc:
                    logger.error(
                        "ConnectionManager.push_logs decrypt failed for %s: %s",
                        connection_id,
                        exc,
                    )
                    return 0

                siem_type = conn.siem_type.lower()
                connector_cls = CONNECTOR_REGISTRY.get(siem_type)
                if connector_cls is None:
                    logger.error(
                        "ConnectionManager.push_logs: no connector for '%s'", siem_type
                    )
                    return 0

                try:
                    async with connector_cls(creds) as connector:
                        return await connector.push_logs(logs)
                except Exception as exc:
                    logger.error(
                        "ConnectionManager.push_logs error for %s: %s",
                        connection_id,
                        exc,
                    )
                    return 0
        except ValueError:
            raise
        except Exception as exc:
            logger.error(
                "ConnectionManager.push_logs unexpected error for %s: %s",
                connection_id,
                exc,
            )
            return 0

    async def push_rule(
        self,
        connection_id: str,
        rule_text: str,
        rule_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Deploy a detection rule to the SIEM platform.

        Args:
            connection_id: UUID string.
            rule_text:     Raw rule / query string.
            rule_name:     Human-readable rule name.
            metadata:      Optional metadata (severity, tags, description, etc.).

        Returns:
            {"success": bool, "message": str}

        Never raises — errors are returned in the dict.
        """
        try:
            async with async_session() as db:
                conn = await self._fetch_or_raise(db, connection_id)
                try:
                    creds = _decrypt(conn.encrypted_credentials)
                except Exception as exc:
                    return {
                        "success": False,
                        "message": f"Credential decryption failed: {exc}",
                    }

                siem_type = conn.siem_type.lower()
                connector_cls = CONNECTOR_REGISTRY.get(siem_type)
                if connector_cls is None:
                    return {
                        "success": False,
                        "message": f"No connector for siem_type '{siem_type}'.",
                    }

                try:
                    async with connector_cls(creds) as connector:
                        return await connector.push_rule(rule_text, rule_name, metadata)
                except Exception as exc:
                    logger.error(
                        "ConnectionManager.push_rule error for %s: %s",
                        connection_id,
                        exc,
                    )
                    return {"success": False, "message": str(exc)}
        except ValueError:
            raise
        except Exception as exc:
            logger.error(
                "ConnectionManager.push_rule unexpected error for %s: %s",
                connection_id,
                exc,
            )
            return {"success": False, "message": str(exc)}
