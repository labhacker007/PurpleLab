"""Factory that instantiates the right connector from a SIEMConnection DB record.

Usage::

    from backend.siem_integration.connector_factory import get_connector

    connector = get_connector(connection, decrypted_creds)
    async with connector as conn:
        info = await conn.test_connection()
"""
from __future__ import annotations

import logging
from typing import Union

from backend.db.models import SIEMConnection
from backend.siem_integration.connectors.elastic_connector import (
    ElasticConfig,
    ElasticConnector,
)
from backend.siem_integration.connectors.sentinel_connector import (
    SentinelConfig,
    SentinelConnector,
)
from backend.siem_integration.connectors.splunk_connector import (
    SplunkConfig,
    SplunkConnector,
)

logger = logging.getLogger(__name__)

ConnectorType = Union[SplunkConnector, ElasticConnector, SentinelConnector]

# Supported siem_type values
_SUPPORTED_TYPES = {"splunk", "elastic", "sentinel"}


class UnsupportedSIEMTypeError(ValueError):
    """Raised when the siem_type on a SIEMConnection is not supported."""


def get_connector(connection: SIEMConnection, decrypted_creds: dict) -> ConnectorType:
    """Return an instantiated (but not yet connected) connector for *connection*.

    The returned object is an async context manager — callers should use it
    as ``async with get_connector(...) as conn:``.

    Args:
        connection: ORM record from the ``siem_connections`` table.
        decrypted_creds: Credentials dict that was decrypted from
            ``connection.encrypted_credentials`` by the caller.

    Returns:
        An instantiated SplunkConnector, ElasticConnector, or SentinelConnector.

    Raises:
        UnsupportedSIEMTypeError: If ``connection.siem_type`` is not one of
            "splunk", "elastic", or "sentinel".
    """
    siem_type = (connection.siem_type or "").lower().strip()
    base_url = connection.base_url or ""
    settings = connection.settings or {}

    if siem_type == "splunk":
        return _build_splunk(base_url, decrypted_creds, settings)
    if siem_type == "elastic":
        return _build_elastic(base_url, decrypted_creds, settings)
    if siem_type == "sentinel":
        return _build_sentinel(base_url, decrypted_creds, settings)

    raise UnsupportedSIEMTypeError(
        f"Unsupported siem_type '{siem_type}'. "
        f"Supported values: {', '.join(sorted(_SUPPORTED_TYPES))}."
    )


# ── Builder helpers ───────────────────────────────────────────────────────────

def _build_splunk(base_url: str, creds: dict, settings: dict) -> SplunkConnector:
    """Build a SplunkConnector from credentials and settings.

    Expected credential keys (all optional — sensible defaults apply):
        hec_token   : HEC ingest token (raw, without "Splunk " prefix)
        username    : REST API username
        password    : REST API password
        hec_url     : HEC base URL (e.g. https://splunk:8088). Falls back to base_url.
        rest_url    : REST API base URL (e.g. https://splunk:8089). Falls back to base_url.
    """
    hec_url = creds.get("hec_url") or settings.get("hec_url") or base_url
    rest_url = creds.get("rest_url") or settings.get("rest_url") or base_url
    hec_token = creds.get("hec_token", "")
    # Strip any "Splunk " prefix — the connector adds it back internally
    if hec_token.startswith("Splunk "):
        hec_token = hec_token[len("Splunk "):]

    config = SplunkConfig(
        hec_url=hec_url,
        hec_token=hec_token,
        rest_url=rest_url,
        username=creds.get("username", ""),
        password=creds.get("password", ""),
        index=settings.get("index", "main"),
        sourcetype=settings.get("sourcetype", "purplelab"),
        verify_ssl=settings.get("verify_ssl", True),
        timeout=float(settings.get("timeout", 30.0)),
    )
    return SplunkConnector(config)


def _build_elastic(base_url: str, creds: dict, settings: dict) -> ElasticConnector:
    """Build an ElasticConnector from credentials and settings.

    Expected credential keys:
        api_key     : Elasticsearch API key in "id:key" format (preferred)
        username    : Basic auth username
        password    : Basic auth password
        kibana_url  : Kibana base URL (optional, defaults to base_url:5601)
    """
    kibana_url = (
        creds.get("kibana_url")
        or settings.get("kibana_url")
        or ""
    )
    config = ElasticConfig(
        url=base_url,
        api_key=creds.get("api_key", ""),
        username=creds.get("username", ""),
        password=creds.get("password", ""),
        index=settings.get("index", "purplelab-logs"),
        kibana_url=kibana_url,
        verify_ssl=settings.get("verify_ssl", True),
        timeout=float(settings.get("timeout", 30.0)),
    )
    return ElasticConnector(config)


def _build_sentinel(base_url: str, creds: dict, settings: dict) -> SentinelConnector:
    """Build a SentinelConnector from credentials and settings.

    Expected credential keys:
        workspace_id      : Log Analytics workspace ID (GUID)
        workspace_key     : Primary shared key for HMAC signing
        tenant_id         : Azure AD tenant ID
        client_id         : Service principal / app client ID
        client_secret     : Service principal client secret
        subscription_id   : Azure subscription ID
        resource_group    : Resource group containing the workspace
        workspace_name    : Workspace name (ARM resource name)
        dce_endpoint      : (optional) Data Collection Endpoint URL
        dcr_immutable_id  : (optional) Data Collection Rule immutable ID
    """
    config = SentinelConfig(
        workspace_id=creds.get("workspace_id", ""),
        workspace_key=creds.get("workspace_key", ""),
        tenant_id=creds.get("tenant_id", ""),
        client_id=creds.get("client_id", ""),
        client_secret=creds.get("client_secret", ""),
        subscription_id=creds.get("subscription_id", ""),
        resource_group=creds.get("resource_group", ""),
        workspace_name=creds.get("workspace_name", ""),
        dce_endpoint=creds.get("dce_endpoint", settings.get("dce_endpoint", "")),
        dcr_immutable_id=creds.get("dcr_immutable_id", settings.get("dcr_immutable_id", "")),
        log_table=settings.get("log_table", "PurpleLabEvents_CL"),
        verify_ssl=settings.get("verify_ssl", True),
        timeout=float(settings.get("timeout", 30.0)),
    )
    return SentinelConnector(config)
