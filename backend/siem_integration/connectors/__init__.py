"""SIEM platform connectors.

New-style connectors (used by ConnectionManager):
    SplunkConnector   — splunk.py
    ElasticConnector  — elastic.py
    SentinelConnector — sentinel.py

Legacy connectors (used by connector_factory.py / API routes directly):
    splunk_connector.py, elastic_connector.py, sentinel_connector.py
"""
from __future__ import annotations

from backend.siem_integration.connectors.base import BaseSIEMConnector
from backend.siem_integration.connectors.elastic import ElasticConnector
from backend.siem_integration.connectors.sentinel import SentinelConnector
from backend.siem_integration.connectors.splunk import SplunkConnector

# Registry mapping siem_type strings → connector class
CONNECTOR_REGISTRY: dict[str, type[BaseSIEMConnector]] = {
    "splunk": SplunkConnector,
    "elastic": ElasticConnector,
    "sentinel": SentinelConnector,
    "microsoft_sentinel": SentinelConnector,
}

__all__ = [
    "BaseSIEMConnector",
    "SplunkConnector",
    "ElasticConnector",
    "SentinelConnector",
    "CONNECTOR_REGISTRY",
]
