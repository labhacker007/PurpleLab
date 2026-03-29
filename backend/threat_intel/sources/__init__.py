"""Threat intelligence sources for purple team simulation planning.

These sources inform WHAT to simulate — threat actor TTPs, technique behaviour,
attack patterns — not blue-team IOC investigation.
"""
from __future__ import annotations

from typing import Any

from backend.threat_intel.sources.mitre_attack import MITREAttackSource
from backend.threat_intel.sources.web_search import WebSearchSource

__all__ = [
    "MITREAttackSource",
    "WebSearchSource",
]
