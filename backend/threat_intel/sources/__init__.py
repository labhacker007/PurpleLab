"""External threat intelligence source connectors.

Exports all source classes and provides ``get_threat_intel_sources`` factory
that returns only the sources that are configured/available.
"""
from __future__ import annotations

from typing import Any

from backend.threat_intel.sources.abusech import AbuseEHSource
from backend.threat_intel.sources.mitre_attack import MITREAttackSource
from backend.threat_intel.sources.otx import OTXSource
from backend.threat_intel.sources.virustotal import VirusTotalSource
from backend.threat_intel.sources.web_search import WebSearchSource

__all__ = [
    "MITREAttackSource",
    "WebSearchSource",
    "VirusTotalSource",
    "OTXSource",
    "AbuseEHSource",
    "get_threat_intel_sources",
]


def get_threat_intel_sources(settings: Any) -> dict[str, Any]:
    """Return initialised threat intelligence sources based on available API keys.

    AbuseEH (URLhaus / MalwareBazaar / ThreatFox) is always included as it
    requires no API key.  VirusTotal and OTX are included only when the
    corresponding key is present in settings.

    Args:
        settings: Application settings object (backend.config.Settings or any
                  object with VIRUSTOTAL_API_KEY and OTX_API_KEY attributes).

    Returns:
        dict mapping source name → source instance.
        Keys: "virustotal", "otx", "abusech"
    """
    sources: dict[str, Any] = {}

    vt_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    if vt_key:
        sources["virustotal"] = VirusTotalSource(vt_key)

    otx_key = getattr(settings, "OTX_API_KEY", "")
    if otx_key:
        sources["otx"] = OTXSource(otx_key)

    # Always available — free, no key required
    sources["abusech"] = AbuseEHSource()

    return sources
