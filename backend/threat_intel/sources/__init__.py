"""External threat intelligence source connectors."""

from backend.threat_intel.sources.mitre_attack import MITREAttackSource
from backend.threat_intel.sources.web_search import WebSearchSource

__all__ = ["MITREAttackSource", "WebSearchSource"]
