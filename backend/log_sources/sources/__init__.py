"""Concrete log source implementations."""
from backend.log_sources.sources.cloud_trail import AWSCloudTrailSource
from backend.log_sources.sources.dns import DNSLogSource
from backend.log_sources.sources.firewall import PaloAltoFirewallSource
from backend.log_sources.sources.kubernetes_audit import KubernetesAuditSource

__all__ = [
    "AWSCloudTrailSource",
    "DNSLogSource",
    "PaloAltoFirewallSource",
    "KubernetesAuditSource",
]
