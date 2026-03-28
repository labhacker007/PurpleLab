"""Environment templates — pre-configured SOC setups for quick start.

TODO: Define templates for common SIEM deployments:
- Splunk Enterprise with Windows + Linux sources
- Microsoft Sentinel with Azure AD + Defender
- Elastic Security with Sysmon + network data
"""
from __future__ import annotations

ENVIRONMENT_TEMPLATES: list[dict] = [
    {
        "id": "splunk_enterprise",
        "name": "Splunk Enterprise SOC",
        "description": "Standard Splunk deployment with Windows EventLog, Sysmon, and firewall data",
        "siem_platform": "splunk",
        "log_sources": ["windows_eventlog", "sysmon", "firewall", "proxy", "dns"],
    },
    {
        "id": "sentinel_cloud",
        "name": "Microsoft Sentinel Cloud SOC",
        "description": "Azure Sentinel with Entra ID, Defender, and CloudTrail integration",
        "siem_platform": "sentinel",
        "log_sources": ["windows_eventlog", "cloud_trail", "dns"],
    },
    {
        "id": "elastic_siem",
        "name": "Elastic Security",
        "description": "Elastic SIEM with Sysmon, Linux audit, and network flow data",
        "siem_platform": "elastic",
        "log_sources": ["sysmon", "linux_audit", "firewall", "dns"],
    },
]
