"""Shared constants used throughout PurpleLab."""
from __future__ import annotations

# ── MITRE ATT&CK Tactics (Enterprise) ────────────────────────────────────────

MITRE_TACTICS: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# ── Severity Levels ──────────────────────────────────────────────────────────

SEVERITY_LEVELS: list[str] = ["critical", "high", "medium", "low", "informational"]

# ── Log Source Types ─────────────────────────────────────────────────────────

LOG_SOURCE_TYPES: list[str] = [
    "windows_eventlog",
    "sysmon",
    "linux_audit",
    "firewall",
    "proxy",
    "dns",
    "cloud_trail",
    "network_flow",
    "endpoint_telemetry",
]

# ── Detection Rule Languages ────────────────────────────────────────────────

RULE_LANGUAGES: list[str] = [
    "spl",       # Splunk Search Processing Language
    "kql",       # Kusto Query Language (Sentinel)
    "esql",      # Elasticsearch Query Language
    "sigma",     # Sigma generic format
    "yara_l",    # Chronicle YARA-L
]

# ── SIEM Platforms ───────────────────────────────────────────────────────────

SIEM_PLATFORMS: list[str] = [
    "splunk",
    "sentinel",
    "elastic",
    "qradar",
    "chronicle",
]

# ── Data Models ──────────────────────────────────────────────────────────────

DATA_MODELS: list[str] = [
    "cim",   # Splunk Common Information Model
    "asim",  # Microsoft Advanced SIEM Information Model
    "ecs",   # Elastic Common Schema
]

# ── Product Categories ───────────────────────────────────────────────────────

PRODUCT_CATEGORIES: list[str] = [
    "siem",
    "edr",
    "itdr",
    "email",
    "itsm",
    "cloud",
    "vulnerability",
]
