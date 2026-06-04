"""Topology Graph — product observer resolution for simulation sessions.

Core concept: not every product "sees" every event. A perimeter firewall
sees inbound/outbound network connections but NOT local process creation.
An EDR sees every process on the endpoint but NOT cloud API calls.

This module:
1. Defines the OBSERVER_MAP: technique → which product categories can observe it
2. Builds a per-environment TopologyGraph from the session's product selections
3. Resolves generate_for_products(technique_id) → list of (product, source_id)
   pairs that should emit events for that technique

Architecture:
  Environment
    ├── endpoint tier:   EDR, Sysmon, Windows Event Log
    ├── perimeter tier:  Firewall, Proxy, NDR
    ├── identity tier:   IdP/SSO, PAM, MFA
    ├── cloud tier:      CloudTrail, CSPM, CASB
    ├── email tier:      Email Gateway, DLP
    └── server tier:     DC, SIEM (collection point)

Observation rules:
  - EDR/Endpoint agents observe: process, file, registry, network (egress), memory
  - Perimeter (firewall/proxy): network (external), URL, DNS
  - Identity (Okta/AAD): auth, account, MFA, SSO
  - Cloud: API calls, resource access, config change
  - Email: message delivery, attachment, link click

Each technique maps to one or more "observation tiers". The graph resolves
which installed products cover each tier, producing a filtered event set that
only includes sources that would realistically see the activity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Observation tiers ─────────────────────────────────────────────────────────

class Tier:
    ENDPOINT     = "endpoint"      # EDR, Sysmon, WinEvtLog — on the workstation
    PERIMETER    = "perimeter"     # Firewall, proxy, NDR — at the network boundary
    IDENTITY     = "identity"      # IdP/SSO, MFA, PAM
    CLOUD        = "cloud"         # CloudTrail, CASB, CSPM
    EMAIL        = "email"         # Email gateway, DLP
    DNS          = "dns"           # DNS resolver / RPZ
    SERVER       = "server"        # DC, file server logs
    LATERAL      = "lateral"       # Event visible on the TARGET of lateral movement
    SIEM         = "siem"          # SIEM itself (aggregation, correlation)


# ── Category → tier mapping ───────────────────────────────────────────────────
# Maps product category (from environment config) to observation tier

CATEGORY_TO_TIER: dict[str, str] = {
    "edr":           Tier.ENDPOINT,
    "sysmon":        Tier.ENDPOINT,
    "windows_event": Tier.ENDPOINT,
    "firewall":      Tier.PERIMETER,
    "proxy":         Tier.PERIMETER,
    "cdn_waf":       Tier.PERIMETER,
    "ndr":           Tier.PERIMETER,
    "idp":           Tier.IDENTITY,
    "pam":           Tier.IDENTITY,
    "mfa":           Tier.IDENTITY,
    "cloud":         Tier.CLOUD,
    "casb":          Tier.CLOUD,
    "cspm":          Tier.CLOUD,
    "email":         Tier.EMAIL,
    "email_dlp":     Tier.EMAIL,
    "dns_rpz":       Tier.DNS,
    "dhcp_dns":      Tier.DNS,
    "network_switch": Tier.PERIMETER,
    "siem":          Tier.SIEM,
}

# Maps log_source (schema source_id) → primary tier
SOURCE_TO_TIER: dict[str, str] = {
    "windows_sysmon":       Tier.ENDPOINT,
    "windows_eventlog":     Tier.ENDPOINT,
    "crowdstrike_edr":      Tier.ENDPOINT,
    "sentinelone_edr":      Tier.ENDPOINT,
    "defender_atp":         Tier.ENDPOINT,
    "palo_alto_firewall":   Tier.PERIMETER,
    "fortinet_firewall":    Tier.PERIMETER,
    "cisco_asa_firewall":   Tier.PERIMETER,
    "checkpoint_firewall":  Tier.PERIMETER,
    "bluecoat_proxy":       Tier.PERIMETER,
    "zscaler_proxy":        Tier.PERIMETER,
    "okta_identity":        Tier.IDENTITY,
    "azure_ad":             Tier.IDENTITY,
    "ping_identity":        Tier.IDENTITY,
    "aws_cloudtrail":       Tier.CLOUD,
    "azure_monitor":        Tier.CLOUD,
    "gcp_audit":            Tier.CLOUD,
    "o365_exchange":        Tier.EMAIL,
    "proofpoint_email":     Tier.EMAIL,
    "mimecast_email":       Tier.EMAIL,
    "infoblox_dns":         Tier.DNS,
    "windows_dns":          Tier.DNS,
    "splunk_siem":          Tier.SIEM,
    "elastic_siem":         Tier.SIEM,
    "microsoft_sentinel":   Tier.SIEM,
    # Generic aliases
    "sysmon":               Tier.ENDPOINT,
    "edr_endpoint":         Tier.ENDPOINT,
    "network_traffic":      Tier.PERIMETER,
    "auth":                 Tier.IDENTITY,
    "cloud_trail":          Tier.CLOUD,
    "email_security":       Tier.EMAIL,
    "dns":                  Tier.DNS,
}


# ── Technique → Observable tiers ─────────────────────────────────────────────
# For each MITRE technique, which tiers would realistically see evidence.
# Multiple tiers = multi-source correlated events (realistic).

TECHNIQUE_OBSERVERS: dict[str, list[str]] = {

    # ── Initial Access ────────────────────────────────────────────────────────
    "T1566.001": [Tier.EMAIL, Tier.ENDPOINT],           # Spearphishing Attachment
    "T1566.002": [Tier.EMAIL, Tier.ENDPOINT, Tier.DNS], # Spearphishing Link
    "T1566.003": [Tier.EMAIL],                           # Spearphishing via Service
    "T1190":     [Tier.PERIMETER, Tier.SERVER],          # Exploit Public-Facing App
    "T1133":     [Tier.PERIMETER, Tier.IDENTITY],        # External Remote Services (VPN)
    "T1078":     [Tier.IDENTITY, Tier.ENDPOINT, Tier.PERIMETER],  # Valid Accounts
    "T1078.001": [Tier.ENDPOINT],                        # Default Accounts
    "T1078.002": [Tier.IDENTITY, Tier.SERVER],           # Domain Accounts
    "T1078.003": [Tier.IDENTITY],                        # Local Accounts
    "T1078.004": [Tier.CLOUD, Tier.IDENTITY],            # Cloud Accounts
    "T1195.002": [Tier.ENDPOINT],                        # Compromise Software Supply Chain

    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059.001": [Tier.ENDPOINT],                        # PowerShell
    "T1059.002": [Tier.ENDPOINT],                        # AppleScript
    "T1059.003": [Tier.ENDPOINT],                        # Windows Command Shell
    "T1059.004": [Tier.ENDPOINT],                        # Unix Shell
    "T1059.007": [Tier.ENDPOINT],                        # JavaScript
    "T1047":     [Tier.ENDPOINT],                        # WMI
    "T1053.005": [Tier.ENDPOINT],                        # Scheduled Task
    "T1204.002": [Tier.ENDPOINT, Tier.EMAIL],            # Malicious File (user exec)
    "T1106":     [Tier.ENDPOINT],                        # Native API

    # ── Persistence ──────────────────────────────────────────────────────────
    "T1543.003": [Tier.ENDPOINT],                        # Windows Service
    "T1547.001": [Tier.ENDPOINT],                        # Registry Run Keys
    "T1546.003": [Tier.ENDPOINT],                        # WMI Subscription
    "T1098":     [Tier.IDENTITY, Tier.CLOUD],            # Account Manipulation
    "T1098.001": [Tier.CLOUD],                           # Additional Cloud Credentials
    "T1098.002": [Tier.EMAIL, Tier.IDENTITY],            # Additional Email Delegate Perms
    "T1137":     [Tier.ENDPOINT, Tier.EMAIL],            # Office App Startup

    # ── Privilege Escalation ─────────────────────────────────────────────────
    "T1055":     [Tier.ENDPOINT],                        # Process Injection
    "T1055.001": [Tier.ENDPOINT],                        # DLL Injection
    "T1055.012": [Tier.ENDPOINT],                        # Process Hollowing
    "T1068":     [Tier.ENDPOINT],                        # Exploitation for Privilege Esc
    "T1548.002": [Tier.ENDPOINT],                        # Bypass UAC

    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1027":     [Tier.ENDPOINT],                        # Obfuscated Files
    "T1036.005": [Tier.ENDPOINT],                        # Match Legitimate Name
    "T1070.001": [Tier.ENDPOINT, Tier.SIEM],             # Clear Windows Event Logs
    "T1070.004": [Tier.ENDPOINT],                        # File Deletion
    "T1218.011": [Tier.ENDPOINT],                        # Rundll32
    "T1562.001": [Tier.ENDPOINT],                        # Disable or Modify Tools

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1003.001": [Tier.ENDPOINT],                        # LSASS Memory
    "T1003.002": [Tier.ENDPOINT],                        # Security Account Manager
    "T1003.006": [Tier.SERVER, Tier.IDENTITY],           # DCSync
    "T1110":     [Tier.IDENTITY, Tier.ENDPOINT],         # Brute Force
    "T1110.001": [Tier.IDENTITY],                        # Password Guessing
    "T1110.003": [Tier.IDENTITY, Tier.SERVER],           # Password Spraying
    "T1187":     [Tier.ENDPOINT, Tier.PERIMETER],        # Forced Auth (Net-NTLMv2 capture)
    "T1556":     [Tier.IDENTITY, Tier.SERVER],           # Modify Auth Process

    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1046":     [Tier.ENDPOINT, Tier.PERIMETER],        # Network Service Scanning
    "T1082":     [Tier.ENDPOINT],                        # System Information Discovery
    "T1083":     [Tier.ENDPOINT],                        # File and Dir Discovery
    "T1087":     [Tier.ENDPOINT, Tier.SERVER],           # Account Discovery
    "T1087.002": [Tier.ENDPOINT, Tier.SERVER],           # Domain Account Discovery
    "T1482":     [Tier.ENDPOINT, Tier.SERVER],           # Domain Trust Discovery
    "T1135":     [Tier.ENDPOINT],                        # Network Share Discovery
    "T1057":     [Tier.ENDPOINT],                        # Process Discovery
    "T1033":     [Tier.ENDPOINT],                        # System Owner/User Discovery
    "T1069":     [Tier.ENDPOINT, Tier.SERVER],           # Permission Groups Discovery
    "T1526":     [Tier.CLOUD],                           # Cloud Service Discovery
    "T1580":     [Tier.CLOUD],                           # Cloud Infrastructure Discovery

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1021.001": [Tier.ENDPOINT, Tier.PERIMETER, Tier.LATERAL],  # RDP
    "T1021.002": [Tier.ENDPOINT, Tier.LATERAL],          # SMB/WinRM
    "T1021.006": [Tier.ENDPOINT, Tier.LATERAL],          # WinRM
    "T1550.002": [Tier.ENDPOINT, Tier.SERVER],           # Pass the Hash
    "T1550.003": [Tier.ENDPOINT, Tier.SERVER],           # Pass the Ticket
    "T1570":     [Tier.ENDPOINT, Tier.PERIMETER],        # Lateral Tool Transfer

    # ── Collection ────────────────────────────────────────────────────────────
    "T1005":     [Tier.ENDPOINT],                        # Data from Local System
    "T1039":     [Tier.ENDPOINT, Tier.SERVER],           # Data from Network Shared Drive
    "T1114.001": [Tier.EMAIL, Tier.IDENTITY],            # Local Email Collection
    "T1114.002": [Tier.EMAIL, Tier.CLOUD, Tier.IDENTITY], # Remote Email Collection
    "T1560.001": [Tier.ENDPOINT],                        # Archive via Utility

    # ── C2 ────────────────────────────────────────────────────────────────────
    "T1071.001": [Tier.ENDPOINT, Tier.PERIMETER, Tier.DNS],  # Web Protocols
    "T1071.004": [Tier.DNS, Tier.PERIMETER],             # DNS
    "T1572":     [Tier.ENDPOINT, Tier.PERIMETER],        # Protocol Tunneling
    "T1095":     [Tier.ENDPOINT, Tier.PERIMETER],        # Non-Standard Port
    "T1219":     [Tier.ENDPOINT, Tier.PERIMETER],        # Remote Access Software
    "T1090.003": [Tier.ENDPOINT, Tier.PERIMETER],        # Multi-hop Proxy

    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1041":     [Tier.ENDPOINT, Tier.PERIMETER],        # Exfil over C2 Channel
    "T1048":     [Tier.PERIMETER, Tier.DNS],             # Exfil over Alt Protocol
    "T1537":     [Tier.CLOUD],                           # Transfer to Cloud Account
    "T1020":     [Tier.ENDPOINT, Tier.PERIMETER],        # Automated Exfil

    # ── Impact ────────────────────────────────────────────────────────────────
    "T1486":     [Tier.ENDPOINT, Tier.SERVER],           # Data Encrypted for Impact
    "T1490":     [Tier.ENDPOINT],                        # Inhibit System Recovery
    "T1485":     [Tier.ENDPOINT, Tier.CLOUD],            # Data Destruction
    "T1499":     [Tier.PERIMETER, Tier.SERVER],          # Endpoint Denial of Service
    "T1496":     [Tier.ENDPOINT, Tier.CLOUD],            # Resource Hijacking (cryptomining)
}

# Default observers when technique is not in the map
DEFAULT_OBSERVERS: list[str] = [Tier.ENDPOINT, Tier.PERIMETER]


# ── TopologyGraph ─────────────────────────────────────────────────────────────

@dataclass
class TopologyNode:
    """A single product in the environment topology."""
    product_id: str       # e.g. "crowdstrike_falcon"
    category: str         # e.g. "edr"
    tier: str             # resolved from CATEGORY_TO_TIER
    source_id: str        # schema registry source_id (e.g. "crowdstrike_edr")
    log_source: str       # legacy source_type used in events
    vendor: str = ""


@dataclass
class TopologyGraph:
    """Resolved product topology for one simulation environment.

    Built from the environment's product selections
    (e.g. {"edr": "crowdstrike", "idp": "okta", "cloud": "aws"}).

    Usage::

        graph = TopologyGraph.from_products({"edr": "crowdstrike", "idp": "okta"})
        observers = graph.resolve_observers("T1078")
        # → [TopologyNode(crowdstrike), TopologyNode(okta), TopologyNode(palo_alto)]
    """
    nodes: list[TopologyNode] = field(default_factory=list)
    # tier → list of nodes in that tier
    by_tier: dict[str, list[TopologyNode]] = field(default_factory=dict)

    @classmethod
    def from_products(cls, products: dict[str, str]) -> "TopologyGraph":
        """Build a topology graph from environment product selections.

        Args:
            products: Dict mapping category → vendor, e.g.
                      {"edr": "crowdstrike", "idp": "okta", "cloud": "aws"}
        """
        graph = cls()
        for category, vendor in (products or {}).items():
            if not vendor:
                continue
            node = _resolve_node(category, vendor)
            if node:
                graph.nodes.append(node)
                graph.by_tier.setdefault(node.tier, []).append(node)

        # If no nodes at all, add synthetic generic nodes for core tiers
        if not graph.nodes:
            graph = cls._default_graph()

        return graph

    @classmethod
    def _default_graph(cls) -> "TopologyGraph":
        """Fallback graph with generic nodes for the four core tiers."""
        graph = cls()
        defaults = [
            TopologyNode("generic_edr",      "edr",      Tier.ENDPOINT,  "edr_endpoint",     "edr_endpoint",     "generic"),
            TopologyNode("generic_fw",        "firewall", Tier.PERIMETER, "network_traffic",  "network_traffic",  "generic"),
            TopologyNode("generic_idp",       "idp",      Tier.IDENTITY,  "auth",             "auth",             "generic"),
            TopologyNode("generic_cloud",     "cloud",    Tier.CLOUD,     "cloud_trail",      "cloud_trail",      "generic"),
        ]
        for node in defaults:
            graph.nodes.append(node)
            graph.by_tier.setdefault(node.tier, []).append(node)
        return graph

    def resolve_observers(self, technique_id: str) -> list[TopologyNode]:
        """Return product nodes that can observe the given technique.

        Looks up the technique's observable tiers then returns installed
        nodes in those tiers. Falls back to DEFAULT_OBSERVERS tiers if
        the technique is not in the map.
        """
        tiers = TECHNIQUE_OBSERVERS.get(technique_id)
        # Try parent technique (T1059.001 → T1059)
        if not tiers and "." in technique_id:
            tiers = TECHNIQUE_OBSERVERS.get(technique_id.split(".")[0])
        if not tiers:
            tiers = DEFAULT_OBSERVERS

        result: list[TopologyNode] = []
        for tier in tiers:
            result.extend(self.by_tier.get(tier, []))

        # Always include at least one node to avoid empty events
        if not result:
            result = self.nodes[:1] if self.nodes else []

        return result

    def resolve_source_ids(self, technique_id: str) -> list[str]:
        """Return schema source_ids for all observer nodes."""
        return [n.source_id for n in self.resolve_observers(technique_id)]

    def resolve_log_sources(self, technique_id: str) -> list[str]:
        """Return legacy log_source strings for observer nodes."""
        return [n.log_source for n in self.resolve_observers(technique_id)]

    def tiers_present(self) -> set[str]:
        """Return the set of tiers covered by installed products."""
        return set(self.by_tier.keys())

    def to_dict(self) -> dict[str, Any]:
        """Serialise graph for API/frontend."""
        return {
            "nodes": [
                {
                    "product_id": n.product_id,
                    "category": n.category,
                    "tier": n.tier,
                    "source_id": n.source_id,
                    "log_source": n.log_source,
                    "vendor": n.vendor,
                }
                for n in self.nodes
            ],
            "tiers": list(self.tiers_present()),
        }


# ── Product node resolution ───────────────────────────────────────────────────

# Maps (category, vendor) → (source_id, log_source)
# source_id must match an entry in the schema registry
# log_source is the legacy source_type string used in generated events

_PRODUCT_SOURCE_MAP: dict[tuple[str, str], tuple[str, str]] = {
    # EDR
    ("edr", "crowdstrike"):    ("crowdstrike_edr",   "edr_endpoint"),
    ("edr", "sentinelone"):    ("sentinelone_edr",   "edr_endpoint"),
    ("edr", "defender"):       ("defender_atp",      "edr_endpoint"),
    ("edr", "carbon_black"):   ("edr_endpoint",      "edr_endpoint"),
    ("edr", "cylance"):        ("edr_endpoint",      "edr_endpoint"),
    ("edr", "generic"):        ("edr_endpoint",      "edr_endpoint"),
    # Firewall / Proxy / NDR
    ("firewall", "palo_alto"): ("palo_alto_firewall", "network_traffic"),
    ("firewall", "fortinet"):  ("fortinet_firewall",  "network_traffic"),
    ("firewall", "cisco"):     ("cisco_asa_firewall",  "network_traffic"),
    ("firewall", "checkpoint"): ("checkpoint_firewall", "network_traffic"),
    ("firewall", "generic"):   ("network_traffic",    "network_traffic"),
    ("proxy", "zscaler"):      ("zscaler_proxy",      "network_traffic"),
    ("proxy", "bluecoat"):     ("bluecoat_proxy",     "network_traffic"),
    ("proxy", "generic"):      ("network_traffic",    "network_traffic"),
    ("cdn_waf", "cloudflare"): ("network_traffic",    "network_traffic"),
    ("cdn_waf", "akamai"):     ("network_traffic",    "network_traffic"),
    # Identity
    ("idp", "okta"):           ("okta_identity",      "auth"),
    ("idp", "azure_ad"):       ("azure_ad",           "auth"),
    ("idp", "ping"):           ("ping_identity",      "auth"),
    ("idp", "duo"):            ("auth",               "auth"),
    ("idp", "generic"):        ("auth",               "auth"),
    # Cloud
    ("cloud", "aws"):          ("aws_cloudtrail",     "cloud_trail"),
    ("cloud", "azure"):        ("azure_monitor",      "cloud_trail"),
    ("cloud", "gcp"):          ("gcp_audit",          "cloud_trail"),
    ("cloud", "generic"):      ("cloud_trail",        "cloud_trail"),
    # Email
    ("email", "o365"):         ("o365_exchange",      "email_security"),
    ("email", "gsuite"):       ("email_security",     "email_security"),
    ("email", "proofpoint"):   ("proofpoint_email",   "email_security"),
    ("email", "mimecast"):     ("mimecast_email",     "email_security"),
    ("email", "generic"):      ("email_security",     "email_security"),
    # DNS
    ("dhcp_dns", "infoblox"):  ("infoblox_dns",       "dns"),
    ("dhcp_dns", "windows"):   ("windows_dns",        "dns"),
    ("dhcp_dns", "generic"):   ("dns",                "dns"),
    # Sysmon (endpoint tier)
    ("sysmon", "generic"):     ("windows_sysmon",     "sysmon"),
    ("sysmon", "sysmon"):      ("windows_sysmon",     "sysmon"),
    # SIEM
    ("siem", "splunk"):        ("splunk_siem",        "siem"),
    ("siem", "elastic"):       ("elastic_siem",       "siem"),
    ("siem", "sentinel"):      ("microsoft_sentinel", "siem"),
    ("siem", "generic"):       ("siem",               "siem"),
}


def _resolve_node(category: str, vendor: str) -> TopologyNode | None:
    """Resolve a (category, vendor) pair to a TopologyNode."""
    tier = CATEGORY_TO_TIER.get(category)
    if not tier:
        return None

    key = (category, vendor.lower())
    if key not in _PRODUCT_SOURCE_MAP:
        # Try generic fallback for this category
        key = (category, "generic")

    if key not in _PRODUCT_SOURCE_MAP:
        return None

    source_id, log_source = _PRODUCT_SOURCE_MAP[key]
    product_id = f"{vendor.lower()}_{category}"
    return TopologyNode(
        product_id=product_id,
        category=category,
        tier=tier,
        source_id=source_id,
        log_source=log_source,
        vendor=vendor.lower(),
    )


# ── Convenience API ───────────────────────────────────────────────────────────

def build_topology(products: dict[str, str]) -> TopologyGraph:
    """Build a TopologyGraph from environment product selections."""
    return TopologyGraph.from_products(products)


def get_observer_log_sources(
    technique_id: str,
    products: dict[str, str],
) -> list[str]:
    """One-shot: return log_source strings that should emit for a technique.

    Args:
        technique_id: MITRE ATT&CK ID (e.g. "T1059.001")
        products: Environment product selections

    Returns:
        List of log_source strings, e.g. ["edr_endpoint", "sysmon"]
    """
    graph = build_topology(products)
    return graph.resolve_log_sources(technique_id)


def topology_aware_event_filter(
    events: list[dict],
    technique_id: str,
    products: dict[str, str],
) -> list[dict]:
    """Filter a list of events to only those from valid observer sources.

    Use this as a post-generation pass to discard events from products
    that don't have line-of-sight to the technique being simulated.

    Args:
        events: List of generated event dicts with 'source_type' key.
        technique_id: MITRE ATT&CK ID.
        products: Environment product selections.

    Returns:
        Filtered list containing only topology-valid events.
    """
    if not products:
        return events

    graph = build_topology(products)
    valid_log_sources = set(graph.resolve_log_sources(technique_id))

    if not valid_log_sources:
        return events

    filtered = []
    for ev in events:
        src = ev.get("source_type", ev.get("log_source", ""))
        if not src or src in valid_log_sources:
            filtered.append(ev)
        elif ev.get("_benign"):
            # Benign events are topology-independent (always include baseline)
            filtered.append(ev)

    return filtered if filtered else events  # Never return empty
