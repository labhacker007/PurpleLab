"""PurpleLab MCP Server — JSON-RPC 2.0 over HTTP.

Exposes PurpleLab's security simulation capabilities as MCP tools that
Joti (and any other MCP client) can call for SOC automation, purple team
exercises, and incident response testing.

Protocol:
  POST /api/v2/mcp
  Content-Type: application/json

  {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
  {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "edr_isolate_host", "arguments": {...}}}

Authentication:
  X-API-Key header (matches PURPLELAB_MCP_API_KEY env var, or "purplelab-dev-key" in dev)
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_MCP_API_KEY = os.getenv("PURPLELAB_MCP_API_KEY", "purplelab-dev-key")


# ── Tool registry ──────────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    # ── EDR ──────────────────────────────────────────────────────────────────
    {
        "name": "edr_get_detections",
        "description": "Fetch EDR detections/alerts from the simulated endpoint fleet. Returns recent detections with hostname, severity, technique, and payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Filter by severity"},
                "limit": {"type": "integer", "default": 20, "description": "Max detections to return"},
            },
        },
    },
    {
        "name": "edr_list_devices",
        "description": "List all managed endpoints in the simulated EDR environment with status, OS, vendor, and IP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["online", "isolated", "offline"], "description": "Filter by device status"},
                "edr_vendor": {"type": "string", "enum": ["crowdstrike", "sentinelone", "defender"], "description": "Filter by EDR vendor"},
            },
        },
    },
    {
        "name": "edr_isolate_host",
        "description": "Isolate (quarantine) a simulated endpoint from the network. Use for active threat containment. Returns action_id for audit trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Device UUID or hostname"},
                "reason": {"type": "string", "description": "Reason for isolation (for audit log)"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["device_id"],
        },
    },
    {
        "name": "edr_release_host",
        "description": "Release a simulated endpoint from network isolation (restore connectivity).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Device UUID or hostname"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
                "reason": {"type": "string"},
            },
            "required": ["device_id"],
        },
    },
    {
        "name": "edr_block_hash",
        "description": "Block a file by SHA-256 hash across the simulated EDR fleet. Prevents execution of the file on all managed endpoints.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sha256": {"type": "string", "description": "SHA-256 hash of the file to block"},
                "filename": {"type": "string", "description": "Optional filename for context"},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["sha256"],
        },
    },
    {
        "name": "edr_block_process",
        "description": "Block a process name from executing on the simulated EDR fleet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "process_name": {"type": "string", "description": "Process name (e.g. mimikatz.exe)"},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["process_name"],
        },
    },
    {
        "name": "edr_hunt_ioc",
        "description": "Hunt for an IOC across the simulated endpoint fleet. Searches recent event logs and returns hits with hostname and context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ioc_type": {"type": "string", "enum": ["ip", "domain", "hash", "filename", "process", "username"], "description": "IOC type"},
                "ioc_value": {"type": "string", "description": "The IOC value to hunt for"},
                "time_range_hours": {"type": "integer", "default": 24, "description": "How far back to search (hours)"},
            },
            "required": ["ioc_type", "ioc_value"],
        },
    },
    {
        "name": "edr_run_command",
        "description": "Execute a live response / RTR command on a simulated endpoint. Returns stdout, stderr, exit code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "device_id": {"type": "string", "description": "Device UUID or hostname"},
                "command": {"type": "string", "description": "Shell command to execute (e.g. 'ps aux', 'netstat -an')"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["device_id", "command"],
        },
    },
    # ── SIEM ─────────────────────────────────────────────────────────────────
    {
        "name": "siem_get_alerts",
        "description": "Fetch recent SIEM alerts from the simulated environment. Returns alerts with severity, technique, source, and timestamp.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "limit": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "siem_search_events",
        "description": "Search simulated SIEM event logs. Query matches against event titles, hostnames, IPs, and payloads.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term (hostname, IP, username, technique, etc.)"},
                "time_range_hours": {"type": "integer", "default": 24},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["query"],
        },
    },
    {
        "name": "siem_deploy_rule",
        "description": "Deploy a detection rule (Sigma/SPL/KQL) into the simulated SIEM environment for validation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_content": {"type": "string", "description": "Rule text (Sigma YAML, SPL, or KQL)"},
                "rule_format": {"type": "string", "enum": ["sigma", "spl", "kql", "esql", "auto"], "default": "auto"},
                "rule_name": {"type": "string"},
            },
            "required": ["rule_content"],
        },
    },
    # ── Identity ─────────────────────────────────────────────────────────────
    {
        "name": "identity_list_users",
        "description": "List simulated directory users from Okta/Entra. Filter by status, department, or risk level.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["active", "locked", "disabled", "suspended"]},
                "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "search": {"type": "string", "description": "Search by username or email"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "identity_lock_user",
        "description": "Lock a user account in the simulated identity provider (Okta lockout / AD account lockout). Blocks authentication.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User UUID, username, or email"},
                "reason": {"type": "string", "description": "Reason for lockout (for audit log)"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "identity_revoke_sessions",
        "description": "Revoke all active sessions for a user (Okta session clear / Entra token revocation). Forces re-authentication.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User UUID, username, or email"},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "identity_disable_user",
        "description": "Disable (deactivate) a user account — stronger than lock. Removes access to all systems.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "identity_force_mfa_reset",
        "description": "Force MFA re-enrollment for a user. Clears all enrolled MFA factors.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["user_id"],
        },
    },
    # ── Network ───────────────────────────────────────────────────────────────
    {
        "name": "network_block_ip",
        "description": "Block an IP address on the simulated firewall (Palo Alto / Cloudflare Gateway). Supports inbound, outbound, or both directions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 or IPv6 address to block"},
                "direction": {"type": "string", "enum": ["inbound", "outbound", "both"], "default": "both"},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
                "duration_hours": {"type": "integer", "description": "Auto-expire block after N hours. Omit for permanent."},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "network_unblock_ip",
        "description": "Remove an IP address from the block list on the simulated firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "network_block_domain",
        "description": "Block a domain on the simulated DNS filter / web proxy (Zscaler / Cisco Umbrella). Optionally blocks all subdomains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "category": {"type": "string", "enum": ["malicious", "phishing", "c2", "spam", "cryptomining"], "default": "malicious"},
                "block_subdomains": {"type": "boolean", "default": True},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "network_unblock_domain",
        "description": "Remove a domain from the DNS/proxy block list.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "network_block_hash",
        "description": "Block a file hash at the network gateway layer (Palo Alto WildFire custom block).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sha256": {"type": "string"},
                "filename": {"type": "string"},
                "reason": {"type": "string"},
                "requester": {"type": "string", "default": "joti-soc-agent"},
            },
            "required": ["sha256"],
        },
    },
    {
        "name": "network_get_blocks",
        "description": "List all active network-layer blocks (IPs, domains, URLs, hashes) across all simulated network controls.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "block_type": {"type": "string", "enum": ["ip", "domain", "url", "hash", "hash_net"]},
                "limit": {"type": "integer", "default": 100},
            },
        },
    },
    # ── Platform ──────────────────────────────────────────────────────────────
    {
        "name": "get_action_log",
        "description": "Retrieve the containment action audit log. Shows all isolation, block, and identity actions taken.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_type": {"type": "string", "description": "Filter by action type (e.g. isolate_host, block_ip, lock_user)"},
                "target_type": {"type": "string", "enum": ["endpoint", "user", "ip", "domain", "hash", "process"]},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "get_environment_status",
        "description": "Get the current status of the PurpleLab simulation environment: active sessions, rule count, detection count, block lists, and platform health.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    # ── CMDB ─────────────────────────────────────────────────────────────────
    {
        "name": "cmdb_list_people",
        "description": "List employees from the enterprise CMDB/HR directory. Returns name, title, department, location, manager, employment type, and status. Use to look up who owns an asset or product.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "department": {"type": "string", "description": "Filter by department (Engineering, Security, Infrastructure, Product, Finance, HR, Legal, Marketing, Sales, Executive)"},
                "status": {"type": "string", "enum": ["active", "inactive"], "description": "Filter by employment status"},
                "employment_type": {"type": "string", "enum": ["employee", "contractor"], "description": "Filter by employment type"},
                "search": {"type": "string", "description": "Search by name, email, or title"},
                "limit": {"type": "integer", "default": 50, "description": "Max results"},
            },
        },
    },
    {
        "name": "cmdb_get_person",
        "description": "Get full profile of an employee including their assigned hardware assets, products they own/lead, department, manager chain, and contact info.",
        "inputSchema": {
            "type": "object",
            "required": ["person_id"],
            "properties": {
                "person_id": {"type": "string", "description": "UUID of the person"},
            },
        },
    },
    {
        "name": "cmdb_list_assets",
        "description": "List hardware assets from the enterprise CMDB: laptops, desktops, servers, mobile devices, tablets, and network equipment. Includes assigned owner, OS, status, and location.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_type": {"type": "string", "enum": ["laptop", "desktop", "server", "mobile", "tablet", "network"], "description": "Filter by asset type"},
                "status": {"type": "string", "enum": ["assigned", "in_storage", "decommissioned"], "description": "Filter by status"},
                "os_type": {"type": "string", "description": "Filter by OS (e.g. macOS, Windows, Linux, RHEL)"},
                "search": {"type": "string", "description": "Search by asset tag, make, model, or serial number"},
                "limit": {"type": "integer", "default": 50, "description": "Max results"},
            },
        },
    },
    {
        "name": "cmdb_get_asset",
        "description": "Get full detail on a hardware asset including assigned user, vulnerabilities, specs, purchase date, and warranty.",
        "inputSchema": {
            "type": "object",
            "required": ["asset_id"],
            "properties": {
                "asset_id": {"type": "string", "description": "UUID of the asset"},
            },
        },
    },
    # ── Product Registry ──────────────────────────────────────────────────────
    {
        "name": "product_registry_list_products",
        "description": "List all products in the enterprise product registry — both internally developed services and vendor/SaaS tools. Returns ownership, tier, data classification, tech stack, and cloud account.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "product_type": {"type": "string", "enum": ["internal", "vendor"], "description": "Filter by product type"},
                "tier": {"type": "string", "enum": ["tier1_critical", "tier2_important", "tier3_standard"], "description": "Filter by business tier"},
                "data_classification": {"type": "string", "enum": ["public", "internal", "confidential", "restricted"], "description": "Filter by data classification"},
                "status": {"type": "string", "enum": ["active", "deprecated", "decommissioned"], "description": "Filter by status"},
                "search": {"type": "string", "description": "Search by name, slug, or vendor"},
                "limit": {"type": "integer", "default": 50, "description": "Max results"},
            },
        },
    },
    {
        "name": "product_registry_get_product",
        "description": "Get full detail on a product including owner/tech_lead contacts, cloud account, deployment info (servers, containers, k8s namespace), compliance frameworks, SLA targets, open vulnerabilities count, and CSPM findings.",
        "inputSchema": {
            "type": "object",
            "required": ["product_id"],
            "properties": {
                "product_id": {"type": "string", "description": "UUID of the product"},
            },
        },
    },
    {
        "name": "product_registry_list_cloud_accounts",
        "description": "List enterprise cloud accounts (AWS, Azure, GCP) with account IDs, owners, monthly cost, security posture flags (CloudTrail, Security Hub, MFA), and region coverage.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Filter by cloud provider"},
                "account_type": {"type": "string", "enum": ["production", "staging", "development", "security", "dr", "sandbox"], "description": "Filter by account type"},
                "status": {"type": "string", "enum": ["active", "suspended", "closed"], "description": "Filter by status"},
                "limit": {"type": "integer", "default": 20, "description": "Max results"},
            },
        },
    },
    # ── Vulnerability Management ──────────────────────────────────────────────
    {
        "name": "vm_get_vulnerabilities",
        "description": "Get vulnerabilities (CVEs) affecting a specific hardware asset or product. Returns CVE details, CVSS score, EPSS score, CISA KEV status, and remediation status per asset.",
        "inputSchema": {
            "type": "object",
            "required": ["asset_type", "asset_id"],
            "properties": {
                "asset_type": {"type": "string", "enum": ["hardware", "product"], "description": "Whether the asset is a hardware device or a software product"},
                "asset_id": {"type": "string", "description": "UUID of the hardware asset or product"},
                "status": {"type": "string", "enum": ["open", "in_remediation", "resolved", "accepted_risk"], "description": "Filter by remediation status"},
            },
        },
    },
    {
        "name": "vm_get_critical_findings",
        "description": "Get critical and high severity open vulnerabilities across the entire org, optionally filtered by product or CISA KEV status. Returns CVE ID, CVSS, EPSS, affected asset count, and overdue status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "default": "critical", "description": "Minimum severity filter"},
                "cisa_kev_only": {"type": "boolean", "default": False, "description": "Only return CISA KEV (Known Exploited Vulnerabilities)"},
                "overdue_only": {"type": "boolean", "default": False, "description": "Only return findings past SLA due date"},
                "limit": {"type": "integer", "default": 30, "description": "Max results"},
            },
        },
    },
    {
        "name": "vm_get_summary",
        "description": "Get org-wide vulnerability management posture: total open findings by severity, CISA KEV count, exploit-available count, overdue count, MTTR trend, and top 5 most-vulnerable products and assets.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    # ── CSPM ──────────────────────────────────────────────────────────────────
    {
        "name": "cspm_get_findings",
        "description": "Get cloud security posture findings (misconfigurations) across cloud accounts. Returns check title, severity, resource ID, cloud provider, section, and remediation steps.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Filter by cloud provider"},
                "account_id": {"type": "string", "description": "Filter by cloud account UUID"},
                "status": {"type": "string", "enum": ["open", "resolved", "suppressed", "in_remediation"], "description": "Filter by status (default: open)"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Filter by severity"},
                "framework": {"type": "string", "description": "Filter by compliance framework (CIS AWS, CIS Azure, CIS GCP, SOC2, NIST CSF, PCI DSS)"},
                "section": {"type": "string", "description": "Filter by check section (IAM, Networking, Logging, S3, RDS, etc.)"},
                "limit": {"type": "integer", "default": 50, "description": "Max results"},
            },
        },
    },
    {
        "name": "cspm_get_summary",
        "description": "Get org-wide cloud security posture: open findings by severity and section, compliance score per framework (CIS AWS/Azure/GCP, SOC2, NIST, PCI DSS), and top 5 failing checks.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "cspm_get_critical_findings",
        "description": "Get critical and high severity open cloud misconfigurations. Particularly useful for finding exposed resources like open security groups (SSH/RDP to 0.0.0.0/0), disabled MFA, public S3 buckets, and missing CloudTrail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Filter by cloud provider"},
                "section": {"type": "string", "description": "Filter by section (IAM, Networking, Logging, Storage, etc.)"},
                "limit": {"type": "integer", "default": 30, "description": "Max results"},
            },
        },
    },
    # ── Simulation control tools ────────────────────────────────────────────
    {
        "name": "simulation_run_scenario",
        "description": (
            "Start a named attack scenario on an existing simulation session. "
            "The scenario injects a predefined set of MITRE techniques and generates "
            "realistic events for each. Use this to trigger a specific threat scenario "
            "(e.g. ransomware, credential-access, lateral-movement) within a running session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session to inject into"},
                "scenario": {
                    "type": "string",
                    "enum": ["ransomware", "credential_access", "lateral_movement", "data_exfiltration",
                             "initial_access_phishing", "supply_chain", "insider_threat"],
                    "description": "Named attack scenario to simulate",
                },
                "event_count": {"type": "integer", "default": 20, "description": "Number of events to generate for the scenario"},
            },
            "required": ["session_id", "scenario"],
        },
    },
    {
        "name": "simulation_inject_alert",
        "description": (
            "Inject a custom alert event into a simulation session. "
            "Use this to test alert triage workflows — the alert appears in the "
            "event stream and is processed by the EDR/Identity/SIEM state machines. "
            "Useful for testing SOAR playbook triggers without running a full scenario."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session"},
                "title": {"type": "string", "description": "Alert title"},
                "technique_id": {"type": "string", "description": "MITRE ATT&CK technique ID (e.g. T1059.001)"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "default": "high"},
                "source_type": {"type": "string", "default": "edr", "description": "Log source type"},
                "hostname": {"type": "string", "description": "Hostname to associate with the alert"},
                "extra_payload": {"type": "object", "description": "Additional fields to include in the alert payload"},
            },
            "required": ["session_id", "title", "technique_id"],
        },
    },
    {
        "name": "simulation_timeline_search",
        "description": (
            "Search simulated events within a session by time range, technique ID, "
            "severity, source type, or keyword. Returns matching events with their "
            "OCSF-normalized fields. Essential for hunting across a simulation to "
            "verify detection coverage or investigate an attack chain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session to search"},
                "technique_id": {"type": "string", "description": "Filter by MITRE technique ID (e.g. T1059.001)"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Filter by severity"},
                "source_type": {"type": "string", "description": "Filter by source type (edr, firewall, auth, etc.)"},
                "keyword": {"type": "string", "description": "Keyword to search in event titles and payload fields"},
                "start_minutes_ago": {"type": "integer", "default": 60, "description": "Search events from N minutes ago"},
                "limit": {"type": "integer", "default": 50, "description": "Maximum events to return"},
                "attack_only": {"type": "boolean", "default": False, "description": "If true, return only attack events (exclude benign baseline)"},
            },
            "required": ["session_id"],
        },
    },
    # ── SOAR action execution ─────────────────────────────────────────────────
    {
        "name": "soar_execute_action",
        "description": (
            "Execute a SOAR response action against a simulation session. "
            "Actions update the state machines (EDR, Identity, Firewall), generate "
            "confirmation events, and write an audit record. Use this to test SOAR playbooks "
            "without touching production — isolate a host, block an IOC, disable an account, "
            "reset a password, kill a process, or quarantine a file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session"},
                "action_type": {
                    "type": "string",
                    "enum": ["isolate_host", "release_host", "disable_account", "enable_account",
                             "reset_password", "block_ioc", "unblock_ioc", "kill_process",
                             "quarantine_file", "deploy_detection", "inject_alert"],
                    "description": "The SOAR action to execute",
                },
                "hostname": {"type": "string", "description": "Target hostname (for host actions)"},
                "username": {"type": "string", "description": "Target username (for account actions)"},
                "ioc_type": {"type": "string", "enum": ["ip", "ipv4", "domain", "sha256", "md5", "url"], "description": "IOC type (for block_ioc)"},
                "ioc_value": {"type": "string", "description": "IOC value to block (for block_ioc)"},
                "process_name": {"type": "string", "description": "Process name to kill (for kill_process)"},
                "sha256": {"type": "string", "description": "File hash to quarantine (for quarantine_file)"},
                "actor": {"type": "string", "default": "joti_soar", "description": "Who is executing the action"},
            },
            "required": ["session_id", "action_type"],
        },
    },
    # ── SIEM search ───────────────────────────────────────────────────────────
    {
        "name": "siem_search",
        "description": (
            "Run a SPL, KQL, AQL, or XQL search query against simulated events in a session. "
            "Use this to hunt across the simulation, verify which events were generated, or "
            "test detection queries before deploying to production SIEM. "
            "Supports simplified query syntax — keywords, sourcetype, host, and technique filters."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session"},
                "query": {"type": "string", "description": "The search query (SPL, KQL, AQL, or XQL)"},
                "query_language": {"type": "string", "enum": ["spl", "kql", "aql", "xql", "eql"], "default": "spl"},
                "earliest_time": {"type": "string", "default": "-60m", "description": "Time range start: -60m, -2h, -1d"},
                "limit": {"type": "integer", "default": 50, "description": "Max events to return"},
            },
            "required": ["session_id", "query"],
        },
    },
    # ── Detection deployment + validation ─────────────────────────────────────
    {
        "name": "siem_deploy_detection",
        "description": (
            "Deploy a Sigma detection rule (or SPL/KQL query) to the simulated SIEM for a session, "
            "then optionally run validation to check if it would have fired against existing events. "
            "Returns: fired=true/false, matched event count, false positive count, and MITRE technique coverage. "
            "Use this to validate Sigma rules before pushing to production."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session to test against"},
                "name": {"type": "string", "description": "Name for this detection rule"},
                "sigma_yaml": {"type": "string", "description": "Sigma YAML rule content"},
                "query_spl": {"type": "string", "description": "Splunk SPL query (alternative to Sigma)"},
                "query_kql": {"type": "string", "description": "KQL query (alternative to Sigma)"},
                "technique_ids": {"type": "array", "items": {"type": "string"}, "description": "MITRE technique IDs this detection covers"},
                "run_validation": {"type": "boolean", "default": True, "description": "Immediately test against existing events"},
            },
            "required": ["session_id", "name"],
        },
    },
    # ── Tabletop exercises ────────────────────────────────────────────────────
    {
        "name": "tabletop_create",
        "description": (
            "Create a tabletop exercise from a scenario template. Available scenarios: "
            "ransomware_response (6 phases, 90min), apt_infiltration (5 phases, 75min), "
            "insider_threat (5 phases, 60min), supply_chain_compromise (6 phases). "
            "Returns an exercise ID and first inject narrative."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scenario_key": {"type": "string", "enum": ["ransomware_response", "apt_infiltration", "insider_threat", "supply_chain_compromise", "bec_wire_fraud"]},
                "session_id": {"type": "string", "description": "Link to a simulation session for realistic telemetry"},
                "team_size": {"type": "integer", "default": 4},
                "name": {"type": "string", "description": "Custom exercise name"},
            },
            "required": ["scenario_key"],
        },
    },
    {
        "name": "tabletop_respond",
        "description": (
            "Submit a team decision for the current tabletop exercise phase. "
            "Provide the decision_index (0-based index into the decisions list) and rationale. "
            "Returns score for this phase and the next inject narrative (or final AAR if complete)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "exercise_id": {"type": "string", "description": "UUID of the tabletop exercise"},
                "decision_index": {"type": "integer", "description": "0-based index of the chosen decision"},
                "rationale": {"type": "string", "description": "Team's reasoning for this decision"},
            },
            "required": ["exercise_id", "decision_index"],
        },
    },
    {
        "name": "tabletop_report",
        "description": (
            "Get the after-action report (AAR) for a completed tabletop exercise. "
            "Returns score, performance rating, per-phase results (correct/incorrect, recommended decision), "
            "strengths identified, gaps, and improvement recommendations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "exercise_id": {"type": "string", "description": "UUID of the completed tabletop exercise"},
            },
            "required": ["exercise_id"],
        },
    },
    # ── Environment + detection coverage tools (NEW) ─────────────────────────
    {
        "name": "env_get_topology",
        "description": (
            "Get the network topology graph for a simulation session's environment. "
            "Returns nodes (hosts, services, network segments) and edges (connections). "
            "Use this to understand which assets are in scope, their roles, and how they "
            "are connected — essential for verifying detection placement and lateral movement paths."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "logs_search_timeline",
        "description": (
            "Search simulated log events within a session using timeline filters. "
            "Filter by MITRE technique, severity, source type (firewall/dns/cloudtrail/edr), "
            "or keyword. Returns events in chronological order with OCSF-normalized fields. "
            "Use this to trace attack chains or verify that specific TTPs generated logs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session"},
                "technique_id": {"type": "string", "description": "MITRE technique ID (e.g. T1568.002)"},
                "source_type": {"type": "string", "description": "Log source (firewall, dns, cloudtrail, edr, auth, sysmon, windows_eventlog)"},
                "keyword": {"type": "string", "description": "Keyword to search in event titles and payload fields"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "start_minutes_ago": {"type": "integer", "default": 120, "description": "Search from N minutes ago"},
                "attack_only": {"type": "boolean", "default": False, "description": "Return only attack events (exclude benign baseline)"},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "detection_test_rule",
        "description": (
            "Test a Sigma YAML, SPL, or KQL detection rule against events already in a simulation session. "
            "Returns whether the rule fired, how many events matched, estimated false positive rate, "
            "and which MITRE techniques were covered. Use this to validate detection logic before "
            "deploying to a production SIEM."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session to test against"},
                "rule_name": {"type": "string", "description": "Name for this rule (for reference)"},
                "sigma_yaml": {"type": "string", "description": "Sigma YAML rule content"},
                "query_spl": {"type": "string", "description": "Splunk SPL query (alternative to Sigma)"},
                "query_kql": {"type": "string", "description": "KQL query (alternative to Sigma)"},
                "technique_ids": {"type": "array", "items": {"type": "string"}, "description": "MITRE IDs this rule targets"},
            },
            "required": ["session_id", "rule_name"],
        },
    },
    {
        "name": "detection_get_coverage",
        "description": (
            "Get the MITRE ATT&CK detection coverage heatmap for rules deployed in a session. "
            "Returns per-technique coverage status (detected/not detected), rule count per technique, "
            "total deployed rules, and a list of uncovered techniques. "
            "Use this to identify detection gaps after a purple team exercise."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the simulation session (optional — returns org-wide if omitted)"},
            },
        },
    },
    # ── Vendor persona management ─────────────────────────────────────────────
    {
        "name": "vendor_list_personas",
        "description": (
            "List all available vendor product personas that PurpleLab can emulate. "
            "Returns personas grouped by category (EDR, SIEM, IdP, Firewall) with their "
            "supported capabilities and API endpoint prefixes. Use this to discover "
            "what product stacks are available to assign to a simulation environment."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "enum": ["edr", "siem", "idp", "firewall", "all"], "default": "all"},
            },
        },
    },
    # ── Vulnerability Management ──────────────────────────────────────────────
    {
        "name": "vm_get_summary",
        "description": (
            "Fetch the org-wide vulnerability posture snapshot from PurpleLab VM: "
            "total open CVEs by severity, CISA KEV count, exploit-available count, "
            "mean time to remediate (MTTR), top 5 affected products, and top 5 critical assets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "vm_list_findings",
        "description": (
            "List CVE findings from PurpleLab VM. Filter by severity or status. "
            "Returns CVE ID, title, severity, CVSS score, affected asset, KEV/exploit flags, and status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Filter by CVE severity",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "resolved", "false_positive"],
                    "description": "Filter by finding status (default: open)",
                },
                "limit": {"type": "integer", "default": 50, "description": "Max findings to return (max 200)"},
                "skip": {"type": "integer", "default": 0, "description": "Offset for pagination"},
            },
        },
    },
    {
        "name": "vm_list_critical_vulns",
        "description": (
            "Quick shortcut: list all CRITICAL severity open CVE findings from PurpleLab VM. "
            "Useful for prioritised triage — returns top critical CVEs with asset and exploit info."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20, "description": "Max results"},
            },
        },
    },
]

# Build a name → definition index for fast lookup
TOOL_INDEX: dict[str, dict] = {t["name"]: t for t in TOOLS}


# ── Tool handlers ─────────────────────────────────────────────────────────────

def _action_result(success: bool, action: str, target: str, detail: dict | None = None) -> dict:
    """Standardized response for MCP action tools (isolate, block, kill, etc.)."""
    from datetime import datetime as _dt
    return {
        "success": success,
        "action": action,
        "target": target,
        "detail": detail or {},
        "timestamp": _dt.utcnow().isoformat(),
    }


async def _call_tool(name: str, arguments: dict[str, Any]) -> Any:
    """Route a tool call to the appropriate API handler and return the result."""
    import httpx

    base = "http://localhost:8000/api/v2"

    if name == "edr_get_detections":
        params = {}
        if "severity" in arguments:
            params["severity"] = arguments["severity"]
        params["limit"] = arguments.get("limit", 20)
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/edr/detections", params=params, timeout=15)
            return r.json()

    elif name == "edr_list_devices":
        params = {k: v for k, v in arguments.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/edr/devices", params=params, timeout=15)
            return r.json()

    elif name == "edr_isolate_host":
        device_id = arguments["device_id"]
        body = {"reason": arguments.get("reason", ""), "requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/edr/devices/{device_id}/isolate", json=body, timeout=15)
            return _action_result(r.status_code < 300, "isolate", str(device_id), r.json())

    elif name == "edr_release_host":
        device_id = arguments["device_id"]
        params = {"requester": arguments.get("requester", "joti-soc-agent"), "reason": arguments.get("reason", "")}
        async with httpx.AsyncClient() as c:
            r = await c.delete(f"{base}/edr/devices/{device_id}/isolate", params=params, timeout=15)
            return r.json()

    elif name == "edr_block_hash":
        body = {
            "sha256": arguments["sha256"],
            "filename": arguments.get("filename"),
            "reason": arguments.get("reason", ""),
            "requester": arguments.get("requester", "joti-soc-agent"),
        }
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/edr/block/hash", json=body, timeout=15)
            return _action_result(r.status_code < 300, "block_hash", arguments.get("sha256", ""), r.json())

    elif name == "edr_block_process":
        body = {
            "process_name": arguments["process_name"],
            "reason": arguments.get("reason", ""),
            "requester": arguments.get("requester", "joti-soc-agent"),
        }
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/edr/block/process", json=body, timeout=15)
            return r.json()

    elif name == "edr_hunt_ioc":
        body = {
            "ioc_type": arguments["ioc_type"],
            "ioc_value": arguments["ioc_value"],
            "time_range_hours": arguments.get("time_range_hours", 24),
        }
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/edr/hunt", json=body, timeout=15)
            return r.json()

    elif name == "edr_run_command":
        device_id = arguments["device_id"]
        body = {"command": arguments["command"], "requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/edr/devices/{device_id}/command", json=body, timeout=30)
            return r.json()

    elif name == "siem_get_alerts":
        params = {}
        if "severity" in arguments:
            params["severity"] = arguments["severity"]
        params["limit"] = arguments.get("limit", 20)
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/edr/detections", params=params, timeout=15)
            data = r.json()
            # Reformat as SIEM-style alerts
            data["alerts"] = data.pop("detections", [])
            return data

    elif name == "siem_search_events":
        # Search generated event data — queries the GeneratedEvent table (populated by
        # simulation sessions) and falls back to the synthetic ECS detections endpoint
        # (which always has seed data even without a running session).
        from backend.db.session import async_session
        from backend.db.models import GeneratedEvent
        from sqlalchemy import select as _select

        query_str = (arguments.get("query") or "").lower()
        limit = int(arguments.get("limit") or 50)
        hits = []

        try:
            async with async_session() as sess:
                stmt = _select(GeneratedEvent).order_by(GeneratedEvent.created_at.desc()).limit(limit * 10)
                result = await sess.execute(stmt)
                all_events = result.scalars().all()

            for e in all_events:
                text_repr = str(e.payload or {}) + " " + (e.title or "")
                if not query_str or query_str in text_repr.lower():
                    hits.append({
                        "id": str(e.id),
                        "title": e.title,
                        "severity": e.severity,
                        "product_type": e.product_type,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                        "payload": e.payload or {},
                        "source": "generated_events",
                    })
        except Exception as _exc:
            logger.warning("siem_search_events_db_error: %s", _exc)

        # Fallback: if DB has < 3 matches, also search the ECS detections endpoint
        # (returns both real GeneratedEvents and synthetic seed data)
        if len(hits) < 3:
            try:
                async with httpx.AsyncClient() as c:
                    r = await c.get(f"{base}/edr/detections", params={"limit": limit * 2}, timeout=15)
                    detections = r.json().get("detections", [])
                for det in detections:
                    text_repr = str(det).lower()
                    if not query_str or query_str in text_repr:
                        # Avoid duplicates already in hits
                        det_id = det.get("detection_id", "")
                        if not any(h.get("id") == det_id for h in hits):
                            hits.append({
                                "id": det_id,
                                "title": det.get("title"),
                                "severity": det.get("severity"),
                                "product_type": det.get("product_type"),
                                "created_at": det.get("timestamp"),
                                "payload": det.get("raw_payload") or {},
                                "source": "edr_detections",
                                "hostname": det.get("hostname"),
                                "technique": det.get("technique"),
                            })
            except Exception as _exc2:
                logger.warning("siem_search_events_fallback_error: %s", _exc2)

        hits = hits[:limit]
        return {"query": arguments.get("query"), "results": hits, "total": len(hits)}

    elif name == "siem_deploy_rule":
        # Persist to ImportedRule DB table so rule_id is stable and retrievable
        from backend.db.session import async_session
        from backend.db.models import ImportedRule
        import uuid as _uuid

        rule_name = arguments.get("rule_name") or f"rule_{_uuid.uuid4().hex[:8]}"
        try:
            async with async_session() as sess:
                rule = ImportedRule(
                    name=rule_name,
                    language=arguments.get("rule_format") or arguments.get("language") or "sigma",
                    source_query=arguments.get("rule_content") or arguments.get("query") or arguments.get("sigma_yaml") or "",
                    severity=arguments.get("severity") or "medium",
                    mitre_techniques=arguments.get("technique_ids") or arguments.get("mitre_techniques") or [],
                    enabled=True,
                    source="joti_pipeline",
                    metadata_={"deployed_by": "joti", "org_id": arguments.get("org_id")},
                )
                sess.add(rule)
                await sess.commit()
                await sess.refresh(rule)
                rule_id = str(rule.id)
            return {
                "success": True,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "platform": "purplelab",
                "status": "active",
            }
        except Exception as _exc:
            logger.warning("siem_deploy_rule_db_error: %s", _exc)
            return {"success": False, "error": str(_exc), "rule_name": rule_name}

    elif name == "identity_list_users":
        params = {k: v for k, v in {
            "status": arguments.get("status"),
            "risk_level": arguments.get("risk_level"),
            "search": arguments.get("search"),
            "limit": arguments.get("limit", 50),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/identity/users", params=params, timeout=15)
            return r.json()

    elif name == "identity_lock_user":
        body = {"reason": arguments.get("reason", ""), "requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/identity/users/{arguments['user_id']}/lock", json=body, timeout=15)
            return r.json()

    elif name == "identity_revoke_sessions":
        body = {"reason": arguments.get("reason", ""), "requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/identity/users/{arguments['user_id']}/revoke-sessions", json=body, timeout=15)
            return r.json()

    elif name == "identity_disable_user":
        body = {"reason": arguments.get("reason", ""), "requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/identity/users/{arguments['user_id']}/disable", json=body, timeout=15)
            return r.json()

    elif name == "identity_force_mfa_reset":
        body = {"reason": arguments.get("reason", ""), "requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/identity/users/{arguments['user_id']}/force-mfa-reset", json=body, timeout=15)
            return r.json()

    elif name == "network_block_ip":
        body = {
            "ip": arguments["ip"],
            "direction": arguments.get("direction", "both"),
            "reason": arguments.get("reason", ""),
            "requester": arguments.get("requester", "joti-soc-agent"),
            "duration_hours": arguments.get("duration_hours"),
        }
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/network/block/ip", json=body, timeout=15)
            return r.json()

    elif name == "network_unblock_ip":
        params = {"requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.delete(f"{base}/network/block/ip/{arguments['ip']}", params=params, timeout=15)
            return r.json()

    elif name == "network_block_domain":
        body = {
            "domain": arguments["domain"],
            "category": arguments.get("category", "malicious"),
            "block_subdomains": arguments.get("block_subdomains", True),
            "reason": arguments.get("reason", ""),
            "requester": arguments.get("requester", "joti-soc-agent"),
        }
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/network/block/domain", json=body, timeout=15)
            return r.json()

    elif name == "network_unblock_domain":
        params = {"requester": arguments.get("requester", "joti-soc-agent")}
        async with httpx.AsyncClient() as c:
            r = await c.delete(f"{base}/network/block/domain/{arguments['domain']}", params=params, timeout=15)
            return r.json()

    elif name == "network_block_hash":
        body = {
            "sha256": arguments["sha256"],
            "filename": arguments.get("filename"),
            "reason": arguments.get("reason", ""),
            "requester": arguments.get("requester", "joti-soc-agent"),
        }
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/network/block/hash", json=body, timeout=15)
            return r.json()

    elif name == "network_get_blocks":
        params = {k: v for k, v in {
            "block_type": arguments.get("block_type"),
            "limit": arguments.get("limit", 100),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/network/blocks", params=params, timeout=15)
            return r.json()

    elif name == "get_action_log":
        params = {k: v for k, v in {
            "action_type": arguments.get("action_type"),
            "target_type": arguments.get("target_type"),
            "limit": arguments.get("limit", 50),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/edr/actions", params=params, timeout=15)
            return r.json()

    elif name == "get_environment_status":
        async with httpx.AsyncClient() as c:
            health = (await c.get("http://localhost:8000/health", timeout=5)).json()
            rules = (await c.get(f"{base}/rules/stats", timeout=10)).json()
            detections = (await c.get(f"{base}/edr/detections?limit=1", timeout=10)).json()
            blocks = (await c.get(f"{base}/network/blocks/stats", timeout=10)).json()
            devices = (await c.get(f"{base}/edr/devices?limit=1", timeout=10)).json()
            users = (await c.get(f"{base}/identity/users?limit=1", timeout=10)).json()
        return {
            "platform": "purplelab",
            "version": "2.0.0",
            "health": health,
            "rules": rules,
            "detections": {"total": detections.get("total", 0)},
            "blocks": blocks,
            "managed_endpoints": devices.get("total", 0),
            "simulated_users": users.get("total", 0),
        }

    # ── CMDB tools ────────────────────────────────────────────────────────────
    elif name == "cmdb_list_people":
        params = {k: v for k, v in {
            "department": arguments.get("department"),
            "status": arguments.get("status"),
            "employment_type": arguments.get("employment_type"),
            "search": arguments.get("search"),
            "limit": arguments.get("limit", 50),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/cmdb/people", params=params, timeout=15)
            return r.json()

    elif name == "cmdb_get_person":
        person_id = arguments["person_id"]
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/cmdb/people/{person_id}", timeout=15)
            return r.json()

    elif name == "cmdb_list_assets":
        params = {k: v for k, v in {
            "asset_type": arguments.get("asset_type"),
            "status": arguments.get("status"),
            "os_type": arguments.get("os_type"),
            "search": arguments.get("search"),
            "limit": arguments.get("limit", 50),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/cmdb/assets", params=params, timeout=15)
            return r.json()

    elif name == "cmdb_get_asset":
        asset_id = arguments["asset_id"]
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/cmdb/assets/{asset_id}", timeout=15)
            return r.json()

    # ── Product Registry tools ─────────────────────────────────────────────────
    elif name == "product_registry_list_products":
        params = {k: v for k, v in {
            "product_type": arguments.get("product_type"),
            "tier": arguments.get("tier"),
            "data_classification": arguments.get("data_classification"),
            "status": arguments.get("status"),
            "search": arguments.get("search"),
            "limit": arguments.get("limit", 50),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/registry/products", params=params, timeout=15)
            return r.json()

    elif name == "product_registry_get_product":
        product_id = arguments["product_id"]
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/registry/products/{product_id}", timeout=15)
            return r.json()

    elif name == "product_registry_list_cloud_accounts":
        params = {k: v for k, v in {
            "cloud_provider": arguments.get("cloud_provider"),
            "account_type": arguments.get("account_type"),
            "status": arguments.get("status"),
            "limit": arguments.get("limit", 20),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/registry/cloud-accounts", params=params, timeout=15)
            return r.json()

    # ── Vulnerability Management tools ────────────────────────────────────────
    elif name == "vm_get_vulnerabilities":
        asset_type = arguments["asset_type"]
        asset_id = arguments["asset_id"]
        params = {}
        if "status" in arguments:
            params["status"] = arguments["status"]
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/vm/asset/{asset_type}/{asset_id}", params=params, timeout=15)
            return r.json()

    elif name == "vm_get_critical_findings":
        params = {k: v for k, v in {
            "severity": arguments.get("severity", "critical"),
            "cisa_kev": arguments.get("cisa_kev_only"),
            "overdue": arguments.get("overdue_only"),
            "limit": arguments.get("limit", 30),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/vm/findings", params=params, timeout=15)
            return r.json()

    elif name == "vm_get_summary":
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/vm/summary", timeout=15)
            return r.json()

    # ── CSPM tools ────────────────────────────────────────────────────────────
    elif name == "cspm_get_findings":
        params = {k: v for k, v in {
            "cloud_provider": arguments.get("cloud_provider"),
            "account_id": arguments.get("account_id"),
            "status": arguments.get("status", "open"),
            "severity": arguments.get("severity"),
            "framework": arguments.get("framework"),
            "section": arguments.get("section"),
            "limit": arguments.get("limit", 50),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/cspm/findings", params=params, timeout=15)
            return r.json()

    elif name == "cspm_get_summary":
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/cspm/summary", timeout=15)
            return r.json()

    elif name == "cspm_get_critical_findings":
        params = {k: v for k, v in {
            "cloud_provider": arguments.get("cloud_provider"),
            "section": arguments.get("section"),
            "severity": "critical",
            "status": "open",
            "limit": arguments.get("limit", 30),
        }.items() if v is not None}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/cspm/findings", params=params, timeout=15)
            return r.json()

    # ── Simulation control tools ──────────────────────────────────────────────

    elif name == "simulation_run_scenario":
        session_id = arguments["session_id"]
        scenario = arguments["scenario"]
        event_count = int(arguments.get("event_count", 20))

        # Named scenario → technique_ids mapping
        _SCENARIO_TECHNIQUES: dict[str, list[str]] = {
            "ransomware": ["T1566.001", "T1059.001", "T1486", "T1490", "T1041"],
            "credential_access": ["T1078", "T1110.003", "T1003.001", "T1550.002"],
            "lateral_movement": ["T1021.001", "T1021.002", "T1047", "T1078"],
            "data_exfiltration": ["T1005", "T1041", "T1048", "T1071.001"],
            "initial_access_phishing": ["T1566.001", "T1059.001", "T1547.001"],
            "supply_chain": ["T1195", "T1059.001", "T1078", "T1041"],
            "insider_threat": ["T1078", "T1005", "T1041", "T1070.001"],
        }

        technique_ids = _SCENARIO_TECHNIQUES.get(scenario, ["T1059.001", "T1078"])

        # Fetch existing session config and augment with scenario techniques
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/sessions/{session_id}", timeout=10)
            if r.status_code == 404:
                return {"success": False, "error": f"Session {session_id} not found"}
            session_data = r.json()

        existing_config = session_data.get("config") or {}
        scenario_config = {
            **existing_config,
            "technique_ids": technique_ids,
            "event_count": event_count,
            "simulation_mode": "ttps",
            "scenario_name": scenario,
        }

        # Start (or re-start) event generation
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{base}/sessions/{session_id}/start", timeout=10)

        from backend.engine.session_manager import get_session_manager
        mgr = get_session_manager()
        await mgr.start_session(session_id, scenario_config)

        return {
            "success": True,
            "session_id": session_id,
            "scenario": scenario,
            "techniques": technique_ids,
            "event_count": event_count,
            "message": f"Scenario '{scenario}' started: {len(technique_ids)} techniques, {event_count} events",
        }

    elif name == "simulation_inject_alert":
        session_id = arguments["session_id"]
        title = arguments["title"]
        technique_id = arguments.get("technique_id", "T1059.001")
        severity = arguments.get("severity", "high")
        source_type = arguments.get("source_type", "edr")
        hostname = arguments.get("hostname", "CORP-WS-01")
        extra = arguments.get("extra_payload") or {}

        # Build realistic alert payload based on source_type
        from datetime import datetime, timezone as _tz
        ts = datetime.now(_tz.utc).isoformat()
        payload = {
            "event_title": title,
            "_technique": technique_id,
            "_simulated": True,
            "_type": "injected_alert",
            "Timestamp": ts,
            **extra,
        }
        if source_type in ("edr", "crowdstrike"):
            payload.update({
                "ComputerName": hostname,
                "DetectName": title,
                "TechniqueId": technique_id,
                "SeverityName": severity.capitalize(),
            })
        elif source_type in ("auth", "okta"):
            payload.update({"displayMessage": title, "outcome.result": "FAILURE"})
        elif source_type == "firewall":
            payload.update({"action": "deny", "type": "THREAT", "devname": hostname})

        from backend.engine.session_manager import get_session_manager
        mgr = get_session_manager()
        event_dict = await mgr.store_event(session_id, {
            "product_type": source_type,
            "severity": severity,
            "title": technique_id,
            "payload": payload,
            "target_url": "",
            "status_code": 200,
            "success": True,
        })

        return {
            "success": event_dict is not None,
            "session_id": session_id,
            "event_id": event_dict.get("id") if event_dict else None,
            "title": title,
            "technique_id": technique_id,
            "severity": severity,
            "source_type": source_type,
            "message": f"Alert injected into session {session_id}",
        }

    elif name == "simulation_timeline_search":
        session_id = arguments["session_id"]
        technique_id = arguments.get("technique_id")
        severity_filter = arguments.get("severity")
        source_type_filter = arguments.get("source_type")
        keyword = arguments.get("keyword", "").lower()
        start_minutes_ago = int(arguments.get("start_minutes_ago", 60))
        limit = int(arguments.get("limit", 50))
        attack_only = bool(arguments.get("attack_only", False))

        from datetime import datetime, timezone as _tz, timedelta as _td
        from backend.db.session import async_session as _async_session
        from backend.db.models import GeneratedEvent as _GE
        from sqlalchemy import select as _select

        cutoff = datetime.now(_tz.utc) - _td(minutes=start_minutes_ago)

        async with _async_session() as db:
            import uuid as _uuid
            q = (_select(_GE)
                 .where(_GE.session_id == _uuid.UUID(session_id))
                 .where(_GE.created_at >= cutoff.replace(tzinfo=None))
                 .order_by(_GE.created_at.desc())
                 .limit(limit * 3))  # Fetch extra to allow filtering

            if severity_filter:
                q = q.where(_GE.severity == severity_filter)
            if source_type_filter:
                q = q.where(_GE.product_type == source_type_filter)
            if technique_id:
                q = q.where(_GE.title == technique_id)

            rows = (await db.execute(q)).scalars().all()

        events = []
        for row in rows:
            payload = row.payload or {}

            # Attack-only filter
            if attack_only and payload.get("_type") not in ("attack", "state_transition", "injected_alert"):
                continue

            # Keyword filter
            if keyword:
                searchable = (row.title or "") + str(payload)
                if keyword not in searchable.lower():
                    continue

            events.append({
                "id": str(row.id),
                "technique_id": row.title or "",
                "severity": row.severity or "info",
                "source_type": row.product_type or "",
                "title": payload.get("event_title") or payload.get("DetectName") or row.title or "",
                "hostname": payload.get("ComputerName") or payload.get("Computer") or payload.get("hostname") or "",
                "type": payload.get("_type", "unknown"),
                "timestamp": row.created_at.isoformat() if row.created_at else None,
                "ocsf": payload.get("_ocsf"),
            })
            if len(events) >= limit:
                break

        return {
            "session_id": session_id,
            "total_found": len(events),
            "search_params": {
                "technique_id": technique_id,
                "severity": severity_filter,
                "source_type": source_type_filter,
                "keyword": keyword or None,
                "start_minutes_ago": start_minutes_ago,
                "attack_only": attack_only,
            },
            "events": events,
        }

    elif name == "soar_execute_action":
        session_id = arguments["session_id"]
        action_type = arguments["action_type"]
        params = {
            "hostname":     arguments.get("hostname", ""),
            "username":     arguments.get("username") or arguments.get("user", ""),
            "ioc_type":     arguments.get("ioc_type", "ip"),
            "ioc_value":    arguments.get("ioc_value", ""),
            "process_name": arguments.get("process_name", ""),
            "sha256":       arguments.get("sha256", ""),
            "actor":        arguments.get("actor", "joti_soar"),
        }
        from backend.engine.action_executor import execute_action
        result = await execute_action(session_id, action_type, params)
        return result.dict()

    elif name == "siem_search":
        from backend.api.v2.sim_siem import SearchRequest, search_events
        req = SearchRequest(
            session_id=arguments["session_id"],
            query=arguments["query"],
            query_language=arguments.get("query_language", "spl"),
            earliest_time=arguments.get("earliest_time", "-60m"),
            limit=int(arguments.get("limit", 50)),
        )
        return await search_events(req)

    elif name == "siem_deploy_detection":
        from backend.api.v2.sim_siem import DeployDetectionRequest, deploy_detection
        req = DeployDetectionRequest(
            session_id=arguments["session_id"],
            name=arguments["name"],
            sigma_yaml=arguments.get("sigma_yaml"),
            query_spl=arguments.get("query_spl"),
            query_kql=arguments.get("query_kql"),
            technique_ids=arguments.get("technique_ids", []),
            run_validation=bool(arguments.get("run_validation", True)),
            deployed_by="joti_soar",
        )
        return await deploy_detection(req)

    elif name == "tabletop_create":
        from backend.api.v2.tabletop import CreateExerciseRequest, create_exercise
        req = CreateExerciseRequest(
            scenario_key=arguments["scenario_key"],
            session_id=arguments.get("session_id"),
            team_size=int(arguments.get("team_size", 4)),
            name=arguments.get("name", ""),
        )
        exercise = await create_exercise(req)
        # Auto-start and return first inject
        from backend.api.v2.tabletop import start_exercise
        started = await start_exercise(exercise["id"])
        return {**exercise, "first_inject": started.get("inject")}

    elif name == "tabletop_respond":
        from backend.api.v2.tabletop import RespondRequest, respond_to_phase
        req = RespondRequest(
            decision_index=int(arguments["decision_index"]),
            rationale=arguments.get("rationale", ""),
        )
        return await respond_to_phase(arguments["exercise_id"], req)

    elif name == "tabletop_report":
        from backend.api.v2.tabletop import get_after_action_report
        return await get_after_action_report(arguments["exercise_id"])

    elif name == "env_get_topology":
        session_id = arguments["session_id"]
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/sessions/{session_id}/topology", timeout=15)
            if r.status_code == 200:
                return r.json()
            # Fallback: return the session's config-level topology summary
            sr = await c.get(f"{base}/sessions/{session_id}", timeout=15)
            if sr.status_code != 200:
                return {"error": f"Session {session_id} not found", "nodes": [], "edges": []}
            session = sr.json()
            cfg = session.get("config") or {}
            return {
                "session_id": session_id,
                "environment_id": cfg.get("environment_id"),
                "simulation_context": session.get("simulation_context"),
                "products": cfg.get("products", []),
                "nodes": [],
                "edges": [],
                "note": "Full topology graph unavailable; session config returned",
            }

    elif name == "logs_search_timeline":
        # Delegate to simulation_timeline_search handler with compatible args
        return await _call_tool("simulation_timeline_search", {
            "session_id": arguments["session_id"],
            "technique_id": arguments.get("technique_id"),
            "severity": arguments.get("severity"),
            "source_type": arguments.get("source_type"),
            "keyword": arguments.get("keyword"),
            "start_minutes_ago": arguments.get("start_minutes_ago", 120),
            "attack_only": arguments.get("attack_only", False),
            "limit": arguments.get("limit", 50),
        })

    elif name == "detection_test_rule":
        from backend.api.v2.sim_siem import DeployDetectionRequest, deploy_detection
        req = DeployDetectionRequest(
            session_id=arguments["session_id"],
            name=arguments["rule_name"],
            sigma_yaml=arguments.get("sigma_yaml"),
            query_spl=arguments.get("query_spl"),
            query_kql=arguments.get("query_kql"),
            technique_ids=arguments.get("technique_ids", []),
            run_validation=True,
            deployed_by="mcp_test",
        )
        result = await deploy_detection(req)
        # Return test-oriented view (don't persist permanently — this is a test)
        return {
            "session_id": arguments["session_id"],
            "rule_name": arguments["rule_name"],
            "fired": result.get("validation", {}).get("fired", False),
            "match_count": result.get("validation", {}).get("match_count", 0),
            "fp_count": result.get("validation", {}).get("fp_count", 0),
            "fp_rate": result.get("validation", {}).get("fp_rate", 0.0),
            "techniques_covered": result.get("technique_ids", []),
            "deployed_id": result.get("detection_id"),
            "detail": result,
        }

    elif name == "detection_get_coverage":
        session_id = arguments.get("session_id")
        params = {}
        if session_id:
            params["session_id"] = session_id
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/sim-siem/coverage", params=params, timeout=15)
            data = r.json()
        # Enrich with uncovered-techniques list
        coverage = data.get("coverage", {})
        uncovered = [t for t, v in coverage.items() if not v.get("detected")]
        data["uncovered_techniques"] = uncovered
        data["coverage_pct"] = (
            round(100 * len(data.get("detected_techniques", [])) / max(len(coverage), 1), 1)
            if coverage else 0.0
        )
        return data

    elif name == "vendor_list_personas":
        from backend.engine.product_personas import ALL_PERSONAS, PERSONAS_BY_CATEGORY
        category = arguments.get("category", "all")
        if category == "all":
            personas = list(ALL_PERSONAS.values())
        else:
            personas = PERSONAS_BY_CATEGORY.get(category, [])
        return {
            "personas": [
                {
                    "key": p.key,
                    "vendor": p.vendor,
                    "product": p.product,
                    "category": p.category,
                    "api_prefix": p.api_prefix,
                    "auth_scheme": p.auth_scheme,
                    "capabilities": p.capabilities,
                }
                for p in personas
            ],
            "total": len(personas),
        }

    elif name == "vm_get_summary":
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/vm/summary", timeout=15)
            r.raise_for_status()
        return r.json()

    elif name == "vm_list_findings":
        params: dict = {"limit": arguments.get("limit", 50), "skip": arguments.get("skip", 0)}
        if arguments.get("severity"):
            params["severity"] = arguments["severity"]
        if arguments.get("status"):
            params["status"] = arguments["status"]
        else:
            params["status"] = "open"
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/vm/findings", params=params, timeout=15)
            r.raise_for_status()
        return r.json()

    elif name == "vm_list_critical_vulns":
        params = {"severity": "critical", "status": "open", "limit": arguments.get("limit", 20), "skip": 0}
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{base}/vm/findings", params=params, timeout=15)
            r.raise_for_status()
        data = r.json()
        findings = data.get("findings", [])
        # Sort by CVSS score descending so highest-risk CVEs appear first
        findings.sort(key=lambda f: f.get("cvss_score") or 0, reverse=True)
        return {"findings": findings, "total": data.get("total", len(findings))}

    else:
        raise ValueError(f"Unknown tool: {name}")


# ── MCP JSON-RPC dispatcher ───────────────────────────────────────────────────

async def handle_request(body: dict[str, Any], api_key: Optional[str]) -> dict[str, Any]:
    """Process one JSON-RPC 2.0 request and return a response dict."""
    rpc_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params") or {}

    def _ok(result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

    def _err(code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}

    # Auth check (skip for tools/list discovery)
    if method != "tools/list":
        expected = _MCP_API_KEY
        if api_key != expected:
            return _err(-32001, "Unauthorized: invalid or missing API key")

    if method == "tools/list":
        return _ok({"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name") or params.get("tool")
        arguments = params.get("arguments") or params.get("input") or {}

        if not tool_name:
            return _err(-32602, "Missing required param: name")
        if tool_name not in TOOL_INDEX:
            return _err(-32602, f"Unknown tool: {tool_name}")

        try:
            result = await _call_tool(tool_name, arguments)
            import json as _json
            text_body = _json.dumps(result, default=str) if isinstance(result, (dict, list)) else str(result)
            return _ok({"content": [{"type": "text", "text": text_body}]})
        except Exception as exc:
            logger.exception("Tool %s failed: %s", tool_name, exc)
            return _err(-32603, f"Tool execution error: {exc}")

    elif method == "initialize":
        return _ok({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "purplelab-mcp", "version": "2.0.0"},
        })

    elif method == "ping":
        return _ok({})

    else:
        return _err(-32601, f"Method not found: {method}")


from typing import Optional
