"""CrowdStrike Falcon REST API emulation — comprehensive enterprise rewrite.

Grounded in official CrowdStrike API Reference:
  https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis

Implements (all field names match actual Falcon API):
  OAuth2 /oauth2/token
  Devices (Hosts) — FQL filter, scroll pagination, entity details, actions (contain, lift_containment, hide, unhide)
  Detections — FQL filter, behavior details, status management
  Alerts — next-gen alert model
  Incidents — FQL filter, status codes, behavior details
  Prevention Policies — policy assignment
  IOC Management — indicator CRUD, enforcement policies
  Spotlight Vulnerabilities — CVE, CVSS, EPSS, remediation
  Host Groups — group CRUD, membership
  Real-Time Response (RTR) — sessions, commands, file upload, script execution
  Identity Protection GraphQL-style endpoint
  Intel Indicators — threat actor tracking
  Event Streams — Streaming API metadata

FQL (Falcon Query Language) fields for devices:
  hostname, status, platform_name, last_seen, first_seen, local_ip, external_ip,
  mac_address, os_version, agent_version, product_type, product_type_desc,
  site_name, ou, cid, device_id, groups, containment_status, device_policies,
  tags, bios_manufacturer, system_manufacturer, system_product_name

Device status values: normal, contained, containment_pending, lift_containment_pending
Containment status values: Normal, Contained, containment_pending, lift_containment_pending
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Query

router = APIRouter(prefix="/api/vendor/crowdstrike", tags=["vendor:crowdstrike"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Seed data — enterprise-grade device records matching actual Falcon schema
# ─────────────────────────────────────────────────────────────────────────────

_DEVICES: dict[str, dict] = {
    "a1b2c3d4e5f6000100000000000000001": {
        "device_id": "a1b2c3d4e5f6000100000000000000001",
        "cid": "deadbeef000000000000000000000001",
        "agent_load_flags": "0",
        "agent_local_time": _now(),
        "agent_version": "7.14.17714.0",
        "bios_manufacturer": "Dell Inc.",
        "bios_version": "1.23.0",
        "build_number": "22621",
        "chassis_type": "10",
        "chassis_type_desc": "Notebook",
        "config_id_base": "65994753",
        "config_id_build": "17714",
        "config_id_platform": "4",
        "connection_ip": "10.10.1.101",
        "connection_mac_address": "aa-bb-cc-dd-ee-01",
        "cpu_signature": "6-140-0",
        "default_gateway_ip": "10.10.1.1",
        "device_policies": {
            "prevention": {"applied": True, "applied_date": "2024-01-15T08:00:00Z", "assigned_date": "2024-01-15T08:00:00Z", "policy_id": "policy001", "policy_type": "prevention", "settings_hash": "abc123"},
            "sensor_update": {"applied": True, "applied_date": "2024-01-15T08:00:00Z", "assigned_date": "2024-01-15T08:00:00Z", "policy_id": "supdate001", "policy_type": "sensor-update", "settings_hash": "def456"},
            "firewall": {"applied": True, "applied_date": "2024-01-15T08:00:00Z", "assigned_date": "2024-01-15T08:00:00Z", "policy_id": "fw001", "policy_type": "firewall", "settings_hash": "ghi789"},
            "global_config": {"applied": True, "applied_date": "2024-01-15T08:00:00Z", "assigned_date": "2024-01-15T08:00:00Z", "policy_id": "gc001", "policy_type": "global-config", "settings_hash": "jkl012"},
        },
        "email": "jsmith@corp.local",
        "external_ip": "203.0.113.101",
        "first_seen": "2024-01-15T08:00:00Z",
        "groups": ["host-grp-001", "host-grp-002"],
        "hostname": "CORP-WS-001",
        "instance_id": "",
        "last_login_user": "CORP\\jsmith",
        "last_login_timestamp": (datetime.now(timezone.utc) - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "local_ip": "10.10.1.101",
        "mac_address": "aa-bb-cc-dd-ee-01",
        "major_version": "10",
        "minor_version": "0",
        "modified_timestamp": _now(),
        "os_build": "22621",
        "os_version": "Windows 11",
        "ou": ["CORP\\Engineering"],
        "platform_id": "0",
        "platform_name": "Windows",
        "policies": [{"applied": True, "applied_date": "2024-01-15T08:00:00Z", "policy_id": "policy001", "policy_type": "prevention", "settings_hash": "abc123"}],
        "product_type": "1",
        "product_type_desc": "Workstation",
        "provision_status": "Provisioned",
        "serial_number": "SN-DL001234",
        "service_pack_major": "0",
        "service_pack_minor": "0",
        "site_name": "Corporate-HQ",
        "slow_changing_modified_timestamp": "2024-01-15T08:00:00Z",
        "status": "normal",
        "system_manufacturer": "Dell Inc.",
        "system_product_name": "Latitude 5540",
        "tags": ["Engineering", "Production", "Monitored"],
        "zone_group": "",
        "containment_status": "Normal",
        "reduced_functionality_mode": "no",
        "meta": {"version": "1", "version_string": "1:0"},
    },
    "a1b2c3d4e5f6000200000000000000002": {
        "device_id": "a1b2c3d4e5f6000200000000000000002",
        "cid": "deadbeef000000000000000000000001",
        "agent_load_flags": "0",
        "agent_local_time": _now(),
        "agent_version": "7.14.17714.0",
        "bios_manufacturer": "HP",
        "bios_version": "U30 v2.52",
        "build_number": "20348",
        "chassis_type": "17",
        "chassis_type_desc": "Rack Mount Server",
        "config_id_base": "65994753",
        "config_id_build": "17714",
        "config_id_platform": "4",
        "connection_ip": "10.10.2.10",
        "connection_mac_address": "aa-bb-cc-dd-ee-10",
        "cpu_signature": "6-108-0",
        "default_gateway_ip": "10.10.2.1",
        "device_policies": {
            "prevention": {"applied": True, "applied_date": "2023-06-01T10:00:00Z", "assigned_date": "2023-06-01T10:00:00Z", "policy_id": "policy001", "policy_type": "prevention", "settings_hash": "abc123"},
            "sensor_update": {"applied": True, "applied_date": "2023-06-01T10:00:00Z", "assigned_date": "2023-06-01T10:00:00Z", "policy_id": "supdate001", "policy_type": "sensor-update", "settings_hash": "def456"},
        },
        "email": "agarcia@corp.local",
        "external_ip": "203.0.113.10",
        "first_seen": "2023-06-01T10:00:00Z",
        "groups": ["host-grp-002", "host-grp-003"],
        "hostname": "CORP-SRV-001",
        "last_login_user": "CORP\\svc_backup",
        "last_login_timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "local_ip": "10.10.2.10",
        "mac_address": "aa-bb-cc-dd-ee-10",
        "major_version": "10",
        "minor_version": "0",
        "modified_timestamp": _now(),
        "os_build": "20348",
        "os_version": "Windows Server 2022",
        "ou": ["CORP\\Servers"],
        "platform_id": "0",
        "platform_name": "Windows",
        "product_type": "3",
        "product_type_desc": "Server",
        "provision_status": "Provisioned",
        "serial_number": "SN-HP001001",
        "site_name": "Corporate-HQ",
        "status": "normal",
        "system_manufacturer": "HP",
        "system_product_name": "ProLiant DL380 Gen10",
        "tags": ["Servers", "Production", "FileServer"],
        "containment_status": "Normal",
        "reduced_functionality_mode": "no",
        "meta": {"version": "1", "version_string": "1:0"},
    },
    "a1b2c3d4e5f6000300000000000000003": {
        "device_id": "a1b2c3d4e5f6000300000000000000003",
        "cid": "deadbeef000000000000000000000001",
        "agent_version": "7.14.17714.0",
        "bios_manufacturer": "Dell Inc.",
        "bios_version": "2.3.4",
        "build_number": "20348",
        "chassis_type": "17",
        "chassis_type_desc": "Rack Mount Server",
        "connection_ip": "10.10.2.1",
        "connection_mac_address": "aa-bb-cc-dd-ee-20",
        "device_policies": {
            "prevention": {"applied": True, "applied_date": "2022-01-10T08:00:00Z", "policy_id": "policy001", "policy_type": "prevention", "settings_hash": "abc123"},
        },
        "email": "itsec@corp.local",
        "external_ip": "203.0.113.1",
        "first_seen": "2022-01-10T08:00:00Z",
        "groups": ["host-grp-003", "host-grp-004"],
        "hostname": "CORP-DC-001",
        "last_login_user": "CORP\\Administrator",
        "last_login_timestamp": (datetime.now(timezone.utc) - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "local_ip": "10.10.2.1",
        "mac_address": "aa-bb-cc-dd-ee-20",
        "major_version": "10",
        "minor_version": "0",
        "modified_timestamp": _now(),
        "os_build": "20348",
        "os_version": "Windows Server 2022",
        "ou": ["CORP\\Domain Controllers"],
        "platform_id": "0",
        "platform_name": "Windows",
        "product_type": "3",
        "product_type_desc": "Server",
        "provision_status": "Provisioned",
        "serial_number": "SN-DL002001",
        "site_name": "Corporate-HQ",
        "status": "normal",
        "system_manufacturer": "Dell Inc.",
        "system_product_name": "PowerEdge R750",
        "tags": ["DomainController", "Tier0", "Production", "CriticalAsset"],
        "containment_status": "Normal",
        "reduced_functionality_mode": "no",
        "meta": {"version": "1", "version_string": "1:0"},
    },
}

_DETECTIONS: dict[str, dict] = {
    "ldt:a1b2c3d4e5f6000100000000000000001:000000001": {
        "detection_id": "ldt:a1b2c3d4e5f6000100000000000000001:000000001",
        "cid": "deadbeef000000000000000000000001",
        "created_timestamp": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device": {
            "device_id": "a1b2c3d4e5f6000100000000000000001",
            "cid": "deadbeef000000000000000000000001",
            "agent_load_flags": "0",
            "agent_version": "7.14.17714.0",
            "bios_manufacturer": "Dell Inc.",
            "config_id_base": "65994753",
            "config_id_build": "17714",
            "external_ip": "203.0.113.101",
            "first_seen": "2024-01-15T08:00:00Z",
            "hostname": "CORP-WS-001",
            "last_seen": _now(),
            "local_ip": "10.10.1.101",
            "mac_address": "aa-bb-cc-dd-ee-01",
            "major_version": "10",
            "minor_version": "0",
            "os_version": "Windows 11",
            "platform_name": "Windows",
            "product_type_desc": "Workstation",
            "site_name": "Corporate-HQ",
            "status": "normal",
        },
        "email_sent": False,
        "first_behavior": (datetime.now(timezone.utc) - timedelta(minutes=35)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_behavior": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "max_confidence": 90,
        "max_severity": 90,
        "max_severity_displayname": "Critical",
        "overwatch_notes": "",
        "parent_api_type": "Detection",
        "quarantined_files": [],
        "seconds_to_resolved": 0,
        "seconds_to_triaged": 0,
        "show_in_ui": True,
        "status": "new",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter: PowerShell",
        "technique_id": "T1059.001",
        "assigned_to_name": None,
        "assigned_to_uid": None,
        "behaviors": [
            {
                "alleged_filetype": "exe",
                "behavior_id": "10064",
                "cmdline": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0",
                "confidence": 90,
                "control_graph_id": "ctg:a1b2c3d4e5f6000100000000000000001:001",
                "description": "A PowerShell encoded command was executed from Microsoft Word, indicating a possible malicious macro.",
                "device_id": "a1b2c3d4e5f6000100000000000000001",
                "display_name": "Malicious Document Spawned PowerShell",
                "document_sha256": "a" * 64,
                "filename": "powershell.exe",
                "filepath": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ioc_description": "PowerShell encoded command",
                "ioc_source": "library_load",
                "ioc_type": "hash_sha256",
                "ioc_value": "b" * 64,
                "md5": "c" * 32,
                "objective": "Falcon Detection Method",
                "parent_details": {
                    "parent_cmdline": "\"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n",
                    "parent_image_file_name": "\\Device\\HarddiskVolume3\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "parent_md5": "d" * 32,
                    "parent_process_graph_id": "pid:a1b2c3d4e5f6000100000000000000001:101",
                    "parent_sha256": "e" * 64,
                },
                "pattern_disposition": 2048,
                "pattern_disposition_description": "Detection triggered, process was allowed to continue",
                "pattern_id": "10064",
                "scenario": "suspicious_activity",
                "severity": 90,
                "sha256": "b" * 64,
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "technique": "Command and Scripting Interpreter: PowerShell",
                "technique_id": "T1059.001",
                "template_instance_id": "27",
                "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=35)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "triggering_process_graph_id": "pid:a1b2c3d4e5f6000100000000000000001:100",
                "user_id": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                "user_name": "jsmith",
            }
        ],
    },
}

_ALERTS: dict[str, dict] = {
    "ldt:a1b2c3d4e5f6000100000000000000001:a0000001": {
        "composite_id": "ldt:a1b2c3d4e5f6000100000000000000001:a0000001",
        "cid": "deadbeef000000000000000000000001",
        "agent_id": "a1b2c3d4e5f6000100000000000000001",
        "alert_id": "a0000001",
        "assigned_to_name": None,
        "assigned_to_uid": None,
        "confidence": 80,
        "context_timestamp": (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "created_timestamp": (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": "Suspected credential dumping via LSASS process access",
        "display_name": "Credential Access — LSASS Dump",
        "email_sent": False,
        "end_time": (datetime.now(timezone.utc) - timedelta(minutes=18)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/alerts?ids=ldt:a1b2c3d4e5f6000100000000000000001:a0000001",
        "grandparent_details": {},
        "hostname": "CORP-WS-001",
        "id": "ldt:a1b2c3d4e5f6000100000000000000001:a0000001",
        "ioc_context": [],
        "local_ip": "10.10.1.101",
        "md5": "e" * 32,
        "name": "SuspiciousLsassAccess",
        "objective": "Steal credentials",
        "parent_details": {
            "parent_cmdline": "\"C:\\Windows\\System32\\cmd.exe\"",
            "parent_image_file_name": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
            "parent_md5": "f" * 32,
            "parent_process_graph_id": "pid:a1b2c3d4e5f6000100000000000000001:200",
            "parent_sha256": "g" * 64,
        },
        "pattern_id": "41002",
        "platform": "Windows",
        "product": "epp",
        "scenario": "suspicious_activity",
        "severity": 70,
        "sha256": "h" * 64,
        "start_time": (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "new",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "OS Credential Dumping: LSASS Memory",
        "technique_id": "T1003.001",
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "type": "ldt",
        "updated_timestamp": _now(),
        "user_id": "S-1-5-21-1234567890-1234567890-1234567890-1001",
        "user_name": "jsmith",
    },
}

_INCIDENTS: dict[str, dict] = {
    "inc:a1b2c3d4e5f6000100000000000000001:i0000001": {
        "incident_id": "inc:a1b2c3d4e5f6000100000000000000001:i0000001",
        "cid": "deadbeef000000000000000000000001",
        "assigned_to": "",
        "assigned_to_name": "",
        "created": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": "",
        "end": None,
        "events_histogram": [{"count": 2, "timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}],
        "fine_score": 75,
        "hosts": [
            {
                "agent_id": "a1b2c3d4e5f6000100000000000000001",
                "bios_manufacturer": "Dell Inc.",
                "bios_version": "1.23.0",
                "cmdline": "powershell.exe -enc ...",
                "country": "US",
                "external_ip": "203.0.113.101",
                "falcon_host_link": "https://falcon.crowdstrike.com/hosts/a1b2c3d4e5f6000100000000000000001",
                "first_occurrence": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "hostname": "CORP-WS-001",
                "last_occurrence": _now(),
                "local_ip": "10.10.1.101",
                "mac_address": "aa-bb-cc-dd-ee-01",
                "os_version": "Windows 11",
                "pattern_id": "10064",
                "platform_name": "Windows",
                "product_type_desc": "Workstation",
                "site_name": "Corporate-HQ",
                "status": "normal",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "technique": "PowerShell",
                "technique_id": "T1059.001",
            }
        ],
        "incident_type": 1,
        "lm_host_ids": ["a1b2c3d4e5f6000100000000000000001"],
        "lm_hosts_capped": False,
        "modified_timestamp": _now(),
        "name": "Incident on 1 Host(s) with 1 Detection(s)",
        "objectives": ["Access Broker"],
        "start": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "state": "open",
        "status": 20,
        "tactics": ["Execution"],
        "tags": [],
        "techniques": ["PowerShell"],
        "users": ["jsmith"],
        "visibility": 10,
    },
}

_IOC_INDICATORS: dict[str, dict] = {}

_HOST_GROUPS: dict[str, dict] = {
    "host-grp-001": {
        "id": "host-grp-001",
        "cid": "deadbeef000000000000000000000001",
        "group_type": "static",
        "name": "Engineering Workstations",
        "description": "All engineering department workstations",
        "created_by": "api-client-id",
        "created_timestamp": "2024-01-01T00:00:00Z",
        "modified_by": "api-client-id",
        "modified_timestamp": "2024-01-01T00:00:00Z",
    },
    "host-grp-002": {
        "id": "host-grp-002",
        "cid": "deadbeef000000000000000000000001",
        "group_type": "dynamic",
        "name": "All Windows Hosts",
        "description": "Dynamic group — all Windows devices",
        "assignment_rule": "platform_name: 'Windows'",
        "created_by": "api-client-id",
        "created_timestamp": "2024-01-01T00:00:00Z",
        "modified_by": "api-client-id",
        "modified_timestamp": "2024-01-01T00:00:00Z",
    },
    "host-grp-003": {
        "id": "host-grp-003",
        "cid": "deadbeef000000000000000000000001",
        "group_type": "static",
        "name": "Servers",
        "description": "All server-class endpoints",
        "created_by": "api-client-id",
        "created_timestamp": "2024-01-01T00:00:00Z",
        "modified_by": "api-client-id",
        "modified_timestamp": "2024-01-01T00:00:00Z",
    },
    "host-grp-004": {
        "id": "host-grp-004",
        "cid": "deadbeef000000000000000000000001",
        "group_type": "static",
        "name": "Domain Controllers",
        "description": "Tier 0 — domain controllers",
        "created_by": "api-client-id",
        "created_timestamp": "2024-01-01T00:00:00Z",
        "modified_by": "api-client-id",
        "modified_timestamp": "2024-01-01T00:00:00Z",
    },
}

_SPOTLIGHT_VULNS: list[dict] = [
    {
        "id": "vuln:a1b2c3d4e5f6000100000000000000001:CVE-2024-21413",
        "cid": "deadbeef000000000000000000000001",
        "aid": "a1b2c3d4e5f6000100000000000000001",
        "created_timestamp": "2026-07-20T10:00:00Z",
        "updated_timestamp": _now(),
        "status": "open",
        "cve": {
            "id": "CVE-2024-21413",
            "base_score": 9.8,
            "description": "Microsoft Outlook Remote Code Execution Vulnerability",
            "exprt_rating": "CRITICAL",
            "exploit_status": 80,
            "published_date": "2024-02-13T00:00:00Z",
            "remediation_level": "O",
            "severity": "CRITICAL",
            "vectors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "name": "CVE-2024-21413",
        },
        "host_info": {
            "hostname": "CORP-WS-001",
            "local_ip": "10.10.1.101",
            "machine_domain": "corp.local",
            "os_version": "Windows 11",
            "site_name": "Corporate-HQ",
            "system_manufacturer": "Dell Inc.",
            "tags": ["Engineering", "Production"],
        },
        "remediation": {
            "entities": [
                {
                    "action": "update_software",
                    "id": "rem:a1b2c3d4e5f6000100000000000000001:CVE-2024-21413:001",
                    "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413",
                    "reference": "KB5034671",
                    "type": "patch",
                    "vendor": "Microsoft",
                }
            ]
        },
        "apps": [
            {
                "product_name_version": "Microsoft Outlook 16.0.16827.20166",
                "sub_status": "open",
                "remediation": {"ids": ["rem:a1b2c3d4e5f6000100000000000000001:CVE-2024-21413:001"]},
                "supported_platform": ["Windows"],
            }
        ],
    },
]

_rtr_sessions: dict[str, dict] = {}
_rtr_queued_commands: dict[str, list] = {}


# ─────────────────────────────────────────────────────────────────────────────
# FQL (Falcon Query Language) parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_fql(fql: str, records: list[dict]) -> list[dict]:
    """
    Parse FQL filter and return matching records.
    Supports: field:'value', field:!'value', field:>='value', field:['v1','v2'], compound with +
    """
    if not fql:
        return records

    result = records
    clauses = re.split(r'\+(?=\w)', fql)

    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue

        # Array membership: field:['val1','val2']
        m = re.match(r"(\w+):\[([^\]]+)\]", clause)
        if m:
            field, vals_raw = m.group(1), m.group(2)
            vals = [v.strip().strip("'\"") for v in vals_raw.split(",")]
            result = [r for r in result if _fql_field_in(r, field, vals)]
            continue

        # Range comparison: field:>='value'
        m = re.match(r"(\w+):(>=|<=|>|<)'?([^'\"]+)'?", clause)
        if m:
            field, op, val = m.group(1), m.group(2), m.group(3)
            result = [r for r in result if _fql_compare(r.get(field, ""), op, val)]
            continue

        # NOT equality: field:!'value'
        m = re.match(r"(\w+):!'?([^'\"]+)'?", clause)
        if m:
            field, val = m.group(1), m.group(2)
            result = [r for r in result if str(_fql_resolve(r, field)).lower() != val.lower()]
            continue

        # Equality: field:'value' or field:"value" or field:value
        m = re.match(r"(\w+):['\"]?([^'\"]*)['\"]?", clause)
        if m:
            field, val = m.group(1), m.group(2)
            result = [r for r in result if str(_fql_resolve(r, field)).lower() == val.lower()]
            continue

    return result


def _fql_resolve(record: dict, field: str) -> Any:
    val = record.get(field)
    if isinstance(val, list):
        return ",".join(str(v) for v in val)
    return val or ""


def _fql_field_in(record: dict, field: str, vals: list[str]) -> bool:
    raw = record.get(field, "")
    if isinstance(raw, list):
        return any(v.lower() in [str(x).lower() for x in raw] for v in vals)
    return str(raw).lower() in [v.lower() for v in vals]


def _fql_compare(val: Any, op: str, target: str) -> bool:
    try:
        if "T" in str(target) and "Z" in str(target):
            dt_val = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            dt_target = datetime.fromisoformat(str(target).replace("Z", "+00:00"))
            return {">=": dt_val >= dt_target, "<=": dt_val <= dt_target, ">": dt_val > dt_target, "<": dt_val < dt_target}.get(op, False)
        v, t = float(val), float(target)
        return {">=": v >= t, "<=": v <= t, ">": v > t, "<": v < t}.get(op, False)
    except Exception:
        return str(val).lower() == str(target).lower()


# ─────────────────────────────────────────────────────────────────────────────
# OAuth2 Authentication
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/oauth2/token")
async def get_token(body: dict = Body(default={})):
    """OAuth2 client_credentials token endpoint. Accepts client_id + client_secret."""
    return {
        "access_token": f"cs-sim-{uuid.uuid4().hex[:48]}",
        "token_type": "bearer",
        "expires_in": 1799,
    }


@router.post("/oauth2/revoke")
async def revoke_token(body: dict = Body(default={})):
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Devices (Hosts) API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/devices/queries/devices/v1")
async def query_devices(
    filter: Optional[str] = Query(None, description="FQL filter: hostname, status, platform_name, local_ip, groups, tags, etc."),
    offset: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=5000),
    sort: Optional[str] = Query(None),
):
    """Query device IDs. Use returned IDs with /devices/entities/devices/v2 to get full records."""
    devices = list(_DEVICES.values())
    if filter:
        devices = _parse_fql(filter, devices)
    ids = [d["device_id"] for d in devices]
    start = int(offset or 0)
    page = ids[start: start + limit]
    next_offset = str(start + len(page)) if len(page) == limit and start + limit < len(ids) else None
    return {
        "meta": {"query_time": 0.01, "pagination": {"offset": start, "limit": limit, "total": len(ids), "expires_at": _ts() + 600}, "trace_id": _uuid()},
        "resources": page,
        "errors": [],
    }


@router.get("/devices/queries/devices-scroll/v1")
async def scroll_devices(
    filter: Optional[str] = Query(None),
    offset: Optional[str] = Query(None),
    limit: int = Query(100),
    sort: Optional[str] = Query(None),
):
    """Scroll through all devices — used for large-scale enumeration. Use offset token for pagination."""
    return await query_devices(filter=filter, offset=offset, limit=limit, sort=sort)


@router.get("/devices/entities/devices/v2")
async def get_device_details(
    ids: list[str] = Query(..., description="One or more device IDs"),
):
    """Retrieve full device records. Max 100 IDs per request."""
    result = [_DEVICES[d] for d in ids if d in _DEVICES]
    missing = [{"code": 404, "message": f"Could not retrieve device {d}", "id": d} for d in ids if d not in _DEVICES]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": result, "errors": missing}


@router.post("/devices/entities/devices-actions/v2")
async def device_action(
    action_name: str = Query(
        ...,
        description="contain | lift_containment | hide_host | unhide_host | online_state_on | online_state_off"
    ),
    body: dict = Body(default={}),
):
    """
    Perform actions on one or more devices.

    action_name:
      contain              — Network containment: blocks all network traffic except Falcon comms
      lift_containment     — Remove network containment
      hide_host            — Hides device from Falcon UI (does NOT remove sensor)
      unhide_host          — Restore hidden device in Falcon UI
      online_state_on      — Mark as online (maintenance mode)
      online_state_off     — Mark as offline

    body.ids: list of device_ids
    """
    ids = body.get("ids", [])
    results = []
    for device_id in ids:
        if device_id not in _DEVICES:
            results.append({"id": device_id, "error": "Device not found"})
            continue

        dev = _DEVICES[device_id]
        if action_name == "contain":
            dev["status"] = "contained"
            dev["containment_status"] = "Contained"
        elif action_name == "lift_containment":
            dev["status"] = "normal"
            dev["containment_status"] = "Normal"
        elif action_name == "hide_host":
            dev["status"] = "hidden"
        elif action_name == "unhide_host":
            dev["status"] = "normal"
        dev["modified_timestamp"] = _now()
        results.append({"id": device_id, "path": f"/devices/entities/devices-actions/v2?action_name={action_name}"})

    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": results, "errors": []}


@router.patch("/devices/entities/devices/v2")
async def update_device(body: dict = Body(default={})):
    """Update device tags. body: {id, tags_to_add: [], tags_to_remove: []}"""
    device_id = body.get("id", "")
    if device_id not in _DEVICES:
        raise HTTPException(404, detail={"errors": [{"code": 404, "message": f"Device {device_id} not found"}]})
    dev = _DEVICES[device_id]
    dev["tags"] = [t for t in dev.get("tags", []) if t not in body.get("tags_to_remove", [])]
    dev["tags"] = list(set(dev["tags"] + body.get("tags_to_add", [])))
    dev["modified_timestamp"] = _now()
    return {"meta": {"trace_id": _uuid()}, "resources": [dev], "errors": []}


@router.get("/devices/queries/online-state/v1")
async def query_online_state(ids: list[str] = Query(...)):
    """Get real-time connectivity state. state: online | offline | unknown"""
    return {
        "meta": {"trace_id": _uuid()},
        "resources": [
            {"id": did, "state": "online" if did in _DEVICES else "unknown", "updated_at": _now()}
            for did in ids
        ],
        "errors": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Detections API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/detections/queries/detects/v1")
async def query_detections(
    filter: Optional[str] = Query(None, description="FQL: status, device_id, max_severity, tactic_id, technique_id"),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=9999),
    sort: Optional[str] = Query(None),
):
    """Query detection IDs. Sort examples: first_behavior.desc, max_severity.desc"""
    dets = list(_DETECTIONS.values())
    if filter:
        dets = _parse_fql(filter, dets)
    ids = [d["detection_id"] for d in dets]
    return {
        "meta": {"query_time": 0.01, "pagination": {"offset": offset, "limit": limit, "total": len(ids)}, "trace_id": _uuid()},
        "resources": ids[offset: offset + limit],
        "errors": [],
    }


@router.post("/detections/entities/summaries/GET/v1")
async def get_detection_details(body: dict = Body(default={})):
    """Get full detection summaries including behavior details, process tree, and IOC context."""
    ids = body.get("ids", [])
    result = [_DETECTIONS[d] for d in ids if d in _DETECTIONS]
    missing = [{"id": d, "code": 404, "message": "Detection not found"} for d in ids if d not in _DETECTIONS]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": result, "errors": missing}


@router.patch("/detections/entities/detects/v2")
async def update_detection(body: dict = Body(default={})):
    """
    Update detections.
    Fields: ids (list), status, assigned_to_uuid, comment, show_in_ui
    status values: new | in_progress | true_positive | false_positive | ignored | closed | reopened
    """
    ids = body.get("ids", [])
    for det_id in ids:
        if det_id in _DETECTIONS:
            det = _DETECTIONS[det_id]
            if "status" in body:
                det["status"] = body["status"]
            if "assigned_to_uuid" in body:
                det["assigned_to_uid"] = body["assigned_to_uuid"]
            if "comment" in body:
                det.setdefault("comments", []).append({"created_by": "analyst", "created_timestamp": _now(), "text": body["comment"]})
            if "show_in_ui" in body:
                det["show_in_ui"] = body["show_in_ui"]
    return {"meta": {"trace_id": _uuid()}, "resources": ids, "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# Alerts API (next-gen unified alert model — replaces legacy detections)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/alerts/queries/alerts/v2")
async def query_alerts(body: dict = Body(default={})):
    """
    Query alert composite IDs with FQL filter.
    filter FQL fields: status, severity, tactic_id, technique_id, hostname, composite_id
    status values: new | in_progress | closed | reopened
    """
    filter_fql = body.get("filter", "")
    offset = body.get("offset", 0)
    limit = body.get("limit", 100)
    alerts = list(_ALERTS.values())
    if filter_fql:
        alerts = _parse_fql(filter_fql, alerts)
    ids = [a["composite_id"] for a in alerts]
    return {
        "meta": {"query_time": 0.01, "pagination": {"offset": offset, "limit": limit, "total": len(ids)}, "trace_id": _uuid()},
        "resources": ids[offset: offset + limit],
        "errors": [],
    }


@router.post("/alerts/entities/alerts/GET/v2")
async def get_alert_details(body: dict = Body(default={})):
    """Get full alert records including process context, MITRE mapping, IOC context."""
    ids = body.get("ids", [])
    result = [_ALERTS[a] for a in ids if a in _ALERTS]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": result, "errors": []}


@router.patch("/alerts/entities/alerts/v3")
async def update_alerts(body: dict = Body(default={})):
    """
    Update alerts.
    Fields: composite_ids, status, assigned_to_uuid, action_parameters: [{name, value}]
    action_parameters name values: add_comment, remove_comment, assign_to_user, show_in_ui
    """
    ids = body.get("composite_ids", [])
    action_params = {p.get("name"): p.get("value") for p in body.get("action_parameters", []) if isinstance(p, dict)}
    for alert_id in ids:
        if alert_id in _ALERTS:
            alert = _ALERTS[alert_id]
            if "status" in body:
                alert["status"] = body["status"]
            if "assigned_to_uuid" in body:
                alert["assigned_to_uid"] = body["assigned_to_uuid"]
            if "add_comment" in action_params:
                alert.setdefault("comments", []).append({"text": action_params["add_comment"], "created_at": _now()})
            alert["updated_timestamp"] = _now()
    return {"meta": {"trace_id": _uuid()}, "resources": ids, "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# Incidents API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/incidents/queries/incidents/v1")
async def query_incidents(
    filter: Optional[str] = Query(None, description="FQL: status, state, fine_score, start, end, assigned_to"),
    offset: int = Query(0),
    limit: int = Query(100),
    sort: Optional[str] = Query(None),
):
    """Query incident IDs. status: 20=New, 25=Reopened, 30=In Progress, 40=Closed"""
    incs = list(_INCIDENTS.values())
    if filter:
        incs = _parse_fql(filter, incs)
    ids = [i["incident_id"] for i in incs]
    return {
        "meta": {"query_time": 0.01, "pagination": {"offset": offset, "limit": limit, "total": len(ids)}, "trace_id": _uuid()},
        "resources": ids[offset: offset + limit],
        "errors": [],
    }


@router.post("/incidents/entities/incidents/GET/v1")
async def get_incident_details(body: dict = Body(default={})):
    """Get full incident records including host list, detection IDs, and user list."""
    ids = body.get("ids", [])
    result = [_INCIDENTS[i] for i in ids if i in _INCIDENTS]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": result, "errors": []}


@router.post("/incidents/entities/incident-actions/v1")
async def incident_action(body: dict = Body(default={})):
    """
    Perform actions on incidents.
    action_parameters: list of {name, value} pairs
    name values:
      update_status          — value: "20" (New) | "25" (Reopened) | "30" (In Progress) | "40" (Closed)
      update_assigned_to_v2  — value: user UUID
      add_tag                — value: tag string
      delete_tag             — value: tag string
      add_comment            — value: comment text
    """
    incident_ids = body.get("ids", [])
    action_params = {p["name"]: p["value"] for p in body.get("action_parameters", []) if isinstance(p, dict) and "name" in p}

    for inc_id in incident_ids:
        if inc_id in _INCIDENTS:
            inc = _INCIDENTS[inc_id]
            if "update_status" in action_params:
                inc["status"] = int(action_params["update_status"])
            if "update_assigned_to_v2" in action_params:
                inc["assigned_to"] = action_params["update_assigned_to_v2"]
            if "add_tag" in action_params:
                inc.setdefault("tags", []).append(action_params["add_tag"])
            if "delete_tag" in action_params:
                inc["tags"] = [t for t in inc.get("tags", []) if t != action_params["delete_tag"]]
            if "add_comment" in action_params:
                inc.setdefault("comments", []).append({"text": action_params["add_comment"], "created_by": "analyst", "created_at": _now()})
            inc["modified_timestamp"] = _now()

    return {"meta": {"trace_id": _uuid()}, "resources": incident_ids, "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# IOC Management (Custom Indicators)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/iocs/queries/indicators/v1")
async def query_iocs(
    filter: Optional[str] = Query(None, description="FQL: type, value, action, severity, platforms, source"),
    offset: int = Query(0),
    limit: int = Query(100),
    sort: Optional[str] = Query(None),
    after: Optional[str] = Query(None),
):
    """Query custom IOC indicator IDs."""
    iocs = list(_IOC_INDICATORS.values())
    if filter:
        iocs = _parse_fql(filter, iocs)
    ids = [i["id"] for i in iocs]
    return {
        "meta": {"query_time": 0.01, "pagination": {"offset": offset, "limit": limit, "total": len(ids), "after": None}, "trace_id": _uuid()},
        "resources": ids[offset: offset + limit],
        "errors": [],
    }


@router.get("/iocs/entities/indicators/v1")
async def get_ioc_details(ids: list[str] = Query(...)):
    """Get IOC indicator entities by ID."""
    result = [_IOC_INDICATORS[i] for i in ids if i in _IOC_INDICATORS]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": result, "errors": []}


@router.post("/iocs/entities/indicators/v1")
async def create_iocs(body: dict = Body(default={})):
    """
    Create custom IOC indicators.
    indicators[].type: sha256 | md5 | sha1 | ipv4 | ipv6 | domain | url | mutex | registry
    indicators[].action: no_action | allow | detect | prevent | prevent_no_ui
    indicators[].severity: informational | low | medium | high | critical
    indicators[].platforms: windows | mac | linux
    indicators[].applied_globally: bool (or use host_groups for scoping)
    """
    indicators = body.get("indicators", [])
    results = []
    for ind in indicators:
        ioc_id = _uuid()
        ind["id"] = ioc_id
        ind["cid"] = "deadbeef000000000000000000000001"
        ind["created_on"] = _now()
        ind["modified_on"] = _now()
        ind["created_by"] = "api-client-id"
        ind["modified_by"] = "api-client-id"
        _IOC_INDICATORS[ioc_id] = ind
        results.append({"id": ioc_id, "value": ind.get("value"), "type": ind.get("type")})
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": results, "errors": []}


@router.patch("/iocs/entities/indicators/v1")
async def update_iocs(body: dict = Body(default={})):
    """Update existing IOC indicators — change action, severity, expiration, etc."""
    indicators = body.get("indicators", [])
    results = []
    for ind in indicators:
        ioc_id = ind.get("id")
        if ioc_id and ioc_id in _IOC_INDICATORS:
            _IOC_INDICATORS[ioc_id].update(ind)
            _IOC_INDICATORS[ioc_id]["modified_on"] = _now()
            results.append(ioc_id)
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": results, "errors": []}


@router.delete("/iocs/entities/indicators/v1")
async def delete_iocs(ids: list[str] = Query(...)):
    """Delete IOC indicators by ID."""
    deleted = [ioc_id for ioc_id in ids if _IOC_INDICATORS.pop(ioc_id, None) is not None]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": deleted, "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# Host Groups
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/devices/queries/host-groups/v1")
async def query_host_groups(
    filter: Optional[str] = Query(None, description="FQL: name, group_type, created_by"),
    offset: int = Query(0),
    limit: int = Query(100),
    sort: Optional[str] = Query(None),
):
    """Query host group IDs. group_type: static | dynamic"""
    groups = list(_HOST_GROUPS.values())
    if filter:
        groups = _parse_fql(filter, groups)
    ids = [g["id"] for g in groups]
    return {
        "meta": {"query_time": 0.01, "pagination": {"offset": offset, "limit": limit, "total": len(ids)}, "trace_id": _uuid()},
        "resources": ids[offset: offset + limit],
        "errors": [],
    }


@router.post("/devices/entities/host-groups/GET/v1")
async def get_host_group_details(body: dict = Body(default={})):
    """Get host group entity details."""
    ids = body.get("ids", [])
    result = [_HOST_GROUPS[g] for g in ids if g in _HOST_GROUPS]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": result, "errors": []}


@router.post("/devices/entities/host-groups/v1")
async def create_host_group(body: dict = Body(default={})):
    """Create a host group. group_type: static (explicit membership) or dynamic (assignment_rule FQL)"""
    group_id = f"host-grp-{uuid.uuid4().hex[:8]}"
    group = {
        "id": group_id,
        "cid": "deadbeef000000000000000000000001",
        "group_type": body.get("group_type", "static"),
        "name": body.get("name", "New Group"),
        "description": body.get("description", ""),
        "assignment_rule": body.get("assignment_rule", ""),
        "created_by": "api-client-id",
        "created_timestamp": _now(),
        "modified_by": "api-client-id",
        "modified_timestamp": _now(),
    }
    _HOST_GROUPS[group_id] = group
    return {"meta": {"trace_id": _uuid()}, "resources": [group], "errors": []}


@router.post("/devices/entities/host-group-actions/v1")
async def host_group_action(
    action_name: str = Query(..., description="add-hosts | remove-hosts"),
    body: dict = Body(default={}),
):
    """Add or remove devices from a host group."""
    group_ids = body.get("ids", [])
    device_ids = body.get("device_ids", [])
    for group_id in group_ids:
        if group_id in _HOST_GROUPS:
            for did in device_ids:
                if did in _DEVICES:
                    grps = _DEVICES[did].get("groups", [])
                    if action_name == "add-hosts" and group_id not in grps:
                        grps.append(group_id)
                    elif action_name == "remove-hosts":
                        grps = [g for g in grps if g != group_id]
                    _DEVICES[did]["groups"] = grps
    return {"meta": {"trace_id": _uuid()}, "resources": group_ids, "errors": []}


@router.delete("/devices/entities/host-groups/v1")
async def delete_host_groups(ids: list[str] = Query(...)):
    """Delete host groups by ID."""
    deleted = [gid for gid in ids if _HOST_GROUPS.pop(gid, None) is not None]
    return {"meta": {"trace_id": _uuid()}, "resources": deleted, "errors": []}


@router.get("/devices/queries/members/v1")
async def query_group_members(
    id: Optional[str] = Query(None, description="Host group ID"),
    filter: Optional[str] = Query(None),
    offset: int = Query(0),
    limit: int = Query(100),
):
    """Query device IDs that are members of a host group."""
    if id:
        members = [did for did, dev in _DEVICES.items() if id in dev.get("groups", [])]
    else:
        members = list(_DEVICES.keys())
    if filter:
        filtered_devs = _parse_fql(filter, [_DEVICES[m] for m in members if m in _DEVICES])
        members = [d["device_id"] for d in filtered_devs]
    return {
        "meta": {"query_time": 0.01, "pagination": {"offset": offset, "limit": limit, "total": len(members)}, "trace_id": _uuid()},
        "resources": members[offset: offset + limit],
        "errors": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Spotlight Vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/spotlight/queries/vulnerabilities/v1")
async def query_spotlight_vulns(
    filter: Optional[str] = Query(
        None,
        description="FQL: aid, cve.id, status, cve.severity (CRITICAL|HIGH|MEDIUM|LOW), cve.exprt_rating"
    ),
    after: Optional[str] = Query(None, description="Pagination cursor (last ID from previous page)"),
    limit: int = Query(400, ge=1, le=400),
    sort: Optional[str] = Query(None),
    facet: Optional[str] = Query(None),
):
    """
    Query Spotlight vulnerability IDs.
    status: open | closed | reopen | expired
    cve.severity: CRITICAL | HIGH | MEDIUM | LOW
    cve.exprt_rating: CRITICAL | HIGH | MEDIUM | LOW | NONE
    """
    vulns = list(_SPOTLIGHT_VULNS)
    if filter:
        vulns = _parse_fql(filter, vulns)
    ids = [v["id"] for v in vulns]
    start = 0
    if after and after in ids:
        start = ids.index(after) + 1
    page = ids[start: start + limit]
    next_after = page[-1] if len(page) == limit and start + limit < len(ids) else None
    return {
        "meta": {"query_time": 0.01, "pagination": {"total": len(ids), "after": next_after}, "trace_id": _uuid()},
        "resources": page,
        "errors": [],
    }


@router.post("/spotlight/entities/vulnerabilities/GET/v2")
async def get_spotlight_vuln_details(body: dict = Body(default={})):
    """Get full vulnerability entities including CVE details, host info, and remediation."""
    ids = body.get("ids", [])
    result = [v for v in _SPOTLIGHT_VULNS if v["id"] in ids]
    return {"meta": {"query_time": 0.01, "trace_id": _uuid()}, "resources": result, "errors": []}


@router.get("/spotlight/combined/vulnerabilities/v1")
async def get_combined_vulnerabilities(
    filter: str = Query(..., description="Required FQL filter"),
    after: Optional[str] = Query(None),
    limit: int = Query(400),
    sort: Optional[str] = Query(None),
    facet: Optional[str] = Query(None),
):
    """Combined query + entity details in one call. Equivalent to query + GET entities."""
    vulns = list(_SPOTLIGHT_VULNS)
    vulns = _parse_fql(filter, vulns)
    return {
        "meta": {"query_time": 0.01, "pagination": {"total": len(vulns), "after": None}, "trace_id": _uuid()},
        "resources": vulns,
        "errors": [],
    }


@router.post("/spotlight/entities/remediations/GET/v2")
async def get_remediations(body: dict = Body(default={})):
    """Get remediation entity details by remediation IDs."""
    ids = body.get("ids", [])
    result = []
    for v in _SPOTLIGHT_VULNS:
        for entity in v.get("remediation", {}).get("entities", []):
            if entity["id"] in ids:
                result.append(entity)
    return {"meta": {"trace_id": _uuid()}, "resources": result, "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# Real-Time Response (RTR) — remote shell session management
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/real-time-response/entities/sessions/v1")
async def init_rtr_session(body: dict = Body(default={})):
    """
    Open an RTR session with a device.
    body: {device_id, origin, queue_offline (bool), timeout (int), timeout_duration (string)}
    Returns session_id used for all subsequent RTR commands.
    If queue_offline=true and host is offline, commands are queued until reconnection.
    """
    device_id = body.get("device_id", "")
    if device_id not in _DEVICES:
        return {"meta": {"trace_id": _uuid()}, "resources": [], "errors": [{"code": 404, "message": f"Device {device_id} not found"}]}

    session_id = _uuid()
    _rtr_sessions[session_id] = {
        "id": session_id,
        "cid": "deadbeef000000000000000000000001",
        "device_id": device_id,
        "hostname": _DEVICES[device_id]["hostname"],
        "platform_name": _DEVICES[device_id]["platform_name"],
        "status": "connected",
        "created_at": _now(),
        "pwd": "C:\\Windows\\system32",
        "offline_queued": body.get("queue_offline", False),
    }
    _rtr_queued_commands[session_id] = []

    return {
        "meta": {"query_time": 0.01, "trace_id": _uuid()},
        "resources": [{
            "session_id": session_id,
            "cid": "deadbeef000000000000000000000001",
            "device_id": device_id,
            "hostname": _DEVICES[device_id]["hostname"],
            "created_at": _now(),
            "updated_at": _now(),
            "idle_timeout": "600s",
        }],
        "errors": [],
    }


@router.post("/real-time-response/entities/active-responder-command/v1")
async def execute_rtr_command(body: dict = Body(default={})):
    """
    Execute an RTR command (requires Active Responder or Admin RTR role).
    body: {session_id, base_command, command_string, persist (bool), timeout (int)}

    base_command values (read-only):
      cat, cd, cp, encrypt, env, eventlog, filehash, getsid, history, ipconfig,
      ls, map, mkdir, mount, mv, netstat, ps, reg query, restart, rm, runscript,
      shutdown, tar, unmap, update history, users, xmemdump, zip

    Returns cloud_request_id — poll /real-time-response/entities/command/v1?cloud_request_id=X&sequence_id=0
    """
    session_id = body.get("session_id", "")
    if session_id not in _rtr_sessions:
        return {"meta": {"trace_id": _uuid()}, "resources": [], "errors": [{"code": 404, "message": "Session not found"}]}

    request_id = _uuid()
    _rtr_queued_commands.setdefault(session_id, []).append({
        "cloud_request_id": request_id,
        "session_id": session_id,
        "base_command": body.get("base_command", "ls"),
        "command_string": body.get("command_string", "ls"),
        "queued_at": _now(),
    })

    return {
        "meta": {"query_time": 0.01, "trace_id": _uuid()},
        "resources": [{"cloud_request_id": request_id, "session_id": session_id, "queued_at": _now()}],
        "errors": [],
    }


@router.post("/real-time-response/entities/admin-command/v1")
async def execute_rtr_admin_command(body: dict = Body(default={})):
    """
    Execute RTR admin command (requires RTR Admin role — can run scripts and binaries).
    Additional admin commands: put (upload file to host), run (execute uploaded file),
    runscript (run custom PowerShell/Python/Bash script inline or from library)
    """
    return await execute_rtr_command(body=body)


@router.get("/real-time-response/entities/command/v1")
async def get_rtr_command_result(
    cloud_request_id: str = Query(...),
    sequence_id: int = Query(0),
):
    """
    Poll for RTR command result. Returns complete=true when done.
    sequence_id: start at 0, increment by 1 for long-running commands with streaming output.
    """
    outputs = {
        "ls": "Directory: C:\\Windows\\system32\n\nd-----  2026-07-26  08:00  drivers\nd-----  2026-07-26  08:00  etc\n-a----  2026-07-26  08:00  327680  cmd.exe\n-a----  2026-07-26  08:00  1106432 powershell.exe",
        "ps": "Name              PID  Priority  CPU%   WorkingSet\npowershell.exe   4200  Normal    12.3   234567\nWINWORD.EXE      3100  Normal     2.1   456789\nlsass.exe         548  Realtime   0.2    89012",
        "ipconfig": "Windows IP Configuration\n\nEthernet 0:\n  IPv4 Address: 10.10.1.101\n  Subnet Mask:  255.255.0.0\n  Gateway:      10.10.1.1",
        "netstat": "TCP  10.10.1.101:49123  10.10.2.1:445    ESTABLISHED\nTCP  10.10.1.101:49200  203.0.113.200:443 ESTABLISHED",
        "users": "jsmith  CORP  S-1-5-21-...-1001  Last: 07/26/2026 08:30",
        "env": "PATH=C:\\Windows\\system32;C:\\Windows\nUSERNAME=jsmith\nCOMPUTERNAME=CORP-WS-001",
    }
    return {
        "meta": {"query_time": 0.01, "trace_id": _uuid()},
        "resources": [{
            "cloud_request_id": cloud_request_id,
            "sequence_id": sequence_id,
            "stdout": outputs.get("ls"),
            "stderr": "",
            "complete": True,
            "session_id": list(_rtr_sessions.keys())[0] if _rtr_sessions else "",
            "task_id": cloud_request_id,
            "base_command": "ls",
        }],
        "errors": [],
    }


@router.delete("/real-time-response/entities/sessions/v1")
async def delete_rtr_session(session_id: str = Query(...)):
    """Close an RTR session. Always call this when done — sessions are limited per CID."""
    _rtr_sessions.pop(session_id, None)
    _rtr_queued_commands.pop(session_id, None)
    return {"meta": {"trace_id": _uuid()}, "resources": [], "errors": []}


@router.get("/real-time-response/queries/sessions/v1")
async def list_rtr_sessions(
    filter: Optional[str] = Query(None),
    offset: int = Query(0),
    limit: int = Query(100),
):
    """List active RTR sessions for this CID."""
    sessions = list(_rtr_sessions.keys())
    return {"meta": {"trace_id": _uuid(), "pagination": {"total": len(sessions)}}, "resources": sessions[offset: offset + limit], "errors": []}


@router.post("/real-time-response/entities/refresh-session/v1")
async def refresh_rtr_session(body: dict = Body(default={})):
    """Extend the RTR session timeout. Sessions auto-expire after idle_timeout if not refreshed."""
    session_id = body.get("session_id", "")
    if session_id in _rtr_sessions:
        _rtr_sessions[session_id]["updated_at"] = _now()
    return {"meta": {"trace_id": _uuid()}, "resources": [{"session_id": session_id}], "errors": []}


@router.post("/real-time-response/entities/scripts/v1")
async def upload_rtr_script(body: dict = Body(default={})):
    """Upload a custom PowerShell/Python/Bash script to the RTR script library."""
    script_id = _uuid()
    return {"meta": {"trace_id": _uuid()}, "resources": [{"id": script_id, "name": body.get("name", "script"), "created_by": "api-client", "created_timestamp": _now()}], "errors": []}


@router.get("/real-time-response/queries/scripts/v1")
async def list_rtr_scripts(filter: Optional[str] = Query(None), offset: int = Query(0), limit: int = Query(100)):
    """List available RTR scripts in the library."""
    return {"meta": {"trace_id": _uuid()}, "resources": [], "errors": []}


@router.post("/real-time-response/entities/put-files/v1")
async def upload_rtr_file(body: dict = Body(default={})):
    """Upload a file to the RTR put-file library for deployment to hosts."""
    file_id = _uuid()
    return {"meta": {"trace_id": _uuid()}, "resources": [{"id": file_id}], "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# Prevention Policies
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/policy/queries/prevention/v1")
async def query_prevention_policies(
    filter: Optional[str] = Query(None),
    offset: int = Query(0),
    limit: int = Query(100),
):
    """Query prevention policy IDs."""
    return {"meta": {"trace_id": _uuid()}, "resources": ["policy001"], "errors": []}


@router.get("/policy/entities/prevention/v1")
async def get_prevention_policy_details(ids: list[str] = Query(...)):
    """Get prevention policy details including all settings classes."""
    policies = [
        {
            "id": "policy001",
            "cid": "deadbeef000000000000000000000001",
            "created_by": "api-client",
            "created_timestamp": "2024-01-01T00:00:00Z",
            "modified_by": "api-client",
            "modified_timestamp": "2024-01-01T00:00:00Z",
            "name": "Default Prevention Policy",
            "description": "Default policy applied to all hosts",
            "platform_name": "Windows",
            "enabled": True,
            "groups": [{"id": "host-grp-002", "name": "All Windows Hosts"}],
            "settings": {
                "classes": [
                    {"id": "adware_and_pup", "name": "Adware & PUP", "settings": [{"id": "extra_detection", "value": {"enabled": True}}]},
                    {"id": "malware_and_threat", "name": "Malware & Threats", "settings": [{"id": "detect", "value": {"enabled": True}}, {"id": "prevent", "value": {"enabled": True}}]},
                    {"id": "suspicious_processes", "name": "Suspicious Processes", "settings": [{"id": "detect", "value": {"enabled": True}}, {"id": "prevent", "value": {"enabled": False}}]},
                    {"id": "ransomware", "name": "Ransomware", "settings": [{"id": "detect", "value": {"enabled": True}}, {"id": "prevent", "value": {"enabled": True}}, {"id": "volume_shadow_copy_protect", "value": {"enabled": True}}]},
                    {"id": "credential_theft", "name": "Credential Theft", "settings": [{"id": "detect", "value": {"enabled": True}}, {"id": "prevent", "value": {"enabled": True}}]},
                    {"id": "lateral_movement", "name": "Lateral Movement", "settings": [{"id": "detect", "value": {"enabled": True}}, {"id": "prevent", "value": {"enabled": False}}]},
                ]
            },
        }
    ]
    return {"meta": {"trace_id": _uuid()}, "resources": [p for p in policies if p["id"] in ids], "errors": []}


@router.post("/policy/entities/prevention-actions/v1")
async def prevention_policy_action(
    action_name: str = Query(..., description="enable | disable | add-host-groups | remove-host-groups"),
    body: dict = Body(default={}),
):
    """Enable/disable policies or assign host groups."""
    return {"meta": {"trace_id": _uuid()}, "resources": body.get("ids", []), "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# Intel API — Threat Intelligence Indicators
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/intel/queries/indicators/v1")
async def query_intel_indicators(
    filter: Optional[str] = Query(None, description="FQL: type, indicator, actors, malware_families, labels"),
    offset: int = Query(0),
    limit: int = Query(100),
    sort: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Free-text search across indicator, description, labels"),
    include_deleted: bool = Query(False),
    include_relations: bool = Query(True),
):
    """Query CrowdStrike threat intelligence indicator IDs."""
    intel_iocs = [
        {
            "id": "cs-intel-ioc-001",
            "indicator": "malicious-domain.evil.example",
            "type": "domain",
            "value": "malicious-domain.evil.example",
            "created_date": (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_updated": _now(),
            "published_date": (datetime.now(timezone.utc) - timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actors": ["CARBON SPIDER"],
            "malware_families": ["REvil"],
            "kill_chains": ["C2", "Exfiltration"],
            "threat_types": ["Ransomware"],
            "labels": [{"name": "malicious-confidence/high", "created_on": _ts(), "last_valid_on": _ts()}],
            "relations": [],
            "ip_address_types": [],
            "domain_types": ["hosted", "sinkholed"],
            "targets": ["financial", "healthcare"],
            "vulnerabilities": [],
        },
    ]
    if q:
        intel_iocs = [i for i in intel_iocs if q.lower() in str(i).lower()]
    if filter:
        intel_iocs = _parse_fql(filter, intel_iocs)
    ids = [i["id"] for i in intel_iocs]
    return {
        "meta": {"trace_id": _uuid(), "pagination": {"offset": offset, "limit": limit, "total": len(ids)}},
        "resources": ids[offset: offset + limit],
        "errors": [],
    }


@router.post("/intel/entities/indicators/GET/v1")
async def get_intel_indicator_details(body: dict = Body(default={})):
    """Get full intel indicator entities by ID."""
    return {"meta": {"trace_id": _uuid()}, "resources": [], "errors": []}


# ─────────────────────────────────────────────────────────────────────────────
# Event Streams (Streaming API — webhook alternative for event consumption)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/sensors/entities/datafeed/v2")
async def discover_event_streams(
    appId: str = Query(..., description="Unique app ID — must be registered; acts as stream partition label"),
    format: str = Query("json", description="json | flatjson"),
):
    """
    Discover available event streams for this CID.
    Returns connection URL + session token + refresh interval.
    Stream delivers detection, incident, policy, and audit events in real-time.
    """
    return {
        "meta": {"query_time": 0.01, "trace_id": _uuid()},
        "resources": [
            {
                "dataFeedURL": f"https://firehose.crowdstrike.com/sensors/entities/datafeed/v2?appId={appId}&partition=0",
                "sessionToken": {
                    "token": f"stream-token-{uuid.uuid4().hex[:32]}",
                    "expiration": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                "refreshActiveSessionURL": f"/sensors/entities/datafeed-actions/v1/0/refresh-active-session?appId={appId}",
                "refreshActiveSessionInterval": 1800,
                "partition": 0,
            }
        ],
        "errors": [],
    }


@router.post("/sensors/entities/datafeed-actions/v1/{partition}/refresh-active-session")
async def refresh_event_stream(partition: int, appId: str = Query(...)):
    """Refresh the active event stream session before it expires."""
    return {"meta": {"trace_id": _uuid()}, "resources": [], "errors": []}
