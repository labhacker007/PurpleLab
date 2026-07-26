"""Tenable.io REST API emulation.

Grounded in official Tenable.io API Reference:
  https://developer.tenable.com/reference/navigate

Implements:
  Assets API (/assets)
  Workbench API (/workbenches/vulnerabilities, /workbenches/assets)
  Scans API (/scans)
  Export API (/vulns/export, /assets/export) — async chunked pipeline
  Plugins API (/plugins)
  Tags API (/tags)
  Network API (/networks)

Authentication:
  X-ApiKeys: accessKey=<key>;secretKey=<secret>

Response patterns:
  - Most list endpoints return {data: [...], pagination: {offset, limit, total}}
  - Export pipeline: POST → uuid, GET status (PROCESSING/FINISHED), GET chunk
  - Asset IDs are UUID strings
  - Vuln severity: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Path, Query, Request

router = APIRouter(prefix="/api/vendor/tenable", tags=["vendor:tenable"])


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat() + "Z"


def _uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Seed data
# ─────────────────────────────────────────────────────────────────────────────

_ASSETS: list[dict] = [
    {
        "id": "a1b2c3d4-0001-0000-0000-000000000001",
        "has_agent": True,
        "has_plugin_results": True,
        "created_at": "2024-01-15T08:00:00.000Z",
        "updated_at": _now_iso(),
        "last_seen": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
        "last_scan_target": "10.10.1.101",
        "last_schedule_scan_date": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "last_licensed_scan_date": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "last_authenticated_scan_date": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "ipv4s": ["10.10.1.101"],
        "ipv6s": [],
        "fqdns": ["corp-ws-001.corp.local"],
        "hostnames": ["corp-ws-001"],
        "netbios_names": ["CORP-WS-001"],
        "mac_addresses": ["AA:BB:CC:DD:EE:01"],
        "operating_systems": ["Windows 11 Enterprise 22H2"],
        "system_types": ["general-purpose"],
        "agent_names": ["nessus-agent-ws001"],
        "tags": [
            {"tag_uuid": "t1b2c3d4-0001-0000-0000-000000000001", "tag_key": "Environment", "tag_value": "production"},
            {"tag_uuid": "t1b2c3d4-0001-0000-0000-000000000002", "tag_key": "Department", "tag_value": "Engineering"},
        ],
        "network_interfaces": [{"name": "Ethernet", "mac_addresses": ["AA:BB:CC:DD:EE:01"], "ipv4s": ["10.10.1.101"], "ipv6s": [], "fqdns": ["corp-ws-001.corp.local"]}],
        "vulnerability_count": 47,
        "network_id": "00000000-0000-0000-0000-000000000000",
        "agent_uuid": "ag1b2c3d4-0001-0000-0000-000000000001",
        "bios_uuid": "b1234567-1234-1234-1234-123456789001",
    },
    {
        "id": "a1b2c3d4-0002-0000-0000-000000000002",
        "has_agent": True,
        "has_plugin_results": True,
        "created_at": "2023-06-01T10:00:00.000Z",
        "updated_at": _now_iso(),
        "last_seen": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat() + "Z",
        "last_scan_target": "10.10.2.10",
        "last_schedule_scan_date": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat() + "Z",
        "last_licensed_scan_date": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat() + "Z",
        "last_authenticated_scan_date": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat() + "Z",
        "ipv4s": ["10.10.2.10"],
        "ipv6s": [],
        "fqdns": ["corp-srv-001.corp.local"],
        "hostnames": ["corp-srv-001"],
        "netbios_names": ["CORP-SRV-001"],
        "mac_addresses": ["AA:BB:CC:DD:EE:10"],
        "operating_systems": ["Windows Server 2022 Standard 21H2"],
        "system_types": ["server"],
        "agent_names": ["nessus-agent-srv001"],
        "tags": [
            {"tag_uuid": "t1b2c3d4-0001-0000-0000-000000000001", "tag_key": "Environment", "tag_value": "production"},
            {"tag_uuid": "t1b2c3d4-0001-0000-0000-000000000003", "tag_key": "Criticality", "tag_value": "High"},
        ],
        "network_interfaces": [{"name": "Ethernet0", "mac_addresses": ["AA:BB:CC:DD:EE:10"], "ipv4s": ["10.10.2.10"], "ipv6s": [], "fqdns": ["corp-srv-001.corp.local"]}],
        "vulnerability_count": 12,
        "network_id": "00000000-0000-0000-0000-000000000000",
        "agent_uuid": "ag1b2c3d4-0002-0000-0000-000000000002",
        "bios_uuid": "b1234567-1234-1234-1234-123456789002",
    },
    {
        "id": "a1b2c3d4-0003-0000-0000-000000000003",
        "has_agent": True,
        "has_plugin_results": True,
        "created_at": "2022-01-10T08:00:00.000Z",
        "updated_at": _now_iso(),
        "last_seen": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z",
        "last_scan_target": "10.10.2.1",
        "last_schedule_scan_date": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "last_licensed_scan_date": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "last_authenticated_scan_date": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "ipv4s": ["10.10.2.1"],
        "ipv6s": [],
        "fqdns": ["corp-dc-001.corp.local"],
        "hostnames": ["corp-dc-001"],
        "netbios_names": ["CORP-DC-001"],
        "mac_addresses": ["AA:BB:CC:DD:EE:20"],
        "operating_systems": ["Windows Server 2022 Datacenter 21H2"],
        "system_types": ["server"],
        "agent_names": ["nessus-agent-dc001"],
        "tags": [
            {"tag_uuid": "t1b2c3d4-0001-0000-0000-000000000001", "tag_key": "Environment", "tag_value": "production"},
            {"tag_uuid": "t1b2c3d4-0001-0000-0000-000000000003", "tag_key": "Criticality", "tag_value": "Critical"},
            {"tag_uuid": "t1b2c3d4-0001-0000-0000-000000000004", "tag_key": "Role", "tag_value": "Domain Controller"},
        ],
        "network_interfaces": [{"name": "Ethernet0", "mac_addresses": ["AA:BB:CC:DD:EE:20"], "ipv4s": ["10.10.2.1"], "ipv6s": [], "fqdns": ["corp-dc-001.corp.local"]}],
        "vulnerability_count": 8,
        "network_id": "00000000-0000-0000-0000-000000000000",
        "agent_uuid": "ag1b2c3d4-0003-0000-0000-000000000003",
        "bios_uuid": "b1234567-1234-1234-1234-123456789003",
    },
]

_PLUGINS: dict[int, dict] = {
    214928: {
        "id": 214928, "name": "Microsoft Outlook RCE Vulnerability (CVE-2024-21413)",
        "family_name": "Windows : Microsoft Bulletins",
        "attributes": [
            {"attribute_name": "cvss3_base_score", "attribute_value": "9.8"},
            {"attribute_name": "cvss3_vector", "attribute_value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"attribute_name": "cvss_base_score", "attribute_value": "10.0"},
            {"attribute_name": "solution", "attribute_value": "Microsoft has released security updates. Apply the appropriate update for your version."},
            {"attribute_name": "description", "attribute_value": "A remote code execution vulnerability exists in Microsoft Outlook when it fails to properly handle objects in memory. An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the current user."},
            {"attribute_name": "synopsis", "attribute_value": "The remote host is missing a security update."},
            {"attribute_name": "risk_factor", "attribute_value": "Critical"},
            {"attribute_name": "see_also", "attribute_value": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"},
            {"attribute_name": "xref", "attribute_value": "CVE:CVE-2024-21413, IAVA:2024-A-0076-S, MSFT:MS24-5034671"},
            {"attribute_name": "patch_publication_date", "attribute_value": "2024/02/13"},
            {"attribute_name": "plugin_publication_date", "attribute_value": "2024/02/13"},
            {"attribute_name": "plugin_modification_date", "attribute_value": "2024/02/14"},
            {"attribute_name": "cpe", "attribute_value": "cpe:/a:microsoft:outlook"},
            {"attribute_name": "exploit_available", "attribute_value": "true"},
            {"attribute_name": "exploitability_ease", "attribute_value": "Exploits are available"},
            {"attribute_name": "exploit_code_maturity", "attribute_value": "Proof-of-concept exploit"},
            {"attribute_name": "vuln_publication_date", "attribute_value": "2024/02/13"},
        ],
    },
    195539: {
        "id": 195539, "name": "Windows SMB Signing Not Required (MS17-010 variant)",
        "family_name": "Windows",
        "attributes": [
            {"attribute_name": "cvss3_base_score", "attribute_value": "7.5"},
            {"attribute_name": "cvss3_vector", "attribute_value": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"attribute_name": "risk_factor", "attribute_value": "High"},
            {"attribute_name": "description", "attribute_value": "The remote Windows host does not enforce SMB signing. A man-in-the-middle attacker could exploit this to conduct NTLM relay attacks."},
            {"attribute_name": "solution", "attribute_value": "Enable SMB signing via Group Policy."},
        ],
    },
    56984: {
        "id": 56984, "name": "SSL / TLS Versions Supported",
        "family_name": "General",
        "attributes": [
            {"attribute_name": "risk_factor", "attribute_value": "Info"},
            {"attribute_name": "description", "attribute_value": "Reports the SSL/TLS versions and cipher suites accepted by the remote service."},
        ],
    },
}

# Vulnerability instances (linked to assets)
_VULNS: list[dict] = [
    {
        "asset": {
            "agent_uuid": "ag1b2c3d4-0001-0000-0000-000000000001",
            "uuid": "a1b2c3d4-0001-0000-0000-000000000001",
            "hostname": "corp-ws-001",
            "ipv4": "10.10.1.101",
            "fqdn": "corp-ws-001.corp.local",
            "operating_system": "Windows 11 Enterprise 22H2",
            "network_id": "00000000-0000-0000-0000-000000000000",
        },
        "output": "Path: C:\\Program Files (x86)\\Microsoft Office\\Office16\\OUTLOOK.EXE\nVersion: 16.0.16827.20166\nFixed version: 16.0.17126.20132",
        "plugin": {
            "bid": [71252],
            "checks_for_default_account": False,
            "checks_for_malware": False,
            "cpe": ["cpe:/a:microsoft:outlook"],
            "cvss3_base_score": 9.8,
            "cvss3_temporal_score": 9.3,
            "cvss3_temporal_vector": "CVSS:3.1/E:F/RL:O/RC:C",
            "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_base_score": 10.0,
            "cvss_temporal_score": 8.7,
            "cvss_temporal_vector": "CVSS:2.0/E:F/RL:OF/RC:C",
            "cvss_vector": "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "description": "A remote code execution vulnerability exists in Microsoft Outlook.",
            "exploit_available": True,
            "exploit_code_maturity": "proof-of-concept",
            "exploitability_ease": "Exploits are available",
            "exploited_by_malware": True,
            "exploited_by_nessus": False,
            "family": "Windows : Microsoft Bulletins",
            "family_id": 56,
            "has_patch": True,
            "id": 214928,
            "in_the_news": True,
            "ms_bulletin": "MS24-5034671",
            "name": "Microsoft Outlook RCE Vulnerability (CVE-2024-21413)",
            "patch_publication_date": "2024-02-13T00:00:00Z",
            "modification_date": "2024-02-14T00:00:00Z",
            "publication_date": "2024-02-13T00:00:00Z",
            "risk_factor": "critical",
            "see_also": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"],
            "solution": "Apply Microsoft security update KB5034671.",
            "synopsis": "The remote host is missing a security update.",
            "type": "local",
            "unsupported_by_vendor": False,
            "version": "1.2",
            "vpr_score": 9.1,
            "vpr_drivers": {
                "age_of_vuln": {"lower_bound": 365},
                "cvss3_impact_score": 5.9,
                "exploit_code_maturity": "proof-of-concept",
                "threat_intensity_last28": "High",
                "threat_recency": "<=7 days",
                "threat_sources_last28": ["social_media"],
                "product_coverage": "high",
            },
            "xrefs": [
                {"type": "CVE", "id": "CVE-2024-21413"},
                {"type": "IAVA", "id": "2024-A-0076-S"},
            ],
        },
        "port": {"port": 0, "protocol": "TCP", "service": "general"},
        "scan": {
            "completed_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
            "schedule_uuid": "scan-sched-uuid-001",
            "started_at": (datetime.now(timezone.utc) - timedelta(hours=2, minutes=30)).isoformat() + "Z",
            "uuid": "scan-uuid-001",
        },
        "severity": "critical",
        "severity_id": 4,
        "severity_default_id": 4,
        "severity_modification_type": "NONE",
        "first_found": "2026-07-20T10:00:00Z",
        "last_found": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "last_fixed": None,
        "state": "open",
        "indexed": _now_iso(),
    },
    {
        "asset": {
            "agent_uuid": "ag1b2c3d4-0001-0000-0000-000000000001",
            "uuid": "a1b2c3d4-0001-0000-0000-000000000001",
            "hostname": "corp-ws-001",
            "ipv4": "10.10.1.101",
            "fqdn": "corp-ws-001.corp.local",
            "operating_system": "Windows 11 Enterprise 22H2",
        },
        "output": "The remote host does not enforce SMB signing.",
        "plugin": {
            "id": 195539,
            "name": "Windows SMB Signing Not Required",
            "family": "Windows",
            "risk_factor": "high",
            "cvss3_base_score": 7.5,
            "cvss3_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "exploit_available": False,
            "has_patch": False,
            "solution": "Enable SMB signing via Group Policy: Require SMB Signing = Enabled",
            "xrefs": [],
            "vpr_score": 6.5,
        },
        "port": {"port": 445, "protocol": "TCP", "service": "smb"},
        "scan": {
            "completed_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
            "uuid": "scan-uuid-001",
            "started_at": (datetime.now(timezone.utc) - timedelta(hours=2, minutes=30)).isoformat() + "Z",
        },
        "severity": "high",
        "severity_id": 3,
        "severity_default_id": 3,
        "severity_modification_type": "NONE",
        "first_found": "2026-06-01T08:00:00Z",
        "last_found": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat() + "Z",
        "last_fixed": None,
        "state": "open",
        "indexed": _now_iso(),
    },
    {
        "asset": {
            "agent_uuid": "ag1b2c3d4-0002-0000-0000-000000000002",
            "uuid": "a1b2c3d4-0002-0000-0000-000000000002",
            "hostname": "corp-srv-001",
            "ipv4": "10.10.2.10",
            "fqdn": "corp-srv-001.corp.local",
            "operating_system": "Windows Server 2022 Standard 21H2",
        },
        "output": "Deprecated TLS version 1.0 accepted.",
        "plugin": {
            "id": 104743,
            "name": "TLS Version 1.0 Protocol Detection",
            "family": "General",
            "risk_factor": "medium",
            "cvss3_base_score": 5.3,
            "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "exploit_available": False,
            "has_patch": False,
            "solution": "Disable TLS 1.0 and enable TLS 1.2 or higher.",
            "xrefs": [],
            "vpr_score": 4.2,
        },
        "port": {"port": 443, "protocol": "TCP", "service": "https"},
        "scan": {
            "completed_at": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat() + "Z",
            "uuid": "scan-uuid-002",
            "started_at": (datetime.now(timezone.utc) - timedelta(hours=4, minutes=20)).isoformat() + "Z",
        },
        "severity": "medium",
        "severity_id": 2,
        "severity_default_id": 2,
        "severity_modification_type": "NONE",
        "first_found": "2025-11-10T08:00:00Z",
        "last_found": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat() + "Z",
        "last_fixed": None,
        "state": "open",
        "indexed": _now_iso(),
    },
]

# Scan objects
_SCANS: dict[str, dict] = {
    "scan-uuid-001": {
        "uuid": "scan-uuid-001",
        "id": 1,
        "name": "Full Corp Network Scan",
        "description": "Weekly authenticated vulnerability scan of all corporate assets",
        "policy_id": 1,
        "scanner_id": 1,
        "scanner_uuid": "scanner-uuid-001",
        "folder_id": 1,
        "type": "ps",
        "status": "completed",
        "scan_type": "remote",
        "creation_date": _now_ts() - 86400 * 7,
        "last_modification_date": _now_ts() - 7200,
        "starttime": "TZID=UTC:20260726T060000Z",
        "timezone": "UTC",
        "enabled": True,
        "rrules": "FREQ=WEEKLY;INTERVAL=1;BYDAY=MO",
        "emails": "security-team@corp.local",
        "shared": True,
        "owner": "admin@corp.local",
        "owner_id": 1,
        "user_permissions": 128,
        "total_targets": 254,
        "read": False,
        "acls": [{"permissions": 128, "owner": 1, "display_name": "admin", "name": "admin", "id": 1, "type": "default"}],
    },
    "scan-uuid-002": {
        "uuid": "scan-uuid-002",
        "id": 2,
        "name": "Server Infrastructure Scan",
        "description": "Daily server patch compliance scan",
        "policy_id": 2,
        "status": "completed",
        "type": "ps",
        "enabled": True,
        "creation_date": _now_ts() - 86400 * 30,
        "last_modification_date": _now_ts() - 14400,
    },
}

# Export job state
_export_jobs: dict[str, dict] = {}

# Tags
_TAGS: list[dict] = [
    {"uuid": "t1b2c3d4-0001-0000-0000-000000000001", "category_uuid": "cat1", "category_name": "Environment", "value": "production", "type": "static", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
    {"uuid": "t1b2c3d4-0001-0000-0000-000000000002", "category_uuid": "cat2", "category_name": "Department", "value": "Engineering", "type": "static", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
    {"uuid": "t1b2c3d4-0001-0000-0000-000000000003", "category_uuid": "cat3", "category_name": "Criticality", "value": "High", "type": "static", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
    {"uuid": "t1b2c3d4-0001-0000-0000-000000000004", "category_uuid": "cat3", "category_name": "Criticality", "value": "Critical", "type": "static", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
    {"uuid": "t1b2c3d4-0001-0000-0000-000000000005", "category_uuid": "cat4", "category_name": "Role", "value": "Domain Controller", "type": "static", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
]


def _filter_vulns(filters: list[dict]) -> list[dict]:
    """Apply Tenable filter objects to vuln list."""
    result = list(_VULNS)
    for f in filters:
        quality = f.get("quality", "eq")
        field = f.get("filter", "")
        value = str(f.get("value", "")).lower()
        if field == "severity":
            sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            sev_id = sev_map.get(value, -1)
            if quality == "eq":
                result = [v for v in result if v.get("severity_id") == sev_id]
            elif quality == "neq":
                result = [v for v in result if v.get("severity_id") != sev_id]
            elif quality == "gte":
                result = [v for v in result if v.get("severity_id", 0) >= sev_id]
        elif field == "plugin.id":
            pid = int(value) if value.isdigit() else -1
            result = [v for v in result if v["plugin"].get("id") == pid]
        elif field == "state":
            result = [v for v in result if v.get("state") == value]
        elif field == "asset.uuid":
            result = [v for v in result if v["asset"].get("uuid") == value]
        elif field == "asset.hostname":
            result = [v for v in result if value in (v["asset"].get("hostname") or "").lower()]
        elif field == "asset.ipv4":
            result = [v for v in result if value in (v["asset"].get("ipv4") or "")]
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/session")
async def create_session(body: dict = Body(default={})):
    """Create an API session (username/password authentication)."""
    return {
        "token": f"tn-session-{uuid.uuid4().hex[:32]}",
        "name": body.get("username", "admin"),
        "email": "admin@corp.local",
        "type": 64,
        "permission": 128,
        "lastlogin": _now_ts(),
        "container_id": 1,
        "groupuuids": [],
    }


@router.get("/session")
async def get_session():
    return {"name": "admin", "email": "admin@corp.local", "type": 64, "permission": 128}


@router.delete("/session")
async def destroy_session():
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Assets API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/assets")
async def list_assets():
    """List all assets. Returns paginated asset list."""
    return {
        "assets": _ASSETS,
        "total": len(_ASSETS),
    }


@router.get("/assets/{asset_uuid}")
async def get_asset(asset_uuid: str):
    """Get asset details by UUID."""
    a = next((a for a in _ASSETS if a["id"] == asset_uuid), None)
    if not a:
        raise HTTPException(404, {"statusCode": 404, "error": "Not Found", "message": f"Asset '{asset_uuid}' not found."})
    return a


@router.get("/assets/{asset_uuid}/vulnerabilities")
async def get_asset_vulns(
    asset_uuid: str,
    severity: Optional[str] = Query(None, description="critical,high,medium,low,info"),
):
    """Get all vulnerabilities for a specific asset."""
    vulns = [v for v in _VULNS if v["asset"].get("uuid") == asset_uuid]
    if severity:
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sev_ids = {sev_map.get(s.strip(), -1) for s in severity.split(",")}
        vulns = [v for v in vulns if v.get("severity_id") in sev_ids]
    return {
        "vulnerabilities": [{"plugin_id": v["plugin"]["id"], "plugin_name": v["plugin"]["name"],
                             "plugin_family": v["plugin"]["family"],
                             "count": 1, "vulnerability_state": v["state"],
                             "severity": v["severity_id"],
                             "vpr_score": v["plugin"].get("vpr_score")} for v in vulns],
        "total": len(vulns),
    }


@router.post("/assets/bulk-actions/move-to-network")
async def move_assets_network(body: dict = Body(default={})):
    return {"request_uuid": _uuid(), "num_assets_updated": len(body.get("asset_uuids", []))}


@router.post("/assets/bulk-actions/delete")
async def bulk_delete_assets(body: dict = Body(default={})):
    return {"request_uuid": _uuid()}


@router.post("/assets/import")
async def import_assets(body: dict = Body(default={})):
    """Import assets with custom attributes."""
    return {"task_uuid": _uuid()}


# ─────────────────────────────────────────────────────────────────────────────
# Workbenches API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/workbenches/assets")
async def workbench_assets(
    date_range: int = Query(30, description="Days back to include"),
    filters: Optional[str] = Query(None),
    filter_search_type: str = Query("and"),
    offset: int = Query(0),
    limit: int = Query(100),
):
    """Asset workbench — all assets with vulnerability counts."""
    return {
        "total": len(_ASSETS),
        "assets": [
            {
                **a,
                "counts": {
                    "vulnerabilities": {
                        "total": a["vulnerability_count"],
                        "severities": [
                            {"count": 1, "level": 4, "name": "Critical"},
                            {"count": 2, "level": 3, "name": "High"},
                            {"count": a["vulnerability_count"] - 3, "level": 2, "name": "Medium"},
                        ]
                    }
                }
            }
            for a in _ASSETS[offset: offset + limit]
        ],
    }


@router.get("/workbenches/assets/{asset_uuid}/vulnerabilities")
async def workbench_asset_vulns(
    asset_uuid: str,
    date_range: int = Query(30),
    offset: int = Query(0),
    limit: int = Query(100),
):
    """All vulnerabilities on a specific asset."""
    vulns = [v for v in _VULNS if v["asset"].get("uuid") == asset_uuid]
    return {
        "total": len(vulns),
        "vulnerabilities": vulns[offset: offset + limit],
    }


@router.get("/workbenches/assets/{asset_uuid}/vulnerabilities/{plugin_id}/outputs")
async def workbench_vuln_outputs(asset_uuid: str, plugin_id: int):
    """Detailed plugin output for a specific vuln on an asset."""
    v = next((x for x in _VULNS if x["asset"].get("uuid") == asset_uuid and x["plugin"].get("id") == plugin_id), None)
    if not v:
        raise HTTPException(404, {"error": "Vulnerability not found"})
    return {
        "outputs": [{
            "plugin_output": v["output"],
            "states": [{"name": v["state"], "results": [{"application_protocol": v["port"]["service"], "port": v["port"]["port"], "transport_protocol": v["port"]["protocol"], "assets": [{"hostname": v["asset"]["hostname"], "id": v["asset"]["uuid"], "ipv4": v["asset"]["ipv4"]}]}]}],
        }]
    }


@router.get("/workbenches/vulnerabilities")
async def workbench_vulns(
    date_range: int = Query(30),
    offset: int = Query(0),
    limit: int = Query(100),
    sort_field: str = Query("severity"),
    sort_order: str = Query("desc"),
    filter_search_type: str = Query("and"),
):
    """All vulnerabilities across all assets."""
    vulns = list(_VULNS)
    # Sort by severity (desc by default)
    if sort_order == "desc":
        vulns = sorted(vulns, key=lambda v: v.get("severity_id", 0), reverse=True)
    return {
        "total": len(vulns),
        "vulnerabilities": vulns[offset: offset + limit],
    }


@router.get("/workbenches/vulnerabilities/{plugin_id}/outputs")
async def workbench_plugin_outputs(plugin_id: int, date_range: int = Query(30)):
    """All affected assets and outputs for a plugin."""
    vulns = [v for v in _VULNS if v["plugin"].get("id") == plugin_id]
    return {
        "outputs": [
            {
                "plugin_output": v["output"],
                "states": [{"name": v["state"], "results": [{"application_protocol": v["port"]["service"], "port": v["port"]["port"], "transport_protocol": v["port"]["protocol"], "assets": [{"hostname": v["asset"]["hostname"], "id": v["asset"]["uuid"], "ipv4": v["asset"].get("ipv4")}]}]}],
            }
            for v in vulns
        ]
    }


@router.get("/workbenches/assets/{asset_uuid}/info")
async def workbench_asset_info(asset_uuid: str, date_range: int = Query(30)):
    """Get detailed asset info from workbench."""
    a = next((a for a in _ASSETS if a["id"] == asset_uuid), None)
    if not a:
        raise HTTPException(404, {"error": "Asset not found"})
    vulns_on_asset = [v for v in _VULNS if v["asset"].get("uuid") == asset_uuid]
    return {
        "info": {
            **a,
            "acls": [],
            "counts": {
                "audits": {"total": 0, "statuses": []},
                "vulnerabilities": {"total": len(vulns_on_asset), "severities": [
                    {"count": sum(1 for v in vulns_on_asset if v["severity_id"] == 4), "level": 4, "name": "Critical"},
                    {"count": sum(1 for v in vulns_on_asset if v["severity_id"] == 3), "level": 3, "name": "High"},
                    {"count": sum(1 for v in vulns_on_asset if v["severity_id"] == 2), "level": 2, "name": "Medium"},
                    {"count": sum(1 for v in vulns_on_asset if v["severity_id"] == 1), "level": 1, "name": "Low"},
                    {"count": sum(1 for v in vulns_on_asset if v["severity_id"] == 0), "level": 0, "name": "Info"},
                ]},
            },
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scans API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scans")
async def list_scans(folder_id: Optional[int] = Query(None)):
    """List all scans."""
    scans = list(_SCANS.values())
    return {
        "scans": scans,
        "folders": [
            {"id": 1, "name": "My Scans", "type": "main", "default_tag": 0, "custom": 0},
            {"id": 2, "name": "Trash", "type": "trash", "default_tag": 0, "custom": 0},
        ],
        "timestamp": _now_ts(),
    }


@router.post("/scans")
async def create_scan(body: dict = Body(default={})):
    """Create a new scan."""
    scan_uuid = _uuid()
    scan_id = max(s["id"] for s in _SCANS.values()) + 1
    new_scan = {
        "uuid": scan_uuid,
        "id": scan_id,
        "name": body.get("settings", {}).get("name", "New Scan"),
        "description": body.get("settings", {}).get("description", ""),
        "status": "empty",
        "type": body.get("uuid", "ps"),
        "enabled": True,
        "creation_date": _now_ts(),
        "last_modification_date": _now_ts(),
        "owner": "admin@corp.local",
    }
    _SCANS[scan_uuid] = new_scan
    return {"scan": new_scan}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details including hosts and results."""
    # Find by UUID or numeric ID
    scan = _SCANS.get(scan_id)
    if not scan:
        scan = next((s for s in _SCANS.values() if str(s.get("id")) == scan_id), None)
    if not scan:
        raise HTTPException(404, {"statusCode": 404, "error": "Not Found", "message": f"Scan '{scan_id}' not found."})

    return {
        "info": {**scan, "hasaudittrail": True, "haskb": True, "policyid": scan.get("policy_id", 1), "scanner_name": "Internal Scanner"},
        "hosts": [
            {"host_id": 1, "host_index": 0, "hostname": "corp-ws-001", "progress": "0-1/1", "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0, "severity": 2, "numchecksconsidered": 50},
            {"host_id": 2, "host_index": 1, "hostname": "corp-srv-001", "progress": "0-1/1", "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 2, "severity": 1, "numchecksconsidered": 50},
            {"host_id": 3, "host_index": 2, "hostname": "corp-dc-001", "progress": "0-1/1", "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 3, "severity": 0, "numchecksconsidered": 50},
        ],
        "notes": [],
        "remediations": {"remediations": [], "num_hosts": 3, "num_cves": 2, "num_impacted_hosts": 2, "num_remediated_cves": 0},
        "risks": [],
        "filters": [],
        "history": [{"history_id": 1, "uuid": scan.get("uuid"), "creation_date": scan.get("creation_date"), "last_modification_date": scan.get("last_modification_date"), "status": scan.get("status", "completed"), "type": "local"}],
        "comphosts": [],
        "compliance": [],
        "vulnerabilities": [
            {"plugin_id": v["plugin"]["id"], "plugin_name": v["plugin"]["name"], "plugin_family": v["plugin"]["family"],
             "count": 1, "vuln_index": i, "severity": v["severity_id"], "severity_index": v["severity_id"]}
            for i, v in enumerate(_VULNS)
        ],
    }


@router.post("/scans/{scan_id}/launch")
async def launch_scan(scan_id: str, body: dict = Body(default={})):
    """Launch a scan."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, {"error": "Scan not found"})
    scan["status"] = "running"
    return {"scan_uuid": scan.get("uuid")}


@router.post("/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    scan = _SCANS.get(scan_id)
    if scan:
        scan["status"] = "paused"
    return {}


@router.post("/scans/{scan_id}/resume")
async def resume_scan(scan_id: str):
    scan = _SCANS.get(scan_id)
    if scan:
        scan["status"] = "running"
    return {}


@router.post("/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    scan = _SCANS.get(scan_id)
    if scan:
        scan["status"] = "canceled"
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Export API — asynchronous bulk export pipeline
# POST /vulns/export → uuid → poll status → download chunks
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/vulns/export")
async def export_vulns(body: dict = Body(default={})):
    """
    Initiate a vulnerability export.
    Body: {num_assets_per_chunk, filters: [{filter, quality, value}], include_unlicensed}
    """
    filters = body.get("filters", [])
    vulns = _filter_vulns(filters)
    chunk_size = max(body.get("num_assets_per_chunk", 50), 1)

    export_uuid = _uuid()
    chunks = [vulns[i:i + chunk_size] for i in range(0, max(len(vulns), 1), chunk_size)]

    _export_jobs[export_uuid] = {
        "uuid": export_uuid,
        "status": "FINISHED",  # Instant for simulation
        "chunks_available": list(range(1, len(chunks) + 1)),
        "filters": filters,
        "chunks": {i + 1: chunk for i, chunk in enumerate(chunks)},
        "created": _now_ts(),
    }
    return {"export_uuid": export_uuid}


@router.get("/vulns/export/{export_uuid}/status")
async def get_vuln_export_status(export_uuid: str):
    """Check export job status."""
    job = _export_jobs.get(export_uuid)
    if not job:
        raise HTTPException(404, {"statusCode": 404, "error": "Not Found", "message": "Export job not found."})
    return {
        "uuid": export_uuid,
        "status": job["status"],   # PROCESSING | FINISHED | ERROR | CANCELLED
        "chunks_available": job["chunks_available"],
        "filters": job["filters"],
        "created": job["created"],
        "finished_at": _now_ts() if job["status"] == "FINISHED" else None,
        "total_chunks": len(job["chunks_available"]),
    }


@router.get("/vulns/export/{export_uuid}/chunks/{chunk_id}")
async def download_vuln_chunk(export_uuid: str, chunk_id: int):
    """Download a chunk from an export job. Returns NDJSON."""
    job = _export_jobs.get(export_uuid)
    if not job:
        raise HTTPException(404, {"error": "Export job not found"})
    if chunk_id not in job.get("chunks", {}):
        raise HTTPException(404, {"error": f"Chunk {chunk_id} not found"})
    return job["chunks"][chunk_id]


@router.post("/assets/export")
async def export_assets(body: dict = Body(default={})):
    """Export asset inventory."""
    export_uuid = _uuid()
    _export_jobs[export_uuid] = {
        "uuid": export_uuid,
        "status": "FINISHED",
        "chunks_available": [1],
        "chunks": {1: _ASSETS},
        "created": _now_ts(),
    }
    return {"export_uuid": export_uuid}


@router.get("/assets/export/{export_uuid}/status")
async def get_asset_export_status(export_uuid: str):
    return await get_vuln_export_status(export_uuid)


@router.get("/assets/export/{export_uuid}/chunks/{chunk_id}")
async def download_asset_chunk(export_uuid: str, chunk_id: int):
    return await download_vuln_chunk(export_uuid, chunk_id)


# ─────────────────────────────────────────────────────────────────────────────
# Plugins API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/plugins/plugin/{plugin_id}")
async def get_plugin(plugin_id: int):
    """Get plugin details by ID."""
    p = _PLUGINS.get(plugin_id)
    if not p:
        # Return a minimal plugin for unknown IDs
        return {
            "id": plugin_id,
            "name": f"Plugin {plugin_id}",
            "family_name": "General",
            "attributes": [
                {"attribute_name": "risk_factor", "attribute_value": "Info"},
                {"attribute_name": "description", "attribute_value": "Plugin description not available in simulation."},
            ],
        }
    return p


@router.get("/plugins/families")
async def list_plugin_families():
    return {
        "families": [
            {"id": 56, "name": "Windows : Microsoft Bulletins", "count": 4200},
            {"id": 11, "name": "Windows", "count": 1800},
            {"id": 1, "name": "General", "count": 900},
            {"id": 22, "name": "Web Servers", "count": 750},
            {"id": 16, "name": "Databases", "count": 600},
            {"id": 26, "name": "Misc.", "count": 500},
        ]
    }


@router.get("/plugins/families/{family_id}")
async def list_plugins_in_family(family_id: int, offset: int = Query(0), limit: int = Query(100)):
    plugins = [{"id": p["id"], "name": p["name"]} for p in _PLUGINS.values()]
    return {"plugins": plugins[offset: offset + limit], "total": len(plugins)}


# ─────────────────────────────────────────────────────────────────────────────
# Tags API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/tags/values")
async def list_tag_values(
    f: Optional[str] = Query(None, description="JSON filter"),
    limit: int = Query(5000),
    offset: int = Query(0),
):
    return {
        "pagination": {"total": len(_TAGS), "offset": offset, "limit": limit},
        "values": _TAGS[offset: offset + limit],
    }


@router.post("/tags/values")
async def create_tag_value(body: dict = Body(default={})):
    tag_uuid = _uuid()
    tag = {
        "uuid": tag_uuid,
        "category_uuid": body.get("category_uuid", _uuid()),
        "category_name": body.get("category_name", "Custom"),
        "value": body.get("value", ""),
        "type": body.get("type", "static"),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    _TAGS.append(tag)
    return tag


@router.post("/tags/assets/assignments")
async def assign_tags(body: dict = Body(default={})):
    """Assign tags to assets."""
    return {"job_uuid": _uuid()}


# ─────────────────────────────────────────────────────────────────────────────
# Networks
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/networks")
async def list_networks(offset: int = Query(0), limit: int = Query(100)):
    return {
        "networks": [
            {"uuid": "00000000-0000-0000-0000-000000000000", "name": "Default", "description": "Default network", "is_default": True, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z", "scanner_count": 1},
        ],
        "pagination": {"total": 1, "offset": offset, "limit": limit},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Agents API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scanners/{scanner_id}/agents")
async def list_agents(
    scanner_id: int,
    offset: int = Query(0),
    limit: int = Query(100),
    f: Optional[str] = Query(None),
    ft: str = Query("and"),
    w: Optional[str] = Query(None),
):
    agents = [
        {
            "id": i + 1,
            "uuid": a.get("agent_uuid", _uuid()),
            "name": a["agent_names"][0] if a.get("agent_names") else f"agent-{i}",
            "distro": a.get("operating_systems", ["Unknown"])[0],
            "ip": a["ipv4s"][0] if a.get("ipv4s") else "",
            "last_scanned": a["last_seen"],
            "last_connect": a["last_seen"],
            "status": "on",
            "linked_on": a.get("created_at"),
            "platform": "WINDOWS",
            "version": "10.7.3",
        }
        for i, a in enumerate(_ASSETS)
    ]
    return {
        "agents": agents[offset: offset + limit],
        "pagination": {"total": len(agents), "offset": offset, "limit": limit},
    }
