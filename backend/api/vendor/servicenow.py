"""ServiceNow CMDB + ITSM REST API emulation.

Grounded in the official ServiceNow REST API Reference:
  https://developer.servicenow.com/dev.do#!/reference/api/tokyo/rest/c_TableAPI

Implements:
  Table API (CRUD on all tables)
  CMDB Instance API (CI relationships)
  Aggregate API (stats)
  Import Set API (bulk CI import)

Key CMDB Tables:
  cmdb_ci              — base Configuration Item
  cmdb_ci_computer     — computers (workstations, servers)
  cmdb_ci_server       — servers (extends cmdb_ci_computer)
  cmdb_ci_network_device — switches, routers, firewalls
  cmdb_ci_service      — business services
  cmdb_ci_appl         — applications (software)
  cmdb_ci_ip_switch    — network switches

Key ITSM Tables:
  incident             — IT incident management
  change_request       — change management
  problem              — problem management
  task                 — generic task
  sc_request           — service catalog request
  sc_req_item          — catalog request item

Authentication:
  Basic: Authorization: Basic base64(user:pass)
  Token: X-UserToken header (from POST /api/now/auth/token)
  OAuth2: POST /oauth_token.do with client_credentials grant

Response envelope:
  { "result": [<objects>] }           (list)
  { "result": { <object> } }          (single)
  { "error": { "message": "...", "detail": "..." } }  (error)
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Path, Query, Request

router = APIRouter(prefix="/api/vendor/servicenow", tags=["vendor:servicenow"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _sid() -> str:
    return uuid.uuid4().hex


# ─────────────────────────────────────────────────────────────────────────────
# Seed data — enterprise CMDB and ITSM records
# ─────────────────────────────────────────────────────────────────────────────

_COMPUTERS: list[dict] = [
    {
        "sys_id": "1a2b3c4d5e6f7890abcdef1234567801",
        "name": "CORP-WS-001", "asset_tag": "P001234",
        "sys_class_name": "cmdb_ci_computer",
        "manufacturer": {"value": "a1b2c3d4e5f60001abcdef1234567801", "display_value": "Dell Inc."},
        "model_id": {"value": "a1b2c3d4e5f60002abcdef1234567801", "display_value": "Latitude 5540"},
        "os": "Windows 11 Enterprise", "os_version": "10.0.22621",
        "ip_address": "10.10.1.101", "mac_address": "AA:BB:CC:DD:EE:01",
        "cpu_count": "4", "cpu_speed": "2400", "cpu_type": "Intel Core i7",
        "ram": "16384", "disk_space": "512000",
        "install_status": "1", "operational_status": "1",
        "environment": "production", "classification": "Workstation",
        "assigned_to": {"value": "a1b2c3d4e5f60003abcdef1234567801", "display_value": "John Smith"},
        "department": {"value": "a1b2c3d4e5f60004abcdef1234567801", "display_value": "Engineering"},
        "location": {"value": "a1b2c3d4e5f60005abcdef1234567801", "display_value": "HQ - Floor 3"},
        "managed_by": {"value": "a1b2c3d4e5f60006abcdef1234567801", "display_value": "IT Operations"},
        "support_group": {"value": "a1b2c3d4e5f60007abcdef1234567801", "display_value": "Desktop Support"},
        "host_name": "corp-ws-001.corp.local", "serial_number": "SN-DL001234",
        "warranty_expiration": "2027-06-30", "virtual": "false",
        "discovery_source": "SCCM", "running_process_count": "47",
        "sys_created_on": "2024-01-15 08:00:00", "sys_updated_on": _now(),
        "u_used_for": "General Computing", "u_criticality": "3",
    },
    {
        "sys_id": "1a2b3c4d5e6f7890abcdef1234567802",
        "name": "CORP-SRV-001", "asset_tag": "S000001",
        "sys_class_name": "cmdb_ci_server",
        "manufacturer": {"value": "a1b2c3d4e5f60001abcdef1234567802", "display_value": "HP"},
        "model_id": {"value": "a1b2c3d4e5f60002abcdef1234567802", "display_value": "ProLiant DL380 Gen10"},
        "os": "Windows Server 2022 Standard", "os_version": "10.0.20348",
        "ip_address": "10.10.2.10", "mac_address": "AA:BB:CC:DD:EE:10",
        "cpu_count": "16", "cpu_speed": "3200", "cpu_type": "Intel Xeon Gold 6314U",
        "ram": "65536", "disk_space": "4096000",
        "install_status": "1", "operational_status": "1",
        "environment": "production", "classification": "Physical Server",
        "assigned_to": {"value": "a1b2c3d4e5f60003abcdef1234567802", "display_value": "Ana Garcia"},
        "department": {"value": "a1b2c3d4e5f60004abcdef1234567802", "display_value": "IT Operations"},
        "location": {"value": "a1b2c3d4e5f60005abcdef1234567802", "display_value": "DataCenter A - Rack 12"},
        "managed_by": {"value": "a1b2c3d4e5f60006abcdef1234567802", "display_value": "Server Team"},
        "support_group": {"value": "a1b2c3d4e5f60007abcdef1234567802", "display_value": "Server Operations"},
        "host_name": "corp-srv-001.corp.local", "serial_number": "SN-HP001001",
        "warranty_expiration": "2028-01-31", "virtual": "false",
        "discovery_source": "SCCM", "running_process_count": "125",
        "sys_created_on": "2023-06-01 10:00:00", "sys_updated_on": _now(),
        "u_used_for": "File Server", "u_criticality": "1",
    },
    {
        "sys_id": "1a2b3c4d5e6f7890abcdef1234567803",
        "name": "CORP-DC-001", "asset_tag": "S000002",
        "sys_class_name": "cmdb_ci_server",
        "manufacturer": {"value": "a1b2c3d4e5f60001abcdef1234567803", "display_value": "Dell Inc."},
        "model_id": {"value": "a1b2c3d4e5f60002abcdef1234567803", "display_value": "PowerEdge R750"},
        "os": "Windows Server 2022 Datacenter", "os_version": "10.0.20348",
        "ip_address": "10.10.2.1", "mac_address": "AA:BB:CC:DD:EE:20",
        "cpu_count": "24", "cpu_speed": "3600", "cpu_type": "Intel Xeon Platinum 8362",
        "ram": "131072", "disk_space": "8192000",
        "install_status": "1", "operational_status": "1",
        "environment": "production", "classification": "Domain Controller",
        "assigned_to": {"value": "a1b2c3d4e5f60003abcdef1234567803", "display_value": "IT Operations"},
        "department": {"value": "a1b2c3d4e5f60004abcdef1234567803", "display_value": "IT Operations"},
        "location": {"value": "a1b2c3d4e5f60005abcdef1234567803", "display_value": "DataCenter A - Rack 1"},
        "managed_by": {"value": "a1b2c3d4e5f60006abcdef1234567803", "display_value": "AD Team"},
        "support_group": {"value": "a1b2c3d4e5f60007abcdef1234567803", "display_value": "Directory Services"},
        "host_name": "corp-dc-001.corp.local", "serial_number": "SN-DL002001",
        "warranty_expiration": "2029-06-30", "virtual": "false",
        "discovery_source": "Active Directory", "running_process_count": "89",
        "sys_created_on": "2022-01-10 08:00:00", "sys_updated_on": _now(),
        "u_used_for": "Domain Controller / Active Directory", "u_criticality": "1",
    },
    {
        "sys_id": "1a2b3c4d5e6f7890abcdef1234567804",
        "name": "CORP-FW-001", "asset_tag": "N000001",
        "sys_class_name": "cmdb_ci_network_device",
        "manufacturer": {"value": "a1b2c3d4e5f60001abcdef1234567804", "display_value": "Palo Alto Networks"},
        "model_id": {"value": "a1b2c3d4e5f60002abcdef1234567804", "display_value": "PA-5250"},
        "ip_address": "10.10.0.1", "mac_address": "AA:BB:CC:DD:EE:FF",
        "os": "PAN-OS", "os_version": "11.1.2",
        "install_status": "1", "operational_status": "1",
        "environment": "production", "classification": "Firewall",
        "location": {"value": "a1b2c3d4e5f60005abcdef1234567804", "display_value": "DataCenter A - Edge Rack"},
        "managed_by": {"value": "a1b2c3d4e5f60006abcdef1234567804", "display_value": "Network Security"},
        "sys_created_on": "2023-01-01 00:00:00", "sys_updated_on": _now(),
        "u_criticality": "1",
    },
]

# install_status codes: 1=In Use, 2=On Order, 3=In Maintenance, 6=In Stock, 7=Retired, 8=Stolen, 100=Missing
# operational_status codes: 1=Operational, 2=Non-Operational, 3=Repair in Progress, 4=DR Standby, 5=Ready, 6=Retired
_INSTALL_STATUS = {"1": "In Use", "2": "On Order", "3": "In Maintenance", "6": "In Stock", "7": "Retired", "8": "Stolen"}
_OP_STATUS = {"1": "Operational", "2": "Non-Operational", "3": "Repair in Progress", "4": "DR Standby"}

_INCIDENTS: list[dict] = [
    {
        "sys_id": "inc0000000000000000000000000001",
        "number": "INC0001001",
        "short_description": "User unable to access VPN after password reset",
        "description": "User John Smith (jsmith@corp.local) reports unable to connect to VPN since password was reset at 14:30 UTC. Cisco AnyConnect returns error 'Authentication failed'. User is remote and cannot access corporate resources.",
        "category": "Network",
        "subcategory": "VPN",
        "contact_type": "Phone",
        "state": "2",           # 1=New, 2=In Progress, 3=On Hold, 4=Resolved, 5=Closed, 6=Cancelled
        "priority": "2",        # 1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning
        "urgency": "2",         # 1=High, 2=Medium, 3=Low
        "impact": "2",          # 1=High, 2=Medium, 3=Low
        "severity": "2",
        "caller_id": {"value": "a1b2c3d4e5f60003abcdef1234567801", "display_value": "John Smith"},
        "assignment_group": {"value": "a1b2c3d4e5f60007abcdef1234567810", "display_value": "Network Support"},
        "assigned_to": {"value": "a1b2c3d4e5f60003abcdef1234567805", "display_value": "Ana Garcia"},
        "cmdb_ci": {"value": "1a2b3c4d5e6f7890abcdef1234567801", "display_value": "CORP-WS-001"},
        "opened_at": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "sys_created_on": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "sys_updated_on": _now(),
        "resolved_at": None, "closed_at": None,
        "close_code": None, "resolution_notes": None,
        "work_notes": "[code]2026-07-26 09:00:00 - Ana Garcia\nChecking AD account status and VPN group membership.[/code]",
        "sla_due": (datetime.now(timezone.utc) + timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S"),
        "escalation": "0",
        "reopen_count": "0",
        "notify": "1",
        "u_affected_users": "1",
        "correlation_id": None, "correlation_display": None,
    },
    {
        "sys_id": "inc0000000000000000000000000002",
        "number": "INC0001002",
        "short_description": "Suspicious PowerShell execution detected on CORP-WS-001",
        "description": "Security monitoring detected encoded PowerShell command on CORP-WS-001 at 08:45 UTC. Command: powershell.exe -enc <base64_payload>. Process spawned by Microsoft Office Word. User: jsmith. Possible phishing attack via malicious document.",
        "category": "Security",
        "subcategory": "Malware/Ransomware",
        "contact_type": "Monitoring Tool",
        "state": "1",
        "priority": "1",
        "urgency": "1",
        "impact": "2",
        "severity": "1",
        "caller_id": {"value": "a1b2c3d4e5f60003abcdef1234567806", "display_value": "SOC Monitoring"},
        "assignment_group": {"value": "a1b2c3d4e5f60007abcdef1234567811", "display_value": "Security Operations"},
        "assigned_to": None,
        "cmdb_ci": {"value": "1a2b3c4d5e6f7890abcdef1234567801", "display_value": "CORP-WS-001"},
        "opened_at": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
        "sys_created_on": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
        "sys_updated_on": _now(),
        "resolved_at": None, "closed_at": None,
        "close_code": None, "resolution_notes": None,
        "work_notes": "",
        "sla_due": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "escalation": "0",
        "reopen_count": "0",
        "notify": "2",
        "u_affected_users": "1",
        "correlation_id": None, "correlation_display": None,
    },
]

_CHANGE_REQUESTS: list[dict] = [
    {
        "sys_id": "chg0000000000000000000000000001",
        "number": "CHG0010001",
        "short_description": "Emergency patch deployment - CVE-2024-21413 (Microsoft Outlook RCE)",
        "description": "Emergency patching required for CVE-2024-21413 (CVSS 9.8). Microsoft Outlook Remote Code Execution vulnerability. Affects all Windows workstations running Outlook 2016-2024.",
        "type": "Emergency",
        "state": "1",    # -5=Pending Approval, -4=Scheduled, -3=Pending Change Task, 1=Open, 2=Work In Progress, 3=Review, 4=Closed, 5=Cancelled, 7=Implement
        "priority": "1",
        "risk": "2",     # 1=High, 2=Moderate, 3=Low, 4=None
        "impact": "2",
        "urgency": "1",
        "category": "Software",
        "start_date": (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "end_date": (datetime.now(timezone.utc) + timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S"),
        "assignment_group": {"value": "a1b2c3d4e5f60007abcdef1234567812", "display_value": "Desktop Engineering"},
        "assigned_to": {"value": "a1b2c3d4e5f60003abcdef1234567807", "display_value": "Patch Management Team"},
        "cmdb_ci": {"value": "", "display_value": "Multiple CIs"},
        "opened_at": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "sys_created_on": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "sys_updated_on": _now(),
        "close_code": None, "close_notes": None,
        "review_date": (datetime.now(timezone.utc) + timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S"),
        "cab_recommendation": None,
        "work_notes": "[code]2026-07-26 10:00:00 - Patch Manager\nTesting patch on dev group. Estimated 2h deployment window.[/code]",
        "test_plan": "1. Deploy to 5 test workstations\n2. Verify Outlook functionality\n3. Monitor for 30min\n4. Deploy to all endpoints in waves",
        "backout_plan": "Uninstall KB5034671 via SCCM",
    },
]

# In-memory mutable state for created records
_dynamic_incidents: dict[str, dict] = {}
_dynamic_changes: dict[str, dict] = {}
_dynamic_cis: dict[str, dict] = {}

_TABLE_DATA: dict[str, list[dict]] = {
    "cmdb_ci_computer": _COMPUTERS[:1],
    "cmdb_ci_server": _COMPUTERS[1:3],
    "cmdb_ci_network_device": _COMPUTERS[3:],
    "cmdb_ci": _COMPUTERS,
    "incident": _INCIDENTS,
    "change_request": _CHANGE_REQUESTS,
    "problem": [],
    "task": [],
    "sc_request": [],
    "sc_req_item": [],
}


def _parse_sn_query(query: str, records: list[dict]) -> list[dict]:
    """
    Parse ServiceNow encoded query string and filter records.
    Format: field=value^ANDfield2=value2^ORfield3=value3
    Supports: =, !=, LIKE, STARTSWITH, ENDSWITH, >, <, >=, <=, IN, ISEMPTY, ISNOTEMPTY
    """
    if not query:
        return records

    # Split on ^AND and ^OR (simplified — treat all as AND)
    conditions = re.split(r'\^(?:AND|OR)?', query)
    result = records
    for cond in conditions:
        if not cond.strip():
            continue
        # ISEMPTY / ISNOTEMPTY
        m_empty = re.match(r'(\w+)(ISEMPTY|ISNOTEMPTY)', cond)
        if m_empty:
            field, op = m_empty.group(1), m_empty.group(2)
            if op == "ISEMPTY":
                result = [r for r in result if not r.get(field)]
            else:
                result = [r for r in result if r.get(field)]
            continue
        # LIKE / STARTSWITH / ENDSWITH
        m_like = re.match(r'(\w+)(LIKE|STARTSWITH|ENDSWITH)(.*)', cond)
        if m_like:
            field, op, val = m_like.group(1), m_like.group(2), m_like.group(3)
            result = [r for r in result if _str_match(r.get(field), op, val)]
            continue
        # IN
        m_in = re.match(r'(\w+)IN(.*)', cond)
        if m_in:
            field, vals = m_in.group(1), [v.strip() for v in m_in.group(2).split(",")]
            result = [r for r in result if str(_dv(r.get(field))) in vals or str(r.get(field)) in vals]
            continue
        # Standard: field=value, field!=value, field>value, field>=value, etc.
        m_std = re.match(r'(\w+)(!=|>=|<=|>|<|=)(.*)', cond)
        if m_std:
            field, op, val = m_std.group(1), m_std.group(2), m_std.group(3)
            result = [r for r in result if _compare(_dv(r.get(field)) or r.get(field), op, val)]
    return result


def _dv(v: Any) -> Any:
    """Extract display_value from a reference field dict."""
    if isinstance(v, dict):
        return v.get("display_value") or v.get("value") or ""
    return v


def _str_match(val: Any, op: str, pattern: str) -> bool:
    s = str(val or "").lower()
    p = pattern.lower()
    if op == "LIKE":
        return p in s
    if op == "STARTSWITH":
        return s.startswith(p)
    if op == "ENDSWITH":
        return s.endswith(p)
    return False


def _compare(val: Any, op: str, target: str) -> bool:
    try:
        if op == "=":
            return str(val).lower() == target.lower()
        if op == "!=":
            return str(val).lower() != target.lower()
        v, t = float(val), float(target)
        return {"<": v < t, ">": v > t, "<=": v <= t, ">=": v >= t}.get(op, False)
    except (TypeError, ValueError):
        return str(val).lower() == target.lower()


def _apply_display_value(record: dict, display_value: str) -> dict:
    """Transform reference fields based on sysparm_display_value."""
    if display_value == "true":
        return {k: (v["display_value"] if isinstance(v, dict) else v) for k, v in record.items()}
    if display_value == "all":
        return {k: ({"display_value": v.get("display_value", ""), "value": v.get("value", ""), "link": ""} if isinstance(v, dict) else {"display_value": str(v), "value": str(v)}) for k, v in record.items()}
    return record  # default: return raw values


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/oauth_token.do")
async def get_oauth_token(body: dict = Body(default={})):
    """OAuth2 client_credentials grant."""
    return {
        "access_token": f"sn-sim-{uuid.uuid4().hex[:32]}",
        "refresh_token": f"sn-rt-{uuid.uuid4().hex[:32]}",
        "token_type": "Bearer",
        "expires_in": 1800,
        "scope": "useraccount",
    }


@router.post("/api/now/auth/token")
async def get_session_token():
    """Obtain a session token (used by some ServiceNow clients)."""
    return {"result": {"token": f"sn-tok-{uuid.uuid4().hex[:32]}"}}


# ─────────────────────────────────────────────────────────────────────────────
# Table API — GET (list)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/now/table/{table_name}")
async def list_records(
    table_name: str,
    sysparm_query: Optional[str] = Query(None, description="Encoded query: field=value^ANDfield2=value2"),
    sysparm_fields: Optional[str] = Query(None, description="Comma-separated field names to return"),
    sysparm_limit: int = Query(10000, ge=1, le=10000),
    sysparm_offset: int = Query(0, ge=0),
    sysparm_display_value: str = Query("false", description="true|false|all"),
    sysparm_exclude_reference_link: bool = Query(False),
    sysparm_query_category: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
):
    """
    GET records from any ServiceNow table.
    Supports sysparm_query encoded query syntax.
    """
    # Get base data
    base = list(_TABLE_DATA.get(table_name, []))

    # Add dynamic records
    for rec in _dynamic_incidents.values():
        if table_name in ("incident",) and rec not in base:
            base.append(rec)
    for rec in _dynamic_changes.values():
        if table_name in ("change_request",) and rec not in base:
            base.append(rec)
    for rec in _dynamic_cis.values():
        if table_name.startswith("cmdb_ci") and rec not in base:
            base.append(rec)

    # Apply encoded query
    filtered = _parse_sn_query(sysparm_query or "", base)

    # Pagination
    paginated = filtered[sysparm_offset: sysparm_offset + sysparm_limit]

    # Apply display_value transformation
    transformed = [_apply_display_value(r, sysparm_display_value) for r in paginated]

    # Field selection
    if sysparm_fields:
        fields = [f.strip() for f in sysparm_fields.split(",")]
        transformed = [{f: r.get(f) for f in fields} for r in transformed]

    return {"result": transformed}


# ─────────────────────────────────────────────────────────────────────────────
# Table API — GET single record
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/now/table/{table_name}/{sys_id}")
async def get_record(
    table_name: str,
    sys_id: str,
    sysparm_fields: Optional[str] = Query(None),
    sysparm_display_value: str = Query("false"),
    sysparm_exclude_reference_link: bool = Query(False),
):
    """GET a single record by sys_id."""
    all_records = list(_TABLE_DATA.get(table_name, []))
    all_records += list(_dynamic_incidents.values()) + list(_dynamic_changes.values()) + list(_dynamic_cis.values())

    record = next((r for r in all_records if r.get("sys_id") == sys_id or r.get("number") == sys_id), None)
    if not record:
        raise HTTPException(status_code=404, detail={"error": {"message": f"No Record found for query: sys_id={sys_id}", "detail": f"GlideRecord - Error fetching record from table {table_name}"}})

    out = _apply_display_value(record, sysparm_display_value)
    if sysparm_fields:
        fields = [f.strip() for f in sysparm_fields.split(",")]
        out = {f: out.get(f) for f in fields}

    return {"result": out}


# ─────────────────────────────────────────────────────────────────────────────
# Table API — POST (create)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/api/now/table/{table_name}")
async def create_record(
    table_name: str,
    body: dict = Body(default={}),
    sysparm_display_value: str = Query("false"),
    sysparm_fields: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
):
    """Create a new record in any table."""
    sid = _sid()
    now = _now()

    # Build the record with provided fields + defaults
    record: dict[str, Any] = {
        "sys_id": sid,
        "sys_created_on": now,
        "sys_updated_on": now,
        "sys_class_name": table_name,
        **body,
    }

    # Auto-generate number for ticketing tables
    if table_name == "incident" and "number" not in record:
        n = 1000 + len(_INCIDENTS) + len(_dynamic_incidents) + 1
        record["number"] = f"INC{n:07d}"
        # Defaults for incidents
        record.setdefault("state", "1")
        record.setdefault("priority", "3")
        record.setdefault("urgency", "3")
        record.setdefault("impact", "3")
        record.setdefault("escalation", "0")
        record.setdefault("reopen_count", "0")
        _dynamic_incidents[sid] = record

    elif table_name == "change_request" and "number" not in record:
        n = 10000 + len(_CHANGE_REQUESTS) + len(_dynamic_changes) + 1
        record["number"] = f"CHG{n:07d}"
        record.setdefault("state", "1")
        record.setdefault("type", "Standard")
        record.setdefault("risk", "3")
        _dynamic_changes[sid] = record

    elif table_name.startswith("cmdb_ci"):
        _dynamic_cis[sid] = record

    out = _apply_display_value(record, sysparm_display_value)
    return {"result": out}


# ─────────────────────────────────────────────────────────────────────────────
# Table API — PUT (full replace) / PATCH (partial update)
# ─────────────────────────────────────────────────────────────────────────────

@router.put("/api/now/table/{table_name}/{sys_id}")
@router.patch("/api/now/table/{table_name}/{sys_id}")
async def update_record(
    table_name: str,
    sys_id: str,
    body: dict = Body(default={}),
    sysparm_display_value: str = Query("false"),
    session_id: Optional[str] = Query(None),
):
    """Update a record (PUT = full replace, PATCH = partial update)."""
    all_records: list[dict] = (
        list(_TABLE_DATA.get(table_name, []))
        + list(_dynamic_incidents.values())
        + list(_dynamic_changes.values())
        + list(_dynamic_cis.values())
    )
    record = next((r for r in all_records if r.get("sys_id") == sys_id or r.get("number") == sys_id), None)
    if not record:
        record = {"sys_id": sys_id, "sys_class_name": table_name}
        _dynamic_incidents[sys_id] = record

    record.update(body)
    record["sys_updated_on"] = _now()

    return {"result": _apply_display_value(record, sysparm_display_value)}


# ─────────────────────────────────────────────────────────────────────────────
# Table API — DELETE
# ─────────────────────────────────────────────────────────────────────────────

@router.delete("/api/now/table/{table_name}/{sys_id}")
async def delete_record(table_name: str, sys_id: str):
    """Delete a record. Returns 204 No Content on success."""
    _dynamic_incidents.pop(sys_id, None)
    _dynamic_changes.pop(sys_id, None)
    _dynamic_cis.pop(sys_id, None)
    return None  # 204


# ─────────────────────────────────────────────────────────────────────────────
# CMDB Instance API — CI details with relationships
# ─────────────────────────────────────────────────────────────────────────────

_CMDB_RELATIONSHIPS: list[dict] = [
    {
        "sys_id": "rel" + _sid()[:28],
        "type": {"value": "Runs on::Runs", "display_value": "Runs on::Runs"},
        "parent": {"value": "1a2b3c4d5e6f7890abcdef1234567801", "display_value": "CORP-WS-001"},
        "child": {"value": "a1b2c3d4e5f60002abcdef1234567899", "display_value": "Microsoft Office 365"},
    },
    {
        "sys_id": "rel" + _sid()[:28],
        "type": {"value": "Depends on::Used by", "display_value": "Depends on::Used by"},
        "parent": {"value": "1a2b3c4d5e6f7890abcdef1234567802", "display_value": "CORP-SRV-001"},
        "child": {"value": "1a2b3c4d5e6f7890abcdef1234567803", "display_value": "CORP-DC-001"},
    },
    {
        "sys_id": "rel" + _sid()[:28],
        "type": {"value": "Protected by::Protects", "display_value": "Protected by::Protects"},
        "parent": {"value": "1a2b3c4d5e6f7890abcdef1234567801", "display_value": "CORP-WS-001"},
        "child": {"value": "1a2b3c4d5e6f7890abcdef1234567804", "display_value": "CORP-FW-001"},
    },
]


@router.get("/api/now/cmdb/instance/{class_name}/{sys_id}")
async def get_cmdb_instance(
    class_name: str,
    sys_id: str,
    sysparm_fields: Optional[str] = Query(None),
    sysparm_display_value: str = Query("false"),
):
    """Get a CI instance with its attributes and relationship data."""
    all_ci = _COMPUTERS + list(_dynamic_cis.values())
    ci = next((c for c in all_ci if c.get("sys_id") == sys_id or c.get("name") == sys_id), None)
    if not ci:
        raise HTTPException(404, {"error": {"message": f"CI not found: {sys_id}"}})

    # Get relationships
    rels = [r for r in _CMDB_RELATIONSHIPS
            if r["parent"].get("value") == sys_id or r["child"].get("value") == sys_id]

    return {
        "result": {
            "attributes": _apply_display_value(ci, sysparm_display_value),
            "outbound_relations": [r for r in rels if r["parent"].get("value") == sys_id],
            "inbound_relations": [r for r in rels if r["child"].get("value") == sys_id],
        }
    }


@router.get("/api/now/cmdb/instance/{class_name}")
async def list_cmdb_instances(
    class_name: str,
    sysparm_query: Optional[str] = Query(None),
    sysparm_limit: int = Query(100),
    sysparm_offset: int = Query(0),
    sysparm_display_value: str = Query("false"),
    sysparm_fields: Optional[str] = Query(None),
):
    """List CI instances of a given class with optional query."""
    records = [c for c in _COMPUTERS if c.get("sys_class_name", "").startswith("cmdb_ci")]
    if class_name != "cmdb_ci":
        records = [c for c in _COMPUTERS if c.get("sys_class_name") == class_name]
    records += [c for c in _dynamic_cis.values() if c.get("sys_class_name", "").startswith(class_name)]

    filtered = _parse_sn_query(sysparm_query or "", records)
    paginated = filtered[sysparm_offset: sysparm_offset + sysparm_limit]
    transformed = [_apply_display_value(r, sysparm_display_value) for r in paginated]

    if sysparm_fields:
        fields = [f.strip() for f in sysparm_fields.split(",")]
        transformed = [{f: r.get(f) for f in fields} for r in transformed]

    return {"result": transformed}


# ─────────────────────────────────────────────────────────────────────────────
# CMDB Relationships API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/now/cmdb/relationships")
async def get_cmdb_relationships(
    sys_id: str = Query(..., description="sys_id of the CI to get relationships for"),
    sysparm_limit: int = Query(100),
    direction: Optional[str] = Query(None, description="inbound|outbound"),
):
    """Get all CI relationships for a given CI."""
    rels = [r for r in _CMDB_RELATIONSHIPS
            if r["parent"].get("value") == sys_id or r["child"].get("value") == sys_id]
    if direction == "inbound":
        rels = [r for r in rels if r["child"].get("value") == sys_id]
    elif direction == "outbound":
        rels = [r for r in rels if r["parent"].get("value") == sys_id]
    return {"result": rels[:sysparm_limit]}


# ─────────────────────────────────────────────────────────────────────────────
# Aggregate API — stats and counts
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/now/stats/{table_name}")
async def get_aggregate_stats(
    table_name: str,
    sysparm_count: bool = Query(True),
    sysparm_query: Optional[str] = Query(None),
    sysparm_group_by: Optional[str] = Query(None, description="Comma-separated fields to group by"),
    sysparm_sum_fields: Optional[str] = Query(None),
    sysparm_avg_fields: Optional[str] = Query(None),
    sysparm_min_fields: Optional[str] = Query(None),
    sysparm_max_fields: Optional[str] = Query(None),
):
    """
    Aggregate API — count, sum, avg, min, max grouped by fields.
    Example: /api/now/stats/incident?sysparm_query=state=1&sysparm_count=true&sysparm_group_by=priority
    """
    base = list(_TABLE_DATA.get(table_name, []))
    base += list(_dynamic_incidents.values()) + list(_dynamic_changes.values())
    filtered = _parse_sn_query(sysparm_query or "", base)

    if sysparm_group_by:
        group_fields = [f.strip() for f in sysparm_group_by.split(",")]
        groups: dict[str, list] = {}
        for r in filtered:
            key = tuple(str(_dv(r.get(f, ""))) for f in group_fields)
            groups.setdefault(str(key), []).append(r)
        stats = []
        for key_str, recs in groups.items():
            entry: dict[str, Any] = {"count": len(recs)}
            keys = eval(key_str) if isinstance(key_str, str) and key_str.startswith("(") else (key_str,)
            for i, f in enumerate(group_fields):
                entry[f] = keys[i] if isinstance(keys, tuple) else keys
            stats.append(entry)
        return {"result": {"stats": stats}}

    return {"result": {"stats": {"count": len(filtered)}}}


# ─────────────────────────────────────────────────────────────────────────────
# Import Set API — bulk CI import
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/api/now/import/{staging_table}")
async def bulk_import(staging_table: str, body: dict = Body(default={})):
    """
    Import Set API — bulk import CIs or records.
    Body: {"records": [{...}, {...}]} or single record object.
    Returns transform result with status per record.
    """
    records_in = body.get("records", [body])
    results = []
    for rec in records_in:
        sid = _sid()
        ci_rec = {"sys_id": sid, "sys_created_on": _now(), "sys_updated_on": _now(),
                  "sys_class_name": "cmdb_ci_computer", **rec}
        _dynamic_cis[sid] = ci_rec
        results.append({
            "transform_map": staging_table,
            "table": "cmdb_ci_computer",
            "status": "inserted",
            "sys_id": sid,
            "display_name": rec.get("name", "Unknown CI"),
            "error": None,
        })
    return {"result": results}


# ─────────────────────────────────────────────────────────────────────────────
# Attachment API
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/api/now/attachment/file")
async def upload_attachment(
    table_name: str = Query(...),
    table_sys_id: str = Query(...),
    file_name: str = Query(...),
    content_type: Optional[str] = Query(None),
    request: Request = None,
):
    """Upload a file attachment to a record."""
    return {
        "result": {
            "sys_id": _sid(),
            "table_name": table_name,
            "table_sys_id": table_sys_id,
            "file_name": file_name,
            "content_type": content_type or "application/octet-stream",
            "size_bytes": 0,
            "download_link": f"/api/now/attachment/{_sid()}/file",
            "sys_created_on": _now(),
        }
    }


@router.get("/api/now/attachment")
async def list_attachments(
    table_name: Optional[str] = Query(None),
    table_sys_id: Optional[str] = Query(None),
):
    return {"result": []}


# ─────────────────────────────────────────────────────────────────────────────
# Health / Metadata
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/now/table")
async def list_tables():
    """List available tables."""
    return {
        "result": [
            {"name": t, "label": t.replace("_", " ").title(), "is_extendable": True}
            for t in _TABLE_DATA.keys()
        ]
    }


@router.get("/api/now/ui/meta/{table_name}")
async def get_table_metadata(table_name: str):
    """Return table metadata (field definitions)."""
    return {
        "result": {
            "name": table_name,
            "label": table_name.replace("_", " ").title(),
            "fields": {
                "sys_id": {"type": "GUID", "label": "Sys ID"},
                "name": {"type": "String", "label": "Name"},
                "state": {"type": "Integer", "label": "State"},
                "priority": {"type": "Integer", "label": "Priority"},
                "sys_created_on": {"type": "DateTime", "label": "Created"},
                "sys_updated_on": {"type": "DateTime", "label": "Updated"},
            }
        }
    }
