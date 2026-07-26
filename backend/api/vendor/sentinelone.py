"""SentinelOne Singularity Platform API emulation — enterprise rewrite.

Grounded in official SentinelOne API documentation:
  https://usea1-partners.sentinelone.net/api-doc/overview

Base URL pattern: https://<management>.sentinelone.net/web/api/v2.1/

Auth:
  POST /web/api/v2.1/users/login   — returns token
  POST /web/api/v2.1/users/login/by-api-token — API token login
  All requests: Authorization: ApiToken {token}

Implements:
  Agents — list, filter, get, actions (disconnect/reconnect/abort-scan/initiate-scan/decommission/
           fetch-logs/restart-services/uninstall/move-to-site/mark-compromised/trigger-scan)
  Threats — list, filter, get, mitigate (kill/quarantine/remediate/rollback/approve-unquarantine)
  Deep Visibility — init-query, events, cancel query
  Exclusions — process/path/hash/certificate/network CRUD
  Sites — list, get, create
  Groups — list, get, create, move agents
  Policies — get/update per-site and per-group
  Custom Rules (STAR) — custom detection rules
  Activities — audit log
  Restrictions — network/process IOC blocks
  Accounts — account-level management
  Packages — sensor installer packages

Agent networkStatus: connected | disconnected | connecting | disconnecting
Agent infected values: true | false
Agent machineType: desktop | laptop | server | kubernetes node | tablet
Agent modelName: (hardware model string)
Threat mitigation status: mitigated | active | blocked | suspicious | suspicious_resolved | pending
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Query

router = APIRouter(prefix="/api/vendor/sentinelone", tags=["vendor:sentinelone"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _uuid() -> str:
    return str(uuid.uuid4())


def _s1_id() -> str:
    """SentinelOne uses 18-digit numeric IDs."""
    import random
    return str(random.randint(100000000000000000, 999999999999999999))


_SIM_TOKEN = f"S1-sim-{uuid.uuid4().hex[:32]}"

# ─────────────────────────────────────────────────────────────────────────────
# Seed data — agents, threats, exclusions
# ─────────────────────────────────────────────────────────────────────────────

_AGENTS: dict[str, dict] = {
    "193821748291038571": {
        "id": "193821748291038571",
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, "CORP-WS-001")),
        "agentVersion": "23.4.1.7162",
        "allowRemoteShell": True,
        "appsVulnerabilityStatus": "not_applicable",
        "computerName": "CORP-WS-001",
        "consoleMigrationStatus": "N/A",
        "coreCount": 8,
        "cpuCount": 1,
        "cpuId": "Intel(R) Core(TM) i7-1165G7 @ 2.80GHz",
        "createdAt": "2024-01-15T08:00:00.000Z",
        "updatedAt": (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "lastActiveDate": (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "lastLoggedInUserName": "jsmith",
        "domain": "CORP",
        "encryptedApplications": False,
        "externalId": "",
        "externalIp": "203.0.113.101",
        "firewallEnabled": True,
        "groupId": "grp-001",
        "groupIp": "10.10.1.0/24",
        "groupName": "Engineering",
        "id": "193821748291038571",
        "inRemoteShellSession": False,
        "infected": False,
        "installerType": ".msi",
        "isActive": True,
        "isDecommissioned": False,
        "isPendingUninstall": False,
        "isUninstalled": False,
        "isUpToDate": True,
        "lastIpToMgmt": "10.10.1.101",
        "licenseKey": "",
        "locationEnabled": True,
        "locationType": "not_applicable",
        "locations": None,
        "machineType": "laptop",
        "mitigationMode": "detect",
        "mitigationModeSuspicious": "detect",
        "modelName": "Dell Latitude 5540",
        "networkInterfaces": [
            {"gatewayIp": "10.10.1.1", "gatewayMacAddress": "00-00-00-00-00-01", "id": _s1_id(), "inet": ["10.10.1.101"], "inet6": [], "name": "Ethernet 0", "physical": "AA-BB-CC-DD-EE-01"}
        ],
        "networkQuarantineEnabled": False,
        "networkStatus": "connected",
        "operationalState": "na",
        "operationalStateExpiration": None,
        "osArch": "64 bit",
        "osBits": 64,
        "osName": "Windows 11 Pro",
        "osRevision": "22621",
        "osStartTime": (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "osType": "windows",
        "osUsername": None,
        "rangerStatus": "NotApplicable",
        "rangerVersion": None,
        "registeredAt": "2024-01-15T08:00:00.000Z",
        "remoteProfilingState": "disabled",
        "scanAbortedAt": None,
        "scanFinishedAt": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "scanStartedAt": (datetime.now(timezone.utc) - timedelta(hours=2, minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "scanStatus": "finished",
        "serialNumber": "SN-DL001234",
        "siteId": "site-001",
        "siteName": "Corporate-HQ",
        "storageName": None,
        "storageType": None,
        "tags": {"sentinelone": []},
        "threatRebootRequired": False,
        "totalMemory": 32768,
        "userActionsNeeded": [],
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, "CORP-WS-001")),
    },
    "193821748291038572": {
        "id": "193821748291038572",
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, "CORP-SRV-001")),
        "agentVersion": "23.4.1.7162",
        "allowRemoteShell": True,
        "computerName": "CORP-SRV-001",
        "coreCount": 16,
        "cpuCount": 2,
        "cpuId": "Intel(R) Xeon(R) Silver 4214R CPU @ 2.40GHz",
        "createdAt": "2023-06-01T10:00:00.000Z",
        "updatedAt": _now(),
        "lastActiveDate": _now(),
        "lastLoggedInUserName": "svc_backup",
        "domain": "CORP",
        "externalIp": "203.0.113.10",
        "firewallEnabled": True,
        "groupId": "grp-002",
        "groupName": "Servers",
        "infected": False,
        "isActive": True,
        "isDecommissioned": False,
        "isPendingUninstall": False,
        "isUninstalled": False,
        "isUpToDate": True,
        "lastIpToMgmt": "10.10.2.10",
        "machineType": "server",
        "mitigationMode": "protect",
        "mitigationModeSuspicious": "protect",
        "modelName": "HP ProLiant DL380 Gen10",
        "networkInterfaces": [
            {"gatewayIp": "10.10.2.1", "id": _s1_id(), "inet": ["10.10.2.10"], "inet6": [], "name": "Ethernet 0", "physical": "AA-BB-CC-DD-EE-10"}
        ],
        "networkQuarantineEnabled": False,
        "networkStatus": "connected",
        "osArch": "64 bit",
        "osBits": 64,
        "osName": "Windows Server 2022 Standard",
        "osRevision": "20348",
        "osType": "windows",
        "rangerStatus": "NotApplicable",
        "scanStatus": "finished",
        "serialNumber": "SN-HP001001",
        "siteId": "site-001",
        "siteName": "Corporate-HQ",
        "totalMemory": 65536,
        "userActionsNeeded": [],
    },
    "193821748291038573": {
        "id": "193821748291038573",
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, "CORP-DC-001")),
        "agentVersion": "23.4.1.7162",
        "allowRemoteShell": True,
        "computerName": "CORP-DC-001",
        "coreCount": 16,
        "cpuCount": 2,
        "cpuId": "Intel(R) Xeon(R) Gold 6330 CPU @ 2.00GHz",
        "createdAt": "2022-01-10T08:00:00.000Z",
        "updatedAt": _now(),
        "lastActiveDate": _now(),
        "lastLoggedInUserName": "Administrator",
        "domain": "CORP",
        "externalIp": "203.0.113.1",
        "firewallEnabled": True,
        "groupId": "grp-003",
        "groupName": "DomainControllers",
        "infected": False,
        "isActive": True,
        "isDecommissioned": False,
        "isPendingUninstall": False,
        "isUninstalled": False,
        "isUpToDate": True,
        "lastIpToMgmt": "10.10.2.1",
        "machineType": "server",
        "mitigationMode": "protect",
        "mitigationModeSuspicious": "protect",
        "modelName": "Dell PowerEdge R750",
        "networkInterfaces": [
            {"gatewayIp": "10.10.2.1", "id": _s1_id(), "inet": ["10.10.2.1"], "inet6": [], "name": "Ethernet 0", "physical": "AA-BB-CC-DD-EE-20"}
        ],
        "networkQuarantineEnabled": False,
        "networkStatus": "connected",
        "osArch": "64 bit",
        "osBits": 64,
        "osName": "Windows Server 2022 Standard",
        "osRevision": "20348",
        "osType": "windows",
        "rangerStatus": "NotApplicable",
        "scanStatus": "finished",
        "serialNumber": "SN-DL002001",
        "siteId": "site-001",
        "siteName": "Corporate-HQ",
        "totalMemory": 131072,
        "userActionsNeeded": [],
    },
}

_THREATS: dict[str, dict] = {
    "thr-001": {
        "id": "thr-001",
        "agentComputerName": "CORP-WS-001",
        "agentDomain": "CORP",
        "agentId": "193821748291038571",
        "agentIp": "10.10.1.101",
        "agentIsActive": True,
        "agentIsDecommissioned": False,
        "agentMachineType": "laptop",
        "agentOsType": "windows",
        "agentVersion": "23.4.1.7162",
        "analystVerdictDescription": None,
        "analystVerdict": "undefined",
        "annotationUrl": None,
        "annotation": None,
        "browserType": None,
        "certId": "",
        "classification": "Malware",
        "classificationSource": "Engine",
        "cloudFilesHashVerdict": "undefined",
        "collectionId": None,
        "commandLine": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0",
        "confidenceLevel": "malicious",
        "containerLabels": None,
        "containerName": None,
        "createdAt": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "detectionEngines": [
            {"key": "pre_execution_suspicious_activity", "title": "Pre-Execution"},
            {"key": "dbf_suspicious_scripts_static_indicators", "title": "Static AI — Malicious"},
        ],
        "detectionType": "dynamic",
        "engines": ["DBT_BEHAVIORAL_INDICATORS"],
        "fileContentHash": "b" * 64,
        "fileDisplayName": "powershell.exe",
        "fileExtensionType": "Executable",
        "filePath": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "fileSize": 491520,
        "fileVerificationType": "SignedVerified",
        "fromCloud": False,
        "fromUrl": None,
        "id": "thr-001",
        "incidentStatus": "unresolved",
        "incidentStatusDescription": "Unresolved",
        "indicatorCategories": ["Execution", "Defense Evasion"],
        "indicatorDescription": "Suspicious PowerShell Encoded Command",
        "indicatorMetadata": {},
        "indicatorName": "ExecutePowerShellEncodedCommand",
        "initiatedBy": "soc_analyst",
        "initiatedByDescription": "SOC Analyst",
        "initiatingUserId": None,
        "initiatingUsername": None,
        "isFileless": False,
        "isValidCertificate": True,
        "k8sClusterName": None,
        "k8sControllerLabels": None,
        "k8sControllerName": None,
        "k8sNamespace": None,
        "k8sNode": None,
        "k8sPodName": None,
        "k8sPodLabels": None,
        "maliciousGroupId": None,
        "maliciousProcessArguments": "-enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0",
        "md5": "c" * 32,
        "mitigatedPreemptively": False,
        "mitigationStatus": "active",
        "mitigationStatusDescription": "Active",
        "originatorProcess": "WINWORD.EXE",
        "parentProcessId": 3100,
        "processId": 4200,
        "processUser": "jsmith",
        "publisherName": "MICROSOFT CORPORATION",
        "reachedEventsLimit": False,
        "rebootRequired": False,
        "sha1": "a" * 40,
        "sha256": "b" * 64,
        "signedStatus": "signed",
        "siteId": "site-001",
        "siteName": "Corporate-HQ",
        "storylineId": "sl-" + uuid.uuid4().hex[:16],
        "threatName": "PowerShell.Trojan.Encoded",
        "updatedAt": _now(),
        "username": "jsmith",
        "whiteningOptions": ["certificate", "path"],
    },
}

_EXCLUSIONS: dict[str, dict] = {}
_SITES: dict[str, dict] = {
    "site-001": {
        "id": "site-001",
        "accountId": "acc-001",
        "accountName": "CorporateHQ",
        "activeLicenses": 3,
        "createdAt": "2022-01-01T00:00:00.000Z",
        "description": "Corporate Headquarters site",
        "expiration": None,
        "externalId": "",
        "isDefault": True,
        "licenses": {"bundles": [{"displayName": "Singularity Complete", "majorVersion": 3, "minorVersion": 0, "name": "core", "surfaces": [{"count": 100, "maxAllowed": 1000, "name": "desktops"}, {"count": 3, "maxAllowed": 200, "name": "servers"}]}]},
        "name": "Corporate-HQ",
        "policy": {"inheritedFrom": "account", "policyId": None},
        "registrationToken": "SIT-sim-token",
        "siteType": "Paid",
        "sku": "core",
        "state": "active",
        "suite": "Complete",
        "totalLicenses": 1000,
        "updatedAt": _now(),
    },
}

_GROUPS: dict[str, dict] = {
    "grp-001": {"id": "grp-001", "createdAt": "2024-01-01T00:00:00.000Z", "description": "Engineering workstations", "filterId": None, "inherits": True, "isDefault": False, "name": "Engineering", "rank": 1, "registrationToken": "GRP-sim-001", "siteId": "site-001", "totalAgents": 1, "type": "static", "updatedAt": _now()},
    "grp-002": {"id": "grp-002", "createdAt": "2023-01-01T00:00:00.000Z", "description": "Production servers", "filterId": None, "inherits": True, "isDefault": False, "name": "Servers", "rank": 2, "registrationToken": "GRP-sim-002", "siteId": "site-001", "totalAgents": 1, "type": "static", "updatedAt": _now()},
    "grp-003": {"id": "grp-003", "createdAt": "2022-01-01T00:00:00.000Z", "description": "Domain controllers — Tier 0", "filterId": None, "inherits": True, "isDefault": False, "name": "DomainControllers", "rank": 0, "registrationToken": "GRP-sim-003", "siteId": "site-001", "totalAgents": 1, "type": "static", "updatedAt": _now()},
}

_DV_QUERIES: dict[str, dict] = {}
_ACTIVITIES: list[dict] = []


def _s1_response(data: Any, pagination: Optional[dict] = None, errors: Optional[list] = None) -> dict:
    """Standard SentinelOne API response envelope."""
    resp: dict = {"data": data, "errors": errors or []}
    if pagination is not None:
        resp["pagination"] = pagination
    return resp


def _filter_agents(agents: list[dict], filters: dict) -> list[dict]:
    result = agents
    for field, val in filters.items():
        if val is None:
            continue
        val_lower = str(val).lower()
        # Handle comma-separated values (S1 accepts multiple values for many filters)
        vals = [v.strip().lower() for v in val_lower.split(",")]
        if field == "computerName":
            result = [a for a in result if a.get("computerName", "").lower() in vals]
        elif field == "computerName__contains":
            result = [a for a in result if any(v in a.get("computerName", "").lower() for v in vals)]
        elif field == "networkStatus":
            result = [a for a in result if a.get("networkStatus", "").lower() in vals]
        elif field == "infected":
            bool_val = val_lower in ("true", "1", "yes")
            result = [a for a in result if a.get("infected") == bool_val]
        elif field == "machineType":
            result = [a for a in result if a.get("machineType", "").lower() in vals]
        elif field == "osType":
            result = [a for a in result if a.get("osType", "").lower() in vals]
        elif field == "siteIds":
            result = [a for a in result if a.get("siteId", "") in vals]
        elif field == "groupIds":
            result = [a for a in result if a.get("groupId", "") in vals]
        elif field == "ids":
            result = [a for a in result if a.get("id", "") in vals]
        elif field == "uuid":
            result = [a for a in result if a.get("uuid", "") in vals]
        elif field == "lastIpToMgmt":
            result = [a for a in result if a.get("lastIpToMgmt", "") in vals]
        elif field == "isActive":
            bool_val = val_lower in ("true", "1")
            result = [a for a in result if a.get("isActive") == bool_val]
        elif field == "isDecommissioned":
            bool_val = val_lower in ("true", "1")
            result = [a for a in result if a.get("isDecommissioned") == bool_val]
        elif field == "scanStatus":
            result = [a for a in result if a.get("scanStatus", "").lower() in vals]
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/web/api/v2.1/users/login")
async def login(body: dict = Body(default={})):
    """Login with username/password. Returns token."""
    return _s1_response({
        "token": _SIM_TOKEN,
        "userId": "usr-sim-001",
    })


@router.post("/web/api/v2.1/users/login/by-api-token")
async def login_by_api_token(body: dict = Body(default={})):
    """Exchange an API token for a session token."""
    return _s1_response({
        "token": _SIM_TOKEN,
        "userId": "usr-sim-001",
    })


@router.get("/web/api/v2.1/users/api-token-details")
async def get_api_token_details(Authorization: Optional[str] = Header(None)):
    """Get details about the current API token."""
    return _s1_response({
        "expiresAt": (datetime.now(timezone.utc) + timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "createdAt": "2024-01-01T00:00:00.000Z",
        "userId": "usr-sim-001",
    })


# ─────────────────────────────────────────────────────────────────────────────
# Agents
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/agents")
async def list_agents(
    computerName: Optional[str] = Query(None, description="Exact computer name match"),
    computerName__contains: Optional[str] = Query(None, description="Partial computer name match"),
    networkStatus: Optional[str] = Query(None, description="connected | disconnected | connecting | disconnecting"),
    infected: Optional[str] = Query(None, description="true | false"),
    machineType: Optional[str] = Query(None, description="desktop | laptop | server | kubernetes node | tablet"),
    osType: Optional[str] = Query(None, description="windows | linux | macos"),
    siteIds: Optional[str] = Query(None, description="Comma-separated site IDs"),
    groupIds: Optional[str] = Query(None, description="Comma-separated group IDs"),
    ids: Optional[str] = Query(None, description="Comma-separated agent IDs"),
    uuid: Optional[str] = Query(None, description="Agent UUID"),
    lastIpToMgmt: Optional[str] = Query(None, description="Management IP address"),
    isActive: Optional[str] = Query(None, description="true | false"),
    isDecommissioned: Optional[str] = Query(None, description="true | false"),
    scanStatus: Optional[str] = Query(None, description="none | inProgress | aborted | finished"),
    limit: int = Query(10, ge=1, le=1000),
    cursor: Optional[str] = Query(None),
    sortBy: Optional[str] = Query(None, description="computerName | id | lastActiveDate | networkStatus"),
    sortOrder: Optional[str] = Query("asc", description="asc | desc"),
    countOnly: bool = Query(False),
):
    """
    List agents with filters.
    Supports cursor-based pagination (nextCursor in response for next page).
    """
    agents = list(_AGENTS.values())
    agents = _filter_agents(agents, {
        "computerName": computerName, "computerName__contains": computerName__contains,
        "networkStatus": networkStatus, "infected": infected, "machineType": machineType,
        "osType": osType, "siteIds": siteIds, "groupIds": groupIds, "ids": ids,
        "uuid": uuid, "lastIpToMgmt": lastIpToMgmt, "isActive": isActive,
        "isDecommissioned": isDecommissioned, "scanStatus": scanStatus,
    })

    total = len(agents)
    if countOnly:
        return _s1_response(total)

    # Cursor pagination
    start = 0
    if cursor:
        try:
            start = int(cursor)
        except ValueError:
            start = 0
    page = agents[start: start + limit]
    next_cursor = str(start + len(page)) if start + len(page) < total else None

    return _s1_response(page, pagination={"nextCursor": next_cursor, "totalItems": total})


@router.get("/web/api/v2.1/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get a specific agent by ID."""
    if agent_id not in _AGENTS:
        raise HTTPException(404, detail={"errors": [{"code": 4000010, "detail": f"Agent {agent_id} not found"}]})
    return _s1_response(_AGENTS[agent_id])


@router.get("/web/api/v2.1/agents/count")
async def count_agents(
    networkStatus: Optional[str] = Query(None),
    infected: Optional[str] = Query(None),
    siteIds: Optional[str] = Query(None),
):
    """Count agents matching filter criteria."""
    agents = list(_AGENTS.values())
    agents = _filter_agents(agents, {"networkStatus": networkStatus, "infected": infected, "siteIds": siteIds})
    return _s1_response(len(agents))


@router.post("/web/api/v2.1/agents/actions/disconnect")
async def disconnect_agents(body: dict = Body(default={})):
    """
    Disconnect (network quarantine) agents.
    body: {filter: {ids: [...]}, data: {}}
    """
    ids = _extract_ids(body)
    affected = 0
    for agent_id in ids:
        if agent_id in _AGENTS:
            _AGENTS[agent_id]["networkStatus"] = "disconnected"
            _AGENTS[agent_id]["networkQuarantineEnabled"] = True
            _AGENTS[agent_id]["updatedAt"] = _now()
            affected += 1
    return _s1_response({"affected": affected})


@router.post("/web/api/v2.1/agents/actions/reconnect")
async def reconnect_agents(body: dict = Body(default={})):
    """Remove network quarantine from agents."""
    ids = _extract_ids(body)
    affected = 0
    for agent_id in ids:
        if agent_id in _AGENTS:
            _AGENTS[agent_id]["networkStatus"] = "connected"
            _AGENTS[agent_id]["networkQuarantineEnabled"] = False
            _AGENTS[agent_id]["updatedAt"] = _now()
            affected += 1
    return _s1_response({"affected": affected})


@router.post("/web/api/v2.1/agents/actions/initiate-scan")
async def initiate_scan(body: dict = Body(default={})):
    """Initiate a full-disk scan on agents."""
    ids = _extract_ids(body)
    affected = 0
    for agent_id in ids:
        if agent_id in _AGENTS:
            _AGENTS[agent_id]["scanStatus"] = "inProgress"
            _AGENTS[agent_id]["scanStartedAt"] = _now()
            _AGENTS[agent_id]["updatedAt"] = _now()
            affected += 1
    return _s1_response({"affected": affected})


@router.post("/web/api/v2.1/agents/actions/abort-scan")
async def abort_scan(body: dict = Body(default={})):
    """Abort an in-progress scan."""
    ids = _extract_ids(body)
    affected = 0
    for agent_id in ids:
        if agent_id in _AGENTS:
            _AGENTS[agent_id]["scanStatus"] = "aborted"
            _AGENTS[agent_id]["scanAbortedAt"] = _now()
            _AGENTS[agent_id]["updatedAt"] = _now()
            affected += 1
    return _s1_response({"affected": affected})


@router.post("/web/api/v2.1/agents/actions/fetch-logs")
async def fetch_logs(body: dict = Body(default={})):
    """Request log bundle from agents (async — check via activities)."""
    ids = _extract_ids(body)
    return _s1_response({"affected": len(ids)})


@router.post("/web/api/v2.1/agents/actions/restart-services")
async def restart_services(body: dict = Body(default={})):
    """Restart SentinelOne services on agents."""
    ids = _extract_ids(body)
    return _s1_response({"affected": len([i for i in ids if i in _AGENTS])})


@router.post("/web/api/v2.1/agents/actions/mark-compromised")
async def mark_compromised(body: dict = Body(default={})):
    """Mark agents as compromised (infected=true)."""
    ids = _extract_ids(body)
    affected = 0
    for agent_id in ids:
        if agent_id in _AGENTS:
            _AGENTS[agent_id]["infected"] = True
            _AGENTS[agent_id]["updatedAt"] = _now()
            affected += 1
    return _s1_response({"affected": affected})


@router.post("/web/api/v2.1/agents/actions/decommission")
async def decommission_agents(body: dict = Body(default={})):
    """Decommission agents (marks as no longer managed)."""
    ids = _extract_ids(body)
    affected = 0
    for agent_id in ids:
        if agent_id in _AGENTS:
            _AGENTS[agent_id]["isDecommissioned"] = True
            _AGENTS[agent_id]["isActive"] = False
            _AGENTS[agent_id]["updatedAt"] = _now()
            affected += 1
    return _s1_response({"affected": affected})


@router.post("/web/api/v2.1/agents/actions/move-to-site")
async def move_to_site(body: dict = Body(default={})):
    """Move agents to a different site."""
    ids = _extract_ids(body)
    target_site_id = (body.get("data") or {}).get("targetSiteId", "")
    affected = 0
    for agent_id in ids:
        if agent_id in _AGENTS and target_site_id in _SITES:
            _AGENTS[agent_id]["siteId"] = target_site_id
            _AGENTS[agent_id]["siteName"] = _SITES[target_site_id]["name"]
            affected += 1
    return _s1_response({"affected": affected})


@router.post("/web/api/v2.1/groups/{group_id}/move-agents")
async def move_agents_to_group(group_id: str, body: dict = Body(default={})):
    """Move agents to a different group."""
    agent_ids = body.get("data", {}).get("agentIds", [])
    affected = 0
    for agent_id in agent_ids:
        if agent_id in _AGENTS and group_id in _GROUPS:
            _AGENTS[agent_id]["groupId"] = group_id
            _AGENTS[agent_id]["groupName"] = _GROUPS[group_id]["name"]
            affected += 1
    return _s1_response({"affected": affected})


def _extract_ids(body: dict) -> list[str]:
    """Extract agent IDs from S1 action body (body.filter.ids or body.ids)."""
    if isinstance(body.get("filter"), dict):
        ids = body["filter"].get("ids", [])
        if ids:
            return ids if isinstance(ids, list) else [ids]
    return body.get("ids", [])


# ─────────────────────────────────────────────────────────────────────────────
# Threats
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/threats")
async def list_threats(
    ids: Optional[str] = Query(None),
    agentId: Optional[str] = Query(None),
    computerName: Optional[str] = Query(None),
    computerName__contains: Optional[str] = Query(None),
    mitigationStatus: Optional[str] = Query(None, description="mitigated | active | blocked | suspicious | pending"),
    classification: Optional[str] = Query(None, description="Malware | PUA | SuspiciousActivity | Exploits | Other"),
    confidenceLevel: Optional[str] = Query(None, description="malicious | suspicious | benign"),
    incidentStatus: Optional[str] = Query(None, description="unresolved | in_progress | resolved | undefined"),
    osType: Optional[str] = Query(None),
    siteIds: Optional[str] = Query(None),
    limit: int = Query(25, ge=1, le=1000),
    cursor: Optional[str] = Query(None),
    sortBy: Optional[str] = Query(None),
    sortOrder: Optional[str] = Query("desc"),
    countOnly: bool = Query(False),
):
    """
    List threats/detections.
    mitigationStatus: mitigated | active | blocked | suspicious | suspicious_resolved | pending
    classification: Malware | PUA | SuspiciousActivity | Exploits | Other
    confidenceLevel: malicious | suspicious | benign
    incidentStatus: unresolved | in_progress | resolved | undefined
    """
    threats = list(_THREATS.values())

    if ids:
        id_list = [i.strip() for i in ids.split(",")]
        threats = [t for t in threats if t["id"] in id_list]
    if agentId:
        threats = [t for t in threats if t.get("agentId") == agentId]
    if computerName:
        threats = [t for t in threats if t.get("agentComputerName", "").lower() == computerName.lower()]
    if computerName__contains:
        threats = [t for t in threats if computerName__contains.lower() in t.get("agentComputerName", "").lower()]
    if mitigationStatus:
        vals = [v.strip().lower() for v in mitigationStatus.split(",")]
        threats = [t for t in threats if t.get("mitigationStatus", "").lower() in vals]
    if classification:
        threats = [t for t in threats if t.get("classification", "").lower() == classification.lower()]
    if confidenceLevel:
        threats = [t for t in threats if t.get("confidenceLevel", "").lower() == confidenceLevel.lower()]
    if incidentStatus:
        threats = [t for t in threats if t.get("incidentStatus", "").lower() == incidentStatus.lower()]
    if osType:
        threats = [t for t in threats if t.get("agentOsType", "").lower() == osType.lower()]

    total = len(threats)
    if countOnly:
        return _s1_response(total)

    start = int(cursor or 0)
    page = threats[start: start + limit]
    next_cursor = str(start + len(page)) if start + len(page) < total else None
    return _s1_response(page, pagination={"nextCursor": next_cursor, "totalItems": total})


@router.get("/web/api/v2.1/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get a specific threat by ID."""
    if threat_id not in _THREATS:
        raise HTTPException(404, detail={"errors": [{"code": 4000010, "detail": f"Threat {threat_id} not found"}]})
    return _s1_response(_THREATS[threat_id])


@router.post("/web/api/v2.1/threats/mitigation/kill")
async def kill_threat(body: dict = Body(default={})):
    """Kill the threat process."""
    ids = _get_threat_ids(body)
    for tid in ids:
        if tid in _THREATS:
            _THREATS[tid]["mitigationStatus"] = "mitigated"
            _THREATS[tid]["mitigationStatusDescription"] = "Killed"
    return _s1_response({"affected": len(ids)})


@router.post("/web/api/v2.1/threats/mitigation/quarantine")
async def quarantine_threat(body: dict = Body(default={})):
    """Quarantine the threat file."""
    ids = _get_threat_ids(body)
    for tid in ids:
        if tid in _THREATS:
            _THREATS[tid]["mitigationStatus"] = "mitigated"
            _THREATS[tid]["mitigationStatusDescription"] = "Quarantined"
    return _s1_response({"affected": len(ids)})


@router.post("/web/api/v2.1/threats/mitigation/remediate")
async def remediate_threat(body: dict = Body(default={})):
    """Remediate the threat (kill + quarantine + rollback)."""
    ids = _get_threat_ids(body)
    for tid in ids:
        if tid in _THREATS:
            _THREATS[tid]["mitigationStatus"] = "mitigated"
            _THREATS[tid]["mitigationStatusDescription"] = "Remediated"
            _THREATS[tid]["incidentStatus"] = "resolved"
    return _s1_response({"affected": len(ids)})


@router.post("/web/api/v2.1/threats/mitigation/rollback-remediation")
async def rollback_remediation(body: dict = Body(default={})):
    """Rollback previous remediation (restore quarantined files)."""
    ids = _get_threat_ids(body)
    return _s1_response({"affected": len(ids)})


@router.post("/web/api/v2.1/threats/mitigation/approve-unquarantine")
async def approve_unquarantine(body: dict = Body(default={})):
    """Approve unquarantine action for threats in pending unquarantine state."""
    ids = _get_threat_ids(body)
    return _s1_response({"affected": len(ids)})


@router.post("/web/api/v2.1/threats/analyst-verdict")
async def update_analyst_verdict(body: dict = Body(default={})):
    """
    Set analyst verdict on threats.
    data.analystVerdict: true_positive | false_positive | suspicious | undefined
    """
    ids = _get_threat_ids(body)
    verdict = (body.get("data") or {}).get("analystVerdict", "undefined")
    for tid in ids:
        if tid in _THREATS:
            _THREATS[tid]["analystVerdict"] = verdict
    return _s1_response({"affected": len(ids)})


@router.post("/web/api/v2.1/threats/incident")
async def update_threat_incident(body: dict = Body(default={})):
    """
    Update threat incident status.
    data.incidentStatus: unresolved | in_progress | resolved | undefined
    """
    ids = _get_threat_ids(body)
    status = (body.get("data") or {}).get("incidentStatus", "unresolved")
    for tid in ids:
        if tid in _THREATS:
            _THREATS[tid]["incidentStatus"] = status
    return _s1_response({"affected": len(ids)})


@router.get("/web/api/v2.1/threats/{threat_id}/timeline")
async def get_threat_timeline(threat_id: str):
    """Get event timeline for a specific threat."""
    return _s1_response([
        {"activityType": 23, "data": {"computerName": "CORP-WS-001", "userName": "jsmith"}, "description": "Threat detected", "id": _s1_id(), "primaryDescription": "Detected by AI", "secondaryDescription": None, "siteId": "site-001", "threatId": threat_id, "createdAt": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "updatedAt": _now()},
        {"activityType": 13, "data": {}, "description": "Threat reported to cloud", "id": _s1_id(), "primaryDescription": "Threat uploaded", "createdAt": (datetime.now(timezone.utc) - timedelta(minutes=29)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "updatedAt": _now()},
    ])


def _get_threat_ids(body: dict) -> list[str]:
    """Extract threat IDs from mitigation action body."""
    f = body.get("filter", {}) or {}
    ids = f.get("ids", [])
    if not ids:
        ids = body.get("ids", [])
    return ids if isinstance(ids, list) else [ids]


# ─────────────────────────────────────────────────────────────────────────────
# Deep Visibility — query-based EDR telemetry
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/web/api/v2.1/dv/init-query")
async def dv_init_query(body: dict = Body(default={})):
    """
    Initialize a Deep Visibility query.
    body: {query: str, fromDate: ISO8601, toDate: ISO8601, limit: int, siteIds: [...]}
    query uses PowerQuery DSL: EventType = 'Process Creation' AND SrcProcUser = 'jsmith'
    Returns queryId for polling.
    EventType values: Process Creation | File Creation | File Deletion | File Modification |
                      Network Connection | Registry Value Creation | Registry Value Modified |
                      Registry Value Deleted | DNS Request | Command Script | Login | Logout |
                      Driver Load | Module Load | File Scan
    """
    query_id = _uuid()
    _DV_QUERIES[query_id] = {
        "id": query_id,
        "query": body.get("query", ""),
        "fromDate": body.get("fromDate", ""),
        "toDate": body.get("toDate", ""),
        "status": "FINISHED",
        "progressStatus": 100,
    }
    return _s1_response({"queryId": query_id})


@router.get("/web/api/v2.1/dv/events")
async def dv_get_events(
    queryId: str = Query(...),
    limit: int = Query(100, ge=1, le=20000),
    cursor: Optional[str] = Query(None),
):
    """
    Get Deep Visibility events for a completed query.
    Poll until responseState = 'FINISHED' or 'FAILED'.
    """
    if queryId not in _DV_QUERIES:
        return _s1_response([], pagination={"nextCursor": None, "totalItems": 0})

    events = [
        {
            "eventType": "Process Creation",
            "agentId": "193821748291038571",
            "agentComputerName": "CORP-WS-001",
            "agentIp": "10.10.1.101",
            "siteId": "site-001",
            "siteName": "Corporate-HQ",
            "trueContext": uuid.uuid4().hex,
            "parentPid": 3100,
            "parentProcessName": "WINWORD.EXE",
            "parentProcessStartTime": (datetime.now(timezone.utc) - timedelta(minutes=31)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "pid": 4200,
            "processName": "powershell.exe",
            "processDisplayName": "powershell.exe",
            "processCmd": "powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBuAHYAbwBr...",
            "processImagePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "processStartTime": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "sha256": "b" * 64,
            "md5": "c" * 32,
            "user": "CORP\\jsmith",
            "publisherName": "MICROSOFT CORPORATION",
            "signedStatus": "Signed",
            "eventTime": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "eventIndex": 0,
        },
        {
            "eventType": "Network Connection",
            "agentId": "193821748291038571",
            "agentComputerName": "CORP-WS-001",
            "agentIp": "10.10.1.101",
            "siteId": "site-001",
            "pid": 4200,
            "processName": "powershell.exe",
            "srcIp": "10.10.1.101",
            "srcPort": 49123,
            "dstIp": "203.0.113.200",
            "dstPort": 443,
            "protocol": "TCP",
            "networkDirection": "OUTGOING",
            "netEventDirection": "OUTGOING",
            "dnsRequest": "malicious-domain.evil.example",
            "eventTime": (datetime.now(timezone.utc) - timedelta(minutes=29)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "eventIndex": 1,
        },
    ]

    return _s1_response(events, pagination={"nextCursor": None, "totalItems": len(events), "responseState": "FINISHED"})


@router.get("/web/api/v2.1/dv/query-status")
async def dv_query_status(queryId: str = Query(...)):
    """Get the status of a Deep Visibility query."""
    if queryId not in _DV_QUERIES:
        raise HTTPException(404, detail={"errors": [{"detail": "Query not found"}]})
    q = _DV_QUERIES[queryId]
    return _s1_response({"queryId": queryId, "responseState": "FINISHED", "progressStatus": 100, "query": q.get("query", "")})


@router.post("/web/api/v2.1/dv/cancel-query")
async def dv_cancel_query(body: dict = Body(default={})):
    """Cancel a running Deep Visibility query."""
    query_id = body.get("queryId", "")
    if query_id in _DV_QUERIES:
        _DV_QUERIES[query_id]["status"] = "CANCELLED"
    return _s1_response({"success": True})


# ─────────────────────────────────────────────────────────────────────────────
# Exclusions (whitelisting)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/exclusions")
async def list_exclusions(
    type: Optional[str] = Query(None, description="white_hash | path | certificate | browser | file_type | linux_kernel_module | signer_identity | tx_path_hash"),
    siteIds: Optional[str] = Query(None),
    limit: int = Query(100),
    cursor: Optional[str] = Query(None),
):
    """List exclusions (whitelisted paths, hashes, certs)."""
    exclusions = list(_EXCLUSIONS.values())
    if type:
        exclusions = [e for e in exclusions if e.get("type") == type]
    return _s1_response(exclusions, pagination={"nextCursor": None, "totalItems": len(exclusions)})


@router.post("/web/api/v2.1/exclusions")
async def create_exclusion(body: dict = Body(default={})):
    """
    Create an exclusion.
    data fields:
      type: white_hash | path | certificate | browser | file_type
      value: hash/path/cert fingerprint
      os: windows | linux | macos
      pathExclusionType: suppress | allow (for path type)
      mode: suppress | allow
      description: string
      siteIds: [str]
      source: user | sentinelctl | star_exclude
    """
    exc_id = _s1_id()
    exclusion = {
        "id": exc_id,
        "createdAt": _now(),
        "updatedAt": _now(),
        "type": body.get("data", {}).get("type", "white_hash"),
        "value": body.get("data", {}).get("value", ""),
        "description": body.get("data", {}).get("description", ""),
        "os": body.get("data", {}).get("os", "windows"),
        "mode": body.get("data", {}).get("mode", "suppress"),
        "pathExclusionType": body.get("data", {}).get("pathExclusionType", None),
        "siteIds": body.get("data", {}).get("siteIds", ["site-001"]),
        "userId": "usr-sim-001",
        "userName": "analyst@corp.local",
        "source": body.get("data", {}).get("source", "user"),
    }
    _EXCLUSIONS[exc_id] = exclusion
    return _s1_response(exclusion)


@router.delete("/web/api/v2.1/exclusions")
async def delete_exclusions(body: dict = Body(default={})):
    """Delete exclusions by IDs."""
    ids = body.get("data", {}).get("ids", []) or body.get("ids", [])
    affected = 0
    for eid in ids:
        if str(eid) in _EXCLUSIONS:
            del _EXCLUSIONS[str(eid)]
            affected += 1
    return _s1_response({"affected": affected})


# ─────────────────────────────────────────────────────────────────────────────
# Custom Detection Rules (STAR)
# ─────────────────────────────────────────────────────────────────────────────

_STAR_RULES: dict[str, dict] = {}


@router.get("/web/api/v2.1/cloud-detection/rules")
async def list_star_rules(limit: int = Query(25), cursor: Optional[str] = Query(None)):
    """List STAR (SentinelOne Threat Analysis Rules) — custom detection rules."""
    rules = list(_STAR_RULES.values())
    return _s1_response(rules, pagination={"nextCursor": None, "totalItems": len(rules)})


@router.post("/web/api/v2.1/cloud-detection/rules")
async def create_star_rule(body: dict = Body(default={})):
    """Create a custom STAR detection rule (PowerQuery DSL)."""
    rule_id = _s1_id()
    rule = {
        "id": rule_id,
        "createdAt": _now(),
        "updatedAt": _now(),
        "name": body.get("data", {}).get("name", "Custom Rule"),
        "queryLang": "2.0",
        "queryType": "events",
        "query": body.get("data", {}).get("query", ""),
        "description": body.get("data", {}).get("description", ""),
        "treatAsThreat": body.get("data", {}).get("treatAsThreat", "None"),
        "status": "Active",
        "severity": body.get("data", {}).get("severity", "Low"),
        "siteIds": body.get("data", {}).get("siteIds", ["site-001"]),
        "networkQuarantine": body.get("data", {}).get("networkQuarantine", False),
        "reachedLimit": False,
        "creator": "analyst@corp.local",
    }
    _STAR_RULES[rule_id] = rule
    return _s1_response(rule)


@router.delete("/web/api/v2.1/cloud-detection/rules")
async def delete_star_rules(body: dict = Body(default={})):
    """Delete STAR rules by IDs."""
    ids = body.get("data", {}).get("ids", [])
    for rid in ids:
        _STAR_RULES.pop(str(rid), None)
    return _s1_response({"affected": len(ids)})


# ─────────────────────────────────────────────────────────────────────────────
# Sites
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/sites")
async def list_sites(limit: int = Query(10), cursor: Optional[str] = Query(None)):
    """List sites."""
    sites = list(_SITES.values())
    return _s1_response({"sites": sites, "allSites": {"activeLicenses": sum(s["activeLicenses"] for s in sites), "totalLicenses": sum(s["totalLicenses"] for s in sites)}}, pagination={"nextCursor": None, "totalItems": len(sites)})


@router.get("/web/api/v2.1/sites/{site_id}")
async def get_site(site_id: str):
    """Get a specific site."""
    if site_id not in _SITES:
        raise HTTPException(404, detail={"errors": [{"detail": f"Site {site_id} not found"}]})
    return _s1_response(_SITES[site_id])


# ─────────────────────────────────────────────────────────────────────────────
# Groups
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/groups")
async def list_groups(siteIds: Optional[str] = Query(None), limit: int = Query(25), cursor: Optional[str] = Query(None)):
    """List agent groups."""
    groups = list(_GROUPS.values())
    if siteIds:
        site_list = [s.strip() for s in siteIds.split(",")]
        groups = [g for g in groups if g.get("siteId") in site_list]
    return _s1_response(groups, pagination={"nextCursor": None, "totalItems": len(groups)})


@router.get("/web/api/v2.1/groups/{group_id}")
async def get_group(group_id: str):
    """Get a specific group."""
    if group_id not in _GROUPS:
        raise HTTPException(404, detail={"errors": [{"detail": f"Group {group_id} not found"}]})
    return _s1_response(_GROUPS[group_id])


@router.post("/web/api/v2.1/groups")
async def create_group(body: dict = Body(default={})):
    """Create a new agent group."""
    grp_id = _s1_id()
    group = {
        "id": grp_id,
        "createdAt": _now(),
        "description": body.get("data", {}).get("description", ""),
        "inherits": body.get("data", {}).get("inherits", True),
        "isDefault": False,
        "name": body.get("data", {}).get("name", "New Group"),
        "rank": 99,
        "registrationToken": f"GRP-sim-{grp_id[:8]}",
        "siteId": body.get("data", {}).get("siteId", "site-001"),
        "totalAgents": 0,
        "type": body.get("data", {}).get("type", "static"),
        "updatedAt": _now(),
    }
    _GROUPS[grp_id] = group
    return _s1_response(group)


# ─────────────────────────────────────────────────────────────────────────────
# Activities (audit log)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/activities")
async def list_activities(
    siteIds: Optional[str] = Query(None),
    agentIds: Optional[str] = Query(None),
    limit: int = Query(25),
    cursor: Optional[str] = Query(None),
    sortBy: Optional[str] = Query("createdAt"),
    sortOrder: Optional[str] = Query("desc"),
):
    """
    List platform activities (audit log).
    activityType values: 23=Threat detected, 1001=Agent registered, 1002=Agent decommissioned,
    3014=Network quarantine applied, 3015=Network quarantine removed, etc.
    """
    activities = [
        {"id": _s1_id(), "activityType": 23, "agentId": "193821748291038571", "agentUpdatedVersion": None, "comments": None, "createdAt": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "data": {"computerName": "CORP-WS-001", "confidenceLevel": "malicious", "fileDisplayName": "powershell.exe", "filePath": "...", "fullScopeDetails": "Threat 'PowerShell.Trojan.Encoded' detected", "threatId": "thr-001", "username": "jsmith"}, "description": None, "hash": None, "osFamily": None, "primaryDescription": "Threat thr-001 detected", "secondaryDescription": None, "siteId": "site-001", "threatId": "thr-001", "updatedAt": _now(), "userId": None},
    ]
    return _s1_response(activities, pagination={"nextCursor": None, "totalItems": len(activities)})


# ─────────────────────────────────────────────────────────────────────────────
# Restrictions (network/process IOC block)
# ─────────────────────────────────────────────────────────────────────────────

_RESTRICTIONS: dict[str, dict] = {}


@router.get("/web/api/v2.1/restrictions")
async def list_restrictions(type: Optional[str] = Query(None), limit: int = Query(25), cursor: Optional[str] = Query(None)):
    """
    List restrictions.
    type: black_hash (block by SHA256/MD5/SHA1) | Path
    """
    restr = list(_RESTRICTIONS.values())
    if type:
        restr = [r for r in restr if r.get("type") == type]
    return _s1_response(restr, pagination={"nextCursor": None, "totalItems": len(restr)})


@router.post("/web/api/v2.1/restrictions")
async def create_restriction(body: dict = Body(default={})):
    """Block a hash or path on all endpoints."""
    restr_id = _s1_id()
    restriction = {
        "id": restr_id,
        "createdAt": _now(),
        "updatedAt": _now(),
        "type": body.get("data", {}).get("type", "black_hash"),
        "value": body.get("data", {}).get("value", ""),
        "description": body.get("data", {}).get("description", ""),
        "os": body.get("data", {}).get("os", "windows"),
        "siteIds": body.get("data", {}).get("siteIds", ["site-001"]),
        "userId": "usr-sim-001",
        "userName": "analyst@corp.local",
    }
    _RESTRICTIONS[restr_id] = restriction
    return _s1_response(restriction)


@router.delete("/web/api/v2.1/restrictions")
async def delete_restrictions(body: dict = Body(default={})):
    """Remove restrictions."""
    ids = body.get("data", {}).get("ids", [])
    for rid in ids:
        _RESTRICTIONS.pop(str(rid), None)
    return _s1_response({"affected": len(ids)})


# ─────────────────────────────────────────────────────────────────────────────
# Accounts
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/accounts")
async def list_accounts():
    """List accounts in this management console."""
    return _s1_response([
        {"id": "acc-001", "createdAt": "2022-01-01T00:00:00.000Z", "updatedAt": _now(), "name": "CorporateHQ", "accountType": "Trial", "activeLicenses": 3, "totalLicenses": 1000, "state": "active", "isDefault": True, "numberOfSites": 1, "numberOfUsers": 5, "usersCount": 5}
    ])


# ─────────────────────────────────────────────────────────────────────────────
# System info
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/web/api/v2.1/system/status")
async def system_status():
    """Get console system status."""
    return _s1_response({"health": "ok", "is_snapshot_compatible": True})


@router.get("/web/api/v2.1/system/configuration")
async def system_configuration():
    """Get system configuration."""
    return _s1_response({"consoleVersion": "2.5.0.1234", "dbVersion": None})
