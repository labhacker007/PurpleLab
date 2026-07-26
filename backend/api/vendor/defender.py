"""Microsoft Defender for Endpoint (MDE) REST API emulation — enterprise rewrite.

Grounded in official MDE API documentation:
  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/

Primary base URL: https://api.securitycenter.microsoft.com/api/
Auth base:        https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token

Implements:
  OAuth2 token (client_credentials for app auth)
  Machines — list, get, search by IP/hostname/tag, isolate/release/scan, vulns, recommendations
  Alerts — list, update, create investigationNote, relate to evidence
  Incidents — list, update, cases view
  Advanced Hunting — KQL queries via POST /advancedqueries/run
  Indicators — custom IOC CRUD (SHA256/IP/Domain/Cert)
  Machine actions — isolation, AV scan, offboard, restriction, investigation package
  Software inventory — per-machine software + vulnerability correlation
  Threat & Vulnerability Management (TVM) — vulns, recommendations, exposureScore
  Investigation — investigation packages, file analysis
  Live Response — session, commands, file upload
  Library — file and script upload

Machine health statuses: Active | Inactive | ImpairedCommunication | NoSensorData | NoSensorDataImpairedCommunication
Risk score levels: High | Medium | Low | None
Exposure levels: High | Medium | Low
onboardingStatus: Onboarded | CanBeOnboarded | Unsupported | InsufficientInfo
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, HTTPException, Query

router = APIRouter(prefix="/api/vendor/defender", tags=["vendor:defender"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Seed data — MDE machines, alerts, incidents
# ─────────────────────────────────────────────────────────────────────────────

_MACHINES: dict[str, dict] = {
    "mde-machine-001": {
        "id": "mde-machine-001",
        "computerDnsName": "CORP-WS-001.corp.local",
        "firstSeen": "2024-01-15T08:00:00Z",
        "lastSeen": (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "osPlatform": "Windows10",
        "osVersion": "10.0.22621.2506",
        "osBuild": 22621,
        "lastIpAddress": "10.10.1.101",
        "lastExternalIpAddress": "203.0.113.101",
        "version": "22H2",
        "agentVersion": "10.8750.19041.2193",
        "sensorHealthState": "Active",
        "healthStatus": "Active",
        "isAadJoined": True,
        "machineTags": ["Engineering", "Production", "Monitored"],
        "exposureLevel": "Medium",
        "onboardingStatus": "Onboarded",
        "defenderAvStatus": "Updated",
        "rbacGroupId": 1,
        "rbacGroupName": "Engineering",
        "riskScore": "Medium",
        "aadDeviceId": f"{uuid.UUID('11111111-2222-3333-4444-555555555555')}",
        "managedBy": "MicrosoftDefender",
        "managedByStatus": "Managed",
        "isolationStatus": "NotIsolated",
        "osProcessor": "x64",
        "vmMetadata": None,
    },
    "mde-machine-002": {
        "id": "mde-machine-002",
        "computerDnsName": "CORP-SRV-001.corp.local",
        "firstSeen": "2023-06-01T10:00:00Z",
        "lastSeen": (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "osPlatform": "WindowsServer2022",
        "osVersion": "10.0.20348.1970",
        "osBuild": 20348,
        "lastIpAddress": "10.10.2.10",
        "lastExternalIpAddress": "203.0.113.10",
        "version": "21H2",
        "agentVersion": "10.8750.19041.2193",
        "sensorHealthState": "Active",
        "healthStatus": "Active",
        "isAadJoined": True,
        "machineTags": ["Servers", "Production", "FileServer"],
        "exposureLevel": "High",
        "onboardingStatus": "Onboarded",
        "defenderAvStatus": "Updated",
        "rbacGroupId": 2,
        "rbacGroupName": "Servers",
        "riskScore": "High",
        "aadDeviceId": f"{uuid.UUID('22222222-3333-4444-5555-666666666666')}",
        "managedBy": "MicrosoftDefender",
        "managedByStatus": "Managed",
        "isolationStatus": "NotIsolated",
        "osProcessor": "x64",
        "vmMetadata": None,
    },
    "mde-machine-003": {
        "id": "mde-machine-003",
        "computerDnsName": "CORP-DC-001.corp.local",
        "firstSeen": "2022-01-10T08:00:00Z",
        "lastSeen": (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "osPlatform": "WindowsServer2022",
        "osVersion": "10.0.20348.1970",
        "osBuild": 20348,
        "lastIpAddress": "10.10.2.1",
        "lastExternalIpAddress": "203.0.113.1",
        "version": "21H2",
        "agentVersion": "10.8750.19041.2193",
        "sensorHealthState": "Active",
        "healthStatus": "Active",
        "isAadJoined": True,
        "machineTags": ["DomainController", "Tier0", "CriticalAsset"],
        "exposureLevel": "High",
        "onboardingStatus": "Onboarded",
        "defenderAvStatus": "Updated",
        "rbacGroupId": 3,
        "rbacGroupName": "DomainControllers",
        "riskScore": "High",
        "aadDeviceId": f"{uuid.UUID('33333333-4444-5555-6666-777777777777')}",
        "managedBy": "MicrosoftDefender",
        "managedByStatus": "Managed",
        "isolationStatus": "NotIsolated",
        "osProcessor": "x64",
        "vmMetadata": None,
    },
}

_ALERTS: dict[str, dict] = {
    "mde-alert-001": {
        "id": "mde-alert-001",
        "title": "Suspicious PowerShell command line",
        "description": "An encoded PowerShell command was executed, potentially indicating obfuscated malicious script execution.",
        "severity": "High",
        "status": "New",
        "classification": None,
        "determination": None,
        "investigationState": "Running",
        "investigationId": 1001,
        "assignedTo": None,
        "category": "Execution",
        "detectionSource": "WindowsDefenderAtp",
        "threatFamilyName": None,
        "threatName": "PowerShellObfuscatedCommand",
        "mitreTechniques": ["T1059.001"],
        "machineId": "mde-machine-001",
        "computerDnsName": "CORP-WS-001.corp.local",
        "firstEventTime": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastEventTime": (datetime.now(timezone.utc) - timedelta(minutes=25)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastUpdateTime": _now(),
        "creationTime": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resolvedTime": None,
        "aadTenantId": "aad-tenant-sim-001",
        "relatedUser": {
            "userName": "jsmith",
            "domainName": "CORP",
            "sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
        },
        "evidence": [
            {
                "entityType": "Process",
                "evidenceCreationTime": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "fileName": "powershell.exe",
                "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
                "processId": 4200,
                "processCommandLine": "powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBuAHYAbwBr...",
                "processorArchitecture": "Amd64",
                "parentProcessId": 3100,
                "parentProcessCreationTime": (datetime.now(timezone.utc) - timedelta(minutes=31)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "processCreationTime": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sha1": "a" * 40,
                "sha256": "b" * 64,
                "accountName": "jsmith",
                "domainName": "CORP",
                "userSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                "verdict": "Suspicious",
            }
        ],
        "incidentId": "mde-incident-001",
        "comments": [],
    },
    "mde-alert-002": {
        "id": "mde-alert-002",
        "title": "LSASS memory access",
        "description": "An attempt to read memory from the Local Security Authority Subsystem Service was detected.",
        "severity": "High",
        "status": "New",
        "classification": None,
        "determination": None,
        "investigationState": "PendingApproval",
        "investigationId": 1002,
        "assignedTo": None,
        "category": "CredentialAccess",
        "detectionSource": "WindowsDefenderAtp",
        "threatFamilyName": None,
        "threatName": "Mimikatz",
        "mitreTechniques": ["T1003.001"],
        "machineId": "mde-machine-001",
        "computerDnsName": "CORP-WS-001.corp.local",
        "firstEventTime": (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastEventTime": (datetime.now(timezone.utc) - timedelta(minutes=18)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastUpdateTime": _now(),
        "creationTime": (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resolvedTime": None,
        "aadTenantId": "aad-tenant-sim-001",
        "relatedUser": {"userName": "jsmith", "domainName": "CORP", "sid": "S-1-5-21-1234567890-1234567890-1234567890-1001"},
        "evidence": [],
        "incidentId": "mde-incident-001",
        "comments": [],
    },
}

_INCIDENTS: dict[str, dict] = {
    "mde-incident-001": {
        "id": "mde-incident-001",
        "incidentName": "Multi-stage attack on CORP-WS-001",
        "createdTime": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastUpdateTime": _now(),
        "assignedTo": None,
        "classification": None,
        "determination": None,
        "status": "Active",
        "severity": "High",
        "tags": [],
        "alerts": ["mde-alert-001", "mde-alert-002"],
        "devices": [{"mdatpDeviceId": "mde-machine-001", "computerDnsName": "CORP-WS-001.corp.local"}],
        "users": [{"accountSid": "S-1-5-21-1234567890-1234567890-1234567890-1001", "accountName": "jsmith", "accountDomain": "CORP"}],
    },
}

_INDICATORS: dict[str, dict] = {}
_MACHINE_ACTIONS: dict[str, dict] = {}


def _odata_filter(filter_str: Optional[str], records: list[dict]) -> list[dict]:
    """Apply simple OData $filter expressions to records."""
    if not filter_str:
        return records
    result = records
    # eq filter: field eq 'value' or field eq value
    for m in re.finditer(r"(\w+)\s+eq\s+'?([^'\s]+)'?", filter_str, re.IGNORECASE):
        field, val = m.group(1), m.group(2)
        result = [r for r in result if str(r.get(field, "")).lower() == val.lower()]
    # ne filter
    for m in re.finditer(r"(\w+)\s+ne\s+'?([^'\s]+)'?", filter_str, re.IGNORECASE):
        field, val = m.group(1), m.group(2)
        result = [r for r in result if str(r.get(field, "")).lower() != val.lower()]
    return result


# ─────────────────────────────────────────────────────────────────────────────
# OAuth2 Authentication
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/oauth2/v2.0/token")
@router.post("/{tenant_id}/oauth2/v2.0/token")
async def get_token(
    tenant_id: Optional[str] = None,
    body: dict = Body(default={}),
):
    """OAuth2 client_credentials token. Required: client_id, client_secret, scope, grant_type."""
    return {
        "token_type": "Bearer",
        "expires_in": 3599,
        "ext_expires_in": 3599,
        "access_token": f"mde-sim-{uuid.uuid4().hex[:48]}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Machines API — /api/machines
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/machines")
async def list_machines(
    filter: Optional[str] = Query(None, alias="$filter", description="OData filter: computerDnsName eq 'CORP-WS-001', healthStatus eq 'Active', riskScore eq 'High'"),
    top: int = Query(100, alias="$top"),
    skip: int = Query(0, alias="$skip"),
    orderby: Optional[str] = Query(None, alias="$orderby"),
):
    """
    List machines. OData filter fields:
      id, computerDnsName, lastIpAddress, osPlatform, osVersion, sensorHealthState,
      healthStatus, riskScore (High|Medium|Low|None), exposureLevel (High|Medium|Low),
      onboardingStatus, lastSeen, firstSeen, machineTags, rbacGroupId
    """
    machines = list(_MACHINES.values())
    machines = _odata_filter(filter, machines)
    total = len(machines)
    page = machines[skip: skip + top]
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Machines",
        "@odata.count": total,
        "value": page,
    }


@router.get("/api/machines/{machine_id}")
async def get_machine(machine_id: str):
    """Get a specific machine by ID."""
    if machine_id not in _MACHINES:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Machine {machine_id} not found"}})
    return _MACHINES[machine_id]


@router.get("/api/machines/findbyhostname/{hostname}")
async def find_machine_by_hostname(hostname: str):
    """Find machines matching a hostname (partial or exact)."""
    matches = [m for m in _MACHINES.values() if hostname.lower() in m["computerDnsName"].lower()]
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Machines", "value": matches}


@router.get("/api/machines/findbyip/{ip}/{timestamp}")
async def find_machine_by_ip(ip: str, timestamp: str):
    """Find machine by IP address at a given timestamp."""
    matches = [m for m in _MACHINES.values() if m.get("lastIpAddress") == ip]
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Machines", "value": matches}


@router.get("/api/machines/{machine_id}/alerts")
async def get_machine_alerts(machine_id: str):
    """Get alerts associated with a specific machine."""
    alerts = [a for a in _ALERTS.values() if a.get("machineId") == machine_id]
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Alerts", "value": alerts}


@router.get("/api/machines/{machine_id}/software")
async def get_machine_software(machine_id: str):
    """Get software inventory for a machine (TVM data)."""
    software = [
        {"id": f"{machine_id}:microsoft-_-outlook", "name": "microsoft outlook", "vendor": "microsoft", "version": "16.0.16827.20166", "weaknesses": 1, "publicExploit": True, "activeAlert": True, "exposedMachines": 1, "impactScore": 9.8},
        {"id": f"{machine_id}:google-_-chrome", "name": "google chrome", "vendor": "google", "version": "121.0.6167.184", "weaknesses": 0, "publicExploit": False, "activeAlert": False, "exposedMachines": 0, "impactScore": 0.0},
        {"id": f"{machine_id}:microsoft-_-windows10", "name": "windows 10", "vendor": "microsoft", "version": "22H2", "weaknesses": 2, "publicExploit": False, "activeAlert": False, "exposedMachines": 1, "impactScore": 6.5},
    ]
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Software", "value": software}


@router.get("/api/machines/{machine_id}/vulnerabilities")
async def get_machine_vulnerabilities(machine_id: str):
    """Get CVEs affecting a specific machine (TVM)."""
    vulns = [
        {"id": f"{machine_id}:CVE-2024-21413", "name": "CVE-2024-21413", "description": "Microsoft Outlook RCE", "severity": "Critical", "cvssV3": 9.8, "exposedMachines": 1, "publishedOn": "2024-02-13", "updatedOn": "2024-02-20", "publicExploit": True, "exploitVerified": False, "exploitTypes": ["Remote code execution"], "exploitUris": []},
        {"id": f"{machine_id}:CVE-2024-20674", "name": "CVE-2024-20674", "description": "Windows Kerberos Security Feature Bypass", "severity": "Critical", "cvssV3": 9.0, "exposedMachines": 1, "publishedOn": "2024-01-09", "updatedOn": "2024-01-16", "publicExploit": False, "exploitVerified": False, "exploitTypes": [], "exploitUris": []},
    ]
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Vulnerabilities", "value": vulns}


@router.get("/api/machines/{machine_id}/recommendations")
async def get_machine_recommendations(machine_id: str):
    """Get security recommendations for a machine."""
    recs = [
        {"id": f"va-{machine_id}-_-microsoft-_-outlook", "productName": "outlook", "recommendationName": "Update Microsoft Outlook", "weaknesses": 1, "vendor": "microsoft", "recommendedVersion": "16.0.17126.20132", "recommendationCategory": "Application", "subCategory": "Update", "severityScore": 9.8, "publicExploit": True, "activeAlert": True, "associatedThreats": ["CVE-2024-21413"], "remediationType": "Update", "status": "Active", "configScoreImpact": 0, "exposureImpact": -5.23, "totalMachineCount": 3, "exposedMachinesCount": 1, "nonProductivityImpactedAssets": 0, "relatedComponent": "microsoft outlook"},
    ]
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Recommendations", "value": recs}


@router.post("/api/machines/{machine_id}/isolate")
async def isolate_machine(machine_id: str, body: dict = Body(default={})):
    """
    Isolate a machine (network isolation).
    body: {Comment: str, IsolationType: Full|Selective}
    IsolationType: Full (all traffic blocked) | Selective (only non-essential traffic blocked)
    """
    if machine_id not in _MACHINES:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Machine {machine_id} not found"}})

    action_id = _uuid()
    _MACHINES[machine_id]["isolationStatus"] = "Isolated"
    _MACHINE_ACTIONS[action_id] = {
        "id": action_id,
        "type": "Isolate",
        "title": "Isolate machine",
        "requestor": "analyst@corp.local",
        "requestorComment": body.get("Comment", "Isolating due to security incident"),
        "status": "Succeeded",
        "machineId": machine_id,
        "computerDnsName": _MACHINES[machine_id]["computerDnsName"],
        "creationDateTimeUtc": _now(),
        "lastUpdateDateTimeUtc": _now(),
        "relatedFileInfo": None,
        "cancellationRequestor": None,
        "cancellationComment": None,
        "cancellationDateTimeUtc": None,
        "errorHResult": 0,
        "scope": body.get("IsolationType", "Full"),
        "requestSource": "PublicApi",
        "externalId": None,
        "requestorObjectId": _uuid(),
        "rbacGroupId": 1,
        "startTime": _now(),
        "requestType": "Isolate",
    }
    return _MACHINE_ACTIONS[action_id]


@router.post("/api/machines/{machine_id}/unisolate")
async def unisolate_machine(machine_id: str, body: dict = Body(default={})):
    """Remove isolation from a machine."""
    if machine_id not in _MACHINES:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Machine {machine_id} not found"}})

    action_id = _uuid()
    _MACHINES[machine_id]["isolationStatus"] = "NotIsolated"
    _MACHINE_ACTIONS[action_id] = {
        "id": action_id,
        "type": "Unisolate",
        "title": "Unisolate machine",
        "requestor": "analyst@corp.local",
        "requestorComment": body.get("Comment", "Releasing isolation after investigation"),
        "status": "Succeeded",
        "machineId": machine_id,
        "computerDnsName": _MACHINES[machine_id]["computerDnsName"],
        "creationDateTimeUtc": _now(),
        "lastUpdateDateTimeUtc": _now(),
        "scope": None,
        "requestSource": "PublicApi",
        "errorHResult": 0,
        "startTime": _now(),
    }
    return _MACHINE_ACTIONS[action_id]


@router.post("/api/machines/{machine_id}/runAntiVirusScan")
async def run_av_scan(machine_id: str, body: dict = Body(default={})):
    """
    Initiate an antivirus scan on the machine.
    body: {Comment: str, ScanType: Quick|Full}
    """
    if machine_id not in _MACHINES:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Machine {machine_id} not found"}})

    action_id = _uuid()
    _MACHINE_ACTIONS[action_id] = {
        "id": action_id,
        "type": "RunAntiVirusScan",
        "title": "Run Antivirus Scan",
        "requestor": "analyst@corp.local",
        "requestorComment": body.get("Comment", "Manual scan triggered"),
        "status": "Succeeded",
        "machineId": machine_id,
        "computerDnsName": _MACHINES[machine_id]["computerDnsName"],
        "creationDateTimeUtc": _now(),
        "lastUpdateDateTimeUtc": _now(),
        "scope": body.get("ScanType", "Full"),
        "requestSource": "PublicApi",
        "errorHResult": 0,
        "startTime": _now(),
    }
    return _MACHINE_ACTIONS[action_id]


@router.post("/api/machines/{machine_id}/collectInvestigationPackage")
async def collect_investigation_package(machine_id: str, body: dict = Body(default={})):
    """
    Collect investigation package (forensic artifacts) from the machine.
    Package includes: processes, network connections, event logs, registry exports, etc.
    """
    if machine_id not in _MACHINES:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Machine {machine_id} not found"}})

    action_id = _uuid()
    _MACHINE_ACTIONS[action_id] = {
        "id": action_id,
        "type": "CollectInvestigationPackage",
        "title": "Collect Investigation Package",
        "requestor": "analyst@corp.local",
        "requestorComment": body.get("Comment", "Collecting forensic artifacts"),
        "status": "Succeeded",
        "machineId": machine_id,
        "computerDnsName": _MACHINES[machine_id]["computerDnsName"],
        "creationDateTimeUtc": _now(),
        "lastUpdateDateTimeUtc": _now(),
        "fileInstances": [
            {"id": _uuid(), "fileUrl": f"https://api.securitycenter.microsoft.com/api/machineactions/{action_id}/getPackageUri", "expirationDateTimeUtc": (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ],
        "scope": None,
        "requestSource": "PublicApi",
        "errorHResult": 0,
        "startTime": _now(),
    }
    return _MACHINE_ACTIONS[action_id]


@router.post("/api/machines/{machine_id}/restrictCodeExecution")
async def restrict_code_execution(machine_id: str, body: dict = Body(default={})):
    """Restrict application execution on a machine (only Microsoft-signed apps allowed)."""
    action_id = _uuid()
    _MACHINE_ACTIONS[action_id] = {
        "id": action_id,
        "type": "RestrictCodeExecution",
        "status": "Succeeded",
        "machineId": machine_id,
        "requestorComment": body.get("Comment", ""),
        "creationDateTimeUtc": _now(),
        "lastUpdateDateTimeUtc": _now(),
    }
    return _MACHINE_ACTIONS[action_id]


@router.post("/api/machines/{machine_id}/unrestrict_code_execution")
async def unrestrict_code_execution(machine_id: str, body: dict = Body(default={})):
    """Remove code execution restriction."""
    action_id = _uuid()
    _MACHINE_ACTIONS[action_id] = {"id": action_id, "type": "UnrestrictCodeExecution", "status": "Succeeded", "machineId": machine_id, "creationDateTimeUtc": _now()}
    return _MACHINE_ACTIONS[action_id]


@router.post("/api/machines/{machine_id}/offboard")
async def offboard_machine(machine_id: str, body: dict = Body(default={})):
    """Offboard a machine from MDE (remove sensor)."""
    if machine_id in _MACHINES:
        _MACHINES[machine_id]["onboardingStatus"] = "CanBeOnboarded"
        _MACHINES[machine_id]["healthStatus"] = "Inactive"
    action_id = _uuid()
    return {"id": action_id, "type": "Offboard", "status": "Succeeded", "machineId": machine_id, "creationDateTimeUtc": _now()}


# ─────────────────────────────────────────────────────────────────────────────
# Machine Actions
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/machineactions")
async def list_machine_actions(
    filter: Optional[str] = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top"),
    skip: int = Query(0, alias="$skip"),
):
    """List machine actions. Filter: machineId eq 'X', type eq 'Isolate', status eq 'Succeeded'"""
    actions = list(_MACHINE_ACTIONS.values())
    actions = _odata_filter(filter, actions)
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#MachineActions",
        "value": actions[skip: skip + top],
    }


@router.get("/api/machineactions/{action_id}")
async def get_machine_action(action_id: str):
    """Get a specific machine action by ID."""
    if action_id not in _MACHINE_ACTIONS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": "Action not found"}})
    return _MACHINE_ACTIONS[action_id]


@router.post("/api/machineactions/{action_id}/cancel")
async def cancel_machine_action(action_id: str, body: dict = Body(default={})):
    """Cancel a pending machine action."""
    if action_id in _MACHINE_ACTIONS:
        _MACHINE_ACTIONS[action_id]["status"] = "Cancelled"
        _MACHINE_ACTIONS[action_id]["cancellationComment"] = body.get("Comment", "")
    return _MACHINE_ACTIONS.get(action_id, {"id": action_id, "status": "Cancelled"})


# ─────────────────────────────────────────────────────────────────────────────
# Alerts API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/alerts")
async def list_alerts(
    filter: Optional[str] = Query(None, alias="$filter", description="OData: severity eq 'High', status eq 'New', machineId eq '...', category eq 'Execution'"),
    top: int = Query(100, alias="$top"),
    skip: int = Query(0, alias="$skip"),
    orderby: Optional[str] = Query(None, alias="$orderby"),
):
    """
    List alerts. OData filter fields:
      id, title, severity (Informational|Low|Medium|High), status (New|InProgress|Resolved),
      machineId, computerDnsName, category, detectionSource, lastUpdateTime, creationTime
    """
    alerts = list(_ALERTS.values())
    alerts = _odata_filter(filter, alerts)
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Alerts",
        "@odata.count": len(alerts),
        "value": alerts[skip: skip + top],
    }


@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get a specific alert with full evidence chain."""
    if alert_id not in _ALERTS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Alert {alert_id} not found"}})
    return _ALERTS[alert_id]


@router.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id: str, body: dict = Body(default={})):
    """
    Update an alert.
    Fields: status (New|InProgress|Resolved), assignedTo, classification, determination, comment
    classification: TruePositive | FalsePositive | BenignPositive
    determination: NotAvailable | Apt | Malware | SecurityPersonnel | SecurityTesting | UnwantedSoftware | Other
    """
    if alert_id not in _ALERTS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Alert {alert_id} not found"}})
    alert = _ALERTS[alert_id]
    for field in ("status", "assignedTo", "classification", "determination"):
        if field in body:
            alert[field] = body[field]
    if "comment" in body:
        alert.setdefault("comments", []).append({"createBy": "analyst@corp.local", "createTime": _now(), "text": body["comment"]})
    alert["lastUpdateTime"] = _now()
    return alert


@router.post("/api/alerts/{alert_id}/comments")
async def create_alert_comment(alert_id: str, body: dict = Body(default={})):
    """Add a comment to an alert."""
    if alert_id not in _ALERTS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Alert {alert_id} not found"}})
    comment = {"createBy": "analyst@corp.local", "createTime": _now(), "text": body.get("Comment", "")}
    _ALERTS[alert_id].setdefault("comments", []).append(comment)
    return comment


# ─────────────────────────────────────────────────────────────────────────────
# Incidents API
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/incidents")
async def list_incidents(
    filter: Optional[str] = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top"),
    skip: int = Query(0, alias="$skip"),
):
    """List incidents. Filter fields: id, incidentName, status (Active|Resolved), severity."""
    incidents = list(_INCIDENTS.values())
    incidents = _odata_filter(filter, incidents)
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Incidents",
        "value": incidents[skip: skip + top],
    }


@router.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get a specific incident with linked alerts and affected devices."""
    if incident_id not in _INCIDENTS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Incident {incident_id} not found"}})
    inc = dict(_INCIDENTS[incident_id])
    inc["alerts"] = [_ALERTS[a] for a in inc["alerts"] if a in _ALERTS]
    return inc


@router.patch("/api/incidents/{incident_id}")
async def update_incident(incident_id: str, body: dict = Body(default={})):
    """Update an incident: status, assignedTo, classification, determination, tags."""
    if incident_id not in _INCIDENTS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Incident {incident_id} not found"}})
    inc = _INCIDENTS[incident_id]
    for field in ("status", "assignedTo", "classification", "determination", "tags"):
        if field in body:
            inc[field] = body[field]
    inc["lastUpdateTime"] = _now()
    return inc


# ─────────────────────────────────────────────────────────────────────────────
# Advanced Hunting — KQL queries
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/api/advancedqueries/run")
async def run_advanced_hunting(body: dict = Body(default={})):
    """
    Run a KQL (Kusto Query Language) Advanced Hunting query.
    body: {Query: string}

    Available tables:
      DeviceInfo, DeviceNetworkInfo, DeviceProcessEvents, DeviceNetworkEvents,
      DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents,
      DeviceImageLoadEvents, DeviceEvents, DeviceAlertEvents,
      AlertInfo, AlertEvidence, IdentityLogonEvents, IdentityQueryEvents,
      EmailEvents, EmailAttachmentInfo, EmailUrlInfo

    Returns: {Schema: [{Name, Type}], Results: [{...}], Stats: {...}}
    """
    query = body.get("Query", "")

    # Static responses per query pattern
    if "DeviceProcessEvents" in query:
        results = [
            {
                "DeviceName": "CORP-WS-001",
                "DeviceId": "mde-machine-001",
                "Timestamp": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "ProcessId": 4200,
                "FileName": "powershell.exe",
                "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
                "SHA256": "b" * 64,
                "ProcessCommandLine": "powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBuAHYAbwBr...",
                "AccountName": "jsmith",
                "AccountDomain": "CORP",
                "InitiatingProcessFileName": "WINWORD.EXE",
                "InitiatingProcessCommandLine": "\"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE\"",
                "InitiatingProcessId": 3100,
            }
        ]
        schema = [
            {"Name": "DeviceName", "Type": "string"}, {"Name": "DeviceId", "Type": "string"}, {"Name": "Timestamp", "Type": "datetime"},
            {"Name": "ProcessId", "Type": "long"}, {"Name": "FileName", "Type": "string"}, {"Name": "FolderPath", "Type": "string"},
            {"Name": "SHA256", "Type": "string"}, {"Name": "ProcessCommandLine", "Type": "string"}, {"Name": "AccountName", "Type": "string"},
            {"Name": "InitiatingProcessFileName", "Type": "string"},
        ]
    elif "DeviceNetworkEvents" in query:
        results = [
            {"DeviceName": "CORP-WS-001", "DeviceId": "mde-machine-001", "Timestamp": _now(), "LocalIP": "10.10.1.101", "LocalPort": 49123, "RemoteIP": "203.0.113.200", "RemotePort": 443, "RemoteUrl": "malicious-domain.evil.example", "Protocol": "Tcp", "ActionType": "ConnectionSuccess"},
            {"DeviceName": "CORP-WS-001", "DeviceId": "mde-machine-001", "Timestamp": _now(), "LocalIP": "10.10.1.101", "LocalPort": 49124, "RemoteIP": "10.10.2.1", "RemotePort": 445, "RemoteUrl": "", "Protocol": "Tcp", "ActionType": "ConnectionSuccess"},
        ]
        schema = [{"Name": "DeviceName", "Type": "string"}, {"Name": "LocalIP", "Type": "string"}, {"Name": "RemoteIP", "Type": "string"}, {"Name": "RemotePort", "Type": "long"}, {"Name": "RemoteUrl", "Type": "string"}, {"Name": "ActionType", "Type": "string"}]
    elif "DeviceLogonEvents" in query:
        results = [
            {"DeviceName": "CORP-WS-001", "DeviceId": "mde-machine-001", "Timestamp": _now(), "AccountName": "jsmith", "AccountDomain": "CORP", "LogonType": "Interactive", "ActionType": "LogonSuccess", "RemoteIP": "", "IsLocalAdmin": True},
        ]
        schema = [{"Name": "DeviceName", "Type": "string"}, {"Name": "AccountName", "Type": "string"}, {"Name": "LogonType", "Type": "string"}, {"Name": "ActionType", "Type": "string"}]
    elif "DeviceInfo" in query:
        results = [
            {"DeviceName": m["computerDnsName"].split(".")[0], "DeviceId": mid, "OSPlatform": m["osPlatform"], "OSVersion": m["osVersion"], "PublicIP": m["lastExternalIpAddress"], "OnboardingStatus": m["onboardingStatus"], "RiskScore": m["riskScore"], "ExposureLevel": m["exposureLevel"]}
            for mid, m in _MACHINES.items()
        ]
        schema = [{"Name": "DeviceName", "Type": "string"}, {"Name": "DeviceId", "Type": "string"}, {"Name": "OSPlatform", "Type": "string"}, {"Name": "RiskScore", "Type": "string"}]
    elif "AlertInfo" in query or "AlertEvidence" in query:
        results = [{"AlertId": a["id"], "Title": a["title"], "Severity": a["severity"], "Category": a["category"], "AttackTechniques": a.get("mitreTechniques", [])} for a in _ALERTS.values()]
        schema = [{"Name": "AlertId", "Type": "string"}, {"Name": "Title", "Type": "string"}, {"Name": "Severity", "Type": "string"}, {"Name": "Category", "Type": "string"}]
    else:
        results = []
        schema = []

    return {
        "Schema": schema,
        "Results": results,
        "Stats": {
            "ExecutionTime": 0.523,
            "resource_usage": {"cache": {"memory_hit_bytes": 0, "original_bytes": 0}},
            "dataset_statistics": [{"table_row_count": len(results), "table_size": len(results) * 100}],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Indicators (Custom IOCs)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/indicators")
async def list_indicators(
    filter: Optional[str] = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top"),
    skip: int = Query(0, alias="$skip"),
):
    """List custom indicators. Filter: indicatorType eq 'Sha256', action eq 'Block'"""
    indicators = list(_INDICATORS.values())
    indicators = _odata_filter(filter, indicators)
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Indicators", "value": indicators[skip: skip + top]}


@router.get("/api/indicators/{indicator_id}")
async def get_indicator(indicator_id: str):
    """Get a specific custom indicator."""
    if indicator_id not in _INDICATORS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": "Indicator not found"}})
    return _INDICATORS[indicator_id]


@router.post("/api/indicators")
async def create_indicator(body: dict = Body(default={})):
    """
    Create a custom indicator.
    Required: indicatorValue, indicatorType, action, title
    indicatorType: FileSha1 | FileSha256 | FileMd5 | CertificateThumbprint | IpAddress | DomainName | Url
    action: Alert | AlertAndBlock | Block | Warn | Audit | Allowed | BlockAndRemediate
    severity: Informational | Low | Medium | High
    """
    ind_id = _uuid()
    indicator = {
        "id": ind_id,
        "indicatorValue": body.get("indicatorValue", ""),
        "indicatorType": body.get("indicatorType", "FileSha256"),
        "action": body.get("action", "Alert"),
        "title": body.get("title", ""),
        "description": body.get("description", ""),
        "severity": body.get("severity", "Informational"),
        "recommendedActions": body.get("recommendedActions", ""),
        "rbacGroupIds": body.get("rbacGroupIds", []),
        "rbacGroupNames": body.get("rbacGroupNames", []),
        "educateUrl": body.get("educateUrl", None),
        "historicalDetection": body.get("historicalDetection", False),
        "lookBackPeriod": body.get("lookBackPeriod", None),
        "expirationTime": body.get("expirationTime", None),
        "createdBy": "analyst@corp.local",
        "creationTimeDateTimeUtc": _now(),
        "updatedBy": None,
        "lastUpdateTime": _now(),
        "category": 1,
        "mitreTechniques": body.get("mitreTechniques", []),
        "generateAlert": body.get("generateAlert", True),
    }
    _INDICATORS[ind_id] = indicator
    return indicator


@router.delete("/api/indicators/{indicator_id}")
async def delete_indicator(indicator_id: str):
    """Delete a custom indicator."""
    if indicator_id not in _INDICATORS:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": "Indicator not found"}})
    del _INDICATORS[indicator_id]
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# TVM (Threat & Vulnerability Management)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/vulnerabilities")
async def list_vulnerabilities(
    filter: Optional[str] = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top"),
    skip: int = Query(0, alias="$skip"),
):
    """List all vulnerabilities across the organization (TVM)."""
    vulns = [
        {"id": "CVE-2024-21413", "name": "CVE-2024-21413", "description": "Microsoft Outlook RCE", "severity": "Critical", "cvssV3": 9.8, "exposedMachines": 1, "publishedOn": "2024-02-13", "updatedOn": "2024-02-20", "publicExploit": True},
        {"id": "CVE-2024-20674", "name": "CVE-2024-20674", "description": "Windows Kerberos Security Feature Bypass", "severity": "Critical", "cvssV3": 9.0, "exposedMachines": 3, "publishedOn": "2024-01-09", "updatedOn": "2024-01-16", "publicExploit": False},
    ]
    vulns = _odata_filter(filter, vulns)
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Vulnerabilities", "value": vulns[skip: skip + top]}


@router.get("/api/exposureScore")
async def get_exposure_score():
    """Get organization-wide exposure score."""
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#ExposureScore", "score": 42.35, "time": _now(), "rbacGroupId": 0}


@router.get("/api/secureScores")
async def get_secure_scores():
    """Get Microsoft Secure Score for Devices."""
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#SecureScore", "time": _now(), "score": 72.0, "rbacGroupId": 0}


@router.get("/api/recommendations")
async def list_recommendations(
    filter: Optional[str] = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top"),
    skip: int = Query(0, alias="$skip"),
):
    """List security recommendations (TVM)."""
    recs = [
        {"id": "va-microsoft-_-outlook", "productName": "outlook", "recommendationName": "Update Microsoft Outlook", "weaknesses": 1, "vendor": "microsoft", "recommendedVersion": "16.0.17126.20132", "recommendationCategory": "Application", "subCategory": "Update", "severityScore": 9.8, "publicExploit": True, "activeAlert": True, "associatedThreats": ["CVE-2024-21413"], "remediationType": "Update", "status": "Active", "configScoreImpact": 0, "exposureImpact": -5.23, "totalMachineCount": 3, "exposedMachinesCount": 1},
    ]
    return {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Recommendations", "value": recs[skip: skip + top]}


# ─────────────────────────────────────────────────────────────────────────────
# Live Response — remote session & commands
# ─────────────────────────────────────────────────────────────────────────────

_live_sessions: dict[str, dict] = {}


@router.post("/api/machines/{machine_id}/runliveresponse")
async def run_live_response(machine_id: str, body: dict = Body(default={})):
    """
    Run a Live Response command on a machine.
    body: {Comment: str, Commands: [{type, params: {}}]}
    Command types: PutFile | RunScript | GetFile
    PutFile params: {FileName: str}
    RunScript params: {ScriptName: str, Args: str}
    GetFile params: {Path: str}
    """
    if machine_id not in _MACHINES:
        raise HTTPException(404, detail={"error": {"code": "ResourceNotFound", "message": f"Machine {machine_id} not found"}})

    action_id = _uuid()
    commands = body.get("Commands", [])
    _MACHINE_ACTIONS[action_id] = {
        "id": action_id,
        "type": "LiveResponse",
        "requestor": "analyst@corp.local",
        "requestorComment": body.get("Comment", ""),
        "status": "Succeeded",
        "machineId": machine_id,
        "computerDnsName": _MACHINES[machine_id]["computerDnsName"],
        "creationDateTimeUtc": _now(),
        "lastUpdateDateTimeUtc": _now(),
        "commands": [{"index": i, "startTime": _now(), "endTime": _now(), "commandStatus": "Completed", "errors": [], "command": c} for i, c in enumerate(commands)],
        "scope": None,
        "requestSource": "PublicApi",
    }
    return _MACHINE_ACTIONS[action_id]


@router.get("/api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index={command_index})")
async def get_live_response_result(action_id: str, command_index: int):
    """Get download URL for live response command output."""
    return {"value": f"https://api.securitycenter.microsoft.com/api/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index={command_index})/result"}


# ─────────────────────────────────────────────────────────────────────────────
# Library (file/script management for Live Response)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/libraryfiles")
async def list_library_files():
    """List files in the Live Response library."""
    return {
        "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#LibraryFiles",
        "value": [
            {"id": "lib-file-001", "fileName": "collect_forensics.ps1", "description": "Collect forensic artifacts", "createdBy": "analyst@corp.local", "hasParameters": False, "parametersDescription": "", "creationTime": "2024-01-01T00:00:00Z", "lastUpdatedTime": "2024-01-01T00:00:00Z", "fileSize": 2048, "overrideIfExists": False},
        ],
    }


@router.post("/api/libraryfiles")
async def upload_library_file(body: dict = Body(default={})):
    """Upload a script/file to the Live Response library."""
    file_id = _uuid()
    return {"id": file_id, "fileName": body.get("FileName", "file.ps1"), "description": body.get("Description", ""), "createdBy": "analyst@corp.local", "creationTime": _now(), "fileSize": 0, "overrideIfExists": body.get("OverrideIfExists", False)}
