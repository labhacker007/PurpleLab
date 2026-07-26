"""Qualys VMDR + CSPM + Policy Compliance API emulation.

Grounded in official Qualys API Reference:
  https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf
  https://qualysapi.qualys.com/

Implements:
  Host Asset Management (/api/2.0/fo/asset/host/)
  Vulnerability Knowledge Base (/api/2.0/fo/knowledge_base/vuln/)
  Host Detection List (/api/2.0/fo/asset/host/vm/detection/)
  Scan Management (/api/2.0/fo/scan/)
  Report Templates (/api/2.0/fo/report/)
  Asset Group Management (/api/2.0/fo/asset/group/)
  CSPM API (cloud.qualys.com/csapi/v1.0/controls, /findings)
  Container Security (/csapi/v1.0/containers)

Authentication:
  Basic: Authorization: Basic base64(user:pass)
  API Key: X-Requested-With header + Basic (still required)

Response format:
  Most endpoints return XML wrapped in <QUALYS_API_OUTPUT>
  We simulate with JSON for simplicity (same field semantics)
  The Content-Type: application/xml header triggers XML mode on real API

Qualys-specific conventions:
  Severity levels: 1=Confirmed, 2=Potential, 3=Information Gathered
  CVSS severity labels: 1=Low, 2=Low, 3=Medium, 4=High, 5=Critical
  Detection types: Confirmed, Potential, Information Gathered
  Status codes: New, Active, Fixed, Re-Opened
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Form, Header, HTTPException, Query, Request

router = APIRouter(prefix="/api/vendor/qualys", tags=["vendor:qualys"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Seed data
# ─────────────────────────────────────────────────────────────────────────────

_HOSTS: list[dict] = [
    {
        "id": "11001",
        "ip": "10.10.1.101",
        "tracking_method": "IP",
        "network_id": "0",
        "os": "Windows 11 Enterprise",
        "os_cpe": "cpe:/o:microsoft:windows_11:-:enterprise",
        "dns": "corp-ws-001.corp.local",
        "netbios": "CORP-WS-001",
        "qg_hostid": "ec0b2e47-0001-0000-0000-000000000001",
        "last_scan_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_auth_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_auth_scanned_duration": "00:02:14",
        "last_pc_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tags": [{"id": "1001", "name": "Production"}, {"id": "1002", "name": "Engineering"}],
        "asset_groups": [{"id": "501", "title": "Corp Workstations"}],
        "metadata": {
            "ec2": None,
            "azure": None,
            "google": None,
        },
    },
    {
        "id": "11002",
        "ip": "10.10.2.10",
        "tracking_method": "IP",
        "network_id": "0",
        "os": "Windows Server 2022 Standard",
        "os_cpe": "cpe:/o:microsoft:windows_server_2022::-:standard",
        "dns": "corp-srv-001.corp.local",
        "netbios": "CORP-SRV-001",
        "qg_hostid": "ec0b2e47-0002-0000-0000-000000000002",
        "last_scan_datetime": (datetime.now(timezone.utc) - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_auth_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_auth_scanned_duration": "00:04:32",
        "last_pc_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tags": [{"id": "1001", "name": "Production"}, {"id": "1003", "name": "Servers"}],
        "asset_groups": [{"id": "502", "title": "Corp Servers"}],
        "metadata": {},
    },
    {
        "id": "11003",
        "ip": "10.10.2.1",
        "tracking_method": "IP",
        "network_id": "0",
        "os": "Windows Server 2022 Datacenter",
        "os_cpe": "cpe:/o:microsoft:windows_server_2022::-:datacenter",
        "dns": "corp-dc-001.corp.local",
        "netbios": "CORP-DC-001",
        "qg_hostid": "ec0b2e47-0003-0000-0000-000000000003",
        "last_scan_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_auth_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_vm_auth_scanned_duration": "00:03:18",
        "last_pc_scanned_datetime": (datetime.now(timezone.utc) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tags": [{"id": "1001", "name": "Production"}, {"id": "1003", "name": "Servers"}, {"id": "1004", "name": "Domain Controllers"}],
        "asset_groups": [{"id": "502", "title": "Corp Servers"}, {"id": "503", "title": "Active Directory"}],
        "metadata": {},
    },
]

_VULNS_KB: dict[int, dict] = {
    90356: {
        "qid": 90356,
        "vuln_type": "CONFIRMED",
        "severity_level": 5,
        "title": "Microsoft Outlook Remote Code Execution Vulnerability (CVE-2024-21413)",
        "category": "Windows",
        "last_customization": None,
        "last_service_modification_datetime": "2024-02-14T00:00:00Z",
        "published_datetime": "2024-02-13T00:00:00Z",
        "bugtraq_list": [],
        "patchable": 1,
        "software_list": [{"product": "Microsoft Outlook 2016", "vendor": "microsoft"}, {"product": "Microsoft 365 Apps", "vendor": "microsoft"}],
        "vendor_reference_list": [{"id": "MS24-Feb", "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"}],
        "cve_list": [{"id": "CVE-2024-21413", "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21413"}],
        "diagnosis": "A remote code execution vulnerability exists in Microsoft Outlook when it fails to properly handle objects in memory. An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the current user.",
        "diagnosis_comment": None,
        "consequence": "Attacker can execute arbitrary code with the privileges of the current user. If the current user is logged on with administrative user rights, an attacker could take complete control of the affected system.",
        "solution": "Apply the appropriate update:\n- Microsoft 365 Apps: Update to version 16.0.17126.20132 or later\n- Microsoft Outlook 2016: Apply KB5034671\n\nDownload from: https://support.microsoft.com/help/5034671",
        "solution_comment": "Emergency patching recommended given active exploitation.",
        "compliance_list": [],
        "correlation": {"exploits": {"explt_src_list": [{"src_name": "EXPLOIT-DB", "explt_list": [{"ref": "https://exploit-db.com/exploits/51834", "desc": "PoC exploit available"}]}]}, "malware": {}},
        "cvss": {"base": "10.0", "temporal": "8.7", "vector_string": "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
        "cvss3": {"base": "9.8", "temporal": "9.3", "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "pci_flag": 1,
        "is_disabled": 0,
        "change_log_list": [],
    },
    150021: {
        "qid": 150021,
        "vuln_type": "CONFIRMED",
        "severity_level": 4,
        "title": "Windows SMB Signing Not Required",
        "category": "Windows",
        "published_datetime": "2023-01-01T00:00:00Z",
        "patchable": 0,
        "cve_list": [],
        "diagnosis": "The remote Windows host does not require SMB packet signing. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks.",
        "solution": "Configure the following Group Policy settings:\n- Microsoft network server: Digitally sign communications (always): Enabled\n- Microsoft network client: Digitally sign communications (always): Enabled",
        "cvss": {"base": "7.1", "vector_string": "AV:N/AC:M/Au:N/C:N/I:C/A:N"},
        "cvss3": {"base": "7.5", "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "pci_flag": 1,
        "is_disabled": 0,
    },
    105263: {
        "qid": 105263,
        "vuln_type": "CONFIRMED",
        "severity_level": 3,
        "title": "SSL/TLS Protocol Versions Supported",
        "category": "General",
        "published_datetime": "2022-06-01T00:00:00Z",
        "patchable": 0,
        "cve_list": [{"id": "CVE-2011-3389"}],
        "diagnosis": "The remote SSL/TLS service supports deprecated protocol versions (TLS 1.0/1.1).",
        "solution": "Disable TLS 1.0 and 1.1. Enable only TLS 1.2 and TLS 1.3.",
        "cvss": {"base": "4.3", "vector_string": "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
        "cvss3": {"base": "5.3", "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
        "pci_flag": 1,
        "is_disabled": 0,
    },
}

_DETECTIONS: list[dict] = [
    {
        "host_id": "11001",
        "ip": "10.10.1.101",
        "dns": "corp-ws-001.corp.local",
        "netbios": "CORP-WS-001",
        "os": "Windows 11 Enterprise",
        "qg_hostid": "ec0b2e47-0001-0000-0000-000000000001",
        "last_scan_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "detection_list": [
            {
                "unique_vuln_id": "90356-10.10.1.101-0",
                "qid": 90356,
                "type": "Confirmed",
                "severity": 5,
                "port": None,
                "protocol": None,
                "ssl": None,
                "instance": None,
                "results": "Path: C:\\Program Files (x86)\\Microsoft Office\\Office16\\OUTLOOK.EXE\nVersion: 16.0.16827.20166\nFixed version: 16.0.17126.20132",
                "status": "New",
                "first_found_datetime": (datetime.now(timezone.utc) - timedelta(days=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_found_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "qds_severity": "CRITICAL",
                "qds": 92,
                "times_found": 2,
                "last_test_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_update_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "is_ignored": 0,
                "is_disabled": 0,
            },
            {
                "unique_vuln_id": "150021-10.10.1.101-0",
                "qid": 150021,
                "type": "Confirmed",
                "severity": 4,
                "port": 445,
                "protocol": "TCP",
                "ssl": 0,
                "instance": None,
                "results": "The host does not require SMB signing.",
                "status": "Active",
                "first_found_datetime": (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_found_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "qds_severity": "HIGH",
                "qds": 70,
                "times_found": 12,
                "is_ignored": 0,
                "is_disabled": 0,
            },
        ],
    },
    {
        "host_id": "11002",
        "ip": "10.10.2.10",
        "dns": "corp-srv-001.corp.local",
        "netbios": "CORP-SRV-001",
        "os": "Windows Server 2022 Standard",
        "qg_hostid": "ec0b2e47-0002-0000-0000-000000000002",
        "last_scan_datetime": (datetime.now(timezone.utc) - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "detection_list": [
            {
                "unique_vuln_id": "105263-10.10.2.10-443",
                "qid": 105263,
                "type": "Confirmed",
                "severity": 3,
                "port": 443,
                "protocol": "TCP",
                "ssl": 1,
                "results": "TLS 1.0 is supported. Cipher: TLS_RSA_WITH_AES_128_CBC_SHA",
                "status": "Active",
                "first_found_datetime": (datetime.now(timezone.utc) - timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_found_datetime": (datetime.now(timezone.utc) - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "qds_severity": "MEDIUM",
                "qds": 50,
                "times_found": 24,
                "is_ignored": 0,
                "is_disabled": 0,
            },
        ],
    },
]

# CSPM data
_CSPM_CONTROLS: list[dict] = [
    {
        "controlId": "1.1", "controlName": "S3 Bucket Versioning Enabled",
        "service": "AWS S3", "criticality": "CRITICAL",
        "description": "Ensure versioning is enabled on S3 buckets.",
        "rationale": "Versioning allows recovery from accidental deletion or overwrite.",
        "severity": "CRITICAL",
        "cis_id": "2.1.3",
    },
    {
        "controlId": "1.2", "controlName": "S3 Bucket Not Public",
        "service": "AWS S3", "criticality": "CRITICAL",
        "description": "Ensure S3 buckets do not have public access enabled.",
        "rationale": "Public S3 buckets can expose sensitive data to the internet.",
        "severity": "CRITICAL",
        "cis_id": "2.1.5",
    },
    {
        "controlId": "2.1", "controlName": "CloudTrail Enabled in All Regions",
        "service": "AWS CloudTrail", "criticality": "HIGH",
        "description": "Ensure CloudTrail is enabled in all regions.",
        "severity": "HIGH",
        "cis_id": "3.1",
    },
    {
        "controlId": "3.1", "controlName": "MFA Enabled for IAM Users",
        "service": "AWS IAM", "criticality": "HIGH",
        "description": "Ensure MFA is enabled for all IAM users with console access.",
        "severity": "HIGH",
        "cis_id": "1.5",
    },
]

_CSPM_FINDINGS: list[dict] = [
    {
        "findingId": "cspm-finding-001",
        "controlId": "1.2",
        "controlName": "S3 Bucket Not Public",
        "severity": "CRITICAL",
        "resourceName": "corp-logs-bucket",
        "resourceArn": "arn:aws:s3:::corp-logs-bucket",
        "resourceType": "AWS::S3::Bucket",
        "region": "us-east-1",
        "cloudAccountId": "123456789012",
        "status": "FAIL",
        "firstDetectedOn": (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastUpdatedOn": _now_iso(),
        "remediation": "Enable 'Block all public access' in S3 Bucket's Permissions > Block Public Access settings.",
        "tags": [{"key": "Environment", "value": "production"}],
    },
    {
        "findingId": "cspm-finding-002",
        "controlId": "3.1",
        "controlName": "MFA Enabled for IAM Users",
        "severity": "HIGH",
        "resourceName": "user-jsmith",
        "resourceArn": "arn:aws:iam::123456789012:user/jsmith",
        "resourceType": "AWS::IAM::User",
        "region": "global",
        "cloudAccountId": "123456789012",
        "status": "FAIL",
        "firstDetectedOn": (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastUpdatedOn": _now_iso(),
        "remediation": "Navigate to IAM console > Users > jsmith > Security credentials > Assigned MFA device > Assign MFA device.",
        "tags": [],
    },
    {
        "findingId": "cspm-finding-003",
        "controlId": "2.1",
        "controlName": "CloudTrail Enabled in All Regions",
        "severity": "HIGH",
        "resourceName": "ap-southeast-2",
        "resourceArn": "arn:aws:cloudtrail:ap-southeast-2:123456789012:trail",
        "resourceType": "AWS::CloudTrail::Trail",
        "region": "ap-southeast-2",
        "cloudAccountId": "123456789012",
        "status": "FAIL",
        "firstDetectedOn": (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastUpdatedOn": _now_iso(),
        "remediation": "Create a CloudTrail trail for the ap-southeast-2 region.",
        "tags": [],
    },
]

_SCANS: list[dict] = [
    {
        "id": "scan/1803920.20240726001234",
        "ref": "scan/1803920.20240726001234",
        "type": "vm",
        "title": "Corp Full Scan — Weekly Authenticated",
        "user_login": "qualys_svc",
        "launch_datetime": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration": "00:02:15",
        "processing_priority": "0",
        "processed": 1,
        "state": "Finished",
        "target": "10.10.0.0/16",
        "option_profile": {"id": "500001", "title": "Initial Options"},
        "asset_groups": [{"id": "501"}, {"id": "502"}, {"id": "503"}],
        "status": {"state": "Finished", "sub_state": "None"},
        "summary": {"hosts_scanned": 47, "hosts_alive": 46, "hosts_dead": 1},
        "mode": "External",
    },
]

_ASSET_GROUPS: list[dict] = [
    {"id": "501", "title": "Corp Workstations", "owner": "qualys_admin", "last_update": "2024-01-01T00:00:00Z", "network_ids": "0", "ip": "10.10.1.0/24", "dns": None, "domains": None, "host_count": 25},
    {"id": "502", "title": "Corp Servers", "owner": "qualys_admin", "last_update": "2024-01-01T00:00:00Z", "network_ids": "0", "ip": "10.10.2.0/24", "dns": None, "domains": None, "host_count": 15},
    {"id": "503", "title": "Active Directory", "owner": "qualys_admin", "last_update": "2024-01-01T00:00:00Z", "network_ids": "0", "ip": "10.10.2.1-10.10.2.10", "dns": None, "domains": None, "host_count": 3},
]


# ─────────────────────────────────────────────────────────────────────────────
# Auth helper
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/api/2.0/fo/session/")
async def create_session(body: dict = Body(default={})):
    """Create a Qualys session."""
    return {
        "QUALYS_SESSION": f"qualys-session-{uuid.uuid4().hex[:32]}",
        "user": {"id": "1", "login": "qualys_svc", "name": "Qualys Service Account"},
    }


@router.delete("/api/2.0/fo/session/")
async def delete_session():
    return {"status": "success"}


# ─────────────────────────────────────────────────────────────────────────────
# Host Asset Management
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/2.0/fo/asset/host/")
async def list_hosts(
    action: str = Query("list"),
    ids: Optional[str] = Query(None, description="Comma-separated host IDs"),
    ips: Optional[str] = Query(None, description="Comma-separated IPs or CIDR ranges"),
    network_ids: Optional[str] = Query(None),
    ag_ids: Optional[str] = Query(None, description="Asset group IDs"),
    ag_titles: Optional[str] = Query(None),
    os_pattern: Optional[str] = Query(None),
    dns_names: Optional[str] = Query(None),
    tags_include_all: Optional[str] = Query(None),
    tags_include_any: Optional[str] = Query(None),
    show_tags: int = Query(1),
    show_asset_groups: int = Query(1),
    show_operating_system: int = Query(1),
    vm_scan_since: Optional[str] = Query(None),
    no_vm_scan_since: Optional[str] = Query(None),
    truncation_limit: int = Query(10000),
    details: str = Query("All"),
):
    """List host assets with optional filters."""
    hosts = list(_HOSTS)

    if ids:
        id_list = [i.strip() for i in ids.split(",")]
        hosts = [h for h in hosts if h["id"] in id_list]

    if ips:
        ip_list = [i.strip() for i in ips.split(",")]
        hosts = [h for h in hosts if any(h["ip"].startswith(ip.split("/")[0][:8]) for ip in ip_list) or h["ip"] in ip_list]

    if ag_ids:
        ag_list = [i.strip() for i in ag_ids.split(",")]
        hosts = [h for h in hosts if any(ag["id"] in ag_list for ag in h.get("asset_groups", []))]

    if os_pattern:
        pattern = os_pattern.lower()
        hosts = [h for h in hosts if pattern in h.get("os", "").lower()]

    if dns_names:
        dns_list = [d.strip().lower() for d in dns_names.split(",")]
        hosts = [h for h in hosts if any(dns in h.get("dns", "").lower() for dns in dns_list)]

    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "HOST_LIST": {"HOST": hosts[:truncation_limit]},
                "WARNING": {"CODE": "1980", "TEXT": "1980: No host found for the specified criteria."} if not hosts else None,
            }
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Knowledge Base
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/2.0/fo/knowledge_base/vuln/")
async def list_kb_vulns(
    action: str = Query("list"),
    ids: Optional[str] = Query(None, description="Comma-separated QIDs"),
    details: str = Query("All"),
    severity_levels: Optional[str] = Query(None, description="Comma-separated severity levels 1-5"),
    patchable: Optional[int] = Query(None, description="1=patchable, 0=not patchable"),
    published_after_datetime: Optional[str] = Query(None),
    modified_after_datetime: Optional[str] = Query(None),
    cve_ids: Optional[str] = Query(None, description="Comma-separated CVE IDs"),
):
    """Query the Qualys vulnerability knowledge base."""
    vulns = list(_VULNS_KB.values())

    if ids:
        qid_list = [int(i.strip()) for i in ids.split(",") if i.strip().isdigit()]
        vulns = [v for v in vulns if v["qid"] in qid_list]

    if severity_levels:
        sev_list = [int(s.strip()) for s in severity_levels.split(",") if s.strip().isdigit()]
        vulns = [v for v in vulns if v["severity_level"] in sev_list]

    if patchable is not None:
        vulns = [v for v in vulns if v.get("patchable") == patchable]

    if cve_ids:
        cve_list = [c.strip().upper() for c in cve_ids.split(",")]
        vulns = [v for v in vulns if any(c["id"] in cve_list for c in v.get("cve_list", []))]

    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "VULN_LIST": {"VULN": vulns},
            }
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# Host Detection List — the core VMDR output
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/2.0/fo/asset/host/vm/detection/")
async def list_host_detections(
    action: str = Query("list"),
    ips: Optional[str] = Query(None),
    ids: Optional[str] = Query(None, description="Host IDs"),
    qids: Optional[str] = Query(None, description="QIDs to filter by"),
    severities: Optional[str] = Query(None, description="Comma-separated severity levels 1-5"),
    status: Optional[str] = Query(None, description="New,Active,Fixed,Re-Opened"),
    detection_updated_since_datetime: Optional[str] = Query(None),
    detection_updated_before_datetime: Optional[str] = Query(None),
    include_vuln_type: Optional[str] = Query(None, description="Confirmed,Potential,Information Gathered"),
    show_qds: int = Query(1),
    show_qds_factors: int = Query(0),
    show_igs: int = Query(0),
    truncation_limit: int = Query(1000),
    output_format: str = Query("JSON"),
):
    """
    List vulnerability detections per host.
    This is the primary VMDR endpoint used by SOAR integrations.
    """
    detections = list(_DETECTIONS)

    if ips:
        ip_list = [i.strip() for i in ips.split(",")]
        detections = [d for d in detections if d["ip"] in ip_list]

    if ids:
        id_list = [i.strip() for i in ids.split(",")]
        detections = [d for d in detections if d["host_id"] in id_list]

    if qids:
        qid_list = [int(q.strip()) for q in qids.split(",") if q.strip().isdigit()]
        for d in detections:
            d = dict(d)
            d["detection_list"] = [det for det in d["detection_list"] if det["qid"] in qid_list]

    if severities:
        sev_list = [int(s.strip()) for s in severities.split(",") if s.strip().isdigit()]
        for d in detections:
            d["detection_list"] = [det for det in d["detection_list"] if det["severity"] in sev_list]

    if status:
        stat_list = [s.strip() for s in status.split(",")]
        for d in detections:
            d["detection_list"] = [det for det in d["detection_list"] if det["status"] in stat_list]

    if include_vuln_type:
        type_list = [t.strip() for t in include_vuln_type.split(",")]
        for d in detections:
            d["detection_list"] = [det for det in d["detection_list"] if det["type"] in type_list]

    # Remove hosts with no detections after filtering
    detections = [d for d in detections if d.get("detection_list")]

    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "HOST_LIST_VM_DETECTION_OUTPUT": {
                    "HOST_LIST": {"HOST": detections[:truncation_limit]}
                }
            }
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scan Management
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/2.0/fo/scan/")
async def list_scans(
    action: str = Query("list"),
    type: Optional[str] = Query(None, description="vm,pc,scap"),
    state: Optional[str] = Query(None),
    launched_after_datetime: Optional[str] = Query(None),
    scan_ref: Optional[str] = Query(None),
):
    """List scans."""
    scans = list(_SCANS)
    if type:
        scans = [s for s in scans if s.get("type") == type]
    if state:
        scans = [s for s in scans if s.get("state") == state]
    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "SCAN_LIST": {"SCAN": scans},
            }
        }
    }


@router.post("/api/2.0/fo/scan/")
async def launch_scan(
    action: str = Query("launch"),
    scan_title: Optional[str] = Form(None),
    option_id: Optional[str] = Form(None),
    option_title: Optional[str] = Form(None),
    target_from: str = Form("assets"),
    ip: Optional[str] = Form(None),
    asset_group_ids: Optional[str] = Form(None),
    iscanner_name: Optional[str] = Form(None),
):
    """Launch a new scan."""
    scan_ref = f"scan/1803920.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    new_scan = {
        "id": scan_ref,
        "ref": scan_ref,
        "type": "vm",
        "title": scan_title or "On-demand Scan",
        "user_login": "qualys_svc",
        "launch_datetime": _now_iso(),
        "state": "Running",
        "target": ip or "All Assets",
        "status": {"state": "Running", "sub_state": "RunningScanner"},
    }
    _SCANS.append(new_scan)
    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "SCAN_REF": scan_ref,
                "ITEM_LIST": {"ITEM": [{"KEY": "SCAN_REF", "VALUE": scan_ref}]},
            }
        }
    }


@router.post("/api/2.0/fo/scan/{scan_ref}/action")
async def scan_action(scan_ref: str, action: str = Query("pause")):
    """Pause, resume, cancel, or delete a scan."""
    scan = next((s for s in _SCANS if s.get("ref") == f"scan/{scan_ref}" or s.get("id") == scan_ref), None)
    if not scan:
        raise HTTPException(404, {"error": f"Scan {scan_ref} not found"})
    if action == "pause":
        scan["state"] = "Paused"
    elif action == "resume":
        scan["state"] = "Running"
    elif action == "cancel":
        scan["state"] = "Cancelled"
    return {"QUALYS_API_OUTPUT": {"RESPONSE": {"DATETIME": _now_iso(), "CODE": "999", "TEXT": "Action completed."}}}


# ─────────────────────────────────────────────────────────────────────────────
# Asset Groups
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/2.0/fo/asset/group/")
async def list_asset_groups(
    action: str = Query("list"),
    ids: Optional[str] = Query(None),
    title: Optional[str] = Query(None),
    truncation_limit: int = Query(1000),
):
    """List asset groups."""
    groups = list(_ASSET_GROUPS)
    if ids:
        id_list = [i.strip() for i in ids.split(",")]
        groups = [g for g in groups if g["id"] in id_list]
    if title:
        groups = [g for g in groups if title.lower() in g["title"].lower()]
    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "ASSET_GROUP_LIST": {"ASSET_GROUP": groups[:truncation_limit]},
            }
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# CSPM API — cloud.qualys.com/csapi/v1.0
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/csapi/v1.0/controls")
async def list_cspm_controls(
    filter: Optional[str] = Query(None),
    pageNo: int = Query(1, ge=1),
    pageSize: int = Query(50, ge=1, le=100),
):
    """List CSPM controls (policies)."""
    controls = list(_CSPM_CONTROLS)
    if filter:
        filter_lower = filter.lower()
        controls = [c for c in controls if filter_lower in c["controlName"].lower() or filter_lower in c["service"].lower()]
    start = (pageNo - 1) * pageSize
    return {
        "data": controls[start: start + pageSize],
        "count": len(controls[start: start + pageSize]),
        "total": len(controls),
        "responseCode": "SUCCESS",
        "responseMessage": "Success",
    }


@router.get("/csapi/v1.0/controls/{control_id}")
async def get_cspm_control(control_id: str):
    """Get a specific CSPM control."""
    c = next((c for c in _CSPM_CONTROLS if c["controlId"] == control_id), None)
    if not c:
        raise HTTPException(404, {"responseCode": "ERROR", "responseMessage": f"Control {control_id} not found."})
    return {"data": c, "responseCode": "SUCCESS"}


@router.get("/csapi/v1.0/findings")
async def list_cspm_findings(
    filter: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    pageNo: int = Query(1, ge=1),
    pageSize: int = Query(50, ge=1, le=100),
):
    """List CSPM findings across all cloud accounts."""
    findings = list(_CSPM_FINDINGS)
    if severity:
        sev_list = [s.strip().upper() for s in severity.split(",")]
        findings = [f for f in findings if f["severity"] in sev_list]
    if status:
        stat_list = [s.strip().upper() for s in status.split(",")]
        findings = [f for f in findings if f["status"] in stat_list]
    if filter:
        filter_lower = filter.lower()
        findings = [f for f in findings if filter_lower in f["controlName"].lower() or filter_lower in f["resourceName"].lower()]
    start = (pageNo - 1) * pageSize
    return {
        "data": findings[start: start + pageSize],
        "count": len(findings[start: start + pageSize]),
        "total": len(findings),
        "responseCode": "SUCCESS",
        "responseMessage": "Success",
    }


@router.get("/csapi/v1.0/findings/{finding_id}")
async def get_cspm_finding(finding_id: str):
    """Get a specific CSPM finding."""
    f = next((x for x in _CSPM_FINDINGS if x["findingId"] == finding_id), None)
    if not f:
        raise HTTPException(404, {"responseCode": "ERROR", "responseMessage": f"Finding {finding_id} not found."})
    return {"data": f, "responseCode": "SUCCESS"}


@router.post("/csapi/v1.0/findings/{finding_id}/remediate")
async def remediate_cspm_finding(finding_id: str, body: dict = Body(default={})):
    """Mark a CSPM finding as remediated."""
    f = next((x for x in _CSPM_FINDINGS if x["findingId"] == finding_id), None)
    if not f:
        raise HTTPException(404, {"responseCode": "ERROR", "responseMessage": f"Finding {finding_id} not found."})
    f["status"] = "PASS"
    f["lastUpdatedOn"] = _now_iso()
    return {"responseCode": "SUCCESS", "responseMessage": "Finding marked as remediated."}


@router.get("/csapi/v1.0/resources")
async def list_cspm_resources(
    filter: Optional[str] = Query(None),
    resourceType: Optional[str] = Query(None),
    cloudAccountId: Optional[str] = Query(None),
    pageNo: int = Query(1, ge=1),
    pageSize: int = Query(50, ge=1, le=100),
):
    """List cloud resources discovered by CSPM."""
    resources = [
        {
            "resourceId": f["resourceArn"],
            "resourceName": f["resourceName"],
            "resourceType": f["resourceType"],
            "region": f["region"],
            "cloudAccountId": f["cloudAccountId"],
            "status": f["status"],
            "severity": f["severity"],
            "controlFailCount": 1,
        }
        for f in _CSPM_FINDINGS
    ]
    if resourceType:
        resources = [r for r in resources if r["resourceType"] == resourceType]
    if cloudAccountId:
        resources = [r for r in resources if r["cloudAccountId"] == cloudAccountId]
    start = (pageNo - 1) * pageSize
    return {
        "data": resources[start: start + pageSize],
        "total": len(resources),
        "responseCode": "SUCCESS",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Report Management
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/2.0/fo/report/")
async def list_reports(
    action: str = Query("list"),
    state: Optional[str] = Query(None),
):
    """List vulnerability reports."""
    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "REPORT_LIST": {"REPORT": [
                    {"id": "1001", "title": "Executive VM Report — July 2026", "type": "Map", "state": "Finished", "launch_datetime": "2026-07-24T00:00:00Z", "output_format": "pdf", "user_login": "qualys_svc"},
                    {"id": "1002", "title": "Technical Patch Report — Q3 2026", "type": "Scan", "state": "Finished", "launch_datetime": "2026-07-24T08:00:00Z", "output_format": "csv", "user_login": "qualys_svc"},
                ]},
            }
        }
    }


@router.post("/api/2.0/fo/report/")
async def launch_report(action: str = Query("launch"), body: dict = Body(default={})):
    """Launch a new report."""
    report_id = str(1000 + len(_SCANS))
    return {
        "QUALYS_API_OUTPUT": {
            "RESPONSE": {
                "DATETIME": _now_iso(),
                "ITEM_LIST": {"ITEM": [{"KEY": "ID", "VALUE": report_id}]},
            }
        }
    }
