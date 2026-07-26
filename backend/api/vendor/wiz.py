"""Wiz CSPM GraphQL API emulation.

Grounded in official Wiz API Reference:
  https://win.wiz.io/reference/cloud-security-api

Wiz uses GraphQL exclusively at POST /graphql
All operations are queries or mutations sent as JSON:
  {"query": "query {...}", "variables": {...}}

Key query types:
  issues         — Cloud security issues/misconfigurations
  cloudResources — Cloud assets (VMs, storage, IAM, network)
  controls       — Security controls and policy checks
  vulnerabilities — Container/VM vulnerabilities
  securityFrameworks — Compliance frameworks (CIS, PCI, NIST, etc.)
  subscriptions  — Tenant cloud subscriptions
  cloudAccounts  — Connected cloud accounts

Authentication:
  POST /oauth/token → access_token (client_credentials grant)
  Authorization: Bearer <token>

Issue severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
Issue status: OPEN, IN_PROGRESS, REJECTED, RESOLVED
Resource type: VIRTUAL_MACHINE, STORAGE_BUCKET, DATABASE, NETWORK, IAM_ROLE, CONTAINER, SERVERLESS_FUNCTION, KUBERNETES_NODE
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Request

router = APIRouter(prefix="/api/vendor/wiz", tags=["vendor:wiz"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat() + "Z"


def _uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Seed data
# ─────────────────────────────────────────────────────────────────────────────

_SUBSCRIPTIONS: list[dict] = [
    {
        "id": "sub-aws-001",
        "externalId": "123456789012",
        "name": "Corp AWS Production",
        "cloudProvider": "AWS",
        "status": "CONNECTED",
        "linkedAt": "2024-01-01T00:00:00Z",
        "issueCount": 47,
        "resourceCount": 312,
    },
    {
        "id": "sub-azure-001",
        "externalId": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "name": "Corp Azure Production",
        "cloudProvider": "AZURE",
        "status": "CONNECTED",
        "linkedAt": "2024-03-15T00:00:00Z",
        "issueCount": 23,
        "resourceCount": 180,
    },
]

_CONTROLS: list[dict] = [
    {
        "id": "ctrl-s3-public-001",
        "name": "S3 bucket should not be publicly accessible",
        "description": "Ensure that S3 buckets are not publicly accessible to prevent data exposure.",
        "controlType": "CONFIGURATION",
        "severity": "CRITICAL",
        "enabled": True,
        "query": None,
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
        "tags": ["AWS", "S3", "Data Exposure", "CIS-AWS-2.1.5"],
        "frameworks": [{"name": "CIS AWS Foundations", "section": "2.1.5"}, {"name": "SOC2", "section": "CC6.1"}],
        "resolutionSteps": "1. Open the S3 Console\n2. Select the bucket\n3. Go to Permissions tab\n4. Edit Block Public Access settings\n5. Enable 'Block all public access'",
        "affectedResourceCount": 3,
        "passCount": 47,
        "failCount": 3,
    },
    {
        "id": "ctrl-iam-root-mfa-001",
        "name": "AWS root account should have MFA enabled",
        "description": "Enable MFA on the root account to protect against unauthorized access.",
        "controlType": "CONFIGURATION",
        "severity": "CRITICAL",
        "enabled": True,
        "tags": ["AWS", "IAM", "MFA", "CIS-AWS-1.5"],
        "frameworks": [{"name": "CIS AWS Foundations", "section": "1.5"}, {"name": "PCI-DSS", "section": "8.3.2"}],
        "resolutionSteps": "1. Log into AWS as root user\n2. Navigate to IAM console\n3. Activate MFA on root account",
        "affectedResourceCount": 1,
        "passCount": 0,
        "failCount": 1,
    },
    {
        "id": "ctrl-sg-wide-ssh-001",
        "name": "Security groups should not allow SSH from 0.0.0.0/0",
        "description": "Restrict SSH access to known IP ranges to reduce attack surface.",
        "controlType": "CONFIGURATION",
        "severity": "HIGH",
        "enabled": True,
        "tags": ["AWS", "EC2", "Network", "SSH", "CIS-AWS-5.2"],
        "frameworks": [{"name": "CIS AWS Foundations", "section": "5.2"}, {"name": "NIST SP 800-53", "section": "AC-3"}],
        "resolutionSteps": "1. Go to EC2 > Security Groups\n2. Find groups allowing 0.0.0.0/0 on port 22\n3. Edit inbound rules to restrict to specific CIDR",
        "affectedResourceCount": 2,
        "passCount": 15,
        "failCount": 2,
    },
    {
        "id": "ctrl-vm-unpatched-001",
        "name": "Virtual machines should have latest OS patches",
        "description": "Ensure VMs are running the latest OS patches to address known vulnerabilities.",
        "controlType": "VULNERABILITY",
        "severity": "HIGH",
        "enabled": True,
        "tags": ["AZURE", "VM", "Patching", "CIS-Azure-7.7"],
        "frameworks": [{"name": "CIS Azure Foundations", "section": "7.7"}],
        "resolutionSteps": "1. Enable Azure Update Manager\n2. Assess patches\n3. Schedule maintenance window\n4. Deploy patches",
        "affectedResourceCount": 5,
        "passCount": 20,
        "failCount": 5,
    },
    {
        "id": "ctrl-storage-encryption-001",
        "name": "Storage accounts should use customer-managed keys",
        "description": "Use customer-managed keys for Azure Storage encryption to maintain control over encryption keys.",
        "controlType": "CONFIGURATION",
        "severity": "MEDIUM",
        "enabled": True,
        "tags": ["AZURE", "Storage", "Encryption", "CIS-Azure-3.2"],
        "frameworks": [{"name": "CIS Azure Foundations", "section": "3.2"}],
        "resolutionSteps": "1. Navigate to Azure Storage\n2. Select the storage account\n3. Go to Encryption\n4. Configure customer-managed keys in Key Vault",
        "affectedResourceCount": 8,
        "passCount": 2,
        "failCount": 8,
    },
]

_CLOUD_RESOURCES: list[dict] = [
    {
        "id": "res-s3-001",
        "nativeType": "S3 Bucket",
        "type": "STORAGE_BUCKET",
        "name": "corp-logs-bucket",
        "region": "us-east-1",
        "cloudPlatform": "AWS",
        "subscriptionExternalId": "123456789012",
        "subscriptionName": "Corp AWS Production",
        "status": "Active",
        "openIssuesCount": 2,
        "properties": {
            "arn": "arn:aws:s3:::corp-logs-bucket",
            "isPublic": True,
            "encryption": "SSE-S3",
            "versioning": True,
            "loggingEnabled": True,
            "lifecyclePolicy": "90-day expiry",
            "region": "us-east-1",
        },
        "createdAt": "2023-06-01T00:00:00Z",
        "updatedAt": _now_iso(),
        "tags": [{"key": "Environment", "value": "production"}, {"key": "DataClass", "value": "Confidential"}],
    },
    {
        "id": "res-ec2-001",
        "nativeType": "EC2 Instance",
        "type": "VIRTUAL_MACHINE",
        "name": "prod-web-server-001",
        "region": "us-east-1",
        "cloudPlatform": "AWS",
        "subscriptionExternalId": "123456789012",
        "subscriptionName": "Corp AWS Production",
        "status": "Running",
        "openIssuesCount": 1,
        "properties": {
            "instanceId": "i-0a1b2c3d4e5f67890",
            "instanceType": "t3.medium",
            "imageId": "ami-0123456789abcdef0",
            "privateIpAddress": "172.31.1.100",
            "publicIpAddress": "52.14.125.200",
            "vpcId": "vpc-0a1b2c3d4e5f67890",
            "subnetId": "subnet-0a1b2c3d4e5f67890",
            "securityGroups": ["sg-001-allow-ssh-any"],
            "platform": "Linux/UNIX",
            "architecture": "x86_64",
            "iamInstanceProfile": "prod-web-server-role",
        },
        "createdAt": "2024-03-01T08:00:00Z",
        "updatedAt": _now_iso(),
        "tags": [{"key": "Environment", "value": "production"}, {"key": "Role", "value": "web-server"}],
    },
    {
        "id": "res-sg-001",
        "nativeType": "Security Group",
        "type": "NETWORK",
        "name": "sg-001-allow-ssh-any",
        "region": "us-east-1",
        "cloudPlatform": "AWS",
        "subscriptionExternalId": "123456789012",
        "subscriptionName": "Corp AWS Production",
        "status": "Active",
        "openIssuesCount": 1,
        "properties": {
            "groupId": "sg-0a1b2c3d4e5f67890",
            "vpcId": "vpc-0a1b2c3d4e5f67890",
            "inboundRules": [
                {"protocol": "tcp", "fromPort": 22, "toPort": 22, "cidr": "0.0.0.0/0", "description": "SSH from anywhere"},
                {"protocol": "tcp", "fromPort": 443, "toPort": 443, "cidr": "0.0.0.0/0"},
            ],
            "outboundRules": [{"protocol": "-1", "fromPort": 0, "toPort": 0, "cidr": "0.0.0.0/0"}],
        },
        "createdAt": "2023-01-01T00:00:00Z",
        "updatedAt": _now_iso(),
        "tags": [],
    },
    {
        "id": "res-iam-root-001",
        "nativeType": "AWS Account",
        "type": "IAM_ROLE",
        "name": "AWS Root Account",
        "region": "global",
        "cloudPlatform": "AWS",
        "subscriptionExternalId": "123456789012",
        "subscriptionName": "Corp AWS Production",
        "status": "Active",
        "openIssuesCount": 1,
        "properties": {
            "accountId": "123456789012",
            "mfaEnabled": False,
            "rootAccessKey": True,
            "passwordLastUsed": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat() + "Z",
        },
        "createdAt": "2020-01-01T00:00:00Z",
        "updatedAt": _now_iso(),
        "tags": [],
    },
    {
        "id": "res-azure-vm-001",
        "nativeType": "Virtual Machine",
        "type": "VIRTUAL_MACHINE",
        "name": "corp-azure-vm-001",
        "region": "eastus",
        "cloudPlatform": "AZURE",
        "subscriptionExternalId": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "subscriptionName": "Corp Azure Production",
        "status": "Running",
        "openIssuesCount": 2,
        "properties": {
            "resourceId": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/corp-azure-vm-001",
            "vmSize": "Standard_D2s_v3",
            "osType": "Windows",
            "osVersion": "Windows Server 2019 Datacenter",
            "privateIpAddress": "10.0.1.10",
            "publicIpAddress": None,
            "availabilityZone": "1",
            "diskEncryptionEnabled": True,
            "patchStatus": "Patches available",
            "criticalPatchCount": 3,
        },
        "createdAt": "2024-06-01T00:00:00Z",
        "updatedAt": _now_iso(),
        "tags": [{"key": "Environment", "value": "production"}],
    },
]

_ISSUES: list[dict] = [
    {
        "id": "iss-001",
        "type": "CONTROL_FINDING",
        "control": _CONTROLS[0],
        "resource": _CLOUD_RESOURCES[0],
        "entitySnapshot": {"id": _CLOUD_RESOURCES[0]["id"], "name": _CLOUD_RESOURCES[0]["name"], "type": _CLOUD_RESOURCES[0]["type"]},
        "severity": "CRITICAL",
        "status": "OPEN",
        "title": "S3 Bucket corp-logs-bucket is publicly accessible",
        "description": "The S3 bucket 'corp-logs-bucket' has public access enabled and is accessible from the internet. This may expose sensitive data.",
        "createdAt": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat() + "Z",
        "updatedAt": _now_iso(),
        "dueAt": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat() + "Z",
        "resolvedAt": None,
        "assignedTo": None,
        "notes": [],
        "serviceTickets": [],
        "projects": [],
        "evidenceQuery": "select * from S3Bucket where isPublic = true",
    },
    {
        "id": "iss-002",
        "type": "CONTROL_FINDING",
        "control": _CONTROLS[1],
        "resource": _CLOUD_RESOURCES[3],
        "entitySnapshot": {"id": _CLOUD_RESOURCES[3]["id"], "name": _CLOUD_RESOURCES[3]["name"], "type": _CLOUD_RESOURCES[3]["type"]},
        "severity": "CRITICAL",
        "status": "OPEN",
        "title": "AWS root account does not have MFA enabled",
        "description": "The AWS root account for account 123456789012 does not have MFA enabled. This is a critical security risk.",
        "createdAt": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat() + "Z",
        "updatedAt": _now_iso(),
        "dueAt": None,
        "resolvedAt": None,
        "assignedTo": None,
        "notes": [],
        "serviceTickets": [],
    },
    {
        "id": "iss-003",
        "type": "CONTROL_FINDING",
        "control": _CONTROLS[2],
        "resource": _CLOUD_RESOURCES[2],
        "entitySnapshot": {"id": _CLOUD_RESOURCES[2]["id"], "name": _CLOUD_RESOURCES[2]["name"], "type": _CLOUD_RESOURCES[2]["type"]},
        "severity": "HIGH",
        "status": "OPEN",
        "title": "Security group sg-001-allow-ssh-any allows SSH from any IP",
        "description": "Security group 'sg-001-allow-ssh-any' allows inbound SSH (TCP/22) from 0.0.0.0/0, exposing EC2 instances to potential brute-force attacks.",
        "createdAt": (datetime.now(timezone.utc) - timedelta(days=14)).isoformat() + "Z",
        "updatedAt": _now_iso(),
        "dueAt": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat() + "Z",
        "resolvedAt": None,
        "assignedTo": {"email": "security@corp.local", "name": "Security Team"},
        "notes": [{"text": "Investigating legitimate SSH usage. Coordinator notified.", "createdAt": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat() + "Z"}],
        "serviceTickets": [{"externalId": "SEC-1", "name": "Suspicious SSH Exposure", "url": "https://jira.corp.local/browse/SEC-1"}],
    },
    {
        "id": "iss-004",
        "type": "CONTROL_FINDING",
        "control": _CONTROLS[3],
        "resource": _CLOUD_RESOURCES[4],
        "entitySnapshot": {"id": _CLOUD_RESOURCES[4]["id"], "name": _CLOUD_RESOURCES[4]["name"], "type": _CLOUD_RESOURCES[4]["type"]},
        "severity": "HIGH",
        "status": "IN_PROGRESS",
        "title": "Azure VM corp-azure-vm-001 has 3 critical patches pending",
        "description": "Virtual machine 'corp-azure-vm-001' has 3 critical security patches pending installation.",
        "createdAt": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat() + "Z",
        "updatedAt": _now_iso(),
        "dueAt": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat() + "Z",
        "resolvedAt": None,
        "assignedTo": {"email": "infra@corp.local", "name": "Infrastructure Team"},
        "notes": [],
        "serviceTickets": [],
    },
    {
        "id": "iss-005",
        "type": "CONTROL_FINDING",
        "control": _CONTROLS[4],
        "resource": {"id": "res-storage-001", "name": "corpprodstorage001", "type": "STORAGE_BUCKET"},
        "entitySnapshot": {"id": "res-storage-001", "name": "corpprodstorage001", "type": "STORAGE_BUCKET"},
        "severity": "MEDIUM",
        "status": "OPEN",
        "title": "Azure Storage Account corpprodstorage001 not using customer-managed keys",
        "description": "Storage account is using platform-managed keys instead of customer-managed keys (CMK).",
        "createdAt": (datetime.now(timezone.utc) - timedelta(days=21)).isoformat() + "Z",
        "updatedAt": _now_iso(),
        "dueAt": None,
        "resolvedAt": None,
        "assignedTo": None,
        "notes": [],
        "serviceTickets": [],
    },
]

# Mutable issues state
_dynamic_issues: dict[str, dict] = {}


def _filter_issues(filters: dict) -> list[dict]:
    """Apply filter parameters to issue list."""
    all_issues = list(_ISSUES) + list(_dynamic_issues.values())

    severity = filters.get("severity", [])
    if severity:
        all_issues = [i for i in all_issues if i["severity"] in severity]

    status = filters.get("status", [])
    if status:
        all_issues = [i for i in all_issues if i["status"] in status]

    control_ids = filters.get("controlId", [])
    if control_ids:
        all_issues = [i for i in all_issues if i.get("control", {}).get("id") in control_ids]

    resource_types = filters.get("resourceType", [])
    if resource_types:
        all_issues = [i for i in all_issues if i.get("entitySnapshot", {}).get("type") in resource_types]

    subscription_ids = filters.get("subscriptionId", [])
    if subscription_ids:
        resource_ids = [r["id"] for r in _CLOUD_RESOURCES if r.get("subscriptionExternalId") in subscription_ids]
        all_issues = [i for i in all_issues if i.get("entitySnapshot", {}).get("id") in resource_ids]

    cloud_providers = filters.get("cloudProvider", [])
    if cloud_providers:
        resource_ids_by_cloud = [r["id"] for r in _CLOUD_RESOURCES if r.get("cloudPlatform") in cloud_providers]
        all_issues = [i for i in all_issues if i.get("entitySnapshot", {}).get("id") in resource_ids_by_cloud or i.get("resource", {}).get("cloudPlatform") in cloud_providers]

    return all_issues


# ─────────────────────────────────────────────────────────────────────────────
# OAuth Token
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/oauth/token")
async def get_token(body: dict = Body(default={})):
    """OAuth2 client_credentials grant for Wiz API."""
    return {
        "access_token": f"wiz-sim-{uuid.uuid4().hex[:48]}",
        "token_type": "bearer",
        "expires_in": 86400,
    }


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL endpoint — handles all Wiz queries
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/graphql")
async def graphql_endpoint(body: dict = Body(default={})):
    """
    Universal Wiz GraphQL handler.
    Parses the query operation name or field to dispatch to the right resolver.
    """
    query = body.get("query", "")
    variables = body.get("variables", {}) or {}

    # Detect operation by looking for the first field in the selection set
    # Simplified: scan for known operation names
    op_name = body.get("operationName") or _detect_operation(query)

    handlers = {
        "issues": _resolve_issues,
        "issuesV2": _resolve_issues,
        "cloudResources": _resolve_cloud_resources,
        "cloudResourcesV2": _resolve_cloud_resources,
        "controls": _resolve_controls,
        "subscriptions": _resolve_subscriptions,
        "cloudAccounts": _resolve_subscriptions,
        "securityFrameworks": _resolve_frameworks,
        "vulnerabilities": _resolve_vulnerabilities,
        "updateIssue": _resolve_update_issue,
        "createIssueNote": _resolve_create_issue_note,
        "reopenIssue": _resolve_reopen_issue,
        "rejectIssue": _resolve_reject_issue,
    }

    handler = handlers.get(op_name)
    if handler:
        try:
            result = handler(variables)
            return {"data": result}
        except Exception as e:
            return {"errors": [{"message": str(e)}]}

    # Fallback: try to infer from query content
    if "issues" in query.lower():
        return {"data": _resolve_issues(variables)}
    if "cloudresource" in query.lower():
        return {"data": _resolve_cloud_resources(variables)}
    if "control" in query.lower():
        return {"data": _resolve_controls(variables)}
    if "subscription" in query.lower() or "cloudaccount" in query.lower():
        return {"data": _resolve_subscriptions(variables)}

    return {"data": {}, "errors": [{"message": f"Unknown operation: {op_name or '(unknown)'}. Supported: {list(handlers.keys())}"}]}


def _detect_operation(query: str) -> str:
    """Detect the primary field being queried."""
    # Look for patterns like "query { issues { ... } }" or "mutation UpdateIssue"
    m = re.search(r'(?:query|mutation)\s+(\w+)', query)
    if m:
        op = m.group(1)
        # Normalize common operation name patterns
        op_lower = op.lower()
        if "issue" in op_lower and "update" in op_lower:
            return "updateIssue"
        if "issue" in op_lower and "note" in op_lower:
            return "createIssueNote"
        if "issue" in op_lower and "reopen" in op_lower:
            return "reopenIssue"
        if "issue" in op_lower and "reject" in op_lower:
            return "rejectIssue"
        if "issue" in op_lower:
            return "issuesV2"
        return op

    # Look for first field in query body
    m = re.search(r'\{\s*(\w+)', query)
    if m:
        return m.group(1)
    return ""


def _pagination(items: list, variables: dict) -> dict:
    """Apply Wiz-style pagination: {first, after} cursor pattern."""
    first = variables.get("first", 100)
    after = variables.get("after")
    # Simple offset-based since cursor is opaque
    offset = 0
    if after:
        try:
            offset = int(after)
        except (ValueError, TypeError):
            offset = 0
    page = items[offset: offset + first]
    end_cursor = str(offset + len(page)) if len(page) == first else None
    return {
        "nodes": page,
        "totalCount": len(items),
        "pageInfo": {
            "hasNextPage": end_cursor is not None,
            "endCursor": end_cursor,
        }
    }


def _resolve_issues(variables: dict) -> dict:
    """Resolve the issues query."""
    filters = variables.get("filterBy", {}) or {}
    all_issues = _filter_issues(filters)
    return {"issuesV2": _pagination(all_issues, variables)}


def _resolve_cloud_resources(variables: dict) -> dict:
    """Resolve cloudResources query."""
    filters = variables.get("filterBy", {}) or {}
    resources = list(_CLOUD_RESOURCES)

    resource_types = filters.get("type", [])
    if resource_types:
        resources = [r for r in resources if r["type"] in resource_types]

    cloud_providers = filters.get("cloudProvider", [])
    if cloud_providers:
        resources = [r for r in resources if r["cloudPlatform"] in cloud_providers]

    name_contains = filters.get("name", {}).get("contains")
    if name_contains:
        resources = [r for r in resources if name_contains.lower() in r["name"].lower()]

    has_open_issues = filters.get("hasOpenIssues")
    if has_open_issues is not None:
        resources = [r for r in resources if (r["openIssuesCount"] > 0) == has_open_issues]

    return {"cloudResources": _pagination(resources, variables)}


def _resolve_controls(variables: dict) -> dict:
    """Resolve controls query."""
    filters = variables.get("filterBy", {}) or {}
    controls = list(_CONTROLS)

    severity = filters.get("severity", [])
    if severity:
        controls = [c for c in controls if c["severity"] in severity]

    enabled = filters.get("enabled")
    if enabled is not None:
        controls = [c for c in controls if c["enabled"] == enabled]

    return {"controls": _pagination(controls, variables)}


def _resolve_subscriptions(variables: dict) -> dict:
    """Resolve subscriptions/cloudAccounts query."""
    filters = variables.get("filterBy", {}) or {}
    subs = list(_SUBSCRIPTIONS)

    providers = filters.get("cloudProvider", [])
    if providers:
        subs = [s for s in subs if s["cloudProvider"] in providers]

    return {"subscriptions": _pagination(subs, variables), "cloudAccounts": {"nodes": subs, "totalCount": len(subs), "pageInfo": {"hasNextPage": False, "endCursor": None}}}


def _resolve_frameworks(variables: dict) -> dict:
    """Resolve securityFrameworks query."""
    frameworks = [
        {"id": "fw-cis-aws", "name": "CIS AWS Foundations", "description": "CIS Amazon Web Services Foundations Benchmark v1.5", "version": "1.5.0", "totalControls": 58, "passedControls": 45, "failedControls": 13, "score": 77.6},
        {"id": "fw-cis-azure", "name": "CIS Azure Foundations", "description": "CIS Microsoft Azure Foundations Benchmark v2.0", "version": "2.0.0", "totalControls": 74, "passedControls": 56, "failedControls": 18, "score": 75.7},
        {"id": "fw-pci-dss", "name": "PCI DSS v3.2.1", "description": "Payment Card Industry Data Security Standard", "version": "3.2.1", "totalControls": 138, "passedControls": 112, "failedControls": 26, "score": 81.2},
        {"id": "fw-soc2", "name": "SOC 2 Type II", "description": "Service Organization Control 2", "version": "2017", "totalControls": 64, "passedControls": 52, "failedControls": 12, "score": 81.25},
        {"id": "fw-nist-csf", "name": "NIST CSF", "description": "NIST Cybersecurity Framework v1.1", "version": "1.1", "totalControls": 108, "passedControls": 87, "failedControls": 21, "score": 80.6},
    ]
    return {"securityFrameworks": {"nodes": frameworks, "totalCount": len(frameworks), "pageInfo": {"hasNextPage": False, "endCursor": None}}}


def _resolve_vulnerabilities(variables: dict) -> dict:
    """Resolve vulnerabilities query (container/host vulns)."""
    filters = variables.get("filterBy", {}) or {}
    vulns = [
        {
            "id": "wiz-vuln-001",
            "cveId": "CVE-2024-21413",
            "name": "Microsoft Outlook Remote Code Execution Vulnerability",
            "severity": "CRITICAL",
            "cvssScore": 9.8,
            "epssPercentile": 0.97,
            "exploitabilityScore": "HIGH",
            "hasExploit": True,
            "hasCisaKevExploit": False,
            "vulnerableAssets": {"totalCount": 47},
            "firstDetectedAt": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat() + "Z",
            "lastDetectedAt": _now_iso(),
            "description": "A remote code execution vulnerability exists in Microsoft Outlook when it fails to properly handle objects in memory.",
            "remediationSteps": "Apply Microsoft security update KB5034671",
        },
        {
            "id": "wiz-vuln-002",
            "cveId": "CVE-2023-44487",
            "name": "HTTP/2 Rapid Reset Attack (RESET Flood)",
            "severity": "HIGH",
            "cvssScore": 7.5,
            "epssPercentile": 0.89,
            "exploitabilityScore": "HIGH",
            "hasExploit": True,
            "hasCisaKevExploit": True,
            "vulnerableAssets": {"totalCount": 3},
            "firstDetectedAt": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat() + "Z",
            "lastDetectedAt": _now_iso(),
            "description": "A vulnerability in the HTTP/2 protocol allows attackers to perform a denial of service.",
            "remediationSteps": "Update nginx/apache to latest version or apply HTTP/2 settings.",
        },
    ]

    severity = filters.get("severity", [])
    if severity:
        vulns = [v for v in vulns if v["severity"] in severity]

    return {"vulnerabilities": {"nodes": vulns, "totalCount": len(vulns), "pageInfo": {"hasNextPage": False, "endCursor": None}}}


def _resolve_update_issue(variables: dict) -> dict:
    """Mutation: updateIssue — change status, assignee, due date."""
    issue_id = variables.get("issueId", "")
    patch = variables.get("patch", {}) or {}

    target = next((i for i in _ISSUES if i["id"] == issue_id), None) or _dynamic_issues.get(issue_id)
    if not target:
        raise ValueError(f"Issue {issue_id} not found")

    if "status" in patch:
        target["status"] = patch["status"]
        if patch["status"] in ("RESOLVED", "REJECTED"):
            target["resolvedAt"] = _now_iso()
    if "assignedTo" in patch:
        target["assignedTo"] = patch["assignedTo"]
    if "dueAt" in patch:
        target["dueAt"] = patch["dueAt"]
    if "note" in patch:
        target.setdefault("notes", []).append({"text": patch["note"], "createdAt": _now_iso()})
    target["updatedAt"] = _now_iso()

    return {"updateIssue": {"issue": target}}


def _resolve_create_issue_note(variables: dict) -> dict:
    """Mutation: createIssueNote."""
    issue_id = variables.get("issueId", "")
    note_text = variables.get("text", "")
    target = next((i for i in _ISSUES if i["id"] == issue_id), None) or _dynamic_issues.get(issue_id)
    if not target:
        raise ValueError(f"Issue {issue_id} not found")
    note = {"id": _uuid(), "text": note_text, "createdAt": _now_iso(), "updatedAt": _now_iso()}
    target.setdefault("notes", []).append(note)
    return {"createIssueNote": {"issueNote": note}}


def _resolve_reopen_issue(variables: dict) -> dict:
    issue_id = variables.get("issueId", "")
    target = next((i for i in _ISSUES if i["id"] == issue_id), None) or _dynamic_issues.get(issue_id)
    if target:
        target["status"] = "OPEN"
        target["resolvedAt"] = None
        target["updatedAt"] = _now_iso()
    return {"reopenIssue": {"issue": target}}


def _resolve_reject_issue(variables: dict) -> dict:
    issue_id = variables.get("issueId", "")
    target = next((i for i in _ISSUES if i["id"] == issue_id), None) or _dynamic_issues.get(issue_id)
    if target:
        target["status"] = "REJECTED"
        target["resolvedAt"] = _now_iso()
        target["updatedAt"] = _now_iso()
    return {"rejectIssue": {"issue": target}}


# ─────────────────────────────────────────────────────────────────────────────
# REST convenience endpoints (Wiz also exposes a few REST endpoints)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/v1/issues")
async def rest_list_issues(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """REST wrapper for issue listing (non-graphql clients)."""
    filters = {}
    if severity:
        filters["severity"] = [s.strip().upper() for s in severity.split(",")]
    if status:
        filters["status"] = [s.strip().upper() for s in status.split(",")]
    issues = _filter_issues(filters)
    return {"data": issues[offset: offset + limit], "total": len(issues), "offset": offset, "limit": limit}


@router.get("/api/v1/issues/{issue_id}")
async def rest_get_issue(issue_id: str):
    issue = next((i for i in _ISSUES if i["id"] == issue_id), None) or _dynamic_issues.get(issue_id)
    if not issue:
        raise HTTPException(404, {"error": f"Issue {issue_id} not found"})
    return issue


@router.patch("/api/v1/issues/{issue_id}")
async def rest_update_issue(issue_id: str, body: dict = Body(default={})):
    result = _resolve_update_issue({"issueId": issue_id, "patch": body})
    return result["updateIssue"]["issue"]


@router.get("/api/v1/resources")
async def rest_list_resources(
    type: Optional[str] = None,
    cloudProvider: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    resources = list(_CLOUD_RESOURCES)
    if type:
        resources = [r for r in resources if r["type"] == type.upper()]
    if cloudProvider:
        resources = [r for r in resources if r["cloudPlatform"] == cloudProvider.upper()]
    return {"data": resources[offset: offset + limit], "total": len(resources)}
