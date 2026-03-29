"""Log Source Schema Registry.

Stores vendor log schemas, sample events, and MITRE mappings in the
knowledge base (ChromaDB). Provides the single source of truth that
the agentic log generator reads from to produce realistic events.

Schemas are NEVER hardcoded in generators. Instead:
  1. Registry loads schema definitions (field specs + sample events) into ChromaDB.
  2. AgenticLogGenerator reads the schema from ChromaDB via RAG.
  3. Claude generates events dynamically, grounded in the schema.
  4. Generated templates are cached in Redis/memory — reused until schema version changes.
  5. A monthly job can re-seed from updated vendor documentation.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA_NAMESPACE = "log_schemas"


@dataclass
class LogSourceDefinition:
    """Defines a log source: its schema, sample events, and metadata."""

    # Identity
    source_id: str                      # e.g. "windows_sysmon", "aws_cloudtrail"
    vendor: str                         # e.g. "Microsoft", "Amazon"
    product: str                        # e.g. "Sysmon", "CloudTrail"
    category: str                       # endpoint|cloud|network|identity|email|container|cdn|posture

    # Schema
    version: str                        # Schema version e.g. "15.0"
    format: str                         # json|xml_to_json|cef|leef|syslog_csv|text
    description: str

    # Fields: { field_name: { type, description, example, required } }
    fields: dict[str, dict[str, Any]]

    # Sample events: list of realistic events per event_type
    # { event_type: [sample_event_dict, ...] }
    sample_events: dict[str, list[dict[str, Any]]]

    # MITRE mappings: { technique_id: [event_type, ...] }
    mitre_mappings: dict[str, list[str]]

    # Schema tracking
    doc_url: str = ""
    doc_last_checked: str = ""          # ISO date
    schema_last_updated: str = ""       # ISO date
    update_frequency: str = "stable"    # stable|quarterly|monthly|frequent

    # SIEM integration
    splunk_sourcetype: str = ""
    splunk_index: str = ""
    elastic_index_pattern: str = ""
    sentinel_table: str = ""
    chronicle_log_type: str = ""

    # Normalization
    ossem_category: str = ""
    ecs_category: str = ""             # ECS event.category
    cim_data_model: str = ""           # Splunk CIM model

    # Joti compatibility
    joti_source_type: str = ""         # maps to Joti AlertSource.source_type


# ---------------------------------------------------------------------------
# Canonical schema definitions
# These are the minimal "seed" definitions — field specs + a few sample events.
# Claude uses these as grounding to GENERATE varied, realistic events.
# ---------------------------------------------------------------------------

BUILTIN_SCHEMAS: list[LogSourceDefinition] = [

    # ── Windows Security Event Log ──────────────────────────────────────────
    LogSourceDefinition(
        source_id="windows_security",
        vendor="Microsoft",
        product="Windows Security Event Log",
        category="endpoint",
        version="10.0",
        format="xml_to_json",
        description="Windows Security audit events. Core source for authentication, process creation, account management, and privilege use.",
        fields={
            "EventID": {"type": "integer", "description": "Windows event identifier", "required": True},
            "TimeCreated": {"type": "datetime", "description": "ISO 8601 timestamp", "required": True},
            "Computer": {"type": "string", "description": "Hostname generating the event"},
            "SubjectUserName": {"type": "string", "description": "User who performed the action"},
            "SubjectDomainName": {"type": "string", "description": "Domain of the subject user"},
            "TargetUserName": {"type": "string", "description": "User the action was performed against"},
            "LogonType": {"type": "integer", "description": "2=Interactive 3=Network 4=Batch 5=Service 7=Unlock 10=RemoteInteractive"},
            "ProcessName": {"type": "string", "description": "Full path of new process (4688)"},
            "CommandLine": {"type": "string", "description": "Command line of new process (4688, requires auditing)"},
            "ParentProcessName": {"type": "string", "description": "Parent process path (4688)"},
            "IpAddress": {"type": "string", "description": "Source IP for network logons"},
            "WorkstationName": {"type": "string", "description": "Source workstation name"},
        },
        sample_events={
            "4624_logon_success": [{
                "EventID": 4624, "TimeCreated": "2026-03-28T09:14:22.123Z",
                "Computer": "WKSTN-FIN-042", "SubjectUserName": "jsmith",
                "SubjectDomainName": "CORP", "LogonType": 3,
                "IpAddress": "10.1.2.100", "WorkstationName": "WKSTN-ENG-107"
            }],
            "4625_logon_failure": [{
                "EventID": 4625, "TimeCreated": "2026-03-28T09:14:25.456Z",
                "Computer": "SRV-DC-01", "TargetUserName": "administrator",
                "LogonType": 3, "IpAddress": "185.220.101.34",
                "Status": "0xC000006D", "SubStatus": "0xC000006A"
            }],
            "4688_process_create": [{
                "EventID": 4688, "TimeCreated": "2026-03-28T10:32:11.789Z",
                "Computer": "WKSTN-FIN-042", "SubjectUserName": "jsmith",
                "ProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "NewProcessId": "0x1a4c"
            }],
            "4720_account_created": [{
                "EventID": 4720, "TimeCreated": "2026-03-28T11:05:00.000Z",
                "Computer": "SRV-DC-01", "SubjectUserName": "admin",
                "TargetUserName": "svc_backup2", "TargetDomainName": "CORP"
            }],
        },
        mitre_mappings={
            "T1078": ["4624_logon_success"],
            "T1110": ["4625_logon_failure"],
            "T1059.001": ["4688_process_create"],
            "T1059.003": ["4688_process_create"],
            "T1136": ["4720_account_created"],
            "T1543.003": ["7045_service_install"],
        },
        doc_url="https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/",
        doc_last_checked="2026-03-28",
        update_frequency="stable",
        splunk_sourcetype="WinEventLog:Security",
        splunk_index="wineventlog",
        elastic_index_pattern="winlogbeat-*",
        sentinel_table="SecurityEvent",
        ossem_category="authentication",
        ecs_category="authentication",
        cim_data_model="Authentication",
        joti_source_type="windows_security",
    ),

    # ── Sysmon ──────────────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="windows_sysmon",
        vendor="Microsoft",
        product="Sysinternals Sysmon",
        category="endpoint",
        version="15.0",
        format="xml_to_json",
        description="System Monitor — detailed endpoint telemetry: process creation with full command lines, network connections, file and registry operations, DNS queries.",
        fields={
            "EventID": {"type": "integer", "description": "Sysmon event type: 1=ProcessCreate 3=NetworkConnect 7=ImageLoad 8=CreateRemoteThread 10=ProcessAccess 11=FileCreate 22=DNSQuery 23=FileDelete 25=ProcessTampering"},
            "UtcTime": {"type": "datetime", "description": "UTC timestamp"},
            "ProcessGuid": {"type": "guid", "description": "Unique process GUID"},
            "ProcessId": {"type": "integer", "description": "Process PID"},
            "Image": {"type": "string", "description": "Full process image path"},
            "CommandLine": {"type": "string", "description": "Full command line (Event 1)"},
            "ParentImage": {"type": "string", "description": "Parent process path (Event 1)"},
            "ParentCommandLine": {"type": "string", "description": "Parent command line (Event 1)"},
            "User": {"type": "string", "description": "User context (DOMAIN\\user)"},
            "Hashes": {"type": "string", "description": "MD5,SHA256,IMPHASH"},
            "DestinationIp": {"type": "string", "description": "Destination IP (Event 3)"},
            "DestinationPort": {"type": "integer", "description": "Destination port (Event 3)"},
            "DestinationHostname": {"type": "string", "description": "Destination hostname (Event 3)"},
            "QueryName": {"type": "string", "description": "DNS query name (Event 22)"},
            "QueryResults": {"type": "string", "description": "DNS answers (Event 22)"},
            "TargetFilename": {"type": "string", "description": "File path (Event 11/23)"},
            "TargetObject": {"type": "string", "description": "Registry key path (Event 12/13)"},
        },
        sample_events={
            "1_process_create": [{
                "EventID": 1, "UtcTime": "2026-03-28T09:15:00.000Z",
                "ProcessGuid": "{a4b3c2d1-e5f6-a7b8-c9d0-e1f2a3b4c5d6}",
                "ProcessId": 4876, "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c ipconfig /all",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "User": "CORP\\jsmith",
                "Hashes": "MD5=5746BD7E255DD6A8AFA06F7C42C1BA41,SHA256=b4a28a3e..."
            }],
            "3_network_connect": [{
                "EventID": 3, "UtcTime": "2026-03-28T09:15:01.000Z",
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "DestinationIp": "8.8.8.8", "DestinationPort": 53,
                "DestinationHostname": "", "Protocol": "udp",
                "User": "NT AUTHORITY\\NETWORK SERVICE"
            }],
            "22_dns_query": [{
                "EventID": 22, "UtcTime": "2026-03-28T09:16:00.000Z",
                "ProcessId": 4876, "Image": "C:\\Windows\\System32\\svchost.exe",
                "QueryName": "update.microsoft.com",
                "QueryResults": "type: 5 update.microsoft.com.akadns.net;::ffff:13.89.179.10",
                "User": "NT AUTHORITY\\NETWORK SERVICE"
            }],
        },
        mitre_mappings={
            "T1059.001": ["1_process_create"],
            "T1003.001": ["10_process_access"],
            "T1071.001": ["3_network_connect"],
            "T1071.004": ["22_dns_query"],
            "T1105": ["3_network_connect", "11_file_create"],
            "T1547.001": ["12_registry_add"],
            "T1055": ["8_create_remote_thread"],
        },
        doc_url="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        doc_last_checked="2026-03-28",
        update_frequency="quarterly",
        splunk_sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        elastic_index_pattern="winlogbeat-*",
        sentinel_table="Sysmon",
        ossem_category="process",
        ecs_category="process",
        cim_data_model="Endpoint",
        joti_source_type="sysmon",
    ),

    # ── Linux auditd ────────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="linux_auditd",
        vendor="Linux",
        product="auditd",
        category="endpoint",
        version="3.0",
        format="text",
        description="Linux kernel audit daemon. Records syscalls, file access, network connections, authentication, and privilege changes.",
        fields={
            "type": {"type": "string", "description": "Audit record type: SYSCALL EXECVE PROCTITLE PATH SOCKADDR USER_AUTH USER_LOGIN"},
            "msg": {"type": "string", "description": "Audit message with timestamp and serial: audit(epoch:serial)"},
            "arch": {"type": "string", "description": "Architecture: x86_64 i386"},
            "syscall": {"type": "integer", "description": "Syscall number"},
            "success": {"type": "string", "description": "yes or no"},
            "exit": {"type": "integer", "description": "Syscall return value"},
            "pid": {"type": "integer", "description": "Process ID"},
            "ppid": {"type": "integer", "description": "Parent process ID"},
            "uid": {"type": "integer", "description": "User ID"},
            "gid": {"type": "integer", "description": "Group ID"},
            "auid": {"type": "integer", "description": "Audit user ID (login user)"},
            "comm": {"type": "string", "description": "Command name"},
            "exe": {"type": "string", "description": "Executable path"},
            "key": {"type": "string", "description": "Audit rule key label"},
        },
        sample_events={
            "execve": [{
                "type": "SYSCALL", "msg": "audit(1711623661.123:1042)",
                "arch": "c000003e", "syscall": 59, "success": "yes", "exit": 0,
                "pid": 3847, "ppid": 3812, "uid": 1000, "gid": 1000, "auid": 1000,
                "comm": "bash", "exe": "/bin/bash", "key": "exec"
            }],
            "ssh_login": [{
                "type": "USER_LOGIN", "msg": "audit(1711623700.000:1043)",
                "pid": 2341, "uid": 0, "auid": 1000,
                "exe": "/usr/sbin/sshd", "hostname": "10.1.2.50",
                "addr": "10.1.2.50", "terminal": "ssh", "res": "success"
            }],
        },
        mitre_mappings={
            "T1059.004": ["execve"],
            "T1021.004": ["ssh_login"],
            "T1078.003": ["ssh_login"],
        },
        doc_url="https://man7.org/linux/man-pages/man8/auditd.8.html",
        doc_last_checked="2026-03-28",
        update_frequency="stable",
        splunk_sourcetype="linux:audit",
        elastic_index_pattern="auditbeat-*",
        sentinel_table="CommonSecurityLog",
        ossem_category="process",
        joti_source_type="linux_audit",
    ),

    # ── AWS CloudTrail ──────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="aws_cloudtrail",
        vendor="Amazon",
        product="CloudTrail",
        category="cloud",
        version="1.09",
        format="json",
        description="AWS API call logs for management and data events. Essential for cloud threat detection, IAM abuse, resource changes, and compliance.",
        fields={
            "eventVersion": {"type": "string", "description": "CloudTrail schema version"},
            "userIdentity.type": {"type": "string", "description": "IAMUser|AssumedRole|Root|AWSService|Anonymous"},
            "userIdentity.arn": {"type": "string", "description": "Full ARN of requester"},
            "userIdentity.userName": {"type": "string", "description": "IAM user name (if IAMUser type)"},
            "eventTime": {"type": "datetime", "description": "ISO 8601 UTC timestamp"},
            "eventSource": {"type": "string", "description": "AWS service: ec2.amazonaws.com s3.amazonaws.com iam.amazonaws.com"},
            "eventName": {"type": "string", "description": "API operation name: DescribeInstances GetObject CreateUser"},
            "awsRegion": {"type": "string", "description": "AWS region: us-east-1 us-west-2"},
            "sourceIPAddress": {"type": "string", "description": "Requester IP or AWS service name"},
            "userAgent": {"type": "string", "description": "Client user agent: aws-cli boto3 console.aws.amazon.com"},
            "errorCode": {"type": "string", "description": "Error code if failed: AccessDenied NoSuchBucket"},
            "readOnly": {"type": "boolean", "description": "True for read-only API calls"},
        },
        sample_events={
            "iam_create_user": [{
                "eventVersion": "1.09",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/admin", "userName": "admin"},
                "eventTime": "2026-03-28T14:23:11Z",
                "eventSource": "iam.amazonaws.com", "eventName": "CreateUser",
                "awsRegion": "us-east-1", "sourceIPAddress": "10.1.2.100",
                "userAgent": "aws-cli/2.13.0", "readOnly": False,
                "requestParameters": {"userName": "svc_new"},
            }],
            "s3_list_buckets": [{
                "eventVersion": "1.09",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/jsmith", "userName": "jsmith"},
                "eventTime": "2026-03-28T09:00:00Z",
                "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets",
                "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.1",
                "userAgent": "boto3/1.28.0", "readOnly": True,
                "requestParameters": None,
            }],
        },
        mitre_mappings={
            "T1078.004": ["iam_create_user", "sts_assume_role"],
            "T1530": ["s3_list_buckets", "s3_get_object"],
            "T1562.008": ["cloudtrail_stop_logging", "cloudtrail_delete_trail"],
            "T1087.004": ["iam_list_users", "iam_list_roles"],
        },
        doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html",
        doc_last_checked="2026-03-28",
        update_frequency="quarterly",
        splunk_sourcetype="aws:cloudtrail",
        elastic_index_pattern="filebeat-*-aws.cloudtrail-*",
        sentinel_table="AWSCloudTrail",
        chronicle_log_type="AWS_CLOUDTRAIL",
        ossem_category="cloud",
        joti_source_type="aws_cloudtrail",
    ),

    # ── AWS GuardDuty ───────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="aws_guardduty",
        vendor="Amazon",
        product="GuardDuty",
        category="cloud",
        version="2.0",
        format="json",
        description="AWS threat detection service. Generates findings from CloudTrail, VPC Flow, DNS, and EKS logs.",
        fields={
            "id": {"type": "string", "description": "Unique finding ID"},
            "type": {"type": "string", "description": "Finding type: UnauthorizedAccess:IAMUser/MaliciousIPCaller Recon:EC2/PortProbeUnprotectedPort"},
            "severity": {"type": "number", "description": "Numeric severity 0-10 (2=Low 5=Medium 8=High)"},
            "title": {"type": "string", "description": "Human-readable finding title"},
            "description": {"type": "string", "description": "Finding description"},
            "accountId": {"type": "string", "description": "AWS account ID"},
            "region": {"type": "string", "description": "AWS region"},
            "resource.resourceType": {"type": "string", "description": "AccessKey|Instance|S3Bucket|KubernetesCluster"},
            "service.action.actionType": {"type": "string", "description": "AWS_API_CALL|NETWORK_CONNECTION|DNS_REQUEST|PORT_PROBE"},
        },
        sample_events={
            "credential_access": [{
                "id": "abc123def456", "severity": 8.0,
                "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                "title": "API call made from a known malicious IP address",
                "region": "us-east-1", "accountId": "123456789012",
                "resource": {"resourceType": "AccessKey", "accessKeyDetails": {"userName": "jsmith"}},
                "service": {"action": {"actionType": "AWS_API_CALL", "awsApiCallAction": {"api": "GetCallerIdentity", "remoteIpDetails": {"ipAddressV4": "185.220.101.34"}}}},
            }],
        },
        mitre_mappings={
            "T1078.004": ["credential_access"],
            "T1530": ["s3_data_exfil"],
            "T1046": ["port_probe"],
        },
        doc_url="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html",
        doc_last_checked="2026-03-28",
        update_frequency="monthly",
        splunk_sourcetype="aws:guardduty",
        joti_source_type="guardduty",
    ),

    # ── GCP Cloud Audit Logs ────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="gcp_audit",
        vendor="Google",
        product="Cloud Audit Logs",
        category="cloud",
        version="v1",
        format="json",
        description="GCP Admin Activity, Data Access, and System Event logs. AuditLog protobuf wrapped in LogEntry.",
        fields={
            "logName": {"type": "string", "description": "projects/{project}/logs/cloudaudit.googleapis.com/{activity|data_access|system_event}"},
            "resource.type": {"type": "string", "description": "gce_instance gcs_bucket gke_cluster iam_role"},
            "resource.labels": {"type": "object", "description": "Resource-specific labels: project_id, instance_id, etc."},
            "timestamp": {"type": "datetime", "description": "RFC 3339 timestamp"},
            "severity": {"type": "string", "description": "INFO NOTICE WARNING ERROR CRITICAL"},
            "protoPayload.methodName": {"type": "string", "description": "API method: compute.instances.insert storage.buckets.list"},
            "protoPayload.authenticationInfo.principalEmail": {"type": "string", "description": "Actor email address"},
            "protoPayload.requestMetadata.callerIp": {"type": "string", "description": "Source IP"},
            "protoPayload.status.code": {"type": "integer", "description": "gRPC status code: 0=OK 7=PERMISSION_DENIED"},
        },
        sample_events={
            "create_vm": [{
                "logName": "projects/my-project/logs/cloudaudit.googleapis.com/activity",
                "timestamp": "2026-03-28T14:23:11.123Z",
                "severity": "NOTICE",
                "resource": {"type": "gce_instance", "labels": {"project_id": "my-project", "instance_id": "12345"}},
                "protoPayload": {
                    "methodName": "v1.compute.instances.insert",
                    "authenticationInfo": {"principalEmail": "jsmith@corp.com"},
                    "requestMetadata": {"callerIp": "10.1.2.100"},
                    "status": {"code": 0},
                },
            }],
        },
        mitre_mappings={
            "T1078.004": ["iam_permission_change"],
            "T1578": ["create_vm"],
            "T1087.004": ["list_iam_policy"],
            "T1562.008": ["disable_audit_log"],
        },
        doc_url="https://cloud.google.com/logging/docs/audit",
        doc_last_checked="2026-03-28",
        update_frequency="quarterly",
        splunk_sourcetype="google:gcp:audit",
        sentinel_table="GCPAuditLogs",
        joti_source_type="gcp_audit",
    ),

    # ── Azure Activity Log ──────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="azure_activity",
        vendor="Microsoft",
        product="Azure Activity Log",
        category="cloud",
        version="2022-10-01",
        format="json",
        description="Azure control plane operations: resource creation/deletion, RBAC changes, policy assignments, service health.",
        fields={
            "time": {"type": "datetime", "description": "ISO 8601 UTC timestamp"},
            "operationName": {"type": "string", "description": "e.g. Microsoft.Compute/virtualMachines/write"},
            "status": {"type": "string", "description": "Succeeded Failed Accepted"},
            "caller": {"type": "string", "description": "UPN or service principal of caller"},
            "callerIpAddress": {"type": "string", "description": "Source IP"},
            "resourceId": {"type": "string", "description": "Full Azure resource ID"},
            "resourceGroup": {"type": "string", "description": "Resource group name"},
            "subscriptionId": {"type": "string", "description": "Azure subscription GUID"},
            "category": {"type": "string", "description": "Administrative Security ServiceHealth Alert Autoscale Policy"},
        },
        sample_events={
            "vm_create": [{
                "time": "2026-03-28T14:23:11.123Z",
                "operationName": "Microsoft.Compute/virtualMachines/write",
                "status": "Succeeded", "caller": "jsmith@corp.com",
                "callerIpAddress": "10.1.2.100",
                "resourceId": "/subscriptions/xxxxxxxx/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-new",
                "resourceGroup": "rg-prod", "category": "Administrative",
            }],
        },
        mitre_mappings={
            "T1578": ["vm_create"],
            "T1098": ["role_assignment"],
            "T1562.008": ["delete_diagnostic_setting"],
        },
        doc_url="https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
        doc_last_checked="2026-03-28",
        update_frequency="stable",
        splunk_sourcetype="azure:activity",
        sentinel_table="AzureActivity",
        joti_source_type="azure_activity",
    ),

    # ── Palo Alto PAN-OS ────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="palo_alto_panos",
        vendor="Palo Alto Networks",
        product="PAN-OS Firewall",
        category="network",
        version="11.0",
        format="syslog_csv",
        description="PAN-OS syslog traffic, threat, and system logs. TRAFFIC=allow/deny flows. THREAT=IPS/malware/URL/wildfire detections.",
        fields={
            "type": {"type": "string", "description": "TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT"},
            "subtype": {"type": "string", "description": "TRAFFIC:start/end/drop. THREAT:vulnerability/spyware/virus/url/wildfire"},
            "src_ip": {"type": "string", "description": "Source IP"},
            "dst_ip": {"type": "string", "description": "Destination IP"},
            "src_port": {"type": "integer", "description": "Source port"},
            "dst_port": {"type": "integer", "description": "Destination port"},
            "proto": {"type": "string", "description": "tcp|udp|icmp"},
            "app": {"type": "string", "description": "Application identifier: ssl web-browsing unknown-tcp"},
            "action": {"type": "string", "description": "allow|deny|drop|reset-client|reset-server|reset-both"},
            "bytes_sent": {"type": "integer", "description": "Bytes from client to server"},
            "bytes_received": {"type": "integer", "description": "Bytes from server to client"},
            "rule_name": {"type": "string", "description": "Matching security policy rule"},
            "src_zone": {"type": "string", "description": "Source zone: trust|dmz|untrust"},
            "dst_zone": {"type": "string", "description": "Destination zone"},
            "threat_name": {"type": "string", "description": "Threat signature name (THREAT logs)"},
            "severity": {"type": "string", "description": "informational|low|medium|high|critical"},
        },
        sample_events={
            "traffic_allow": [{
                "type": "TRAFFIC", "subtype": "end",
                "src_ip": "10.1.2.100", "dst_ip": "142.250.80.78",
                "src_port": 54321, "dst_port": 443, "proto": "tcp",
                "app": "ssl", "action": "allow", "bytes_sent": 2048,
                "bytes_received": 8192, "rule_name": "Allow-Corp-Outbound",
                "src_zone": "trust", "dst_zone": "untrust",
                "severity": "informational",
            }],
            "threat_detection": [{
                "type": "THREAT", "subtype": "vulnerability",
                "src_ip": "203.0.113.42", "dst_ip": "10.1.5.10",
                "src_port": 44521, "dst_port": 8080, "proto": "tcp",
                "app": "web-browsing", "action": "reset-both",
                "threat_name": "Apache Log4j Remote Code Execution",
                "severity": "critical", "rule_name": "IPS-Block",
                "src_zone": "untrust", "dst_zone": "dmz",
            }],
        },
        mitre_mappings={
            "T1190": ["threat_detection"],
            "T1071.001": ["traffic_allow"],
            "T1048": ["large_outbound_transfer"],
            "T1110": ["brute_force_deny_cluster"],
        },
        doc_url="https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring",
        doc_last_checked="2026-03-28",
        update_frequency="quarterly",
        splunk_sourcetype="pan:traffic",
        elastic_index_pattern="panw-*",
        joti_source_type="palo_alto",
    ),

    # ── Kubernetes Audit ────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="kubernetes_audit",
        vendor="CNCF",
        product="Kubernetes",
        category="container",
        version="audit.k8s.io/v1",
        format="json",
        description="Kubernetes API server audit log. Records all API requests to the K8s control plane.",
        fields={
            "apiVersion": {"type": "string", "description": "audit.k8s.io/v1"},
            "kind": {"type": "string", "description": "Always Event"},
            "level": {"type": "string", "description": "None|Metadata|Request|RequestResponse"},
            "verb": {"type": "string", "description": "get|list|watch|create|update|patch|delete|exec"},
            "user.username": {"type": "string", "description": "Requesting user or serviceaccount"},
            "user.groups": {"type": "array", "description": "User groups including system:authenticated"},
            "requestURI": {"type": "string", "description": "Full API request URI"},
            "objectRef.resource": {"type": "string", "description": "pods|secrets|configmaps|nodes|clusterrolebindings"},
            "objectRef.namespace": {"type": "string", "description": "Kubernetes namespace"},
            "responseStatus.code": {"type": "integer", "description": "HTTP response code"},
            "sourceIPs": {"type": "array", "description": "Source IP addresses"},
        },
        sample_events={
            "pod_list": [{
                "apiVersion": "audit.k8s.io/v1", "kind": "Event",
                "level": "Metadata", "verb": "list",
                "user": {"username": "jsmith", "groups": ["system:authenticated"]},
                "requestURI": "/api/v1/namespaces/default/pods",
                "objectRef": {"resource": "pods", "namespace": "default", "apiVersion": "v1"},
                "responseStatus": {"code": 200},
                "sourceIPs": ["10.1.2.100"],
            }],
            "exec_into_pod": [{
                "apiVersion": "audit.k8s.io/v1", "kind": "Event",
                "level": "Request", "verb": "create",
                "user": {"username": "jsmith", "groups": ["system:authenticated"]},
                "requestURI": "/api/v1/namespaces/default/pods/webapp-xxx/exec",
                "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "default"},
                "responseStatus": {"code": 101},
                "sourceIPs": ["10.1.2.100"],
            }],
        },
        mitre_mappings={
            "T1613": ["pod_list", "secret_list"],
            "T1552.007": ["secret_read"],
            "T1611": ["exec_into_pod"],
            "T1610": ["privileged_pod_create"],
            "T1098": ["clusterrolebinding_create"],
        },
        doc_url="https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
        doc_last_checked="2026-03-28",
        update_frequency="quarterly",
        splunk_sourcetype="kube:audit",
        elastic_index_pattern="filebeat-*-kubernetes.audit-*",
        sentinel_table="KubeAuditLogs",
        joti_source_type="kubernetes_audit",
    ),

    # ── DNS ─────────────────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="dns",
        vendor="Generic",
        product="DNS Query Log",
        category="network",
        version="1.0",
        format="json",
        description="DNS query and response logs in ECS format. Source: Windows DNS debug log, Zeek dns.log, Pi-hole, Infoblox, etc.",
        fields={
            "dns.question.name": {"type": "string", "description": "Queried domain name"},
            "dns.question.type": {"type": "string", "description": "Record type: A AAAA CNAME MX TXT PTR"},
            "dns.response_code": {"type": "string", "description": "NOERROR NXDOMAIN SERVFAIL REFUSED"},
            "dns.answers": {"type": "array", "description": "Response records with name, type, ttl, data"},
            "source.ip": {"type": "string", "description": "Querying client IP"},
            "destination.ip": {"type": "string", "description": "DNS server IP"},
            "host.name": {"type": "string", "description": "Hostname of querying client"},
        },
        sample_events={
            "normal_query": [{
                "@timestamp": "2026-03-28T09:15:00.000Z",
                "dns": {"question": {"name": "login.microsoft.com", "type": "A"},
                        "response_code": "NOERROR",
                        "answers": [{"name": "login.microsoft.com", "type": "CNAME", "ttl": 300, "data": "aadcdn.msftauth.net"}]},
                "source": {"ip": "10.1.2.100"},
                "host": {"name": "WKSTN-FIN-042"},
            }],
        },
        mitre_mappings={
            "T1071.004": ["c2_txt_query"],
            "T1048.003": ["dns_exfil_subdomain"],
            "T1568.002": ["dga_query"],
            "T1046": ["nxdomain_flood"],
        },
        doc_url="https://www.elastic.co/guide/en/ecs/current/ecs-dns.html",
        doc_last_checked="2026-03-28",
        update_frequency="stable",
        splunk_sourcetype="stream:dns",
        elastic_index_pattern="filebeat-*",
        sentinel_table="DnsEvents",
        joti_source_type="dns",
    ),

    # ── Cloudflare HTTP / WAF ────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="cloudflare",
        vendor="Cloudflare",
        product="Cloudflare Logs",
        category="cdn",
        version="2024",
        format="json",
        description="Cloudflare HTTP request logs, WAF events, firewall events, Bot Management. Available via Logpush.",
        fields={
            "ClientIP": {"type": "string", "description": "Client source IP"},
            "ClientRequestHost": {"type": "string", "description": "Request host header"},
            "ClientRequestMethod": {"type": "string", "description": "HTTP method"},
            "ClientRequestPath": {"type": "string", "description": "Request path"},
            "ClientRequestUserAgent": {"type": "string", "description": "User-Agent header"},
            "EdgeResponseStatus": {"type": "integer", "description": "HTTP response status code"},
            "EdgeStartTimestamp": {"type": "datetime", "description": "Unix timestamp of request"},
            "WAFAction": {"type": "string", "description": "WAF action: allow|block|challenge|managed_challenge"},
            "WAFRuleID": {"type": "string", "description": "Triggered WAF rule ID"},
            "WAFRuleMessage": {"type": "string", "description": "WAF rule description"},
            "BotScore": {"type": "integer", "description": "Bot score 1-99 (1=likely bot)"},
            "FirewallMatchesActions": {"type": "array", "description": "Matched firewall rule actions"},
        },
        sample_events={
            "normal_request": [{
                "ClientIP": "203.0.113.1", "ClientRequestHost": "api.corp.com",
                "ClientRequestMethod": "GET", "ClientRequestPath": "/v1/users",
                "EdgeResponseStatus": 200, "EdgeStartTimestamp": "2026-03-28T09:15:00Z",
                "WAFAction": "allow", "BotScore": 90,
            }],
            "waf_block": [{
                "ClientIP": "185.220.101.34", "ClientRequestHost": "api.corp.com",
                "ClientRequestMethod": "POST", "ClientRequestPath": "/v1/users?id=1 UNION SELECT",
                "EdgeResponseStatus": 403, "EdgeStartTimestamp": "2026-03-28T09:15:01Z",
                "WAFAction": "block", "WAFRuleID": "100016",
                "WAFRuleMessage": "SQLi Attack Vector", "BotScore": 2,
            }],
        },
        mitre_mappings={
            "T1190": ["waf_block"],
            "T1133": ["auth_bypass_attempt"],
            "T1046": ["scanner_bot_traffic"],
        },
        doc_url="https://developers.cloudflare.com/logs/reference/log-fields/",
        doc_last_checked="2026-03-28",
        update_frequency="quarterly",
        splunk_sourcetype="cloudflare:json",
        elastic_index_pattern="filebeat-*-cloudflare*",
        joti_source_type="cloudflare",
    ),

    # ── Wiz ─────────────────────────────────────────────────────────────────
    LogSourceDefinition(
        source_id="wiz",
        vendor="Wiz",
        product="Wiz Security Platform",
        category="posture",
        version="2024",
        format="json",
        description="Wiz cloud security posture findings: vulnerabilities, misconfigurations, network exposures, toxic combinations, and runtime threats.",
        fields={
            "id": {"type": "string", "description": "Finding unique ID"},
            "type": {"type": "string", "description": "TOXIC_COMBINATION|VULNERABILITY|MISCONFIGURATION|THREAT"},
            "severity": {"type": "string", "description": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL"},
            "status": {"type": "string", "description": "OPEN|IN_PROGRESS|RESOLVED|REJECTED"},
            "title": {"type": "string", "description": "Human-readable finding title"},
            "resource.type": {"type": "string", "description": "VirtualMachine|Container|StorageBucket|..."},
            "resource.name": {"type": "string", "description": "Cloud resource name"},
            "resource.cloudPlatform": {"type": "string", "description": "AWS|GCP|AZURE|OCI"},
            "cve.id": {"type": "string", "description": "CVE identifier (vulnerability findings)"},
            "firstSeenAt": {"type": "datetime", "description": "First detection timestamp"},
        },
        sample_events={
            "toxic_combination": [{
                "id": "wiz-abc123", "type": "TOXIC_COMBINATION", "severity": "CRITICAL",
                "status": "OPEN",
                "title": "Internet-exposed VM with admin privileges and critical vulnerability",
                "resource": {"type": "VirtualMachine", "name": "prod-web-01", "cloudPlatform": "AWS"},
                "firstSeenAt": "2026-03-28T00:00:00Z",
            }],
        },
        mitre_mappings={
            "T1190": ["public_exposure"],
            "T1078": ["excessive_permissions"],
            "T1552": ["secrets_in_env"],
        },
        doc_url="https://docs.wiz.io/wiz-docs/docs/api-reference",
        doc_last_checked="2026-03-28",
        update_frequency="frequent",
        splunk_sourcetype="wiz:finding",
        joti_source_type="wiz",
    ),
]


# ---------------------------------------------------------------------------
# Registry Class
# ---------------------------------------------------------------------------

class SchemaRegistry:
    """Manages log source schema definitions in the knowledge base.

    Schemas are stored in ChromaDB (namespace: log_schemas) as JSON text
    with rich metadata. The agentic generator reads them via semantic search.
    """

    def __init__(self) -> None:
        self._cache: dict[str, LogSourceDefinition] = {}
        self._loaded = False

    def _build_cache(self) -> None:
        if not self._loaded:
            for schema in BUILTIN_SCHEMAS:
                self._cache[schema.source_id] = schema
            self._loaded = True

    def get(self, source_id: str) -> LogSourceDefinition | None:
        self._build_cache()
        return self._cache.get(source_id)

    def list_all(self) -> list[LogSourceDefinition]:
        self._build_cache()
        return list(self._cache.values())

    def list_by_category(self, category: str) -> list[LogSourceDefinition]:
        return [s for s in self.list_all() if s.category == category]

    def list_ids(self) -> list[str]:
        return [s.source_id for s in self.list_all()]

    def get_schema_text(self, source_id: str) -> str:
        """Return schema as compact JSON text — used as LLM context."""
        schema = self.get(source_id)
        if not schema:
            return ""
        d = asdict(schema)
        # Trim sample events to first 1 per type to keep tokens down
        for etype in d.get("sample_events", {}):
            d["sample_events"][etype] = d["sample_events"][etype][:1]
        return json.dumps(d, default=str)

    def get_mitre_sources(self, technique_id: str) -> list[LogSourceDefinition]:
        """Return all sources that have mappings for a technique."""
        return [s for s in self.list_all() if technique_id in s.mitre_mappings]

    async def seed_knowledge_base(self, knowledge_store: Any) -> int:
        """Seed all schemas into ChromaDB for semantic retrieval.

        Only seeds if not already present (idempotent).
        Returns count of schemas seeded.
        """
        seeded = 0
        for schema in self.list_all():
            key = f"schema:{schema.source_id}:{schema.version}"
            existing = await knowledge_store.get_knowledge(SCHEMA_NAMESPACE, key)
            if existing is None:
                text = self.get_schema_text(schema.source_id)
                await knowledge_store.store_knowledge(
                    namespace=SCHEMA_NAMESPACE,
                    key=key,
                    content=text,
                    metadata={
                        "source_id": schema.source_id,
                        "vendor": schema.vendor,
                        "product": schema.product,
                        "category": schema.category,
                        "version": schema.version,
                        "update_frequency": schema.update_frequency,
                        "doc_last_checked": schema.doc_last_checked,
                        "mitre_techniques": list(schema.mitre_mappings.keys()),
                        "joti_source_type": schema.joti_source_type,
                    },
                )
                seeded += 1
                logger.info("Seeded schema: %s", schema.source_id)
        return seeded

    async def get_schema_for_technique(
        self, technique_id: str, knowledge_store: Any
    ) -> list[dict[str, Any]]:
        """Find schemas relevant to a MITRE technique via semantic search."""
        # First try direct mapping
        direct = self.get_mitre_sources(technique_id)
        if direct:
            return [asdict(s) for s in direct]
        # Fall back to semantic search
        results = await knowledge_store.search_knowledge(
            namespace=SCHEMA_NAMESPACE,
            query=f"log source for detecting MITRE {technique_id}",
            top_k=3,
        )
        return results


# Singleton
_registry: SchemaRegistry | None = None


def get_registry() -> SchemaRegistry:
    global _registry
    if _registry is None:
        _registry = SchemaRegistry()
    return _registry
