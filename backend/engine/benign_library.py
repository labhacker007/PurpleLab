"""Normal enterprise baseline event library.

Generates realistic background activity for each architecture component so a
simulated time window contains both benign traffic and attacker events — just
like a real SIEM ingesting data from a live enterprise.

Architecture components:
  windows_endpoint  → index=windows,       sourcetype=WinEventLog:Security / Sysmon
  windows_server    → index=windows,       sourcetype=WinEventLog:Security (servers/DCs)
  edr               → index=crowdstrike,   sourcetype=crowdstrike:events
  email             → index=email,         sourcetype=o365:exchange:messageTrace
  proxy_firewall    → index=pan_log,       sourcetype=pan:traffic
  cloud             → index=aws,           sourcetype=aws:cloudtrail
  linux             → index=linux_log,     sourcetype=linux:syslog
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from backend.engine.product_catalog import resolve_schema_for_component
from backend.engine.schema_library import get_vendor_benign_templates


# ── SIEM schema registry ──────────────────────────────────────────────────────

COMPONENT_SCHEMAS: dict[str, dict[str, str]] = {
    "windows_endpoint": {
        "index": "windows",
        "sourcetype": "WinEventLog:Security",
    },
    "windows_server": {
        "index": "windows",
        "sourcetype": "WinEventLog:Security",
    },
    "sysmon": {
        "index": "sysmon",
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    },
    "edr": {
        "index": "crowdstrike",
        "sourcetype": "crowdstrike:events",
    },
    "email": {
        "index": "email",
        "sourcetype": "o365:exchange:messageTrace",
    },
    "proxy_firewall": {
        "index": "pan_log",
        "sourcetype": "pan:traffic",
    },
    "cloud": {
        "index": "aws",
        "sourcetype": "aws:cloudtrail",
    },
    "linux": {
        "index": "linux_log",
        "sourcetype": "linux:syslog",
    },
}

# ── Benign template bank ──────────────────────────────────────────────────────
# Each entry: component, severity, title_template, payload_template
# Placeholder tokens match _build_substitution_map + benign-specific:
#   {hostname}, {server}, {dc}, {username}, {email}, {domain},
#   {src_ip}, {server_ip}
# Extra benign tokens resolved in _resolve_benign_subs():
#   {pid}, {benign_site}, {benign_proc}, {cloud_user}, {s3_bucket},
#   {aws_region}, {linux_user}, {cron_cmd}, {smtp_from}, {smtp_to}

BENIGN_TEMPLATES: list[dict[str, Any]] = [

    # ── Windows Endpoint — Security log ──────────────────────────────────────

    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "User {username} logged on to {hostname} (EID 4624)",
        "payload_template": {
            "EventID": "4624",
            "Channel": "Security",
            "Computer": "{hostname}",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "{domain}",
            "TargetUserName": "{username}",
            "TargetDomainName": "{domain}",
            "LogonType": "2",
            "LogonTypeName": "Interactive",
            "AuthenticationPackageName": "Kerberos",
            "WorkstationName": "{hostname}",
            "IpAddress": "{src_ip}",
            "IpPort": "0",
        },
    },
    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "User {username} logged off from {hostname} (EID 4634)",
        "payload_template": {
            "EventID": "4634",
            "Channel": "Security",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "SubjectDomainName": "{domain}",
            "LogonType": "2",
        },
    },
    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "Process creation: {benign_proc} on {hostname} (EID 4688)",
        "payload_template": {
            "EventID": "4688",
            "Channel": "Security",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "SubjectDomainName": "{domain}",
            "NewProcessName": "C:\\Program Files\\{benign_proc}",
            "CommandLine": "{benign_proc} --no-sandbox --type=renderer",
            "NewProcessId": "{pid}",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
        },
    },
    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "NTLM authentication succeeded for {username} on {hostname} (EID 4776)",
        "payload_template": {
            "EventID": "4776",
            "Channel": "Security",
            "Computer": "{dc}",
            "PackageName": "NTLM V2",
            "TargetUserName": "{username}",
            "Workstation": "{hostname}",
            "Status": "0x0",
        },
    },
    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "Network share accessed: \\\\{server}\\Users on {hostname} (EID 5140)",
        "payload_template": {
            "EventID": "5140",
            "Channel": "Security",
            "Computer": "{server}",
            "SubjectUserName": "{username}",
            "SubjectDomainName": "{domain}",
            "ObjectType": "File",
            "ShareName": "\\\\*\\Users",
            "ShareLocalPath": "C:\\Users",
            "IpAddress": "{src_ip}",
            "IpPort": "49215",
            "AccessMask": "0x1",
        },
    },
    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "Special privileges assigned to new logon for {username} (EID 4672)",
        "payload_template": {
            "EventID": "4672",
            "Channel": "Security",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "SubjectDomainName": "{domain}",
            "PrivilegeList": "SeSecurityPrivilege\nSeBackupPrivilege\nSeRestorePrivilege",
        },
    },
    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "Windows Defender scan completed on {hostname} (EID 1001)",
        "payload_template": {
            "EventID": "1001",
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "Computer": "{hostname}",
            "ScanType": "AntiSpyware",
            "ScanParameters": "Quick scan",
            "ProductVersion": "4.18.2209.7",
            "SignatureVersion": "1.375.1543.0",
            "ThreatName": "No threats found",
            "Result": "Succeeded",
        },
    },
    {
        "component": "windows_endpoint",
        "severity": "info",
        "title_template": "User account local group enumerated for {username} (EID 4798)",
        "payload_template": {
            "EventID": "4798",
            "Channel": "Security",
            "Computer": "{hostname}",
            "TargetUserName": "{username}",
            "TargetDomainName": "{domain}",
            "CallerProcessName": "C:\\Windows\\System32\\svchost.exe",
            "SubjectUserName": "SYSTEM",
        },
    },

    # ── Windows Server / DC — Security log ───────────────────────────────────

    {
        "component": "windows_server",
        "severity": "info",
        "title_template": "Kerberos TGT requested for {username} on {dc} (EID 4768)",
        "payload_template": {
            "EventID": "4768",
            "Channel": "Security",
            "Computer": "{dc}",
            "TargetUserName": "{username}",
            "TargetDomainName": "{domain}",
            "ServiceName": "krbtgt",
            "TicketOptions": "0x40810010",
            "Status": "0x0",
            "TicketEncryptionType": "0x12",
            "IpAddress": "{src_ip}",
            "IpPort": "59412",
        },
    },
    {
        "component": "windows_server",
        "severity": "info",
        "title_template": "Kerberos service ticket issued for {username} → {server} (EID 4769)",
        "payload_template": {
            "EventID": "4769",
            "Channel": "Security",
            "Computer": "{dc}",
            "TargetUserName": "{username}@{domain}",
            "ServiceName": "{server}$",
            "ServiceSid": "S-1-5-21-1001",
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": "0x12",
            "IpAddress": "{src_ip}",
            "Status": "0x0",
        },
    },
    {
        "component": "windows_server",
        "severity": "info",
        "title_template": "Windows service started: Windows Update on {server} (EID 7036)",
        "payload_template": {
            "EventID": "7036",
            "Channel": "System",
            "Computer": "{server}",
            "ServiceName": "wuauserv",
            "ServiceDisplayName": "Windows Update",
            "NewState": "running",
        },
    },
    {
        "component": "windows_server",
        "severity": "info",
        "title_template": "Group Policy updated on {hostname} (EID 1502)",
        "payload_template": {
            "EventID": "1502",
            "Channel": "Microsoft-Windows-GroupPolicy/Operational",
            "Computer": "{hostname}",
            "PrincipalSamName": "{domain}\\{username}",
            "IsMachine": "0",
            "ReasonForSynchronousProcessing": "0",
            "NumberOfGroupPolicyObjects": "7",
        },
    },

    # ── Sysmon telemetry ─────────────────────────────────────────────────────

    {
        "component": "sysmon",
        "severity": "info",
        "title_template": "Sysmon EID 1 — Process: {benign_proc} on {hostname}",
        "payload_template": {
            "EventID": "1",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "{hostname}",
            "UtcTime": "",
            "ProcessGuid": "{pid}",
            "ProcessId": "{pid}",
            "Image": "C:\\Program Files\\{benign_proc}",
            "CommandLine": "{benign_proc} --type=renderer --lang=en-US",
            "CurrentDirectory": "C:\\Users\\{username}\\",
            "User": "{domain}\\{username}",
            "Hashes": "MD5=8D6A95CE0CFFF6A5FDB4FDC95BE71E40",
            "ParentProcessId": "1234",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "C:\\Windows\\explorer.exe",
            "IntegrityLevel": "Medium",
        },
    },
    {
        "component": "sysmon",
        "severity": "info",
        "title_template": "Sysmon EID 3 — Network: {hostname} → {benign_site}:443",
        "payload_template": {
            "EventID": "3",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "{hostname}",
            "Image": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "User": "{domain}\\{username}",
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIp": "{src_ip}",
            "SourcePort": "52311",
            "DestinationIp": "20.236.44.162",
            "DestinationPort": "443",
            "DestinationHostname": "{benign_site}",
        },
    },
    {
        "component": "sysmon",
        "severity": "info",
        "title_template": "Sysmon EID 22 — DNS query: {hostname} → {benign_site}",
        "payload_template": {
            "EventID": "22",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "{hostname}",
            "Image": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "QueryName": "{benign_site}",
            "QueryStatus": "0",
            "QueryResults": "type: 5 20.236.44.162;",
            "User": "{domain}\\{username}",
        },
    },
    {
        "component": "sysmon",
        "severity": "info",
        "title_template": "Sysmon EID 11 — File created: {username} Office doc on {hostname}",
        "payload_template": {
            "EventID": "11",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "{hostname}",
            "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "TargetFilename": "C:\\Users\\{username}\\Documents\\Q4_Budget_Report.docx",
            "CreationUtcTime": "",
            "User": "{domain}\\{username}",
        },
    },

    # ── EDR — CrowdStrike Falcon ─────────────────────────────────────────────

    {
        "component": "edr",
        "severity": "info",
        "title_template": "CrowdStrike: UserLogon event for {username} on {hostname}",
        "payload_template": {
            "event_type": "UserLogon",
            "ComputerName": "{hostname}",
            "UserName": "{username}",
            "UserSid": "S-1-5-21-1004336348-1177238915-682003330-500",
            "LogonType": "2",
            "LogonDomain": "{domain}",
            "RemoteAccount": "false",
            "AuthenticationPackage": "NTLM",
            "cid": "1234567890abcdef1234567890abcdef",
            "event_simpleName": "UserLogon",
            "AgentIdString": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "AgentVersion": "6.40.15806.0",
            "ProductType": "1",
            "Platform": "Win",
        },
    },
    {
        "component": "edr",
        "severity": "info",
        "title_template": "CrowdStrike: ProcessRollup2 — {benign_proc} on {hostname}",
        "payload_template": {
            "event_type": "ProcessRollup2",
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "{hostname}",
            "UserName": "{username}",
            "FileName": "{benign_proc}",
            "FilePath": "\\Device\\HarddiskVolume4\\Program Files\\",
            "CommandLine": "{benign_proc} --type=gpu-process",
            "SHA256HashData": "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576f4d437a6a3e574c3",
            "MD5HashData": "900150983cd24fb0d6963f7d28e17f72",
            "ContextProcessId": "{pid}",
            "ParentProcessId": "1000",
            "GrandparentCommandLine": "C:\\Windows\\explorer.exe",
        },
    },
    {
        "component": "edr",
        "severity": "info",
        "title_template": "CrowdStrike: DnsRequest — {hostname} queries {benign_site}",
        "payload_template": {
            "event_type": "DnsRequest",
            "event_simpleName": "DnsRequest",
            "ComputerName": "{hostname}",
            "UserName": "{username}",
            "DomainName": "{benign_site}",
            "RequestType": "1",
            "IP": "20.54.36.25",
            "Port": "443",
        },
    },
    {
        "component": "edr",
        "severity": "info",
        "title_template": "CrowdStrike: NetworkConnectIP4 — {hostname} → {benign_site}:443",
        "payload_template": {
            "event_type": "NetworkConnectIP4",
            "event_simpleName": "NetworkConnectIP4",
            "ComputerName": "{hostname}",
            "UserName": "{username}",
            "LocalAddressIP4": "{src_ip}",
            "LocalPort": "55321",
            "RemoteAddressIP4": "20.54.36.25",
            "RemotePort": "443",
            "Protocol": "6",
            "ConnectionDirection": "0",
        },
    },
    {
        "component": "edr",
        "severity": "info",
        "title_template": "CrowdStrike: EndOfProcess — {benign_proc} exited on {hostname}",
        "payload_template": {
            "event_type": "EndOfProcess",
            "event_simpleName": "EndOfProcess",
            "ComputerName": "{hostname}",
            "UserName": "{username}",
            "FileName": "{benign_proc}",
            "ProcessEndTime": "1654321000",
            "ProcessStartTime": "1654318000",
            "ExitCode": "0",
        },
    },

    # ── Email — Microsoft 365 Exchange ───────────────────────────────────────

    {
        "component": "email",
        "severity": "info",
        "title_template": "Email delivered: HR announcement → {username}",
        "payload_template": {
            "MessageId": "<abc123@{domain}>",
            "Subject": "Company All-Hands Meeting — Thursday 2pm",
            "SenderAddress": "hr-noreply@{domain}",
            "RecipientAddress": "{email}",
            "RecipientStatus": "Delivered",
            "MessageSizeBytes": "18420",
            "MessageDirection": "Intra",
            "ConnectorId": "Default",
            "DeliveryTimestamp": "",
            "OriginalClientIP": "{src_ip}",
            "Organization": "{domain}",
            "Directionality": "0",
            "AttachmentCount": "0",
            "SafeAttachmentVerdict": "None",
            "SafeLinksVerdict": "None",
        },
    },
    {
        "component": "email",
        "severity": "info",
        "title_template": "Inbound email delivered from vendor to {username}",
        "payload_template": {
            "MessageId": "<vendor-001@vendorcorp.com>",
            "Subject": "Q4 2023 Contract Renewal — Action Required by Dec 31",
            "SenderAddress": "contracts@vendorcorp.com",
            "RecipientAddress": "{email}",
            "RecipientStatus": "Delivered",
            "MessageSizeBytes": "24680",
            "MessageDirection": "Inbound",
            "ConnectorId": "Default Inbound",
            "TLSUsed": "TLS",
            "Directionality": "1",
            "AttachmentCount": "1",
            "AttachmentExtensions": ".pdf",
            "SafeAttachmentVerdict": "Clean",
            "SafeLinksVerdict": "Clean",
        },
    },
    {
        "component": "email",
        "severity": "info",
        "title_template": "Outbound email sent by {username} to external",
        "payload_template": {
            "MessageId": "<outbound-{username}@{domain}>",
            "Subject": "Re: Project Update — Sprint 42 Status",
            "SenderAddress": "{email}",
            "RecipientAddress": "partner@clientcompany.com",
            "RecipientStatus": "Delivered",
            "MessageSizeBytes": "9340",
            "MessageDirection": "Outbound",
            "TLSUsed": "TLS",
            "Directionality": "2",
            "AttachmentCount": "0",
        },
    },
    {
        "component": "email",
        "severity": "info",
        "title_template": "Microsoft Teams calendar invite delivered to {username}",
        "payload_template": {
            "MessageId": "<teams-cal@teams.microsoft.com>",
            "Subject": "Teams meeting: Weekly Standup",
            "SenderAddress": "noreply@email.teams.microsoft.com",
            "RecipientAddress": "{email}",
            "RecipientStatus": "Delivered",
            "MessageSizeBytes": "6120",
            "MessageDirection": "Inbound",
            "ConnectorId": "Microsoft365 Inbound",
            "SafeAttachmentVerdict": "None",
            "Directionality": "1",
        },
    },
    {
        "component": "email",
        "severity": "info",
        "title_template": "Proofpoint: Clean email quarantine release for {username}",
        "payload_template": {
            "action": "released",
            "reason": "False positive",
            "sender": "newsletter@saas-vendor.com",
            "recipient": "{email}",
            "subject": "New features in your account — July 2023",
            "released_by": "admin@{domain}",
            "phish_score": "12",
            "spam_score": "55",
            "verdict": "clean",
        },
    },

    # ── Proxy / Firewall — Palo Alto Networks ────────────────────────────────

    {
        "component": "proxy_firewall",
        "severity": "info",
        "title_template": "Firewall allow: {hostname} → {benign_site}:443 (HTTPS)",
        "payload_template": {
            "log_type": "TRAFFIC",
            "action": "allow",
            "app": "ssl",
            "src": "{src_ip}",
            "dst": "20.236.44.162",
            "dport": "443",
            "sport": "52414",
            "proto": "tcp",
            "from": "trust",
            "to": "untrust",
            "rule": "Allow-Outbound-Web",
            "bytes_sent": "4210",
            "bytes_received": "182440",
            "session_id": "123456",
            "elapsed": "8",
            "host": "{benign_site}",
            "category": "computer-and-internet-info",
        },
    },
    {
        "component": "proxy_firewall",
        "severity": "info",
        "title_template": "Firewall allow: {hostname} → windowsupdate.microsoft.com (HTTP)",
        "payload_template": {
            "log_type": "TRAFFIC",
            "action": "allow",
            "app": "ms-update",
            "src": "{src_ip}",
            "dst": "40.119.44.56",
            "dport": "80",
            "sport": "49901",
            "proto": "tcp",
            "from": "trust",
            "to": "untrust",
            "rule": "Allow-WindowsUpdate",
            "bytes_sent": "860",
            "bytes_received": "984320",
            "session_id": "123460",
            "elapsed": "42",
            "host": "windowsupdate.microsoft.com",
            "category": "computer-and-internet-info",
        },
    },
    {
        "component": "proxy_firewall",
        "severity": "info",
        "title_template": "Firewall allow: {hostname} → teams.microsoft.com:443 (Teams)",
        "payload_template": {
            "log_type": "TRAFFIC",
            "action": "allow",
            "app": "ms-teams",
            "src": "{src_ip}",
            "dst": "52.113.194.132",
            "dport": "443",
            "sport": "53120",
            "proto": "tcp",
            "from": "trust",
            "to": "untrust",
            "rule": "Allow-O365",
            "bytes_sent": "28400",
            "bytes_received": "198220",
            "session_id": "123470",
            "elapsed": "1821",
            "host": "teams.microsoft.com",
            "category": "internet-communications-and-telephony",
        },
    },
    {
        "component": "proxy_firewall",
        "severity": "info",
        "title_template": "Firewall allow: {hostname} → login.microsoftonline.com:443 (SSO)",
        "payload_template": {
            "log_type": "TRAFFIC",
            "action": "allow",
            "app": "ms-office365-base",
            "src": "{src_ip}",
            "dst": "20.190.144.213",
            "dport": "443",
            "sport": "51002",
            "proto": "tcp",
            "from": "trust",
            "to": "untrust",
            "rule": "Allow-O365",
            "bytes_sent": "3120",
            "bytes_received": "18440",
            "session_id": "123480",
            "elapsed": "2",
            "host": "login.microsoftonline.com",
            "category": "online-storage-and-backup",
        },
    },
    {
        "component": "proxy_firewall",
        "severity": "info",
        "title_template": "Firewall allow: {hostname} → zoom.us:443 (video call)",
        "payload_template": {
            "log_type": "TRAFFIC",
            "action": "allow",
            "app": "zoom",
            "src": "{src_ip}",
            "dst": "170.114.52.2",
            "dport": "443",
            "sport": "54021",
            "proto": "tcp",
            "from": "trust",
            "to": "untrust",
            "rule": "Allow-Video-Conf",
            "bytes_sent": "182400",
            "bytes_received": "924800",
            "session_id": "123490",
            "elapsed": "3600",
            "host": "zoom.us",
            "category": "internet-communications-and-telephony",
        },
    },
    {
        "component": "proxy_firewall",
        "severity": "info",
        "title_template": "DNS request: {hostname} → 8.8.8.8 for {benign_site}",
        "payload_template": {
            "log_type": "TRAFFIC",
            "action": "allow",
            "app": "dns",
            "src": "{src_ip}",
            "dst": "8.8.8.8",
            "dport": "53",
            "sport": "51234",
            "proto": "udp",
            "from": "trust",
            "to": "untrust",
            "rule": "Allow-DNS",
            "bytes_sent": "84",
            "bytes_received": "128",
            "session_id": "123500",
            "elapsed": "0",
            "category": "dns",
        },
    },
    {
        "component": "proxy_firewall",
        "severity": "info",
        "title_template": "Firewall allow: {hostname} → github.com:443 (dev)",
        "payload_template": {
            "log_type": "TRAFFIC",
            "action": "allow",
            "app": "github",
            "src": "{src_ip}",
            "dst": "140.82.113.4",
            "dport": "443",
            "sport": "55001",
            "proto": "tcp",
            "from": "trust",
            "to": "untrust",
            "rule": "Allow-Dev-SaaS",
            "bytes_sent": "92400",
            "bytes_received": "2840200",
            "session_id": "123510",
            "elapsed": "124",
            "host": "github.com",
            "category": "computer-and-internet-info",
        },
    },

    # ── Cloud — AWS CloudTrail ────────────────────────────────────────────────

    {
        "component": "cloud",
        "severity": "info",
        "title_template": "AWS: AssumeRole by {cloud_user} in {aws_region}",
        "payload_template": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "accountId": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/{cloud_user}",
                "userName": "{cloud_user}",
                "sessionContext": {"mfaAuthenticated": "true"},
            },
            "eventTime": "",
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "awsRegion": "{aws_region}",
            "sourceIPAddress": "{src_ip}",
            "userAgent": "aws-cli/2.9.0 Python/3.11.0",
            "requestParameters": {
                "roleArn": "arn:aws:iam::123456789012:role/DevOps-Role",
                "roleSessionName": "{cloud_user}-session",
            },
            "responseElements": {"credentials": {"expiration": "2023-12-01T18:00:00Z"}},
        },
    },
    {
        "component": "cloud",
        "severity": "info",
        "title_template": "AWS: S3 GetObject by {cloud_user} from {s3_bucket}",
        "payload_template": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "accountId": "123456789012",
                "userName": "{cloud_user}",
            },
            "eventTime": "",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "{aws_region}",
            "sourceIPAddress": "{src_ip}",
            "userAgent": "aws-sdk-python/1.28.0",
            "requestParameters": {
                "bucketName": "{s3_bucket}",
                "key": "reports/q4-2023/summary.pdf",
            },
            "responseElements": None,
            "additionalEventData": {"bytesTransferredIn": 0, "bytesTransferredOut": 184320},
        },
    },
    {
        "component": "cloud",
        "severity": "info",
        "title_template": "AWS: EC2 DescribeInstances by {cloud_user}",
        "payload_template": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "accountId": "123456789012",
                "userName": "{cloud_user}",
            },
            "eventTime": "",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": "{aws_region}",
            "sourceIPAddress": "{src_ip}",
            "userAgent": "Boto3/1.26.0 Python/3.11.0",
            "requestParameters": {"filterSet": {}, "instancesSet": {}},
            "responseElements": None,
        },
    },
    {
        "component": "cloud",
        "severity": "info",
        "title_template": "AWS: CloudWatch GetMetricData by {cloud_user}",
        "payload_template": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/Monitoring/{cloud_user}",
            },
            "eventTime": "",
            "eventSource": "monitoring.amazonaws.com",
            "eventName": "GetMetricData",
            "awsRegion": "{aws_region}",
            "sourceIPAddress": "AWS Internal",
            "requestParameters": {"metricDataQueries": [{"id": "m1", "metricStat": {}}]},
        },
    },
    {
        "component": "cloud",
        "severity": "info",
        "title_template": "AWS: SSM GetParameter by {cloud_user} (app config fetch)",
        "payload_template": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "accountId": "123456789012",
                "arn": "arn:aws:sts::123456789012:assumed-role/AppRole/{cloud_user}",
            },
            "eventTime": "",
            "eventSource": "ssm.amazonaws.com",
            "eventName": "GetParameter",
            "awsRegion": "{aws_region}",
            "sourceIPAddress": "10.0.1.100",
            "requestParameters": {"name": "/prod/app/db-password", "withDecryption": True},
        },
    },
    {
        "component": "cloud",
        "severity": "info",
        "title_template": "AWS: GetCallerIdentity by {cloud_user}",
        "payload_template": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "accountId": "123456789012",
                "userName": "{cloud_user}",
            },
            "eventTime": "",
            "eventSource": "sts.amazonaws.com",
            "eventName": "GetCallerIdentity",
            "awsRegion": "{aws_region}",
            "sourceIPAddress": "{src_ip}",
        },
    },

    # ── Linux Server — Syslog ─────────────────────────────────────────────────

    {
        "component": "linux",
        "severity": "info",
        "title_template": "SSH login: {linux_user} authenticated on {server}",
        "payload_template": {
            "hostname": "{server}",
            "program": "sshd",
            "pid": "{pid}",
            "message": "Accepted publickey for {linux_user} from {src_ip} port 52841 ssh2: RSA SHA256:abc123",
            "facility": "auth",
            "severity": "info",
            "user": "{linux_user}",
            "src_ip": "{src_ip}",
        },
    },
    {
        "component": "linux",
        "severity": "info",
        "title_template": "Cron job executed: backup script on {server}",
        "payload_template": {
            "hostname": "{server}",
            "program": "CRON",
            "pid": "{pid}",
            "message": "(root) CMD ({cron_cmd})",
            "facility": "cron",
            "severity": "info",
            "user": "root",
        },
    },
    {
        "component": "linux",
        "severity": "info",
        "title_template": "sudo: {linux_user} ran privileged command on {server}",
        "payload_template": {
            "hostname": "{server}",
            "program": "sudo",
            "pid": "{pid}",
            "message": "{linux_user} : TTY=pts/0 ; PWD=/home/{linux_user} ; USER=root ; COMMAND=/usr/bin/apt-get update",
            "facility": "auth",
            "severity": "notice",
            "user": "{linux_user}",
        },
    },
    {
        "component": "linux",
        "severity": "info",
        "title_template": "systemd: nginx service restarted on {server}",
        "payload_template": {
            "hostname": "{server}",
            "program": "systemd",
            "pid": "1",
            "message": "Started A high performance web server and a reverse proxy server (nginx.service).",
            "facility": "daemon",
            "severity": "info",
            "unit": "nginx.service",
        },
    },
    {
        "component": "linux",
        "severity": "info",
        "title_template": "SSH session closed for {linux_user} on {server}",
        "payload_template": {
            "hostname": "{server}",
            "program": "sshd",
            "pid": "{pid}",
            "message": "Disconnected from user {linux_user} {src_ip} port 52841",
            "facility": "auth",
            "severity": "info",
            "user": "{linux_user}",
        },
    },
    {
        "component": "linux",
        "severity": "info",
        "title_template": "logrotate executed on {server}",
        "payload_template": {
            "hostname": "{server}",
            "program": "logrotate",
            "pid": "{pid}",
            "message": "error: error opening /var/log/nginx/error.log: No such file or directory",
            "facility": "cron",
            "severity": "info",
        },
    },
    {
        "component": "linux",
        "severity": "info",
        "title_template": "PAM: successful su for {linux_user} on {server}",
        "payload_template": {
            "hostname": "{server}",
            "program": "su",
            "pid": "{pid}",
            "message": "pam_unix(su:session): session opened for user postgres by {linux_user}(uid=1001)",
            "facility": "auth",
            "severity": "info",
            "user": "{linux_user}",
        },
    },
]


# ── Benign-specific substitution values ──────────────────────────────────────

_BENIGN_SITES = [
    "login.microsoftonline.com",
    "teams.microsoft.com",
    "outlook.office365.com",
    "sharepoint.com",
    "onedrive.live.com",
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "zoom.us",
    "github.com",
    "api.github.com",
    "slack.com",
    "slack-edge.com",
    "okta.com",
    "salesforce.com",
    "servicenow.com",
    "jira.atlassian.com",
    "confluence.atlassian.com",
]

_BENIGN_PROCS = [
    "chrome.exe",
    "msedge.exe",
    "OUTLOOK.EXE",
    "WINWORD.EXE",
    "EXCEL.EXE",
    "Teams.exe",
    "OneDrive.exe",
    "Slack.exe",
    "code.exe",
    "explorer.exe",
    "svchost.exe",
    "RuntimeBroker.exe",
]

_CLOUD_USERS = ["alice.dev", "bob.ops", "carol.admin", "devops-pipeline", "app-service-account"]
_S3_BUCKETS = ["company-reports-prod", "app-data-archive", "log-archive-2023", "backup-store-prod"]
_AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
_LINUX_USERS = ["deploy", "ops", "svc_monitor", "backup", "ubuntu", "jenkins"]
_CRON_CMDS = [
    "/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1",
    "/usr/bin/find /tmp -mtime +7 -delete",
    "/usr/local/bin/health_check.sh",
    "/usr/bin/rsync -avz /data/ backup-server:/data/",
]

# ── Component weight distribution for baseline noise ─────────────────────────
# How many benign events per component (percentage of total benign events)
COMPONENT_WEIGHTS = {
    "windows_endpoint": 0.30,
    "sysmon":            0.15,
    "edr":               0.12,
    "proxy_firewall":    0.22,
    "email":             0.08,
    "cloud":             0.08,
    "windows_server":    0.03,
    "linux":             0.02,
}


# ── Substitution helper ────────────────────────────────────────────────────────

def _resolve_benign_subs(template_str: str, subs: dict[str, str]) -> str:
    """Apply both common and benign-specific substitutions to a string."""
    for k, v in subs.items():
        template_str = template_str.replace(k, str(v))
    return template_str


def _apply_subs(obj: Any, subs: dict[str, str]) -> Any:
    """Recursively apply substitutions to a nested dict/list/str."""
    if isinstance(obj, str):
        return _resolve_benign_subs(obj, subs)
    if isinstance(obj, dict):
        return {k: _apply_subs(v, subs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_apply_subs(item, subs) for item in obj]
    return obj


def _build_subs(
    asset_pool: dict[str, Any],
    context: Any = None,   # SimulationContext | None
) -> dict[str, str]:
    """Build substitution map from asset pool + benign-specific values.

    When a SimulationContext is provided, victim identity fields (hostname,
    username, email, domain, src_ip) come from the context so that benign
    baseline events reference the same entities as the attack events.
    """
    endpoints = asset_pool.get("endpoints") or [{"hostname": "CORP-WS-01", "ip_address": "192.168.1.10"}]
    servers = asset_pool.get("servers") or [{"hostname": "SERVER-DC01", "ip_address": "192.168.1.5"}]
    users = asset_pool.get("users") or [{"username": "jsmith", "email": "jsmith@corp.local"}]
    domain = asset_pool.get("domain", "corp.local")

    if context is not None:
        hostname = context.victim_hostname or random.choice(endpoints)["hostname"]
        src_ip = context.victim_ip or random.choice(endpoints)["ip_address"]
        username = context.victim_username or random.choice(users)["username"]
        email = context.victim_email or f"{username}@{context.domain or domain}"
        domain = context.domain or domain
        sv = random.choice(servers)
        dc = servers[0]
        cloud_user = context.cloud_user_email or random.choice(_CLOUD_USERS)
        s3_bucket = context.s3_bucket_name or random.choice(_S3_BUCKETS)
        aws_region = context.aws_region or random.choice(_AWS_REGIONS)
    else:
        ep = random.choice(endpoints)
        sv = random.choice(servers)
        u = random.choice(users)
        dc = servers[0]
        hostname = ep["hostname"]
        src_ip = ep["ip_address"]
        username = u["username"]
        email = u.get("email", f"{username}@{domain}")
        cloud_user = random.choice(_CLOUD_USERS)
        s3_bucket = random.choice(_S3_BUCKETS)
        aws_region = random.choice(_AWS_REGIONS)

    return {
        "{hostname}": hostname,
        "{server}": sv["hostname"],
        "{dc}": dc["hostname"],
        "{username}": username,
        "{email}": email,
        "{domain}": domain,
        "{src_ip}": src_ip,
        "{server_ip}": sv["ip_address"],
        "{pid}": str(random.randint(1000, 32767)),
        "{benign_site}": random.choice(_BENIGN_SITES),
        "{benign_proc}": random.choice(_BENIGN_PROCS),
        "{cloud_user}": cloud_user,
        "{s3_bucket}": s3_bucket,
        "{aws_region}": aws_region,
        "{linux_user}": random.choice(_LINUX_USERS),
        "{cron_cmd}": random.choice(_CRON_CMDS),
        "{smtp_from}": f"noreply@{random.choice(['vendorcorp.com', 'partner.io', 'hr.' + domain, domain])}",
        "{smtp_to}": f"{username}@{domain}",
        "{date}": datetime.utcnow().strftime("%Y-%m-%d"),
        "{time}": datetime.utcnow().strftime("%H:%M:%S"),
        "{sport}": str(random.randint(49152, 65535)),
        "{timestamp}": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }


# ── Component-to-SIEM log_source mapping ─────────────────────────────────────
# Maps component name → log_source value used by session_manager / frontend
COMPONENT_LOG_SOURCE = {
    "windows_endpoint": "windows_eventlog",
    "windows_server":   "windows_eventlog",
    "sysmon":           "sysmon",
    "edr":              "edr_endpoint",
    "email":            "email_security",
    "proxy_firewall":   "network_traffic",
    "cloud":            "cloud_trail",
    "linux":            "linux_auditd",
}


# ── Main generation function ──────────────────────────────────────────────────

def generate_benign_events(
    event_count: int,
    asset_pool: dict[str, Any],
    duration_seconds: int = 28800,   # 8-hour work day
    context: Any = None,             # SimulationContext | None
) -> list[dict[str, Any]]:
    """Generate realistic baseline enterprise events for a time window.

    Events are distributed across all components proportionally and
    spread across the full duration with randomised offsets so they
    look like organic activity rather than a clock-driven batch.
    When a SimulationContext is provided, victim identity fields are fixed so
    benign and attack events reference the same user/host entities.

    Returns list of event dicts (same shape as attack events) sorted by timestamp.
    """
    if event_count <= 0:
        return []

    # Group templates by component
    by_component: dict[str, list[dict[str, Any]]] = {}
    for tmpl in BENIGN_TEMPLATES:
        comp = tmpl["component"]
        by_component.setdefault(comp, []).append(tmpl)

    # Build per-component event counts based on weights
    counts: dict[str, int] = {}
    remaining = event_count
    components = list(COMPONENT_WEIGHTS.keys())
    for i, comp in enumerate(components):
        if i == len(components) - 1:
            counts[comp] = remaining
        else:
            n = max(1, round(event_count * COMPONENT_WEIGHTS[comp]))
            counts[comp] = n
            remaining = max(0, remaining - n)

    events: list[dict[str, Any]] = []
    # Spread events across work hours with slight clustering in morning and afternoon
    start_offset = 0
    end_offset = duration_seconds

    # Resolve product selections from environment config
    products: dict[str, str] = asset_pool.get("products") or {}

    for comp, n in counts.items():
        log_source = COMPONENT_LOG_SOURCE.get(comp, comp)

        # Resolve SIEM schema — vendor-aware when products configured
        schema = resolve_schema_for_component(comp, products)

        # Try to get vendor-specific templates from schema_library first
        from backend.engine.product_catalog import COMPONENT_TO_CATEGORY
        category = COMPONENT_TO_CATEGORY.get(comp)
        vendor = products.get(category) if category else None
        vendor_templates = get_vendor_benign_templates(category, vendor) if category else []

        # Prefer vendor-specific templates; fall back to generic BENIGN_TEMPLATES
        if vendor_templates:
            templates = vendor_templates
        else:
            templates = by_component.get(comp, [])

        if not templates:
            continue

        for _ in range(n):
            tmpl = random.choice(templates)
            subs = _build_subs(asset_pool, context=context)

            title = _apply_subs(tmpl["title_template"], subs)
            payload = _apply_subs(tmpl.get("payload_template", {}), subs)

            # Vendor templates may override _sourcetype for multi-sourcetype products (e.g. AWS VPC)
            resolved_sourcetype = payload.pop("_sourcetype", schema.get("sourcetype", "WinEventLog:Security"))

            # Add SIEM schema fields to payload
            payload["_index"] = schema.get("index", "windows")
            payload["_sourcetype"] = resolved_sourcetype
            payload["_component"] = comp
            payload["_benign"] = True

            ts_offset = random.randint(start_offset, end_offset)
            ts = (datetime.utcnow() + timedelta(seconds=ts_offset - duration_seconds)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

            events.append({
                "source_type": log_source,
                "technique_id": "",
                "severity": tmpl.get("severity", "info"),
                "title": title,
                "timestamp": ts,
                "payload": payload,
                "_benign": True,
            })

    events.sort(key=lambda e: e.get("timestamp", ""))
    return events
