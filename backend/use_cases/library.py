"""Built-in use case library — seed data for purple team testing.

Each use case represents a specific attack scenario that should be detectable.
Covers the most common and high-value MITRE ATT&CK techniques.
"""
from __future__ import annotations
from typing import Any

BUILTIN_USE_CASES: list[dict[str, Any]] = [
    # Initial Access
    {
        "name": "Spearphishing Link — Credential Harvest",
        "description": "Attacker sends phishing email with link to credential harvesting page. User clicks and submits credentials.",
        "technique_ids": ["T1566.002"],
        "tactic": "initial-access",
        "attack_chain_id": "",
        "expected_log_sources": ["email_gateway", "proxy", "dns"],
        "severity": "high",
        "tags": ["phishing", "initial-access", "credential-theft"],
    },
    # Execution
    {
        "name": "PowerShell Encoded Command Execution",
        "description": "Attacker executes base64-encoded PowerShell command to evade command-line logging.",
        "technique_ids": ["T1059.001"],
        "tactic": "execution",
        "attack_chain_id": "apt29_credential_harvest",
        "expected_log_sources": ["windows_powershell", "sysmon", "windows_security"],
        "severity": "high",
        "tags": ["powershell", "execution", "evasion", "windows"],
    },
    {
        "name": "WMI Remote Execution",
        "description": "Lateral movement via WMI to execute commands on remote hosts.",
        "technique_ids": ["T1047"],
        "tactic": "execution",
        "attack_chain_id": "",
        "expected_log_sources": ["windows_security", "sysmon", "wmi"],
        "severity": "high",
        "tags": ["wmi", "lateral-movement", "windows"],
    },
    # Persistence
    {
        "name": "Registry Run Key Persistence",
        "description": "Malware adds itself to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run for persistence.",
        "technique_ids": ["T1547.001"],
        "tactic": "persistence",
        "attack_chain_id": "",
        "expected_log_sources": ["sysmon", "windows_security"],
        "severity": "medium",
        "tags": ["registry", "persistence", "windows"],
    },
    {
        "name": "Scheduled Task Creation",
        "description": "Attacker creates a scheduled task to maintain persistence across reboots.",
        "technique_ids": ["T1053.005"],
        "tactic": "persistence",
        "attack_chain_id": "",
        "expected_log_sources": ["windows_security", "sysmon"],
        "severity": "medium",
        "tags": ["scheduled-task", "persistence", "windows"],
    },
    # Privilege Escalation
    {
        "name": "Token Impersonation — SeDebugPrivilege",
        "description": "Process enables SeDebugPrivilege to access LSASS memory for credential extraction.",
        "technique_ids": ["T1134.001"],
        "tactic": "privilege-escalation",
        "attack_chain_id": "apt29_credential_harvest",
        "expected_log_sources": ["windows_security", "sysmon"],
        "severity": "critical",
        "tags": ["privilege-escalation", "token", "windows"],
    },
    # Defense Evasion
    {
        "name": "Windows Event Log Clearing",
        "description": "Attacker clears Windows Security and System event logs to cover tracks.",
        "technique_ids": ["T1070.001"],
        "tactic": "defense-evasion",
        "attack_chain_id": "",
        "expected_log_sources": ["windows_security"],
        "severity": "critical",
        "tags": ["log-clearing", "defense-evasion", "windows"],
    },
    {
        "name": "Process Injection — DLL Injection",
        "description": "Malicious DLL injected into legitimate process (e.g., explorer.exe) to evade detection.",
        "technique_ids": ["T1055.001"],
        "tactic": "defense-evasion",
        "attack_chain_id": "",
        "expected_log_sources": ["sysmon"],
        "severity": "high",
        "tags": ["injection", "evasion", "windows"],
    },
    # Credential Access
    {
        "name": "LSASS Memory Dump — Mimikatz",
        "description": "Mimikatz sekurlsa::logonpasswords dumps credentials from LSASS memory.",
        "technique_ids": ["T1003.001"],
        "tactic": "credential-access",
        "attack_chain_id": "apt29_credential_harvest",
        "expected_log_sources": ["windows_security", "sysmon", "crowdstrike"],
        "severity": "critical",
        "tags": ["mimikatz", "credential-dump", "windows", "apt29"],
    },
    {
        "name": "Kerberoasting — SPN Ticket Request",
        "description": "Attacker requests Kerberos service tickets for offline password cracking.",
        "technique_ids": ["T1558.003"],
        "tactic": "credential-access",
        "attack_chain_id": "",
        "expected_log_sources": ["windows_security", "active_directory"],
        "severity": "high",
        "tags": ["kerberos", "credential-access", "active-directory"],
    },
    # Discovery
    {
        "name": "Network Share Discovery",
        "description": "Attacker enumerates network shares using net view or PowerShell.",
        "technique_ids": ["T1135"],
        "tactic": "discovery",
        "attack_chain_id": "",
        "expected_log_sources": ["windows_security", "sysmon"],
        "severity": "medium",
        "tags": ["discovery", "network", "windows"],
    },
    # Lateral Movement
    {
        "name": "Pass-the-Hash — SMB Lateral Movement",
        "description": "Attacker uses captured NTLM hash to authenticate to remote systems via SMB.",
        "technique_ids": ["T1550.002"],
        "tactic": "lateral-movement",
        "attack_chain_id": "",
        "expected_log_sources": ["windows_security", "sysmon"],
        "severity": "critical",
        "tags": ["pass-the-hash", "lateral-movement", "smb"],
    },
    # Collection
    {
        "name": "Cloud Storage Data Staging — S3 Enumeration",
        "description": "Attacker enumerates and exfiltrates data from S3 buckets using compromised credentials.",
        "technique_ids": ["T1530"],
        "tactic": "collection",
        "attack_chain_id": "cloud_account_takeover",
        "expected_log_sources": ["aws_cloudtrail"],
        "severity": "high",
        "tags": ["cloud", "aws", "s3", "exfiltration"],
    },
    # Command and Control
    {
        "name": "DNS Tunneling — C2 Communication",
        "description": "Malware uses DNS TXT/CNAME queries for covert C2 communication.",
        "technique_ids": ["T1071.004"],
        "tactic": "command-and-control",
        "attack_chain_id": "",
        "expected_log_sources": ["dns", "firewall"],
        "severity": "high",
        "tags": ["dns", "c2", "tunneling"],
    },
    # Impact
    {
        "name": "Ransomware — File Encryption",
        "description": "Ransomware encrypts files and drops ransom note. Rapid file modification events detected.",
        "technique_ids": ["T1486"],
        "tactic": "impact",
        "attack_chain_id": "ransomware_precursor",
        "expected_log_sources": ["sysmon", "windows_security", "crowdstrike"],
        "severity": "critical",
        "tags": ["ransomware", "impact", "encryption"],
    },
    # Cloud
    {
        "name": "Cloud Account Takeover — MFA Bypass",
        "description": "Attacker bypasses MFA on cloud account using adversary-in-the-middle phishing proxy.",
        "technique_ids": ["T1078.004", "T1557"],
        "tactic": "initial-access",
        "attack_chain_id": "cloud_account_takeover",
        "expected_log_sources": ["okta", "azure_ad"],
        "severity": "critical",
        "tags": ["cloud", "mfa-bypass", "account-takeover", "okta"],
    },
    # Container Escape
    {
        "name": "Kubernetes Container Escape",
        "description": "Attacker escapes container sandbox to access host node using privileged container.",
        "technique_ids": ["T1611"],
        "tactic": "privilege-escalation",
        "attack_chain_id": "k8s_container_escape",
        "expected_log_sources": ["kubernetes"],
        "severity": "critical",
        "tags": ["kubernetes", "container-escape", "cloud"],
    },
]
