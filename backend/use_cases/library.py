"""Built-in use case library — seed data for purple team testing.

Each use case represents a specific attack scenario that should be detectable.
Covers the most common and high-value MITRE ATT&CK techniques across all 14 tactics.
100+ use cases covering the SOC detection landscape.
"""
from __future__ import annotations
from typing import Any

BUILTIN_USE_CASES: list[dict[str, Any]] = [
    # ════════════════════════════════════════════════════════════════════════════
    # RECONNAISSANCE (TA0043)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Active Directory LDAP Enumeration", "description": "Attacker queries AD via LDAP to enumerate users, groups, and organizational units.", "technique_ids": ["T1087.002"], "tactic": "reconnaissance", "expected_log_sources": ["active_directory", "windows_security"], "severity": "medium", "tags": ["ad", "enumeration", "ldap"]},
    {"name": "External Port Scanning", "description": "Reconnaissance scan of external-facing services from a single source IP.", "technique_ids": ["T1595.001"], "tactic": "reconnaissance", "expected_log_sources": ["firewall", "ids"], "severity": "low", "tags": ["scanning", "network"]},
    {"name": "DNS Zone Transfer Attempt", "description": "Attacker attempts AXFR zone transfer to enumerate all DNS records.", "technique_ids": ["T1590.002"], "tactic": "reconnaissance", "expected_log_sources": ["dns"], "severity": "medium", "tags": ["dns", "enumeration"]},

    # ════════════════════════════════════════════════════════════════════════════
    # RESOURCE DEVELOPMENT (TA0042)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Newly Registered Domain — Phishing Infrastructure", "description": "Detect domains registered within 30 days being used in email links.", "technique_ids": ["T1583.001"], "tactic": "resource-development", "expected_log_sources": ["proxy", "email_gateway", "dns"], "severity": "medium", "tags": ["phishing", "domain"]},
    {"name": "Compromised Legitimate Website (Watering Hole)", "description": "Detect connections to known compromised websites used as watering holes.", "technique_ids": ["T1584.004"], "tactic": "resource-development", "expected_log_sources": ["proxy", "dns"], "severity": "high", "tags": ["watering-hole", "web"]},

    # ════════════════════════════════════════════════════════════════════════════
    # INITIAL ACCESS (TA0001)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Spearphishing Link — Credential Harvest", "description": "Phishing email with link to credential harvesting page. User clicks and submits credentials.", "technique_ids": ["T1566.002"], "tactic": "initial-access", "expected_log_sources": ["email_gateway", "proxy", "dns"], "severity": "high", "tags": ["phishing", "credential-theft"]},
    {"name": "Spearphishing Attachment — Macro-Enabled Document", "description": "Malicious Office document with macro payload delivered via email.", "technique_ids": ["T1566.001"], "tactic": "initial-access", "expected_log_sources": ["email_gateway", "sysmon", "windows_security"], "severity": "high", "tags": ["phishing", "macro", "office"]},
    {"name": "Cloud Account Takeover — MFA Bypass (AiTM)", "description": "Adversary-in-the-middle phishing proxy bypasses MFA on cloud accounts.", "technique_ids": ["T1078.004", "T1557"], "tactic": "initial-access", "expected_log_sources": ["okta", "azure_ad"], "severity": "critical", "tags": ["cloud", "mfa-bypass", "aitm"]},
    {"name": "Drive-by Compromise — Browser Exploit", "description": "User visits compromised website that exploits browser vulnerability.", "technique_ids": ["T1189"], "tactic": "initial-access", "expected_log_sources": ["proxy", "sysmon", "ids"], "severity": "high", "tags": ["browser", "exploit", "web"]},
    {"name": "Valid Accounts — Brute Force Login", "description": "Multiple failed authentication attempts followed by successful login.", "technique_ids": ["T1078", "T1110.001"], "tactic": "initial-access", "expected_log_sources": ["azure_ad", "okta", "windows_security"], "severity": "high", "tags": ["brute-force", "authentication"]},
    {"name": "Trusted Relationship — Supply Chain Compromise", "description": "Attack via compromised third-party software update or vendor access.", "technique_ids": ["T1199", "T1195.002"], "tactic": "initial-access", "expected_log_sources": ["sysmon", "proxy", "firewall"], "severity": "critical", "tags": ["supply-chain", "third-party"]},
    {"name": "External Remote Services — VPN Compromise", "description": "Attacker authenticates to VPN using stolen credentials from impossible travel location.", "technique_ids": ["T1133"], "tactic": "initial-access", "expected_log_sources": ["vpn", "azure_ad"], "severity": "high", "tags": ["vpn", "remote-access"]},
    {"name": "Password Spray Attack", "description": "Single password tested against many accounts to avoid lockout thresholds.", "technique_ids": ["T1110.003"], "tactic": "initial-access", "expected_log_sources": ["azure_ad", "okta", "windows_security"], "severity": "high", "tags": ["password-spray", "authentication"]},
    {"name": "OAuth Token Abuse — Consent Phishing", "description": "Malicious app requests broad OAuth permissions via consent grant phishing.", "technique_ids": ["T1550.001"], "tactic": "initial-access", "expected_log_sources": ["azure_ad", "okta"], "severity": "high", "tags": ["oauth", "cloud", "consent-phishing"]},

    # ════════════════════════════════════════════════════════════════════════════
    # EXECUTION (TA0002)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "PowerShell Encoded Command Execution", "description": "Base64-encoded PowerShell command executed to evade command-line logging.", "technique_ids": ["T1059.001"], "tactic": "execution", "expected_log_sources": ["windows_powershell", "sysmon", "windows_security"], "severity": "high", "tags": ["powershell", "encoded"]},
    {"name": "WMI Remote Execution", "description": "Lateral movement via WMI to execute commands on remote hosts.", "technique_ids": ["T1047"], "tactic": "execution", "expected_log_sources": ["windows_security", "sysmon"], "severity": "high", "tags": ["wmi", "remote"]},
    {"name": "MSHTA Script Execution", "description": "Attacker uses mshta.exe to execute malicious HTA file from URL.", "technique_ids": ["T1218.005"], "tactic": "execution", "expected_log_sources": ["sysmon", "windows_security"], "severity": "high", "tags": ["mshta", "lolbin"]},
    {"name": "Macro-Enabled Office Document Execution", "description": "VBA macro in Office document spawns child process (cmd.exe, powershell.exe).", "technique_ids": ["T1204.002"], "tactic": "execution", "expected_log_sources": ["sysmon", "windows_security"], "severity": "high", "tags": ["macro", "office"]},
    {"name": "WMIC Process Create", "description": "WMIC used to spawn new processes for command execution.", "technique_ids": ["T1047"], "tactic": "execution", "expected_log_sources": ["sysmon", "windows_security"], "severity": "medium", "tags": ["wmic", "lolbin"]},
    {"name": "Certutil Download and Decode", "description": "Certutil.exe used to download and decode malicious payloads.", "technique_ids": ["T1140", "T1105"], "tactic": "execution", "expected_log_sources": ["sysmon", "proxy"], "severity": "high", "tags": ["certutil", "lolbin", "download"]},
    {"name": "Regsvr32 Squiblydoo Attack", "description": "Regsvr32 used to execute COM scriptlet (.sct) file from remote URL.", "technique_ids": ["T1218.010"], "tactic": "execution", "expected_log_sources": ["sysmon", "proxy"], "severity": "high", "tags": ["regsvr32", "lolbin"]},
    {"name": "BITSAdmin Download Execution", "description": "BITS service abused to download and execute payloads.", "technique_ids": ["T1197"], "tactic": "execution", "expected_log_sources": ["sysmon", "windows_security"], "severity": "medium", "tags": ["bitsadmin", "lolbin"]},
    {"name": "Linux Cron Job Execution", "description": "Malicious cron job installed for recurring command execution.", "technique_ids": ["T1053.003"], "tactic": "execution", "expected_log_sources": ["linux_audit", "syslog"], "severity": "medium", "tags": ["linux", "cron"]},
    {"name": "Python/Script Interpreter Execution", "description": "Python, Perl, or other interpreter used to execute malicious scripts.", "technique_ids": ["T1059.006"], "tactic": "execution", "expected_log_sources": ["sysmon", "linux_audit"], "severity": "medium", "tags": ["scripting", "python"]},

    # ════════════════════════════════════════════════════════════════════════════
    # PERSISTENCE (TA0003)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Registry Run Key Persistence", "description": "Malware adds itself to CurrentVersion\\Run for persistence.", "technique_ids": ["T1547.001"], "tactic": "persistence", "expected_log_sources": ["sysmon", "windows_security"], "severity": "medium", "tags": ["registry", "persistence"]},
    {"name": "Scheduled Task Creation", "description": "Scheduled task created for persistence across reboots.", "technique_ids": ["T1053.005"], "tactic": "persistence", "expected_log_sources": ["windows_security", "sysmon"], "severity": "medium", "tags": ["scheduled-task"]},
    {"name": "New Windows Service Installation", "description": "Malicious service installed for SYSTEM-level persistence.", "technique_ids": ["T1543.003"], "tactic": "persistence", "expected_log_sources": ["windows_security", "sysmon"], "severity": "high", "tags": ["service", "persistence"]},
    {"name": "WMI Event Subscription Persistence", "description": "WMI event consumer created for fileless persistence.", "technique_ids": ["T1546.003"], "tactic": "persistence", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["wmi", "fileless"]},
    {"name": "Startup Folder Persistence", "description": "Malicious executable or shortcut placed in user Startup folder.", "technique_ids": ["T1547.001"], "tactic": "persistence", "expected_log_sources": ["sysmon"], "severity": "medium", "tags": ["startup-folder"]},
    {"name": "DLL Search Order Hijacking", "description": "Malicious DLL placed in application directory to hijack load order.", "technique_ids": ["T1574.001"], "tactic": "persistence", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["dll-hijack"]},
    {"name": "SSH Authorized Keys Modification", "description": "Attacker adds SSH public key to authorized_keys for persistent access.", "technique_ids": ["T1098.004"], "tactic": "persistence", "expected_log_sources": ["linux_audit", "syslog"], "severity": "high", "tags": ["linux", "ssh"]},
    {"name": "Azure AD App Registration Backdoor", "description": "Malicious app registration created with broad API permissions.", "technique_ids": ["T1098.001"], "tactic": "persistence", "expected_log_sources": ["azure_ad"], "severity": "critical", "tags": ["cloud", "azure", "backdoor"]},
    {"name": "Golden Ticket — Kerberos TGT Forgery", "description": "Forged Kerberos TGT using compromised KRBTGT hash for persistent domain access.", "technique_ids": ["T1558.001"], "tactic": "persistence", "expected_log_sources": ["windows_security", "active_directory"], "severity": "critical", "tags": ["golden-ticket", "kerberos"]},

    # ════════════════════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION (TA0004)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Token Impersonation — SeDebugPrivilege", "description": "Process enables SeDebugPrivilege to access LSASS memory.", "technique_ids": ["T1134.001"], "tactic": "privilege-escalation", "expected_log_sources": ["windows_security", "sysmon"], "severity": "critical", "tags": ["token", "privilege"]},
    {"name": "UAC Bypass — Fodhelper", "description": "Attacker uses fodhelper.exe to bypass User Account Control.", "technique_ids": ["T1548.002"], "tactic": "privilege-escalation", "expected_log_sources": ["sysmon", "windows_security"], "severity": "high", "tags": ["uac-bypass"]},
    {"name": "Kubernetes Container Escape", "description": "Attacker escapes container sandbox to access host node.", "technique_ids": ["T1611"], "tactic": "privilege-escalation", "expected_log_sources": ["kubernetes"], "severity": "critical", "tags": ["kubernetes", "container-escape"]},
    {"name": "Sudo Abuse — Linux Privilege Escalation", "description": "Exploitation of misconfigured sudoers rules for root escalation.", "technique_ids": ["T1548.003"], "tactic": "privilege-escalation", "expected_log_sources": ["linux_audit", "syslog"], "severity": "high", "tags": ["linux", "sudo"]},
    {"name": "Named Pipe Impersonation", "description": "Service impersonation via named pipe for SYSTEM privilege escalation.", "technique_ids": ["T1134.002"], "tactic": "privilege-escalation", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["named-pipe", "impersonation"]},
    {"name": "Azure Managed Identity Abuse", "description": "Attacker exploits Azure VM managed identity to access cloud resources.", "technique_ids": ["T1078.004"], "tactic": "privilege-escalation", "expected_log_sources": ["azure_ad", "aws_cloudtrail"], "severity": "high", "tags": ["cloud", "identity"]},

    # ════════════════════════════════════════════════════════════════════════════
    # DEFENSE EVASION (TA0005)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Windows Event Log Clearing", "description": "Attacker clears Security and System event logs to cover tracks.", "technique_ids": ["T1070.001"], "tactic": "defense-evasion", "expected_log_sources": ["windows_security"], "severity": "critical", "tags": ["log-clearing"]},
    {"name": "Process Injection — DLL Injection", "description": "Malicious DLL injected into legitimate process to evade detection.", "technique_ids": ["T1055.001"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["injection", "dll"]},
    {"name": "Timestomping — File Time Manipulation", "description": "Attacker modifies file timestamps to blend with legitimate files.", "technique_ids": ["T1070.006"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "medium", "tags": ["timestomping"]},
    {"name": "Process Hollowing", "description": "Legitimate process memory replaced with malicious code.", "technique_ids": ["T1055.012"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["hollowing", "injection"]},
    {"name": "Masquerading — Renamed System Binary", "description": "Attacker renames malicious binary to match legitimate system process name.", "technique_ids": ["T1036.005"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "medium", "tags": ["masquerading"]},
    {"name": "Disable Windows Defender", "description": "Attacker disables Windows Defender real-time protection via registry or PowerShell.", "technique_ids": ["T1562.001"], "tactic": "defense-evasion", "expected_log_sources": ["windows_security", "sysmon"], "severity": "critical", "tags": ["antivirus-disable"]},
    {"name": "Reflective DLL Loading", "description": "DLL loaded directly from memory without touching disk.", "technique_ids": ["T1620"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["reflective", "fileless"]},
    {"name": "AMSI Bypass", "description": "Attacker patches AMSI in memory to evade PowerShell script scanning.", "technique_ids": ["T1562.001"], "tactic": "defense-evasion", "expected_log_sources": ["windows_powershell", "sysmon"], "severity": "high", "tags": ["amsi", "evasion"]},
    {"name": "Indicator Removal — File Deletion", "description": "Attacker deletes dropped tools and malware after execution.", "technique_ids": ["T1070.004"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "medium", "tags": ["cleanup", "file-deletion"]},
    {"name": "NTFS Alternate Data Stream Hiding", "description": "Malicious payload hidden in NTFS alternate data stream.", "technique_ids": ["T1564.004"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "medium", "tags": ["ads", "ntfs", "hiding"]},

    # ════════════════════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS (TA0006)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "LSASS Memory Dump — Mimikatz", "description": "Mimikatz sekurlsa::logonpasswords dumps credentials from LSASS memory.", "technique_ids": ["T1003.001"], "tactic": "credential-access", "expected_log_sources": ["windows_security", "sysmon", "crowdstrike"], "severity": "critical", "tags": ["mimikatz", "credential-dump"]},
    {"name": "Kerberoasting — SPN Ticket Request", "description": "Attacker requests Kerberos service tickets for offline password cracking.", "technique_ids": ["T1558.003"], "tactic": "credential-access", "expected_log_sources": ["windows_security", "active_directory"], "severity": "high", "tags": ["kerberos", "kerberoasting"]},
    {"name": "DCSync — Replication of AD Credentials", "description": "Attacker replicates domain controller data to extract password hashes.", "technique_ids": ["T1003.006"], "tactic": "credential-access", "expected_log_sources": ["windows_security", "active_directory"], "severity": "critical", "tags": ["dcsync", "ad"]},
    {"name": "SAM Database Extraction", "description": "SAM database copied using reg.exe save or Volume Shadow Copy.", "technique_ids": ["T1003.002"], "tactic": "credential-access", "expected_log_sources": ["windows_security", "sysmon"], "severity": "critical", "tags": ["sam", "credential-dump"]},
    {"name": "NTDS.dit Extraction", "description": "Active Directory NTDS.dit file extracted via ntdsutil or Volume Shadow Copy.", "technique_ids": ["T1003.003"], "tactic": "credential-access", "expected_log_sources": ["windows_security", "sysmon"], "severity": "critical", "tags": ["ntds", "ad"]},
    {"name": "Browser Credential Stealing", "description": "Attacker extracts saved passwords from Chrome, Firefox, or Edge browser stores.", "technique_ids": ["T1555.003"], "tactic": "credential-access", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["browser", "credential-theft"]},
    {"name": "Credential Stuffing Attack", "description": "Automated login attempts using leaked credential databases.", "technique_ids": ["T1110.004"], "tactic": "credential-access", "expected_log_sources": ["azure_ad", "okta", "proxy"], "severity": "high", "tags": ["credential-stuffing"]},
    {"name": "AS-REP Roasting", "description": "Request AS-REP for accounts without Kerberos pre-authentication for offline cracking.", "technique_ids": ["T1558.004"], "tactic": "credential-access", "expected_log_sources": ["windows_security", "active_directory"], "severity": "high", "tags": ["asrep", "kerberos"]},
    {"name": "AWS IAM Access Key Theft", "description": "Stolen AWS IAM access keys used from unauthorized IP or region.", "technique_ids": ["T1528"], "tactic": "credential-access", "expected_log_sources": ["aws_cloudtrail"], "severity": "critical", "tags": ["aws", "iam", "cloud"]},

    # ════════════════════════════════════════════════════════════════════════════
    # DISCOVERY (TA0007)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Network Share Discovery", "description": "Attacker enumerates network shares using net view or PowerShell.", "technique_ids": ["T1135"], "tactic": "discovery", "expected_log_sources": ["windows_security", "sysmon"], "severity": "medium", "tags": ["discovery", "network"]},
    {"name": "Domain Trust Discovery", "description": "nltest /domain_trusts or similar used to enumerate AD trust relationships.", "technique_ids": ["T1482"], "tactic": "discovery", "expected_log_sources": ["windows_security", "sysmon"], "severity": "medium", "tags": ["ad", "trust"]},
    {"name": "BloodHound/SharpHound AD Enumeration", "description": "SharpHound collector queries AD for attack path mapping.", "technique_ids": ["T1087.002", "T1069.002"], "tactic": "discovery", "expected_log_sources": ["windows_security", "active_directory"], "severity": "high", "tags": ["bloodhound", "ad"]},
    {"name": "Cloud Infrastructure Discovery", "description": "Attacker enumerates AWS/Azure resources after gaining cloud credentials.", "technique_ids": ["T1580"], "tactic": "discovery", "expected_log_sources": ["aws_cloudtrail", "azure_ad"], "severity": "medium", "tags": ["cloud", "enumeration"]},
    {"name": "Process Discovery — Tasklist/ps", "description": "Attacker lists running processes to identify security tools and targets.", "technique_ids": ["T1057"], "tactic": "discovery", "expected_log_sources": ["sysmon", "linux_audit"], "severity": "low", "tags": ["process", "enumeration"]},
    {"name": "System Information Discovery", "description": "systeminfo, uname, or similar used to fingerprint the target system.", "technique_ids": ["T1082"], "tactic": "discovery", "expected_log_sources": ["sysmon", "linux_audit"], "severity": "low", "tags": ["system-info"]},

    # ════════════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT (TA0008)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Pass-the-Hash — SMB Lateral Movement", "description": "Captured NTLM hash used to authenticate to remote systems via SMB.", "technique_ids": ["T1550.002"], "tactic": "lateral-movement", "expected_log_sources": ["windows_security", "sysmon"], "severity": "critical", "tags": ["pass-the-hash", "smb"]},
    {"name": "PsExec Remote Execution", "description": "PsExec or similar tool used for remote command execution via SMB.", "technique_ids": ["T1021.002", "T1569.002"], "tactic": "lateral-movement", "expected_log_sources": ["windows_security", "sysmon"], "severity": "high", "tags": ["psexec", "smb"]},
    {"name": "RDP Lateral Movement", "description": "Attacker moves laterally using Remote Desktop Protocol with stolen credentials.", "technique_ids": ["T1021.001"], "tactic": "lateral-movement", "expected_log_sources": ["windows_security"], "severity": "high", "tags": ["rdp", "lateral"]},
    {"name": "SSH Lateral Movement — Linux", "description": "Attacker uses compromised SSH keys to move between Linux hosts.", "technique_ids": ["T1021.004"], "tactic": "lateral-movement", "expected_log_sources": ["linux_audit", "syslog"], "severity": "high", "tags": ["ssh", "linux"]},
    {"name": "WinRM Remote Command Execution", "description": "Windows Remote Management used for remote PowerShell execution.", "technique_ids": ["T1021.006"], "tactic": "lateral-movement", "expected_log_sources": ["windows_security", "windows_powershell"], "severity": "high", "tags": ["winrm", "powershell"]},
    {"name": "Pass-the-Ticket — Kerberos Lateral Movement", "description": "Stolen or forged Kerberos ticket used to access remote services.", "technique_ids": ["T1550.003"], "tactic": "lateral-movement", "expected_log_sources": ["windows_security", "active_directory"], "severity": "critical", "tags": ["kerberos", "pass-the-ticket"]},
    {"name": "DCOM Lateral Movement", "description": "DCOM objects used for remote code execution on Windows targets.", "technique_ids": ["T1021.003"], "tactic": "lateral-movement", "expected_log_sources": ["windows_security", "sysmon"], "severity": "high", "tags": ["dcom", "lateral"]},

    # ════════════════════════════════════════════════════════════════════════════
    # COLLECTION (TA0009)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Cloud Storage Data Staging — S3 Enumeration", "description": "Attacker enumerates and exfiltrates data from S3 buckets.", "technique_ids": ["T1530"], "tactic": "collection", "expected_log_sources": ["aws_cloudtrail"], "severity": "high", "tags": ["cloud", "s3", "exfiltration"]},
    {"name": "Email Collection — Mailbox Export", "description": "Attacker exports Exchange/O365 mailbox contents using eDiscovery or PowerShell.", "technique_ids": ["T1114.002"], "tactic": "collection", "expected_log_sources": ["azure_ad", "office365"], "severity": "high", "tags": ["email", "exfiltration"]},
    {"name": "Screen Capture", "description": "Attacker captures screenshots to collect sensitive displayed information.", "technique_ids": ["T1113"], "tactic": "collection", "expected_log_sources": ["sysmon"], "severity": "medium", "tags": ["screen-capture"]},
    {"name": "Clipboard Data Collection", "description": "Malware monitors clipboard for passwords, crypto addresses, and sensitive data.", "technique_ids": ["T1115"], "tactic": "collection", "expected_log_sources": ["sysmon"], "severity": "medium", "tags": ["clipboard"]},
    {"name": "Keylogger Deployment", "description": "Keylogger installed to capture user keystrokes including credentials.", "technique_ids": ["T1056.001"], "tactic": "collection", "expected_log_sources": ["sysmon", "crowdstrike"], "severity": "high", "tags": ["keylogger"]},

    # ════════════════════════════════════════════════════════════════════════════
    # COMMAND AND CONTROL (TA0011)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "DNS Tunneling — C2 Communication", "description": "Malware uses DNS TXT/CNAME queries for covert C2 communication.", "technique_ids": ["T1071.004"], "tactic": "command-and-control", "expected_log_sources": ["dns", "firewall"], "severity": "high", "tags": ["dns", "c2", "tunneling"]},
    {"name": "HTTPS Beaconing — Cobalt Strike", "description": "Cobalt Strike beacon communicates via HTTPS with regular interval pattern.", "technique_ids": ["T1071.001", "T1573.002"], "tactic": "command-and-control", "expected_log_sources": ["proxy", "firewall", "ids"], "severity": "critical", "tags": ["cobalt-strike", "beacon", "c2"]},
    {"name": "Domain Fronting C2", "description": "C2 traffic routed through CDN/cloud provider to mask true destination.", "technique_ids": ["T1090.004"], "tactic": "command-and-control", "expected_log_sources": ["proxy", "firewall"], "severity": "high", "tags": ["domain-fronting", "c2"]},
    {"name": "Tor/I2P Anonymous Communication", "description": "Attacker uses Tor or I2P network for anonymous C2 communication.", "technique_ids": ["T1090.003"], "tactic": "command-and-control", "expected_log_sources": ["proxy", "firewall", "dns"], "severity": "high", "tags": ["tor", "anonymous"]},
    {"name": "Protocol Tunneling — SSH over HTTP", "description": "C2 traffic tunneled through SSH over HTTP/HTTPS to evade monitoring.", "technique_ids": ["T1572"], "tactic": "command-and-control", "expected_log_sources": ["proxy", "firewall"], "severity": "high", "tags": ["tunneling", "ssh"]},
    {"name": "Non-Standard Port C2", "description": "C2 traffic on uncommon port to evade port-based firewall rules.", "technique_ids": ["T1571"], "tactic": "command-and-control", "expected_log_sources": ["firewall", "ids"], "severity": "medium", "tags": ["non-standard-port"]},
    {"name": "Encrypted Channel — Custom Protocol", "description": "Custom encrypted protocol used for C2 to evade deep packet inspection.", "technique_ids": ["T1573.001"], "tactic": "command-and-control", "expected_log_sources": ["firewall", "ids"], "severity": "high", "tags": ["encrypted", "custom-protocol"]},
    {"name": "Slack/Teams/Discord C2", "description": "Legitimate collaboration platforms abused as C2 channels.", "technique_ids": ["T1102.002"], "tactic": "command-and-control", "expected_log_sources": ["proxy", "dns"], "severity": "high", "tags": ["slack", "teams", "c2"]},

    # ════════════════════════════════════════════════════════════════════════════
    # EXFILTRATION (TA0010)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Large Data Transfer — Outbound Anomaly", "description": "Unusually large outbound data transfer to external IP detected.", "technique_ids": ["T1048"], "tactic": "exfiltration", "expected_log_sources": ["firewall", "proxy"], "severity": "high", "tags": ["data-transfer", "anomaly"]},
    {"name": "Exfiltration to Cloud Storage", "description": "Data uploaded to personal cloud storage (Google Drive, Dropbox, OneDrive).", "technique_ids": ["T1567.002"], "tactic": "exfiltration", "expected_log_sources": ["proxy", "dlp"], "severity": "high", "tags": ["cloud-storage", "exfiltration"]},
    {"name": "DNS Exfiltration", "description": "Sensitive data encoded in DNS queries for covert exfiltration.", "technique_ids": ["T1048.003"], "tactic": "exfiltration", "expected_log_sources": ["dns"], "severity": "high", "tags": ["dns", "exfiltration"]},
    {"name": "Exfiltration via Email", "description": "Sensitive data sent as email attachments to external addresses.", "technique_ids": ["T1048.002"], "tactic": "exfiltration", "expected_log_sources": ["email_gateway", "dlp"], "severity": "medium", "tags": ["email", "exfiltration"]},
    {"name": "USB Data Exfiltration", "description": "Sensitive data copied to removable USB storage device.", "technique_ids": ["T1052.001"], "tactic": "exfiltration", "expected_log_sources": ["sysmon", "dlp"], "severity": "medium", "tags": ["usb", "physical"]},

    # ════════════════════════════════════════════════════════════════════════════
    # IMPACT (TA0040)
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Ransomware — File Encryption", "description": "Ransomware encrypts files and drops ransom note.", "technique_ids": ["T1486"], "tactic": "impact", "expected_log_sources": ["sysmon", "windows_security", "crowdstrike"], "severity": "critical", "tags": ["ransomware", "encryption"]},
    {"name": "Data Destruction — Wiper Malware", "description": "Wiper malware destroys data by overwriting disk sectors or deleting files.", "technique_ids": ["T1485"], "tactic": "impact", "expected_log_sources": ["sysmon", "crowdstrike"], "severity": "critical", "tags": ["wiper", "destruction"]},
    {"name": "Account Lockout — Denial of Service", "description": "Mass account lockout caused by intentional failed authentication attempts.", "technique_ids": ["T1531"], "tactic": "impact", "expected_log_sources": ["active_directory", "windows_security"], "severity": "high", "tags": ["lockout", "dos"]},
    {"name": "Resource Hijacking — Cryptomining", "description": "Unauthorized cryptocurrency mining consuming CPU/GPU resources.", "technique_ids": ["T1496"], "tactic": "impact", "expected_log_sources": ["sysmon", "linux_audit", "crowdstrike"], "severity": "medium", "tags": ["cryptomining"]},
    {"name": "Service Stop — Critical Infrastructure", "description": "Attacker stops critical services (SQL, web, backup) before ransomware deployment.", "technique_ids": ["T1489"], "tactic": "impact", "expected_log_sources": ["windows_security", "sysmon"], "severity": "critical", "tags": ["service-stop", "pre-ransomware"]},
    {"name": "Defacement — Web Application", "description": "Web application defaced with attacker's message or propaganda.", "technique_ids": ["T1491.002"], "tactic": "impact", "expected_log_sources": ["waf", "proxy"], "severity": "medium", "tags": ["defacement", "web"]},

    # ════════════════════════════════════════════════════════════════════════════
    # CLOUD-SPECIFIC DETECTIONS
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "AWS Root Account Usage", "description": "AWS root account used for API calls — should never happen in production.", "technique_ids": ["T1078.004"], "tactic": "privilege-escalation", "expected_log_sources": ["aws_cloudtrail"], "severity": "critical", "tags": ["aws", "root-account"]},
    {"name": "Azure Conditional Access Policy Modification", "description": "Conditional Access policy modified to weaken authentication requirements.", "technique_ids": ["T1556"], "tactic": "defense-evasion", "expected_log_sources": ["azure_ad"], "severity": "critical", "tags": ["azure", "conditional-access"]},
    {"name": "AWS S3 Bucket Made Public", "description": "S3 bucket ACL changed to allow public access.", "technique_ids": ["T1530"], "tactic": "collection", "expected_log_sources": ["aws_cloudtrail"], "severity": "critical", "tags": ["aws", "s3", "misconfiguration"]},
    {"name": "GCP Service Account Key Creation", "description": "New service account key created — potential for credential persistence.", "technique_ids": ["T1098"], "tactic": "persistence", "expected_log_sources": ["gcp_audit"], "severity": "high", "tags": ["gcp", "service-account"]},
    {"name": "AWS GuardDuty Finding — Unusual API Call", "description": "GuardDuty detects API calls from unusual geographic location.", "technique_ids": ["T1078.004"], "tactic": "initial-access", "expected_log_sources": ["aws_guardduty", "aws_cloudtrail"], "severity": "high", "tags": ["aws", "guardduty"]},
    {"name": "Azure Key Vault Secret Access Anomaly", "description": "Unusual access pattern to Azure Key Vault secrets detected.", "technique_ids": ["T1555"], "tactic": "credential-access", "expected_log_sources": ["azure_ad"], "severity": "high", "tags": ["azure", "keyvault"]},

    # ════════════════════════════════════════════════════════════════════════════
    # IDENTITY & ACCESS DETECTIONS
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Impossible Travel — Geolocation Anomaly", "description": "User authenticates from two geographically distant locations within short time.", "technique_ids": ["T1078"], "tactic": "initial-access", "expected_log_sources": ["azure_ad", "okta"], "severity": "high", "tags": ["impossible-travel", "identity"]},
    {"name": "Privileged Role Assignment", "description": "User granted Global Admin or equivalent privileged role.", "technique_ids": ["T1098"], "tactic": "privilege-escalation", "expected_log_sources": ["azure_ad", "okta"], "severity": "critical", "tags": ["role-assignment", "admin"]},
    {"name": "MFA Fatigue Attack (Push Bombing)", "description": "Repeated MFA push notifications to trick user into accepting.", "technique_ids": ["T1621"], "tactic": "credential-access", "expected_log_sources": ["okta", "azure_ad"], "severity": "high", "tags": ["mfa-fatigue", "push-bombing"]},
    {"name": "Okta Admin Console Access from Unusual IP", "description": "Admin console accessed from IP not in corporate range.", "technique_ids": ["T1078.004"], "tactic": "initial-access", "expected_log_sources": ["okta"], "severity": "critical", "tags": ["okta", "admin-access"]},
    {"name": "Bulk User Account Creation", "description": "Multiple user accounts created in short time period.", "technique_ids": ["T1136.003"], "tactic": "persistence", "expected_log_sources": ["azure_ad", "active_directory"], "severity": "high", "tags": ["account-creation", "bulk"]},
    {"name": "Service Account Interactive Login", "description": "Service account used for interactive (human) login — indicates credential theft.", "technique_ids": ["T1078.002"], "tactic": "initial-access", "expected_log_sources": ["windows_security", "azure_ad"], "severity": "high", "tags": ["service-account", "anomaly"]},

    # ════════════════════════════════════════════════════════════════════════════
    # ENDPOINT DETECTIONS
    # ════════════════════════════════════════════════════════════════════════════
    {"name": "Sysmon — Suspicious Parent-Child Process", "description": "Office application spawning cmd.exe, powershell.exe, or scripting host.", "technique_ids": ["T1204.002"], "tactic": "execution", "expected_log_sources": ["sysmon"], "severity": "high", "tags": ["process-tree", "office"]},
    {"name": "Sysmon — Driver Load from Temp Directory", "description": "Kernel driver loaded from temp or user-writable directory.", "technique_ids": ["T1014"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon"], "severity": "critical", "tags": ["driver", "rootkit"]},
    {"name": "Living-off-the-Land Binary Execution Chain", "description": "Chain of LOLBin executions indicating attack tooling.", "technique_ids": ["T1218"], "tactic": "defense-evasion", "expected_log_sources": ["sysmon", "windows_security"], "severity": "high", "tags": ["lolbin", "chain"]},
    {"name": "Security Tool Termination", "description": "EDR, AV, or SIEM agent process terminated abnormally.", "technique_ids": ["T1562.001"], "tactic": "defense-evasion", "expected_log_sources": ["crowdstrike", "sysmon"], "severity": "critical", "tags": ["edr-kill", "security-tool"]},
    {"name": "Suspicious Script Block Logging", "description": "PowerShell script block with obfuscated or encoded suspicious content.", "technique_ids": ["T1059.001", "T1027"], "tactic": "execution", "expected_log_sources": ["windows_powershell"], "severity": "high", "tags": ["powershell", "obfuscation"]},
]
