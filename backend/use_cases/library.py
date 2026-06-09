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

    # ════════════════════════════════════════════════════════════════════════════
    # IDENTITY & ACCESS (TA0006 + TA0004 identity sub-techniques)
    # Full simulation metadata — steps, sigma, SPL, KQL
    # ════════════════════════════════════════════════════════════════════════════
    {
        "name": "Kerberoasting — Service Ticket Extraction",
        "description": "Attacker requests Kerberos service tickets for SPN-registered accounts, then cracks them offline to obtain plaintext passwords of service accounts.",
        "technique_ids": ["T1558.003"],
        "tactic": "credential-access",
        "expected_log_sources": ["windows_security", "active_directory"],
        "severity": "high",
        "tags": ["identity", "iam", "kerberos", "credential-access", "active-directory"],
        "sim_metadata": {
            "platforms": ["windows", "active_directory"],
            "prerequisites": ["Domain-joined Windows host", "Service accounts with weak passwords", "Active Directory environment"],
            "simulation_steps": [
                {"step": 1, "action": "Enumerate SPNs", "detail": "Run `Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName` to list all SPN accounts.", "identity_action": None},
                {"step": 2, "action": "Request service tickets", "detail": "Use Rubeus or Impacket GetUserSPNs.py to request AS_REP tickets for each SPN. Event ID 4769 (Kerberos Service Ticket Operations) fires for each request.", "identity_action": None},
                {"step": 3, "action": "Export ticket hashes", "detail": "Rubeus outputs RC4-HMAC hashes. Save to file for offline cracking.", "identity_action": None},
                {"step": 4, "action": "Offline password cracking", "detail": "Run hashcat with rockyou.txt: `hashcat -m 13100 hashes.txt wordlist.txt`", "identity_action": None},
                {"step": 5, "action": "Validate cracked credential", "detail": "Authenticate with recovered password. Use `lock_user` action against svc account to simulate containment.", "identity_action": "lock_user"},
            ],
            "expected_logs": [
                "Windows Security Event ID 4769 — Kerberos Service Ticket Operations (TicketEncryptionType=0x17 RC4-HMAC)",
                "Multiple 4769 events from same source IP in short time window",
                "Target accounts are service accounts (SPN registered)",
                "Logon Type 3 (network) from non-standard workstation",
            ],
            "detection_sigma": """title: Kerberoasting — Anomalous Service Ticket Requests
id: kerberoast-rc4-bulk
status: stable
description: Detects bulk Kerberos service ticket requests with RC4 encryption indicative of Kerberoasting
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|endswith:
      - '$'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  timeframe: 5m
  condition: selection and not filter_krbtgt | count(ServiceName) by SourceAddress > 5
falsepositives:
  - Legacy applications requiring RC4
level: high
""",
            "hunt_query_spl": "index=wineventlog EventCode=4769 TicketEncryptionType=0x17 NOT ServiceName=krbtgt | stats count by SourceAddress, ServiceName | where count > 3 | sort -count",
            "hunt_query_kql": "SecurityEvent | where EventID == 4769 and TicketEncryptionType == \"0x17\" and ServiceName != \"krbtgt\" | summarize RequestCount=count() by IpAddress, ServiceName | where RequestCount > 3 | order by RequestCount desc",
        },
    },
    {
        "name": "Pass-the-Hash — Lateral Movement via NTLM",
        "description": "Attacker uses a captured NTLM password hash to authenticate to remote systems without knowing the plaintext password.",
        "technique_ids": ["T1550.002"],
        "tactic": "lateral-movement",
        "expected_log_sources": ["windows_security", "active_directory"],
        "severity": "critical",
        "tags": ["identity", "iam", "ntlm", "lateral-movement", "windows"],
        "sim_metadata": {
            "platforms": ["windows"],
            "prerequisites": ["NTLM hash obtained (via Mimikatz/secretsdump)", "Target system with SMB/WMI open", "Local admin on target"],
            "simulation_steps": [
                {"step": 1, "action": "Dump NTLM hash", "detail": "Run `sekurlsa::logonpasswords` in Mimikatz or use secretsdump.py to extract NTLM hashes from memory.", "identity_action": None},
                {"step": 2, "action": "Craft PTH session", "detail": "Use `pth-winexe` or Impacket's wmiexec.py: `wmiexec.py -hashes :NTLMhash Administrator@target`", "identity_action": None},
                {"step": 3, "action": "Execute remote command", "detail": "Run `whoami /all` and `net group 'Domain Admins' /domain` on target to verify privilege level.", "identity_action": None},
                {"step": 4, "action": "Lateral movement to DC", "detail": "Chain PTH to reach Domain Controller. Triggers 4624 LogonType=3 with anomalous source workstation.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Lock the compromised account via identity_sim to stop PTH chain propagation.", "identity_action": "lock_user"},
            ],
            "expected_logs": [
                "Windows Security Event ID 4624 — Logon Type 3 (Network) with NTLM authentication",
                "Event ID 4625 followed by 4624 from same source (hash replay)",
                "No corresponding Kerberos ticket events from same session",
                "New logon from workstation that doesn't normally access target",
            ],
            "detection_sigma": """title: Pass-the-Hash — NTLM Network Logon Anomaly
id: pth-ntlm-network-logon
status: stable
description: Detects Pass-the-Hash indicators — NTLM Type 3 network logon from non-standard workstation
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.lateral_movement
  - attack.t1550.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    LogonProcessName: NtLmSsp
  filter_local:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_local
falsepositives:
  - Legacy applications using NTLM over network
  - Workgroup environments without Kerberos
level: high
""",
            "hunt_query_spl": "index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM NOT Account_Name=\"*$\" | stats count by Source_Network_Address, Account_Name | where count > 2 | sort -count",
            "hunt_query_kql": "SecurityEvent | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == \"NTLM\" and AccountName !endswith \"$\" | summarize count() by IpAddress, AccountName | where count_ > 2",
        },
    },
    {
        "name": "Golden Ticket Attack — Forged Kerberos TGT",
        "description": "Attacker forges a Kerberos TGT using the KRBTGT account hash, granting persistent domain admin access without touching AD directly.",
        "technique_ids": ["T1558.001"],
        "tactic": "privilege-escalation",
        "expected_log_sources": ["windows_security", "active_directory"],
        "severity": "critical",
        "tags": ["identity", "iam", "kerberos", "golden-ticket", "domain-persistence"],
        "sim_metadata": {
            "platforms": ["windows", "active_directory"],
            "prerequisites": ["KRBTGT account hash (from DCSync)", "Domain SID", "Mimikatz or Rubeus"],
            "simulation_steps": [
                {"step": 1, "action": "Obtain KRBTGT hash", "detail": "Run DCSync or extract from NTDS.dit: `lsadump::dcsync /user:krbtgt`", "identity_action": None},
                {"step": 2, "action": "Forge Golden Ticket", "detail": "Mimikatz: `kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt`", "identity_action": None},
                {"step": 3, "action": "Verify TGT injection", "detail": "Run `klist` to confirm ticket in memory. Access DC: `dir \\\\DC01\\C$`", "identity_action": None},
                {"step": 4, "action": "Persist with extended ticket", "detail": "Create ticket with 10-year lifetime to survive password resets. Event 4768 fires with anomalous ticket lifetime.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Force MFA re-enrollment and session revocation for all admin accounts.", "identity_action": "force_mfa"},
            ],
            "expected_logs": [
                "Event ID 4768 — TGT requested with unusually long ticket lifetime (>10h)",
                "Event ID 4769 — Service ticket from forged TGT has no corresponding 4768",
                "Event ID 4672 — Special privileges assigned without preceding 4624 domain logon",
                "Logon from non-existent user (golden ticket allows forging any username)",
            ],
            "detection_sigma": """title: Golden Ticket — Anomalous TGT Lifetime
id: golden-ticket-tgt-lifetime
status: experimental
description: Detects forged Golden Tickets via anomalous TGT lifetimes in Kerberos authentication events
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.privilege_escalation
  - attack.t1558.001
logsource:
  product: windows
  service: security
detection:
  selection_tgt:
    EventID: 4768
    Status: '0x0'
  selection_service:
    EventID: 4769
  timeframe: 1m
  condition: selection_service and not selection_tgt within 5m
falsepositives:
  - Service accounts with cached tickets
level: critical
""",
            "hunt_query_spl": "index=wineventlog EventCode=4768 | eval ticket_age=strptime(Ticket_Options, \"%Y-%m-%d\") | where Ticket_Options LIKE \"%forwardable%\" | stats count by Account_Name, Client_Address",
            "hunt_query_kql": "SecurityEvent | where EventID == 4769 | join kind=leftanti (SecurityEvent | where EventID == 4768) on AccountName, IpAddress | project TimeGenerated, AccountName, IpAddress, ServiceName",
        },
    },
    {
        "name": "DCSync Attack — Credential Replication from DC",
        "description": "Attacker abuses Directory Replication Service (DRS) protocol to dump all password hashes from the Domain Controller as if it were a replicating DC.",
        "technique_ids": ["T1003.006"],
        "tactic": "credential-access",
        "expected_log_sources": ["active_directory", "windows_security"],
        "severity": "critical",
        "tags": ["identity", "iam", "dcsync", "active-directory", "domain-admin"],
        "sim_metadata": {
            "platforms": ["windows", "active_directory"],
            "prerequisites": ["Domain Admin or Replication rights", "Network access to Domain Controller"],
            "simulation_steps": [
                {"step": 1, "action": "Check replication rights", "detail": "Verify account has `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` ACE on domain NC.", "identity_action": None},
                {"step": 2, "action": "Execute DCSync for admin hashes", "detail": "Mimikatz: `lsadump::dcsync /domain:corp.local /user:Administrator`. Fires Event ID 4662.", "identity_action": None},
                {"step": 3, "action": "Dump KRBTGT hash", "detail": "Mimikatz: `lsadump::dcsync /user:krbtgt` — enables Golden Ticket creation.", "identity_action": None},
                {"step": 4, "action": "Verify no LSASS access required", "detail": "Confirm no Event 4688 (process create) on DC — DCSync is purely network-based DRS replication.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Immediately revoke sessions for all domain admin accounts and force password resets.", "identity_action": "revoke_sessions"},
            ],
            "expected_logs": [
                "Event ID 4662 — An operation was performed on an object (replication GUIDs: 1131f6aa, 1131f6ad)",
                "Event ID 4624 — Logon from non-DC machine using domain admin account",
                "Unusual volume of 4662 events from a non-DC source",
                "Netlogon debug logs showing DRS bind from non-DC computer",
            ],
            "detection_sigma": """title: DCSync Attack — Suspicious Directory Replication
id: dcsync-replication-rights
status: stable
description: Detects DCSync by monitoring for suspicious directory replication operations from non-DC machines
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.credential_access
  - attack.t1003.006
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_dc:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_dc
falsepositives:
  - Legitimate AD replication between domain controllers
  - Azure AD Connect sync account
level: critical
""",
            "hunt_query_spl": "index=wineventlog EventCode=4662 Properties=\"*1131f6aa*\" OR Properties=\"*1131f6ad*\" | where NOT match(Subject_Account_Name, \"\\$\") | stats count by Subject_Account_Name, src_ip",
            "hunt_query_kql": "SecurityEvent | where EventID == 4662 and Properties has_any (\"1131f6aa\", \"1131f6ad\", \"89e95b76\") and SubjectUserName !endswith \"$\" | summarize count() by SubjectUserName, IpAddress, bin(TimeGenerated, 1h)",
        },
    },
    {
        "name": "MFA Fatigue Attack — Push Notification Bombing",
        "description": "Attacker floods a user's phone with MFA push notifications, exploiting approval fatigue until the user approves to stop the interruptions.",
        "technique_ids": ["T1621"],
        "tactic": "credential-access",
        "expected_log_sources": ["okta", "azure_ad", "entra_id"],
        "severity": "high",
        "tags": ["identity", "iam", "mfa-bypass", "okta", "entra-id", "cloud"],
        "sim_metadata": {
            "platforms": ["cloud", "saas"],
            "prerequisites": ["Valid username and password (from phishing/spray)", "Okta/Entra MFA policy using push notifications"],
            "simulation_steps": [
                {"step": 1, "action": "Obtain valid credentials", "detail": "Use captured credentials from phishing or password spray. Login attempt fails at MFA step.", "identity_action": None},
                {"step": 2, "action": "Initiate push flood", "detail": "Automate repeated MFA challenge attempts every 10-30 seconds. Okta logs `system.mfa.auth.soft_lock` after N attempts.", "identity_action": None},
                {"step": 3, "action": "Wait for user approval", "detail": "After 20-50 push notifications, fatigued user approves. Okta logs `user.authentication.sso` with `factor=push`.", "identity_action": None},
                {"step": 4, "action": "Establish persistent session", "detail": "Create long-lived session cookie. Register new trusted device to enable future MFA bypass.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Force MFA re-enrollment, revoke all active sessions, block push MFA, require number matching.", "identity_action": "force_mfa"},
            ],
            "expected_logs": [
                "Okta: Multiple `system.mfa.auth.challenge.generated` events within 5 minutes for same user",
                "Okta: `user.session.start` from IP with no prior history for this user",
                "Entra: Multiple MFA denials followed by approval within short window",
                "Source IP geolocation mismatch with user's registered device",
            ],
            "detection_sigma": """title: MFA Fatigue — Repeated Push Notification Denials
id: mfa-fatigue-push-bomb
status: stable
description: Detects MFA fatigue attack pattern — multiple rapid MFA challenges followed by success
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.credential_access
  - attack.t1621
logsource:
  product: okta
  service: system
detection:
  selection_fail:
    eventType: 'system.mfa.auth.soft_lock'
  selection_success:
    eventType: 'user.authentication.sso'
    authenticationContext.credentialType: 'push'
  timeframe: 10m
  condition: selection_fail | count() by actor.login > 3
falsepositives:
  - Users who accidentally tap deny multiple times
level: high
""",
            "hunt_query_spl": "index=okta eventType=system.mfa.auth* | bucket _time span=5m | stats count by actor.login, _time | where count > 5 | join actor.login [search index=okta eventType=user.authentication.sso authContext.credentialType=push]",
            "hunt_query_kql": "AADNonInteractiveUserSignInLogs | where ResultType != 0 and AuthenticationRequirement == \"multiFactorAuthentication\" | summarize FailCount=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m) | where FailCount > 5 | join kind=inner (AADSignInLogs | where ResultType == 0) on UserPrincipalName",
        },
    },
    {
        "name": "Impossible Travel — Geographic Anomaly Login",
        "description": "User account logs in from two geographically separated locations within a time window that makes physical travel impossible.",
        "technique_ids": ["T1078.004"],
        "tactic": "initial-access",
        "expected_log_sources": ["okta", "azure_ad", "vpn"],
        "severity": "high",
        "tags": ["identity", "iam", "impossible-travel", "cloud", "account-takeover", "ueba"],
        "sim_metadata": {
            "platforms": ["cloud", "saas"],
            "prerequisites": ["Compromised cloud account credentials", "VPN or proxy to create geographic anomaly"],
            "simulation_steps": [
                {"step": 1, "action": "Normal user login", "detail": "User authenticates from home IP (US-East). Establish baseline location from identity_sim user record.", "identity_action": None},
                {"step": 2, "action": "Attacker login from different continent", "detail": "Authenticate from IP resolving to Eastern Europe within 30 minutes of prior US login. Distance ~9000km, requires >9h travel.", "identity_action": None},
                {"step": 3, "action": "Access sensitive resources", "detail": "Access HR portal, SharePoint, or email from the impossible-travel session.", "identity_action": None},
                {"step": 4, "action": "Persist via new device registration", "detail": "Register a new trusted device to the account to maintain access after password reset.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Immediately lock account, revoke all sessions globally, force password reset and MFA re-enrollment.", "identity_action": "lock_user"},
            ],
            "expected_logs": [
                "Okta/Entra: Two successful logons from IPs 9000+ km apart within 60 minutes",
                "Login from country with no prior login history for this account",
                "Access to high-privilege resources from anomalous geographic location",
                "No VPN connected at time of anomalous login",
            ],
            "detection_sigma": """title: Impossible Travel — Anomalous Geographic Authentication
id: impossible-travel-auth
status: stable
description: Detects successful logins from geographically impossible source IP pairs within a short time window
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.initial_access
  - attack.t1078.004
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    ResultType: 0
    RiskLevelAggregated:
      - medium
      - high
    RiskDetail: 'impossibleTravel'
  condition: selection
falsepositives:
  - VPN users with exit nodes in different countries
  - Traveling employees
level: high
""",
            "hunt_query_spl": "index=okta eventType=user.session.start | iplocation client.ipAddress | eval login_country=Country | stats list(login_country) as countries, list(_time) as times by actor.login | where mvcount(countries) > 1 | eval time_diff=abs(mvindex(times,0)-mvindex(times,1))/3600",
            "hunt_query_kql": "SigninLogs | where ResultType == 0 | extend GeoInfo = parse_json(LocationDetails) | summarize Locations=make_set(GeoInfo.countryOrRegion), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by UserPrincipalName | where array_length(Locations) > 1 and datetime_diff('hour', LastSeen, FirstSeen) < 2",
        },
    },
    {
        "name": "Password Spray — Distributed Authentication Attack",
        "description": "Attacker tries a single common password (e.g., 'Welcome1') against hundreds of accounts to avoid lockout thresholds while still finding weak credentials.",
        "technique_ids": ["T1110.003"],
        "tactic": "credential-access",
        "expected_log_sources": ["okta", "azure_ad", "windows_security"],
        "severity": "high",
        "tags": ["identity", "iam", "password-spray", "credential-access"],
        "sim_metadata": {
            "platforms": ["windows", "cloud", "active_directory"],
            "prerequisites": ["Username list (harvested from LinkedIn/OSINT)", "Single candidate password", "Rate limiting not configured"],
            "simulation_steps": [
                {"step": 1, "action": "Harvest username list", "detail": "Collect usernames from LinkedIn, email format guessing, or Azure AD user enumeration via timing attack on login endpoint.", "identity_action": None},
                {"step": 2, "action": "Spray first password", "detail": "Submit `Welcome1` for all 200 usernames over 20 minutes (1 req/6s to avoid lockout). Generates mass 4625 events.", "identity_action": None},
                {"step": 3, "action": "Wait and spray again", "detail": "Wait 30 minutes. Spray `Company2024!`. Avoid same-account lockout by spreading attempts over time.", "identity_action": None},
                {"step": 4, "action": "Identify valid credentials", "detail": "Monitor for 4624 success after repeated 4625 failures from same source IP.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Disable compromised accounts, force password resets, enable lockout policy.", "identity_action": "disable_user"},
            ],
            "expected_logs": [
                "Event ID 4625 — Failed logons across many different accounts from same source IP",
                "Low failure count per account (1-2) but high total failure count from single source",
                "Spike in authentication failures across entire tenant at same timestamp",
                "Eventual 4624 success for one account from same source IP",
            ],
            "detection_sigma": """title: Password Spray — Distributed Authentication Failures
id: password-spray-many-accounts
status: stable
description: Detects password spray by identifying one source IP with failures across many distinct accounts
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.credential_access
  - attack.t1110.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 15m
  condition: selection | count(TargetUserName) by IpAddress > 20
falsepositives:
  - Network scanners
  - Load balancers with shared source IP
level: high
""",
            "hunt_query_spl": "index=wineventlog EventCode=4625 | bucket _time span=15m | stats dc(Account_Name) as unique_accounts, count as total_failures by Source_Network_Address, _time | where unique_accounts > 15 | sort -unique_accounts",
            "hunt_query_kql": "SecurityEvent | where EventID == 4625 | summarize UniqueAccounts=dcount(TargetUserName), TotalFailures=count() by IpAddress, bin(TimeGenerated, 15m) | where UniqueAccounts > 15 | order by UniqueAccounts desc",
        },
    },
    {
        "name": "OAuth Consent Phishing — Malicious App Authorization",
        "description": "Attacker tricks a user into granting OAuth permissions to a malicious third-party app, enabling persistent access to email, files, and contacts without knowing the user's password.",
        "technique_ids": ["T1550.001", "T1566.002"],
        "tactic": "initial-access",
        "expected_log_sources": ["azure_ad", "okta", "microsoft_365"],
        "severity": "high",
        "tags": ["identity", "iam", "oauth", "consent-phishing", "cloud", "m365"],
        "sim_metadata": {
            "platforms": ["cloud", "saas", "microsoft_365"],
            "prerequisites": ["Azure AD / Microsoft 365 tenant", "Registered malicious OAuth app", "User with email access"],
            "simulation_steps": [
                {"step": 1, "action": "Register malicious OAuth app", "detail": "Register an Azure AD app requesting `Mail.Read`, `Files.ReadWrite.All`, `offline_access` permissions.", "identity_action": None},
                {"step": 2, "action": "Send consent phishing email", "detail": "Send email with link: `https://login.microsoftonline.com/common/oauth2/authorize?client_id=<evil-app>&scope=Mail.Read+Files.ReadWrite.All`", "identity_action": None},
                {"step": 3, "action": "User grants consent", "detail": "User clicks link, authenticates, and grants permissions. Azure AD logs `Consent to application` operation.", "identity_action": None},
                {"step": 4, "action": "Access data with access token", "detail": "Attacker uses refresh token to access mailbox via Graph API: `GET /v1.0/me/messages`. No MFA required.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Revoke all OAuth tokens for the user, remove malicious app permission, force MFA.", "identity_action": "revoke_sessions"},
            ],
            "expected_logs": [
                "Azure AD Audit: `Consent to application` by user for app requesting high-privilege permissions",
                "Azure AD Sign-in: Service principal authentication with `client_credentials` flow",
                "M365 Audit: Mail access via Graph API from unusual application ID",
                "App registration created by external entity (non-admin)",
            ],
            "detection_sigma": """title: OAuth Consent Phishing — High-Privilege App Consent
id: oauth-consent-high-privilege
status: experimental
description: Detects users granting OAuth consent to apps requesting high-privilege delegated permissions
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.initial_access
  - attack.t1550.001
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    OperationName: 'Consent to application'
    TargetResources|contains:
      - 'Mail.Read'
      - 'Files.ReadWrite.All'
      - 'Mail.ReadWrite'
      - 'offline_access'
  condition: selection
falsepositives:
  - Legitimate enterprise app onboarding
  - Admin-approved enterprise applications
level: high
""",
            "hunt_query_spl": "index=azure_ad operationName=\"Consent to application\" | spath modifiedProperties{}.newValue | mvexpand modifiedProperties{}.newValue | search \"Mail.Read\" OR \"Files.ReadWrite\" | stats count by userPrincipalName, appDisplayName, ipAddress",
            "hunt_query_kql": "AuditLogs | where OperationName == 'Consent to application' | extend AppName=tostring(TargetResources[0].displayName), Scopes=tostring(AdditionalDetails) | where Scopes has_any ('Mail.Read', 'Files.ReadWrite.All', 'offline_access') | project TimeGenerated, InitiatedBy, AppName, Scopes",
        },
    },
    {
        "name": "Privileged Account Enumeration — AD Reconnaissance",
        "description": "Attacker enumerates Active Directory for Domain Admins, Tier 0 accounts, and privileged groups to identify high-value targets for credential theft.",
        "technique_ids": ["T1087.002"],
        "tactic": "discovery",
        "expected_log_sources": ["active_directory", "windows_security"],
        "severity": "medium",
        "tags": ["identity", "iam", "enumeration", "active-directory", "reconnaissance"],
        "sim_metadata": {
            "platforms": ["windows", "active_directory"],
            "prerequisites": ["Valid domain credentials", "Domain-joined or network-accessible host"],
            "simulation_steps": [
                {"step": 1, "action": "Enumerate Domain Admins", "detail": "Run `net group 'Domain Admins' /domain` and `Get-ADGroupMember -Identity 'Domain Admins'`. Generates LDAP query events.", "identity_action": None},
                {"step": 2, "action": "Enumerate Tier 0 accounts", "detail": "Query LDAP for adminCount=1 accounts: `Get-ADUser -LDAPFilter '(adminCount=1)' -Properties *`. Identifies accounts with ACL inheritance blocked.", "identity_action": None},
                {"step": 3, "action": "Map privileged group memberships", "detail": "Enumerate Schema Admins, Enterprise Admins, Backup Operators, Account Operators. Use BloodHound for full privilege graph.", "identity_action": None},
                {"step": 4, "action": "Identify service accounts with high privileges", "detail": "Query SPN accounts with Domain Admin membership — prime Kerberoasting targets.", "identity_action": None},
                {"step": 5, "action": "Simulate lock of enumerated account", "detail": "Lock one of the identified privileged accounts to test detection response time.", "identity_action": "lock_user"},
            ],
            "expected_logs": [
                "Event ID 4661 — A handle to an object was requested (AD privileged object access)",
                "LDAP queries for adminCount=1 or group membership from non-admin workstation",
                "Event ID 4799 — Security-enabled local group membership enumeration",
                "BloodHound/SharpHound markers: large volume of LDAP queries in short window",
            ],
            "detection_sigma": """title: AD Privileged Group Enumeration
id: ad-privileged-group-enum
status: stable
description: Detects bulk LDAP enumeration of privileged Active Directory groups from non-admin workstations
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.discovery
  - attack.t1087.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4799
    GroupName|contains:
      - 'Domain Admins'
      - 'Enterprise Admins'
      - 'Schema Admins'
      - 'Backup Operators'
      - 'Account Operators'
  condition: selection
falsepositives:
  - IT admin scripts running membership checks
  - PAM/IAM solutions
level: medium
""",
            "hunt_query_spl": "index=wineventlog EventCode=4799 | stats count by Account_Name, Group_Name, src | where count > 5 | sort -count",
            "hunt_query_kql": "SecurityEvent | where EventID == 4799 | summarize count() by Account_Name, GroupName, Computer | where count_ > 5 | order by count_ desc",
        },
    },
    {
        "name": "Account Takeover — Session Token Hijack",
        "description": "Attacker steals a valid web session cookie or OAuth access token to impersonate a user without credentials or MFA, bypassing all authentication controls.",
        "technique_ids": ["T1539", "T1185"],
        "tactic": "credential-access",
        "expected_log_sources": ["okta", "azure_ad", "proxy_logs"],
        "severity": "critical",
        "tags": ["identity", "iam", "session-hijack", "token-theft", "cloud", "ato"],
        "sim_metadata": {
            "platforms": ["cloud", "saas", "web"],
            "prerequisites": ["Active user session (cookie or OAuth token)", "Network position or browser compromise"],
            "simulation_steps": [
                {"step": 1, "action": "Extract session token", "detail": "Use browser developer tools or memory scraper to extract session cookie. Alternatively, AiTM proxy captures token at authentication.", "identity_action": None},
                {"step": 2, "action": "Replay token from new location", "detail": "Use stolen cookie in new browser/IP: `curl -b 'sessionid=<token>' https://app.company.com/api/profile`. Should succeed without MFA.", "identity_action": None},
                {"step": 3, "action": "Access sensitive data", "detail": "Export emails, download files, exfiltrate data using the hijacked session. No authentication events generated.", "identity_action": None},
                {"step": 4, "action": "Establish persistence", "detail": "Register new device, add recovery email, or create API token from hijacked session.", "identity_action": None},
                {"step": 5, "action": "Containment", "detail": "Revoke all active sessions globally and force re-authentication. Rotate all API tokens.", "identity_action": "revoke_sessions"},
            ],
            "expected_logs": [
                "Same session token used from two different IP addresses",
                "Session continues after impossible travel event without re-authentication",
                "User-agent string change mid-session (token replayed in different browser)",
                "Okta: `user.session.access.admin.app` from IP with no prior login history",
            ],
            "detection_sigma": """title: Session Token Hijack — Cross-IP Session Reuse
id: session-token-ip-change
status: experimental
description: Detects session token reuse from a different IP address than the session was created from
author: PurpleLab Identity Detection
date: 2026/06/09
tags:
  - attack.credential_access
  - attack.t1539
logsource:
  product: okta
  service: system
detection:
  selection:
    eventType: 'app.oauth2.token.grant.implicit'
  filter_same_ip:
    client.ipAddress: '{session_origin_ip}'
  condition: selection and not filter_same_ip
falsepositives:
  - Mobile users on cellular networks with changing IPs
  - Legitimate VPN reconnection events
level: critical
""",
            "hunt_query_spl": "index=okta | transaction actor.login maxspan=1h keepevicted=true | where eventCount > 1 | eval ip_list=mvdedup(client.ipAddress) | where mvcount(ip_list) > 1 | table actor.login, ip_list, _time",
            "hunt_query_kql": "SigninLogs | summarize IPAddresses=make_set(IPAddress), SessionCount=count() by UserPrincipalName, CorrelationId | where array_length(IPAddresses) > 1 | project UserPrincipalName, IPAddresses, SessionCount",
        },
    },
]
