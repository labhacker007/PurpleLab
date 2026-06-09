"""ITDR Simulation Scenarios — Identity Threat Detection & Response.

10 pre-built attack scenarios covering the most common identity-based attack chains:
Kerberoasting, Pass-the-Hash, Golden Ticket, DCSync, MFA Fatigue, Impossible Travel,
Password Spray, Credential Stuffing, Token Theft, Privileged Account Creation.

Each scenario ships with:
  - MITRE ATT&CK technique mapping
  - Step-by-step simulation guide (links to PurpleLab atomics where available)
  - Expected log events per identity platform (Okta / Entra ID / AD / Duo)
  - Production-ready Sigma detection rule
  - Splunk SPL and Microsoft Sentinel KQL hunt queries

Routes (all under /v2/itdr):
  GET  /scenarios                         — list summary cards
  GET  /scenarios/{id}                    — full detail including Sigma + queries
  GET  /scenarios/{id}/sigma              — Sigma YAML only (download)
  GET  /scenarios/{id}/hunt-queries       — SPL + KQL only
  POST /scenarios/{id}/simulate           — dispatch to PurpleLab exercise engine
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from backend.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/itdr", tags=["itdr"])


# ── Scenario catalogue ────────────────────────────────────────────────────────

ITDR_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "kerberoasting",
        "name": "Kerberoasting",
        "technique_id": "T1558.003",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "description": (
            "Adversary requests Kerberos service tickets (TGS) for service accounts with SPNs "
            "and cracks them offline to recover plaintext credentials."
        ),
        "platforms": ["windows", "active_directory"],
        "prerequisites": ["Active Directory domain", "Standard user account"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "enumerate_spns",
                "command": "setspn -T domain -Q */* | findstr /i svc",
                "tool": "setspn",
                "description": "Enumerate all SPN-registered accounts",
            },
            {
                "step": 2,
                "action": "request_tgs",
                "command": "Invoke-Kerberoast -OutputFormat Hashcat | Export-Csv kerberoast.csv",
                "tool": "PowerSploit",
                "description": "Request TGS tickets for all SPN accounts",
                "purplelab_atomic": "T1558.003-1",
            },
            {
                "step": 3,
                "action": "crack_offline",
                "command": "hashcat -m 13100 kerberoast.csv wordlist.txt",
                "tool": "hashcat",
                "description": "Offline crack of RC4/AES Kerberos hashes (simulated — no actual cracking)",
                "simulated": True,
            },
        ],
        "expected_logs": [
            {"source": "Windows Security", "event_id": 4769, "description": "Kerberos service ticket was requested", "key_fields": ["ServiceName", "TicketEncryptionType=0x17"]},
            {"source": "Windows Security", "event_id": 4768, "description": "Kerberos authentication ticket requested"},
        ],
        "detection_sigma": """\
title: Kerberoasting — Multiple TGS Requests with RC4 Encryption
id: kerberoast-01
status: experimental
description: Detects multiple Kerberos service ticket requests using RC4 encryption (0x17) from a single source, which is a hallmark of Kerberoasting.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: "0x17"
    ServiceName|endswith: "$"
  filter:
    ServiceName: "krbtgt"
  condition: selection and not filter | count() by SubjectUserName > 5
falsepositives:
  - Legacy applications using RC4 — whitelist service accounts that legitimately use RC4
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
""",
        "hunt_query_spl": (
            "index=windows EventCode=4769 TicketEncryptionType=0x17 "
            "| stats count by SubjectUserName, ServiceName "
            "| where count > 5 "
            "| sort -count"
        ),
        "hunt_query_kql": (
            "SecurityEvent\n"
            "| where EventID == 4769 and TicketOptions startswith \"0x40810000\"\n"
            "| where TicketEncryptionType == \"0x17\"\n"
            "| summarize count=count() by Account, ServiceName\n"
            "| where count > 5\n"
            "| sort by count desc"
        ),
    },
    {
        "id": "pass_the_hash",
        "name": "Pass-the-Hash (PtH)",
        "technique_id": "T1550.002",
        "mitre_tactic": "Lateral Movement",
        "severity": "critical",
        "description": (
            "Adversary uses captured NTLM password hashes to authenticate to remote systems "
            "without needing the plaintext password."
        ),
        "platforms": ["windows"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "dump_hashes",
                "command": "sekurlsa::logonpasswords",
                "tool": "mimikatz",
                "description": "Dump LSASS for NTLM hashes",
                "purplelab_atomic": "T1003.001-1",
            },
            {
                "step": 2,
                "action": "lateral_movement",
                "command": "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:HASH /run:cmd.exe",
                "tool": "mimikatz",
                "description": "Spawn process using stolen hash for lateral movement",
                "purplelab_atomic": "T1550.002-1",
            },
        ],
        "expected_logs": [
            {"source": "Windows Security", "event_id": 4624, "description": "Successful logon — Type 3 (Network) with NtLmSsp", "key_fields": ["LogonType=3", "AuthenticationPackageName=NTLM"]},
            {"source": "Windows Security", "event_id": 4648, "description": "Explicit credential logon attempt"},
        ],
        "detection_sigma": """\
title: Pass-the-Hash — NTLM Network Logon with High-Privilege Account
id: pth-01
status: experimental
description: Detects NTLM network logons (Type 3) by administrative accounts, which may indicate Pass-the-Hash lateral movement.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    SubjectUserSid: "S-1-0-0"
  filter:
    TargetUserName|endswith: "$"
  condition: selection and not filter
falsepositives:
  - Legacy applications using NTLM — investigate per host
level: high
tags:
  - attack.lateral_movement
  - attack.t1550.002
""",
        "hunt_query_spl": (
            "index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM "
            "| where NOT match(Target_Account_Name, \"\\\\$\") "
            "| stats count by Target_Account_Name, Source_Network_Address, ComputerName "
            "| where count > 3 "
            "| sort -count"
        ),
        "hunt_query_kql": (
            "SecurityEvent\n"
            "| where EventID == 4624 and LogonType == 3\n"
            "| where AuthenticationPackageName == \"NTLM\"\n"
            "| where AccountName !endswith \"$\"\n"
            "| summarize count=count() by AccountName, IpAddress, Computer\n"
            "| where count > 3"
        ),
    },
    {
        "id": "golden_ticket",
        "name": "Golden Ticket",
        "technique_id": "T1558.001",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "description": (
            "Adversary forges a Kerberos TGT (Golden Ticket) using the KRBTGT hash, "
            "granting unlimited access to AD resources with arbitrary lifetimes."
        ),
        "platforms": ["windows", "active_directory"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "extract_krbtgt",
                "command": "lsadump::dcsync /domain:corp.local /user:krbtgt",
                "tool": "mimikatz",
                "description": "Extract KRBTGT hash via DCSync",
                "purplelab_atomic": "T1003.006-1",
            },
            {
                "step": 2,
                "action": "forge_tgt",
                "command": "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-X /krbtgt:HASH /ticket:golden.kirbi",
                "tool": "mimikatz",
                "description": "Forge golden ticket with 10-year validity",
                "purplelab_atomic": "T1558.001-1",
            },
            {
                "step": 3,
                "action": "inject_ticket",
                "command": "kerberos::ptt golden.kirbi",
                "tool": "mimikatz",
                "description": "Inject forged ticket into current session",
            },
        ],
        "expected_logs": [
            {"source": "Windows Security", "event_id": 4769, "description": "TGS request with unusual ticket lifetime (>20h default)", "key_fields": ["TicketLifetime>20h"]},
            {"source": "Windows Security", "event_id": 4672, "description": "Special privileges assigned to new logon"},
            {"source": "Windows Security", "event_id": 4624, "description": "Successful logon with forged ticket"},
        ],
        "detection_sigma": """\
title: Golden Ticket — Anomalous TGT Lifetime or Missing Pre-Auth
id: golden-ticket-01
status: experimental
description: Detects possible Golden Ticket use by looking for TGS requests without a corresponding TGT request in the same session, or tickets with unusual options from a non-DC.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketOptions: "0x40810000"
  filter_dc:
    IpAddress|startswith: "::ffff:10."
  condition: selection and not filter_dc
falsepositives:
  - Domain controllers authenticating on behalf of users
level: high
tags:
  - attack.credential_access
  - attack.t1558.001
""",
        "hunt_query_spl": (
            "index=windows EventCode=4769 "
            "| where TicketOptions==\"0x40810000\" "
            "| stats count by SubjectUserName, ServiceName, IpAddress "
            "| sort -count"
        ),
        "hunt_query_kql": (
            "SecurityEvent\n"
            "| where EventID == 4769\n"
            "| where TicketOptions == \"0x40810000\"\n"
            "| summarize count=count() by Account, ServiceName, IpAddress\n"
            "| sort by count desc"
        ),
    },
    {
        "id": "dcsync",
        "name": "DCSync",
        "technique_id": "T1003.006",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "description": (
            "Adversary abuses Active Directory replication protocols (MS-DRSR) to request "
            "password hashes for any AD account directly from a domain controller."
        ),
        "platforms": ["windows", "active_directory"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "dcsync_krbtgt",
                "command": "lsadump::dcsync /domain:corp.local /user:krbtgt",
                "tool": "mimikatz",
                "purplelab_atomic": "T1003.006-1",
                "description": "Replicate KRBTGT account hash from DC",
            },
            {
                "step": 2,
                "action": "dcsync_admin",
                "command": "lsadump::dcsync /domain:corp.local /user:Administrator",
                "tool": "mimikatz",
                "description": "Replicate Domain Admin hash from DC",
            },
        ],
        "expected_logs": [
            {"source": "Windows Security", "event_id": 4662, "description": "Object replication operation (GetNCChanges)", "key_fields": ["ObjectType=domainDNS", "AccessMask=0x100"]},
            {"source": "Windows Security", "event_id": 4624, "description": "Logon from non-DC IP using replication privilege"},
        ],
        "detection_sigma": """\
title: DCSync — Unauthorized Directory Replication
id: dcsync-01
status: experimental
description: Detects unauthorized DCSync by monitoring for directory replication events (EventID 4662) from non-DC hosts.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectType: "domainDNS"
    AccessMask: "0x100"
    Properties:
      - "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
      - "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
  filter_dc:
    SubjectUserName|endswith: "$"
  condition: selection and not filter_dc
falsepositives:
  - Azure AD Connect sync accounts (whitelist explicitly)
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006
""",
        "hunt_query_spl": (
            "index=windows EventCode=4662 "
            "| where Properties IN (\"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\", \"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2\") "
            "| where NOT match(SubjectUserName, \"\\\\$\") "
            "| stats count by SubjectUserName, SubjectLogonId, IpAddress"
        ),
        "hunt_query_kql": (
            "SecurityEvent\n"
            "| where EventID == 4662\n"
            "| where ObjectType == \"domainDNS\"\n"
            "| where Properties has \"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\"\n"
            "| where SubjectAccount !endswith \"$\"\n"
            "| summarize count=count() by SubjectAccount, IpAddress"
        ),
    },
    {
        "id": "mfa_fatigue",
        "name": "MFA Fatigue / Push Bombing",
        "technique_id": "T1621",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "description": (
            "Adversary repeatedly sends MFA push notifications to a valid user "
            "hoping they'll eventually accept out of frustration or confusion."
        ),
        "platforms": ["okta", "entra_id", "duo"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "obtain_credentials",
                "description": "Use previously obtained valid username:password (from phishing/spray)",
                "simulated": True,
            },
            {
                "step": 2,
                "action": "rapid_mfa_push",
                "command": "for i in $(seq 1 20); do auth_attempt --user target@corp.com --pass P@ssw0rd; sleep 2; done",
                "description": "Send 20 rapid MFA push notifications over 40 seconds",
                "purplelab_atomic": "T1621-1",
            },
        ],
        "expected_logs": [
            {"source": "Okta", "event_type": "user.mfa.okta_verify.deny_push", "description": "User denied MFA push"},
            {"source": "Okta", "event_type": "user.session.start", "description": "Eventual MFA acceptance after repeated denials"},
            {"source": "Entra ID", "event_type": "Sign-in", "description": "Multiple MFA challenges in short window"},
            {"source": "Duo", "event_type": "authentication", "result": "FRAUD", "description": "User reported push as fraud"},
        ],
        "detection_sigma": """\
title: MFA Fatigue — Repeated Push Denials Followed by Accept
id: mfa-fatigue-01
status: experimental
description: Detects MFA fatigue attacks by correlating repeated MFA push denials from the same user within 10 minutes followed by an acceptance.
logsource:
  category: authentication
  product: okta
detection:
  selection_deny:
    eventType: "user.mfa.okta_verify.deny_push"
  selection_accept:
    eventType: "user.authentication.sso"
  condition: selection_deny | count() by actor.alternateId > 3 within 10 minutes | then selection_accept
falsepositives:
  - Users accidentally denying pushes
level: high
tags:
  - attack.credential_access
  - attack.t1621
""",
        "hunt_query_spl": (
            "index=okta eventType=user.mfa.okta_verify.deny_push "
            "| bin _time span=10m "
            "| stats count by _time, actor.alternateId "
            "| where count >= 3 "
            "| join actor.alternateId "
            "[ search index=okta eventType=user.authentication.sso "
            "| rename actor.alternateId as actor.alternateId ]"
        ),
        "hunt_query_kql": (
            "SigninLogs\n"
            "| where ResultType in (\"50074\", \"50076\")\n"
            "| summarize DenyCount=countif(ResultType == \"50074\"), "
            "AcceptCount=countif(ResultType == \"0\") by UserPrincipalName, bin(TimeGenerated, 10m)\n"
            "| where DenyCount >= 3 and AcceptCount > 0"
        ),
    },
    {
        "id": "impossible_travel",
        "name": "Impossible Travel",
        "technique_id": "T1550.004",
        "mitre_tactic": "Defense Evasion",
        "severity": "high",
        "description": (
            "Account logs in from two geographically distant locations within a timeframe "
            "that is physically impossible to travel between."
        ),
        "platforms": ["okta", "entra_id", "any_sso"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "login_from_vpn_us",
                "description": "Authenticate via US-based IP (legitimate session)",
                "simulated": True,
            },
            {
                "step": 2,
                "action": "login_from_vpn_eu",
                "description": "Authenticate via EU-based IP within 30 minutes (impossible for legitimate user)",
                "simulated": True,
                "purplelab_atomic": "T1550.004-impossible-travel",
            },
        ],
        "expected_logs": [
            {"source": "Okta", "event_type": "user.session.start", "description": "Login from US IP followed by EU IP within 30min"},
            {"source": "Entra ID", "event_type": "Sign-in risk", "risk_level": "high", "description": "Impossible travel detected by Entra Identity Protection"},
        ],
        "detection_sigma": """\
title: Impossible Travel — Same Account Login from Two Countries in Short Window
id: impossible-travel-01
status: experimental
description: Detects authentication from two distinct geographic locations within a time window too short for physical travel.
logsource:
  category: authentication
detection:
  selection:
    authentication: success
  condition: |
    Same UserPrincipalName authenticated from CountryA and CountryB
    within 60 minutes where CountryA != CountryB
falsepositives:
  - VPN users — correlate with known VPN egress IPs
  - Split-tunnel setups
level: high
tags:
  - attack.defense_evasion
  - attack.t1550.004
""",
        "hunt_query_spl": (
            "index=okta eventType=user.session.start "
            "| iplocation client.ipAddress "
            "| stats values(Country) as countries values(client.ipAddress) as ips "
            "   earliest(_time) as first_seen latest(_time) as last_seen "
            "   by actor.alternateId "
            "| where mvcount(countries) > 1 "
            "| eval time_diff = last_seen - first_seen "
            "| where time_diff < 3600"
        ),
        "hunt_query_kql": (
            "SigninLogs\n"
            "| where ResultType == \"0\"\n"
            "| summarize Locations=make_set(Location), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 60m)\n"
            "| where array_length(Locations) > 1\n"
            "| mv-expand Locations"
        ),
    },
    {
        "id": "password_spray",
        "name": "Password Spray",
        "technique_id": "T1110.003",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "description": (
            "Adversary attempts a small set of commonly-used passwords against a large number "
            "of accounts to avoid account lockout thresholds."
        ),
        "platforms": ["active_directory", "okta", "entra_id", "o365"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "enumerate_users",
                "description": "Enumerate valid usernames via LDAP or public OWA/O365 endpoint",
                "purplelab_atomic": "T1087.002-1",
            },
            {
                "step": 2,
                "action": "spray_passwords",
                "command": "Invoke-MSOLSpray -UserList users.txt -Password 'Spring2024!'",
                "tool": "MSOLSpray",
                "description": "Try single password against all accounts with 10min delay between rounds",
                "purplelab_atomic": "T1110.003-1",
            },
        ],
        "expected_logs": [
            {"source": "Windows Security", "event_id": 4625, "description": "Failed logon — many different accounts same source"},
            {"source": "Entra ID", "event_type": "Sign-in", "error_code": "50053", "description": "Account locked out"},
            {"source": "Okta", "event_type": "user.session.start", "outcome": "FAILURE", "description": "Authentication failure at low volume per account"},
        ],
        "detection_sigma": """\
title: Password Spray — Low-Rate Failures Across Many Accounts
id: password-spray-01
status: experimental
description: Detects password spray by identifying a single source IP failing authentication against many unique accounts with very few attempts per account.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
  condition: selection | count(distinct TargetUserName) by IpAddress > 10 within 5 minutes
falsepositives:
  - Vulnerability scanners, authentication proxies
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
""",
        "hunt_query_spl": (
            "index=windows EventCode=4625 Logon_Type=3 "
            "| bin _time span=5m "
            "| stats dc(Target_Account_Name) as unique_accts count as attempts "
            "   by _time, Source_Network_Address "
            "| where unique_accts > 10 AND attempts / unique_accts < 3"
        ),
        "hunt_query_kql": (
            "SecurityEvent\n"
            "| where EventID == 4625 and LogonType == 3\n"
            "| summarize UniqueAccounts=dcount(TargetAccount), Attempts=count() by IpAddress, bin(TimeGenerated, 5m)\n"
            "| where UniqueAccounts > 10 and Attempts < UniqueAccounts * 3"
        ),
    },
    {
        "id": "credential_stuffing",
        "name": "Credential Stuffing",
        "technique_id": "T1110.004",
        "mitre_tactic": "Credential Access",
        "severity": "high",
        "description": (
            "Adversary uses username:password pairs from previous data breaches to attempt "
            "authentication — exploiting credential reuse across services."
        ),
        "platforms": ["okta", "entra_id", "web_applications"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "load_breach_list",
                "description": "Load breach credential list (e.g., from HIBP/DeHashed)",
                "simulated": True,
            },
            {
                "step": 2,
                "action": "automated_login_attempts",
                "command": "hydra -C breach_creds.txt -s 443 -f https://app.corp.com http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'",
                "tool": "hydra",
                "description": "Automated credential validation — low rate per IP with rotation",
                "purplelab_atomic": "T1110.004-1",
            },
        ],
        "expected_logs": [
            {"source": "WAF/CloudFront", "description": "High rate of 401/403 from rotating IPs on /login endpoint"},
            {"source": "Okta", "event_type": "user.authentication.auth_via_mfa", "description": "Successful auth from new ASN/country"},
            {"source": "Application", "description": "Multiple failed logins per account from different IPs"},
        ],
        "detection_sigma": """\
title: Credential Stuffing — Many Failures from Multiple IPs Same Accounts
id: cred-stuffing-01
status: experimental
description: Detects credential stuffing by identifying multiple IPs failing on the same accounts with high total failure volume.
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|endswith: "/login"
    sc-status: 401
  condition: selection | count() by cs-uri-stem > 100 within 5 minutes
falsepositives:
  - Load testing, legitimate retry loops
level: high
tags:
  - attack.credential_access
  - attack.t1110.004
""",
        "hunt_query_spl": (
            "index=web path=/login status=401 OR status=403 "
            "| bin _time span=5m "
            "| stats dc(src_ip) as unique_ips count as attempts by _time "
            "| where attempts > 100 AND unique_ips > 10"
        ),
        "hunt_query_kql": (
            "W3CIISLog\n"
            "| where csUriStem endswith \"/login\" and scStatus in (401, 403)\n"
            "| summarize Attempts=count(), UniqueIPs=dcount(cIp) by bin(TimeGenerated, 5m)\n"
            "| where Attempts > 100 and UniqueIPs > 10"
        ),
    },
    {
        "id": "token_theft",
        "name": "OAuth / SAML Token Theft",
        "technique_id": "T1528",
        "mitre_tactic": "Credential Access",
        "severity": "critical",
        "description": (
            "Adversary steals OAuth access tokens or SAML assertions to impersonate users "
            "without needing credentials — common in phishing-as-a-service attacks (AiTM)."
        ),
        "platforms": ["entra_id", "okta", "o365", "any_oauth"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "aitm_proxy",
                "description": "Stand up AiTM proxy (e.g., Evilginx2) between victim and legitimate IdP",
                "tool": "evilginx2",
                "simulated": True,
            },
            {
                "step": 2,
                "action": "capture_session_token",
                "description": "Capture session cookie/OAuth token after victim authenticates through proxy",
                "simulated": True,
                "purplelab_atomic": "T1528-1",
            },
            {
                "step": 3,
                "action": "replay_token",
                "command": "curl -H 'Authorization: Bearer STOLEN_TOKEN' https://graph.microsoft.com/v1.0/me",
                "description": "Replay stolen token from attacker-controlled IP to access resources",
            },
        ],
        "expected_logs": [
            {"source": "Entra ID", "event_type": "Sign-in", "description": "Token replay from new IP/ASN — no MFA challenge"},
            {"source": "Entra ID", "event_type": "Risky sign-in", "risk_level": "high", "description": "Token used from unknown location"},
            {"source": "Microsoft 365", "event_type": "FileAccessed", "description": "Mass file access/download shortly after token replay"},
        ],
        "detection_sigma": """\
title: OAuth Token Theft — Session Used from Different IP Than Issue IP
id: token-theft-01
status: experimental
description: Detects OAuth token replay by correlating the IP that obtained the token versus the IP using it — a sign of AiTM token theft.
logsource:
  category: authentication
  product: azure
detection:
  selection:
    TokenIssuerType: AzureAD
    RiskEventTypes: "tokenIssuerAnomaly"
  condition: selection
falsepositives:
  - VPN users, NAT traversal — correlate with risk score
level: critical
tags:
  - attack.credential_access
  - attack.t1528
""",
        "hunt_query_spl": (
            "index=entra sourcetype=SignInLogs "
            "| eval risk=mvindex('riskEventTypes', 0) "
            "| where risk=\"tokenIssuerAnomaly\" OR risk=\"unlikelyTravel\" "
            "| stats count by userPrincipalName, ipAddress, location, risk"
        ),
        "hunt_query_kql": (
            "SigninLogs\n"
            "| where RiskEventTypes has_any (\"tokenIssuerAnomaly\", \"unlikelyTravel\")\n"
            "| summarize count=count() by UserPrincipalName, IPAddress, Location, RiskLevelDuringSignIn"
        ),
    },
    {
        "id": "privileged_account_creation",
        "name": "Privileged Account Creation / Admin Backdoor",
        "technique_id": "T1136.001",
        "mitre_tactic": "Persistence",
        "severity": "critical",
        "description": (
            "Adversary creates a new privileged account or adds an existing account to "
            "admin groups to maintain persistent access even after password resets."
        ),
        "platforms": ["windows", "active_directory", "entra_id"],
        "simulation_steps": [
            {
                "step": 1,
                "action": "create_backdoor_account",
                "command": "net user backdoor P@ssw0rd123! /add /domain",
                "description": "Create hidden local or domain account",
                "purplelab_atomic": "T1136.001-1",
            },
            {
                "step": 2,
                "action": "add_to_admins",
                "command": "net group 'Domain Admins' backdoor /add /domain",
                "description": "Add account to Domain Admins group",
                "purplelab_atomic": "T1136.001-2",
            },
        ],
        "expected_logs": [
            {"source": "Windows Security", "event_id": 4720, "description": "User account created"},
            {"source": "Windows Security", "event_id": 4728, "description": "Member added to security-enabled global group (Domain Admins)"},
            {"source": "Windows Security", "event_id": 4732, "description": "Member added to security-enabled local group (Administrators)"},
        ],
        "detection_sigma": """\
title: Privileged Account Backdoor — Account Created and Immediately Added to Admin Group
id: priv-account-01
status: experimental
description: Detects the sequence of account creation immediately followed by addition to a privileged group, a common persistence technique.
logsource:
  product: windows
  service: security
detection:
  selection_create:
    EventID: 4720
  selection_add_admin:
    EventID:
      - 4728
      - 4732
    GroupName|contains:
      - "Domain Admins"
      - "Administrators"
      - "Enterprise Admins"
  condition: selection_create | near selection_add_admin within 300s by SubjectUserName
falsepositives:
  - Legitimate admin provisioning — verify with HR/IT processes
level: critical
tags:
  - attack.persistence
  - attack.t1136.001
""",
        "hunt_query_spl": (
            "index=windows (EventCode=4720 OR EventCode=4728 OR EventCode=4732) "
            "| transaction SubjectUserName startswith=EventCode=4720 maxspan=5m "
            "| where eventcount > 1 "
            "| where match(Group_Name, \"(?i)admin\")"
        ),
        "hunt_query_kql": (
            "SecurityEvent\n"
            "| where EventID in (4720, 4728, 4732)\n"
            "| summarize Events=make_list(EventID), Groups=make_list(GroupName) by SubjectAccount, bin(TimeGenerated, 5m)\n"
            "| where Events has 4720 and (Events has 4728 or Events has 4732)\n"
            "| where Groups has_any (\"Domain Admins\", \"Administrators\")"
        ),
    },
]

_SCENARIO_INDEX: dict[str, dict[str, Any]] = {s["id"]: s for s in ITDR_SCENARIOS}


def _get(scenario_id: str) -> Optional[dict[str, Any]]:
    return _SCENARIO_INDEX.get(scenario_id)


def _summary(s: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": s["id"],
        "name": s["name"],
        "technique_id": s["technique_id"],
        "mitre_tactic": s["mitre_tactic"],
        "severity": s["severity"],
        "platforms": s["platforms"],
        "step_count": len(s["simulation_steps"]),
    }


# ── Request schemas ───────────────────────────────────────────────────────────

class SimulateRequest(BaseModel):
    dry_run: bool = True
    environment_id: Optional[str] = None
    notes: Optional[str] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/scenarios")
async def list_itdr_scenarios() -> dict[str, Any]:
    """List all ITDR attack scenarios (summary cards)."""
    return {
        "scenarios": [_summary(s) for s in ITDR_SCENARIOS],
        "total": len(ITDR_SCENARIOS),
    }


@router.get("/scenarios/{scenario_id}")
async def get_itdr_scenario(scenario_id: str) -> dict[str, Any]:
    """Full scenario detail — steps, expected logs, Sigma rule, SPL, KQL."""
    s = _get(scenario_id)
    if not s:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return s


@router.get("/scenarios/{scenario_id}/sigma")
async def get_sigma(scenario_id: str) -> dict[str, Any]:
    """Download just the Sigma YAML for a scenario."""
    s = _get(scenario_id)
    if not s:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return {
        "scenario_id": scenario_id,
        "technique_id": s["technique_id"],
        "sigma_yaml": s.get("detection_sigma", ""),
    }


@router.get("/scenarios/{scenario_id}/hunt-queries")
async def get_hunt_queries(scenario_id: str) -> dict[str, Any]:
    """SPL (Splunk) and KQL (Sentinel) hunt queries for a scenario."""
    s = _get(scenario_id)
    if not s:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return {
        "scenario_id": scenario_id,
        "technique_id": s["technique_id"],
        "hunt_query_spl": s.get("hunt_query_spl", ""),
        "hunt_query_kql": s.get("hunt_query_kql", ""),
    }


@router.post("/scenarios/{scenario_id}/simulate")
async def simulate_scenario(
    scenario_id: str,
    body: SimulateRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """
    Dispatch an ITDR scenario to the PurpleLab exercise engine.

    dry_run=true (default) returns the steps and expected logs without firing.
    Set dry_run=false to create a real exercise session.
    """
    s = _get(scenario_id)
    if not s:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")

    if body.dry_run:
        return {
            "status": "dry_run",
            "scenario": s["name"],
            "technique_id": s["technique_id"],
            "steps": s["simulation_steps"],
            "expected_logs": s["expected_logs"],
            "message": "Dry run — no exercise created. Set dry_run=false to launch a real simulation.",
        }

    background_tasks.add_task(_dispatch_exercise, s, body.environment_id, body.notes)
    return {
        "status": "simulation_started",
        "scenario": s["name"],
        "technique_id": s["technique_id"],
        "message": "Exercise dispatched to the simulation engine. Check Sessions for results.",
    }


async def _dispatch_exercise(
    scenario: dict[str, Any],
    environment_id: Optional[str],
    notes: Optional[str],
) -> None:
    """Create a PurpleLab exercise session from an ITDR scenario template."""
    try:
        base_url = getattr(settings, "BASE_URL", "http://localhost:8002")
        payload = {
            "name": f"ITDR: {scenario['name']}",
            "technique_ids": [scenario["technique_id"]],
            "events": [
                {
                    "action": step.get("action"),
                    "description": step.get("description", ""),
                    "command": step.get("command", ""),
                    "tool": step.get("tool", ""),
                    "simulated": step.get("simulated", False),
                }
                for step in scenario["simulation_steps"]
            ],
            **({"environment_id": environment_id} if environment_id else {}),
            **({"description": notes} if notes else {}),
        }
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(f"{base_url}/v2/scenarios", json=payload)
            if r.status_code not in (200, 201):
                logger.warning("ITDR exercise create failed: %s %s", r.status_code, r.text[:200])
            else:
                logger.info("ITDR exercise created for %s", scenario["technique_id"])
    except Exception as exc:
        logger.error("ITDR dispatch error: %s", exc)
