#!/usr/bin/env python3
"""Bulk-import 50 custom detection rules into PurpleLab via the v2 API."""
import json
import sys
import urllib.request
import urllib.error

BASE = "http://localhost:8002/api/v2"

RULES = [
    # ── Initial Access ──────────────────────────────────────────────────
    {
        "name": "Suspicious PowerShell Encoded Command Execution",
        "format": "sigma",
        "content": """title: Suspicious PowerShell Encoded Command Execution
id: a1b2c3d4-0001-4001-8001-000000000001
status: stable
description: Detects PowerShell execution with encoded command (-EncodedCommand or -enc) which is a common technique used by attackers to obfuscate malicious code
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - ' -EncodedCommand '
      - ' -enc '
      - ' -ec '
  filter:
    CommandLine|contains: 'MicrosoftEdge'
  condition: selection and not filter
falsepositives:
  - Legitimate administrative scripts
  - Software installers using encoded commands
level: high
""",
    },
    {
        "name": "Mimikatz LSASS Memory Access",
        "format": "sigma",
        "content": """title: Mimikatz LSASS Memory Access
id: a1b2c3d4-0002-4001-8001-000000000002
status: stable
description: Detects Mimikatz credential dumping via LSASS process memory access
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1410'
      - '0x1010'
      - '0x1438'
      - '0x143a'
      - '0x1418'
  filter_known_good:
    SourceImage|endswith:
      - '\\MsMpEng.exe'
      - '\\WerFault.exe'
      - '\\csrss.exe'
  condition: selection and not filter_known_good
falsepositives:
  - AV/EDR products scanning LSASS
level: critical
""",
    },
    {
        "name": "PsExec Remote Execution via SMB",
        "format": "sigma",
        "content": """title: PsExec Remote Execution via SMB
id: a1b2c3d4-0003-4001-8001-000000000003
status: stable
description: Detects PsExec lateral movement tool via service creation and named pipe usage
references:
  - https://attack.mitre.org/techniques/T1021/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.execution
  - attack.t1569.002
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
    ServiceName: 'PSEXESVC'
  condition: selection
falsepositives:
  - Legitimate use of PsExec by administrators
level: high
""",
    },
    {
        "name": "Suspicious Scheduled Task Creation",
        "format": "sigma",
        "content": """title: Suspicious Scheduled Task Creation
id: a1b2c3d4-0004-4001-8001-000000000004
status: stable
description: Detects suspicious scheduled task creation for persistence
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.persistence
  - attack.t1053.005
  - attack.privilege_escalation
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\schtasks.exe'
    CommandLine|contains|all:
      - '/create'
      - '/sc'
  filter_common:
    CommandLine|contains:
      - 'MicrosoftEdgeUpdate'
      - 'GoogleUpdate'
      - 'OneDrive'
  condition: selection and not filter_common
falsepositives:
  - Legitimate software scheduling tasks
level: medium
""",
    },
    {
        "name": "Windows Registry Run Key Persistence",
        "format": "sigma",
        "content": """title: Windows Registry Run Key Persistence
id: a1b2c3d4-0005-4001-8001-000000000005
status: stable
description: Detects modifications to common Registry Run keys used for persistence
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      - 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      - 'Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
  filter_legit:
    Details|contains:
      - 'MicrosoftEdge'
      - 'OneDrive.exe'
      - 'SecurityHealth.exe'
  condition: selection and not filter_legit
falsepositives:
  - Legitimate software adding run keys
level: medium
""",
    },
    {
        "name": "LOLBAS CertUtil Download",
        "format": "sigma",
        "content": """title: LOLBAS CertUtil Download
id: a1b2c3d4-0006-4001-8001-000000000006
status: stable
description: Detects CertUtil used to download files from the internet — common LOLBAS technique
references:
  - https://attack.mitre.org/techniques/T1105/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.command_and_control
  - attack.t1105
  - attack.defense_evasion
  - attack.t1218
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-verifyctl'
      - '-decode'
      - '-decodehex'
  condition: selection
falsepositives:
  - Legitimate certificate management
level: high
""",
    },
    {
        "name": "Suspicious WMIC Process Spawn",
        "format": "sigma",
        "content": """title: Suspicious WMIC Process Spawn
id: a1b2c3d4-0007-4001-8001-000000000007
status: stable
description: Detects WMIC spawning processes — used for execution and lateral movement
references:
  - https://attack.mitre.org/techniques/T1047/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.execution
  - attack.t1047
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\\WmiPrvSE.exe'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\mshta.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
  condition: selection
falsepositives:
  - Legitimate WMI management tasks
level: high
""",
    },
    {
        "name": "Pass-the-Hash Network Logon",
        "format": "sigma",
        "content": """title: Pass-the-Hash Network Logon
id: a1b2c3d4-0008-4001-8001-000000000008
status: stable
description: Detects pass-the-hash attacks via anomalous NTLM network logon patterns
references:
  - https://attack.mitre.org/techniques/T1550/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.lateral_movement
  - attack.t1550.002
  - attack.credential_access
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
    WorkstationName: ''
  condition: selection
falsepositives:
  - Some legitimate NTLM network logons
level: medium
""",
    },
    {
        "name": "Suspicious Base64 Encoded Payload in CommandLine",
        "format": "sigma",
        "content": """title: Suspicious Base64 Encoded Payload in CommandLine
id: a1b2c3d4-0009-4001-8001-000000000009
status: stable
description: Detects base64-encoded content in command-line arguments indicating obfuscation
references:
  - https://attack.mitre.org/techniques/T1027/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'JAB'
      - 'JABX'
      - 'TVqQ'
      - 'SQBFAFgA'
      - 'aQBlAHgA'
  condition: selection
falsepositives:
  - Legitimate base64 encoded scripts in some environments
level: high
""",
    },
    {
        "name": "WannaCry SMB Propagation",
        "format": "sigma",
        "content": """title: WannaCry SMB Propagation
id: a1b2c3d4-0010-4001-8001-000000000010
status: stable
description: Detects WannaCry ransomware lateral movement via SMB EternalBlue exploit
references:
  - https://attack.mitre.org/techniques/T1210/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.lateral_movement
  - attack.t1210
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '@WanaDecryptor@'
      - 'tasksche.exe'
      - 'wannacry'
  condition: selection
falsepositives:
  - None expected
level: critical
""",
    },
    # ── Lateral Movement ────────────────────────────────────────────────
    {
        "name": "RDP Brute Force Login Attempt",
        "format": "sigma",
        "content": """title: RDP Brute Force Login Attempt
id: a1b2c3d4-0011-4001-8001-000000000011
status: stable
description: Detects multiple failed RDP login attempts indicating brute-force attack
references:
  - https://attack.mitre.org/techniques/T1110/003/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1110.003
  - attack.initial_access
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 10
  timeframe: 5m
  condition: selection | count() > 10
falsepositives:
  - Users forgetting their password
level: medium
""",
    },
    {
        "name": "Lateral Movement via WMI Remote Execute",
        "format": "sigma",
        "content": """title: Lateral Movement via WMI Remote Execute
id: a1b2c3d4-0012-4001-8001-000000000012
status: stable
description: Detects remote WMI execution used for lateral movement
references:
  - https://attack.mitre.org/techniques/T1021/006/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.lateral_movement
  - attack.t1021.006
  - attack.execution
  - attack.t1047
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\WmiPrvSE.exe'
    CommandLine|contains:
      - 'cmd.exe /c'
      - 'powershell'
  condition: selection
falsepositives:
  - Legitimate remote WMI management
level: high
""",
    },
    {
        "name": "Suspicious Remote Service Creation",
        "format": "sigma",
        "content": """title: Suspicious Remote Service Creation
id: a1b2c3d4-0013-4001-8001-000000000013
status: stable
description: Detects remote service creation via sc.exe indicating potential lateral movement
references:
  - https://attack.mitre.org/techniques/T1569/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1569.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\sc.exe'
    CommandLine|contains|all:
      - ' create '
      - ' \\\\'
  condition: selection
falsepositives:
  - Legitimate service deployment scripts
level: high
""",
    },
    {
        "name": "Kerberoasting Attack — SPN Request",
        "format": "sigma",
        "content": """title: Kerberoasting Attack — SPN Request
id: a1b2c3d4-0014-4001-8001-000000000014
status: stable
description: Detects Kerberoasting by identifying anomalous TGS requests for service principal names
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    ServiceName|endswith: '$'
    TicketEncryptionType: '0x17'
  condition: selection
falsepositives:
  - Legitimate service ticket requests
level: high
""",
    },
    {
        "name": "DCSync Attack — Replication Privilege",
        "format": "sigma",
        "content": """title: DCSync Attack — Replication Privilege
id: a1b2c3d4-0015-4001-8001-000000000015
status: stable
description: Detects DCSync attacks by identifying directory replication privilege abuse
references:
  - https://attack.mitre.org/techniques/T1003/006/
author: SOC Lab Custom Rules
date: 2026/06/02
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
    AccessMask: '0x100'
  filter_dc:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_dc
falsepositives:
  - Domain replication from legitimate domain controllers
level: critical
""",
    },
    # ── Persistence ─────────────────────────────────────────────────────
    {
        "name": "Web Shell Upload via IIS",
        "format": "sigma",
        "content": """title: Web Shell Upload via IIS
id: a1b2c3d4-0016-4001-8001-000000000016
status: stable
description: Detects web shell execution spawned from IIS worker process
references:
  - https://attack.mitre.org/techniques/T1505/003/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.persistence
  - attack.t1505.003
  - attack.initial_access
  - attack.t1190
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\\w3wp.exe'
      - '\\httpd.exe'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\whoami.exe'
      - '\\net.exe'
  condition: selection
falsepositives:
  - Legitimate web application management scripts
level: critical
""",
    },
    {
        "name": "New Local Admin Account Created",
        "format": "sigma",
        "content": """title: New Local Admin Account Created
id: a1b2c3d4-0017-4001-8001-000000000017
status: stable
description: Detects creation of new local administrator accounts
references:
  - https://attack.mitre.org/techniques/T1136/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.persistence
  - attack.t1136.001
logsource:
  product: windows
  service: security
detection:
  selection_create:
    EventID: 4720
  selection_admin:
    EventID: 4732
    GroupName: 'Administrators'
  condition: selection_create or selection_admin
falsepositives:
  - Legitimate user provisioning
level: medium
""",
    },
    {
        "name": "DLL Hijacking via Missing DLL",
        "format": "sigma",
        "content": """title: DLL Hijacking via Missing DLL
id: a1b2c3d4-0018-4001-8001-000000000018
status: stable
description: Detects potential DLL hijacking by identifying DLL loading from unusual paths
references:
  - https://attack.mitre.org/techniques/T1574/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1574.001
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|contains:
      - '\\AppData\\Local\\'
      - '\\AppData\\Roaming\\'
      - '\\Temp\\'
      - '\\Users\\Public\\'
    ImageLoaded|endswith: '.dll'
  filter_known:
    ImageLoaded|contains:
      - '\\AppData\\Local\\Microsoft\\'
      - '\\AppData\\Roaming\\Microsoft\\'
  condition: selection and not filter_known
falsepositives:
  - Some legitimate user-space applications
level: medium
""",
    },
    {
        "name": "Office Macro Execution Spawning Process",
        "format": "sigma",
        "content": """title: Office Macro Execution Spawning Process
id: a1b2c3d4-0019-4001-8001-000000000019
status: stable
description: Detects malicious Office macro execution spawning shell processes
references:
  - https://attack.mitre.org/techniques/T1566/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.execution
  - attack.t1204.002
  - attack.initial_access
  - attack.t1566.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
      - '\\POWERPNT.EXE'
      - '\\OUTLOOK.EXE'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
      - '\\mshta.exe'
  condition: selection
falsepositives:
  - Legitimate Office macros used in business automation
level: high
""",
    },
    {
        "name": "Suspicious Startup Folder Modification",
        "format": "sigma",
        "content": """title: Suspicious Startup Folder Modification
id: a1b2c3d4-0020-4001-8001-000000000020
status: stable
description: Detects file creation in Windows startup folders for persistence
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|contains:
      - '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'
      - '\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'
    TargetFilename|endswith:
      - '.exe'
      - '.bat'
      - '.vbs'
      - '.ps1'
      - '.lnk'
  condition: selection
falsepositives:
  - Legitimate software adding startup entries
level: medium
""",
    },
    # ── Exfiltration / C2 ───────────────────────────────────────────────
    {
        "name": "DNS Tunneling — Long DNS Query",
        "format": "sigma",
        "content": """title: DNS Tunneling — Long DNS Query
id: a1b2c3d4-0021-4001-8001-000000000021
status: stable
description: Detects DNS tunneling via abnormally long DNS query names used for C2 or data exfiltration
references:
  - https://attack.mitre.org/techniques/T1071/004/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
  - attack.t1048.003
logsource:
  category: dns
detection:
  selection:
    query|re: '^.{60,}\.'
  condition: selection
falsepositives:
  - CDN-related long subdomains
level: medium
""",
    },
    {
        "name": "Exfiltration via HTTPS to New Domain",
        "format": "sigma",
        "content": """title: Exfiltration via HTTPS to New Domain
id: a1b2c3d4-0022-4001-8001-000000000022
status: stable
description: Detects large data uploads to recently registered or unknown domains over HTTPS
references:
  - https://attack.mitre.org/techniques/T1048/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.exfiltration
  - attack.t1048.002
logsource:
  product: zeek
  service: ssl
detection:
  selection:
    bytes_sent|gt: 10485760
    server_name|contains:
      - '.xyz'
      - '.top'
      - '.tk'
      - '.pw'
  condition: selection
falsepositives:
  - Legitimate cloud storage uploads
level: medium
""",
    },
    {
        "name": "C2 Beacon — Regular Outbound HTTP Intervals",
        "format": "sigma",
        "content": """title: C2 Beacon — Regular Outbound HTTP Intervals
id: a1b2c3d4-0023-4001-8001-000000000023
status: experimental
description: Detects C2 beaconing behaviour via periodic HTTP requests to same destination
references:
  - https://attack.mitre.org/techniques/T1071/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.command_and_control
  - attack.t1071.001
logsource:
  product: zeek
  service: http
detection:
  selection:
    method: 'GET'
    uri|contains: '/beacon'
    resp_mime_types|contains: 'application/octet-stream'
  condition: selection
falsepositives:
  - Legitimate software update checks
level: medium
""",
    },
    {
        "name": "Data Staging in Temp Directory",
        "format": "sigma",
        "content": """title: Data Staging in Temp Directory
id: a1b2c3d4-0024-4001-8001-000000000024
status: stable
description: Detects data collection and staging in temporary directories before exfiltration
references:
  - https://attack.mitre.org/techniques/T1074/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.collection
  - attack.t1074.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\7z.exe'
      - '\\WinRAR.exe'
      - '\\rar.exe'
      - '\\zip.exe'
    CommandLine|contains:
      - '\\Temp\\'
      - '\\AppData\\'
  condition: selection
falsepositives:
  - Legitimate archiving of temp files
level: medium
""",
    },
    {
        "name": "Rclone Exfiltration to Cloud Storage",
        "format": "sigma",
        "content": """title: Rclone Exfiltration to Cloud Storage
id: a1b2c3d4-0025-4001-8001-000000000025
status: stable
description: Detects rclone tool used by threat actors to exfiltrate data to cloud storage
references:
  - https://attack.mitre.org/techniques/T1567/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.exfiltration
  - attack.t1567.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\rclone.exe'
    CommandLine|contains:
      - 'copy'
      - 'sync'
      - 'move'
  condition: selection
falsepositives:
  - Legitimate cloud backup operations
level: high
""",
    },
    # ── Discovery ───────────────────────────────────────────────────────
    {
        "name": "Network Reconnaissance via Port Scanning",
        "format": "sigma",
        "content": """title: Network Reconnaissance via Port Scanning
id: a1b2c3d4-0026-4001-8001-000000000026
status: stable
description: Detects port scanning activity using common scanning tools
references:
  - https://attack.mitre.org/techniques/T1046/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.discovery
  - attack.t1046
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\nmap.exe'
      - '\\masscan.exe'
      - '\\zmap.exe'
      - '\\netscan.exe'
  condition: selection
falsepositives:
  - Authorized security scanning
level: medium
""",
    },
    {
        "name": "Active Directory Enumeration via LDAP",
        "format": "sigma",
        "content": """title: Active Directory Enumeration via LDAP
id: a1b2c3d4-0027-4001-8001-000000000027
status: stable
description: Detects AD enumeration tools like BloodHound, ADExplorer, SharpHound
references:
  - https://attack.mitre.org/techniques/T1087/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.discovery
  - attack.t1087.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\SharpHound.exe'
      - '\\BloodHound.exe'
      - '\\ADExplorer.exe'
    CommandLine|contains:
      - '--CollectionMethod'
      - 'All'
  condition: selection
falsepositives:
  - Authorized AD auditing
level: high
""",
    },
    {
        "name": "System Information Discovery via Systeminfo",
        "format": "sigma",
        "content": """title: System Information Discovery via Systeminfo
id: a1b2c3d4-0028-4001-8001-000000000028
status: stable
description: Detects system information gathering used in post-exploitation discovery phase
references:
  - https://attack.mitre.org/techniques/T1082/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.discovery
  - attack.t1082
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\systeminfo.exe'
      - '\\ipconfig.exe'
      - '\\net.exe'
      - '\\whoami.exe'
    ParentImage|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
  condition: selection
falsepositives:
  - Legitimate admin activity
level: low
""",
    },
    {
        "name": "Security Software Discovery",
        "format": "sigma",
        "content": """title: Security Software Discovery
id: a1b2c3d4-0029-4001-8001-000000000029
status: stable
description: Detects attempts to enumerate installed security software before disabling it
references:
  - https://attack.mitre.org/techniques/T1518/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.discovery
  - attack.t1518.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'wmic /namespace:\\\\root\\SecurityCenter2'
      - 'Get-MpComputerStatus'
      - 'Get-WmiObject -Namespace root/SecurityCenter'
  condition: selection
falsepositives:
  - Legitimate security auditing scripts
level: medium
""",
    },
    {
        "name": "AWS CloudTrail — Suspicious API Enumeration",
        "format": "sigma",
        "content": """title: AWS CloudTrail — Suspicious API Enumeration
id: a1b2c3d4-0030-4001-8001-000000000030
status: stable
description: Detects excessive AWS API calls indicating cloud environment enumeration
references:
  - https://attack.mitre.org/techniques/T1580/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.discovery
  - attack.t1580
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName|startswith:
      - 'Describe'
      - 'List'
      - 'Get'
    errorCode: 'AccessDenied'
  timeframe: 5m
  condition: selection | count() > 20
falsepositives:
  - New IAM role with missing permissions
level: medium
""",
    },
    # ── Privilege Escalation ────────────────────────────────────────────
    {
        "name": "UAC Bypass via FODHELPER",
        "format": "sigma",
        "content": """title: UAC Bypass via FODHELPER
id: a1b2c3d4-0031-4001-8001-000000000031
status: stable
description: Detects UAC bypass using fodhelper.exe registry manipulation technique
references:
  - https://attack.mitre.org/techniques/T1548/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: 'HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command'
  condition: selection
falsepositives:
  - None known
level: critical
""",
    },
    {
        "name": "Token Impersonation via SeImpersonatePrivilege",
        "format": "sigma",
        "content": """title: Token Impersonation via SeImpersonatePrivilege
id: a1b2c3d4-0032-4001-8001-000000000032
status: stable
description: Detects token impersonation attacks using potato exploits and similar tools
references:
  - https://attack.mitre.org/techniques/T1134/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.privilege_escalation
  - attack.t1134.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\JuicyPotato.exe'
      - '\\PrintSpoofer.exe'
      - '\\RogueWinRM.exe'
      - '\\SweetPotato.exe'
  condition: selection
falsepositives:
  - None expected in production
level: critical
""",
    },
    {
        "name": "Sudo Rights Escalation on Linux",
        "format": "sigma",
        "content": """title: Sudo Rights Escalation on Linux
id: a1b2c3d4-0033-4001-8001-000000000033
status: stable
description: Detects suspicious sudo usage patterns indicating privilege escalation
references:
  - https://attack.mitre.org/techniques/T1548/003/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.privilege_escalation
  - attack.t1548.003
logsource:
  product: linux
  service: auth
detection:
  selection:
    message|contains: 'sudo'
    message|contains|all:
      - 'command not allowed'
  condition: selection
falsepositives:
  - Users learning sudo permissions
level: medium
""",
    },
    # ── Defense Evasion ─────────────────────────────────────────────────
    {
        "name": "Windows Defender Disabled via Registry",
        "format": "sigma",
        "content": """title: Windows Defender Disabled via Registry
id: a1b2c3d4-0034-4001-8001-000000000034
status: stable
description: Detects disabling of Windows Defender via registry modification
references:
  - https://attack.mitre.org/techniques/T1562/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender'
    Details: 'DWORD (0x00000001)'
    TargetObject|endswith: 'DisableAntiSpyware'
  condition: selection
falsepositives:
  - Legitimate policy management
level: high
""",
    },
    {
        "name": "Event Log Clearing",
        "format": "sigma",
        "content": """title: Event Log Clearing
id: a1b2c3d4-0035-4001-8001-000000000035
status: stable
description: Detects clearing of Windows event logs to cover tracks
references:
  - https://attack.mitre.org/techniques/T1070/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.defense_evasion
  - attack.t1070.001
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 104
    Channel: System
  selection2:
    EventID: 1102
    Channel: Security
  condition: 1 of selection*
falsepositives:
  - Legitimate log rotation (rare)
level: high
""",
    },
    {
        "name": "Timestomping — File Metadata Manipulation",
        "format": "sigma",
        "content": """title: Timestomping — File Metadata Manipulation
id: a1b2c3d4-0036-4001-8001-000000000036
status: stable
description: Detects timestomping via PowerShell to alter file metadata for anti-forensics
references:
  - https://attack.mitre.org/techniques/T1070/006/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.defense_evasion
  - attack.t1070.006
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'LastWriteTime'
      - 'CreationTime'
  condition: selection
falsepositives:
  - Legitimate build scripts modifying timestamps
level: medium
""",
    },
    {
        "name": "Process Hollowing — Suspicious Memory Allocation",
        "format": "sigma",
        "content": """title: Process Hollowing — Suspicious Memory Allocation
id: a1b2c3d4-0037-4001-8001-000000000037
status: stable
description: Detects process hollowing via CreateRemoteThread and VirtualAllocEx API calls logged by EDR
references:
  - https://attack.mitre.org/techniques/T1055/012/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.defense_evasion
  - attack.t1055.012
  - attack.privilege_escalation
logsource:
  category: process_tampering
  product: windows
detection:
  selection:
    Type: 'Image is replaced'
  condition: selection
falsepositives:
  - Some AV/EDR self-protection mechanisms
level: critical
""",
    },
    {
        "name": "LOLBas Regsvr32 Script Proxy Execution",
        "format": "sigma",
        "content": """title: LOLBas Regsvr32 Script Proxy Execution
id: a1b2c3d4-0038-4001-8001-000000000038
status: stable
description: Detects regsvr32 scrobj execution to bypass application whitelisting
references:
  - https://attack.mitre.org/techniques/T1218/010/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.defense_evasion
  - attack.t1218.010
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\regsvr32.exe'
    CommandLine|contains:
      - '/u'
      - '/s'
      - '/n'
      - '/i:'
      - 'scrobj.dll'
  condition: selection
falsepositives:
  - Legitimate COM registration
level: high
""",
    },
    # ── Impact ──────────────────────────────────────────────────────────
    {
        "name": "Ransomware — Volume Shadow Copy Deletion",
        "format": "sigma",
        "content": """title: Ransomware — Volume Shadow Copy Deletion
id: a1b2c3d4-0039-4001-8001-000000000039
status: stable
description: Detects deletion of volume shadow copies — a hallmark of ransomware pre-encryption phase
references:
  - https://attack.mitre.org/techniques/T1490/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image|endswith: '\\vssadmin.exe'
    CommandLine|contains:
      - 'delete shadows'
  selection2:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains:
      - 'shadowcopy delete'
  selection3:
    CommandLine|contains:
      - 'Get-WmiObject Win32_ShadowCopy'
      - 'Delete()'
  condition: 1 of selection*
falsepositives:
  - Legitimate backup cleanup scripts (rare)
level: critical
""",
    },
    {
        "name": "Ransomware — Mass File Encryption Activity",
        "format": "sigma",
        "content": """title: Ransomware — Mass File Encryption Activity
id: a1b2c3d4-0040-4001-8001-000000000040
status: stable
description: Detects mass file renaming or encryption patterns indicative of ransomware
references:
  - https://attack.mitre.org/techniques/T1486/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.impact
  - attack.t1486
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.locked'
      - '.encrypted'
      - '.crypt'
      - '.locker'
      - '.encode'
      - '.wannacry'
      - '.wcry'
      - '.wncry'
  timeframe: 30s
  condition: selection | count() > 50
falsepositives:
  - Backup/encryption software
level: critical
""",
    },
    # ── Cloud / AWS specific ────────────────────────────────────────────
    {
        "name": "AWS S3 Bucket Policy Made Public",
        "format": "sigma",
        "content": """title: AWS S3 Bucket Policy Made Public
id: a1b2c3d4-0041-4001-8001-000000000041
status: stable
description: Detects S3 bucket policies being modified to allow public access
references:
  - https://attack.mitre.org/techniques/T1530/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.collection
  - attack.t1530
  - attack.exfiltration
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'PutBucketPolicy'
    requestParameters|contains: '"Effect":"Allow"'
    requestParameters|contains: '"Principal":"*"'
  condition: selection
falsepositives:
  - Intentional public website buckets
level: high
""",
    },
    {
        "name": "AWS IAM Privilege Escalation",
        "format": "sigma",
        "content": """title: AWS IAM Privilege Escalation
id: a1b2c3d4-0042-4001-8001-000000000042
status: stable
description: Detects IAM privilege escalation via CreateLoginProfile or AttachUserPolicy
references:
  - https://attack.mitre.org/techniques/T1078/004/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.privilege_escalation
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName|contains:
      - 'AttachUserPolicy'
      - 'AttachGroupPolicy'
      - 'AttachRolePolicy'
      - 'PutUserPolicy'
      - 'PutGroupPolicy'
      - 'CreateLoginProfile'
      - 'UpdateLoginProfile'
  condition: selection
falsepositives:
  - Legitimate IAM management by admins
level: high
""",
    },
    {
        "name": "AWS CloudTrail Logging Disabled",
        "format": "sigma",
        "content": """title: AWS CloudTrail Logging Disabled
id: a1b2c3d4-0043-4001-8001-000000000043
status: stable
description: Detects disabling of CloudTrail to evade detection
references:
  - https://attack.mitre.org/techniques/T1562/008/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.defense_evasion
  - attack.t1562.008
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName|contains:
      - 'StopLogging'
      - 'DeleteTrail'
      - 'UpdateTrail'
  condition: selection
falsepositives:
  - Legitimate trail management
level: critical
""",
    },
    {
        "name": "Azure — Suspicious Service Principal Creation",
        "format": "sigma",
        "content": """title: Azure — Suspicious Service Principal Creation
id: a1b2c3d4-0044-4001-8001-000000000044
status: stable
description: Detects creation of service principals that could be used for persistence
references:
  - https://attack.mitre.org/techniques/T1136/003/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.persistence
  - attack.t1136.003
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    operationName: 'Add service principal'
    result: 'success'
  condition: selection
falsepositives:
  - Legitimate application registrations
level: medium
""",
    },
    {
        "name": "Kubernetes — Privileged Pod Creation",
        "format": "sigma",
        "content": """title: Kubernetes — Privileged Pod Creation
id: a1b2c3d4-0045-4001-8001-000000000045
status: stable
description: Detects creation of privileged containers which can escape container isolation
references:
  - https://attack.mitre.org/techniques/T1611/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.privilege_escalation
  - attack.t1611
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: 'create'
    objectRef.resource: 'pods'
    requestObject.spec.containers|contains: 'privileged'
  condition: selection
falsepositives:
  - Legitimate privileged workloads
level: high
""",
    },
    # ── Credential Access ───────────────────────────────────────────────
    {
        "name": "NTDS.dit Database Access",
        "format": "sigma",
        "content": """title: NTDS.dit Database Access
id: a1b2c3d4-0046-4001-8001-000000000046
status: stable
description: Detects access to the NTDS.dit Active Directory database file for credential dumping
references:
  - https://attack.mitre.org/techniques/T1003/003/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1003.003
logsource:
  category: file_access
  product: windows
detection:
  selection:
    FileName|contains: 'ntds.dit'
  filter_dc:
    Image|endswith: 'ntdsutil.exe'
  condition: selection and not filter_dc
falsepositives:
  - Domain controller backup operations
level: critical
""",
    },
    {
        "name": "Password Spraying — Multiple Accounts Failure",
        "format": "sigma",
        "content": """title: Password Spraying — Multiple Accounts Failure
id: a1b2c3d4-0047-4001-8001-000000000047
status: stable
description: Detects password spraying by identifying one source IP failing against many accounts
references:
  - https://attack.mitre.org/techniques/T1110/003/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1110.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
  timeframe: 10m
  condition: selection | count(TargetUserName) by IpAddress > 20
falsepositives:
  - Misconfigured service accounts
level: high
""",
    },
    {
        "name": "SSH Brute Force — Linux",
        "format": "sigma",
        "content": """title: SSH Brute Force — Linux
id: a1b2c3d4-0048-4001-8001-000000000048
status: stable
description: Detects SSH brute force attacks via multiple failed authentication attempts
references:
  - https://attack.mitre.org/techniques/T1110/001/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: auth
detection:
  selection:
    message|contains: 'Failed password'
    message|contains: 'sshd'
  timeframe: 5m
  condition: selection | count() > 15
falsepositives:
  - Legitimate users mistyping passwords
level: medium
""",
    },
    {
        "name": "Credential Dumping via Registry Hive Export",
        "format": "sigma",
        "content": """title: Credential Dumping via Registry Hive Export
id: a1b2c3d4-0049-4001-8001-000000000049
status: stable
description: Detects dumping of SAM/SYSTEM/SECURITY registry hives for offline credential cracking
references:
  - https://attack.mitre.org/techniques/T1003/002/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1003.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\reg.exe'
    CommandLine|contains|all:
      - 'save'
    CommandLine|contains:
      - 'hklm\\sam'
      - 'hklm\\system'
      - 'hklm\\security'
  condition: selection
falsepositives:
  - Legitimate registry backup scripts
level: critical
""",
    },
    {
        "name": "Okta — MFA Bypass Attempt",
        "format": "sigma",
        "content": """title: Okta — MFA Bypass Attempt
id: a1b2c3d4-0050-4001-8001-000000000050
status: stable
description: Detects Okta MFA bypass or fatigue attack patterns
references:
  - https://attack.mitre.org/techniques/T1621/
author: SOC Lab Custom Rules
date: 2026/06/02
tags:
  - attack.credential_access
  - attack.t1621
logsource:
  product: okta
  service: system_log
detection:
  selection:
    eventType: 'user.authentication.auth_via_mfa'
    outcome.result: 'FAILURE'
  timeframe: 10m
  condition: selection | count() by actor.alternateId > 5
falsepositives:
  - Users having MFA app issues
level: high
""",
    },
]


def import_rules():
    payload = json.dumps({"rules": RULES}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}/rules/import/bulk",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            print(f"Imported: {result['imported']} rules")
            if result.get("failed"):
                print(f"Failed:   {len(result['failed'])} rules")
                for f in result["failed"]:
                    print(f"  [{f['index']}] {f['error']}")
            return result
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP {e.code}: {body}")
        sys.exit(1)


def get_stats():
    req = urllib.request.Request(f"{BASE}/rules/stats")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    print(f"Importing {len(RULES)} custom detection rules...")
    result = import_rules()
    print()
    stats = get_stats()
    print("Rule store stats:")
    print(f"  Total:           {stats['total']}")
    print(f"  Enabled:         {stats['enabled_count']}")
    print(f"  With MITRE tags: {stats['with_mitre_tags']}")
    print(f"  By severity:     {stats['by_severity']}")
    print(f"  By format:       {stats['by_format']}")
