"""Microsoft Defender for Endpoint — Alert API response format.

Real Defender for Endpoint exposes alerts via the Microsoft 365 Defender API.
Format: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/alerts
"""
import random
from backend.engine.generators.base import BaseGenerator


class DefenderEndpointGenerator(BaseGenerator):
    product_name = "Microsoft Defender for Endpoint"
    product_category = "edr"

    TITLES = [
        "Suspicious PowerShell command line",
        "Credential theft activity detected",
        "Suspicious process injection observed",
        "Ransomware activity detected",
        "Cobalt Strike beacon communication",
        "Suspicious LDAP query executed",
        "Potential lateral movement via SMB",
        "Suspicious file dropped in startup folder",
        "Encoded command execution detected",
        "Malicious file detected on device",
    ]

    CATEGORIES = [
        "SuspiciousActivity", "Malware", "Ransomware", "CredentialAccess",
        "LateralMovement", "DefenseEvasion", "Execution", "CommandAndControl",
        "InitialAccess", "Exfiltration",
    ]

    SEVERITY_MAP = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    DETERMINATION = ["NotAvailable", "Apt", "Malware", "SecurityPersonnel", "UnwantedSoftware", "Other"]
    STATUS = ["New", "New", "New", "InProgress", "Resolved"]

    DETECTION_SOURCES = [
        "WindowsDefenderAtp", "WindowsDefenderAv", "CustomDetection",
        "AutomatedInvestigation", "SmartScreen",
    ]

    FILE_NAMES = [
        "mimikatz.exe", "beacon.dll", "payload.ps1", "rev_shell.exe",
        "nc.exe", "procdump64.exe", "rubeus.exe", "lazagne.exe",
        "sharp_hound.exe", "psexec.exe",
    ]

    FILE_PATHS = [
        "C:\\Users\\{user}\\AppData\\Local\\Temp\\",
        "C:\\Windows\\Temp\\",
        "C:\\ProgramData\\",
        "C:\\Users\\{user}\\Downloads\\",
        "C:\\Users\\Public\\",
    ]

    def _make_evidence(self, user: str) -> list[dict]:
        items = []
        count = random.randint(1, 3)
        for _ in range(count):
            etype = random.choice(["file", "ip", "url", "process"])
            ev = {"entityType": etype, "evidenceCreationTime": self._now_iso()}
            if etype == "file":
                ev["fileName"] = random.choice(self.FILE_NAMES)
                ev["filePath"] = random.choice(self.FILE_PATHS).format(user=user)
                ev["sha256"] = "".join(random.choices("0123456789abcdef", k=64))
                ev["sha1"] = "".join(random.choices("0123456789abcdef", k=40))
            elif etype == "ip":
                ev["ipAddress"] = self._pick_ip()
            elif etype == "url":
                ev["url"] = random.choice([
                    f"https://{self._pick_domain()}/beacon",
                    f"http://{self._pick_ip()}:8080/stage",
                ])
            elif etype == "process":
                ev["fileName"] = random.choice(self.FILE_NAMES)
                ev["processId"] = random.randint(1000, 65000)
                ev["processCommandLine"] = f"cmd.exe /c {random.choice(self.FILE_NAMES)}"
            items.append(ev)
        return items

    def generate(self) -> dict:
        severity = self._pick_severity()
        technique_id, technique_name = self._pick_technique()
        host = self._pick_host()
        user = self._pick_user()
        alert_id = f"da{self._uuid().replace('-', '')[:24]}"
        machine_id = "".join(random.choices("0123456789abcdef", k=40))
        title = random.choice(self.TITLES)

        return {
            "alertId": alert_id,
            "incidentId": random.randint(10000, 99999),
            "serviceSource": "MicrosoftDefenderForEndpoint",
            "detectionSource": random.choice(self.DETECTION_SOURCES),
            "title": title,
            "description": f"{title} on {host}. User: {user}. Technique: {technique_id} ({technique_name}).",
            "severity": self.SEVERITY_MAP[severity],
            "category": random.choice(self.CATEGORIES),
            "status": random.choice(self.STATUS),
            "determination": random.choice(self.DETERMINATION),
            "assignedTo": None,
            "creationTime": self._now_iso(),
            "lastUpdateTime": self._now_iso(),
            "firstEventTime": self._now_iso(),
            "resolvedTime": None,
            "machineId": machine_id,
            "computerDnsName": f"{host.lower()}.corp.example.com",
            "relatedUser": {
                "userName": user,
                "domainName": "CORP",
            },
            "mitreTechniques": [technique_id],
            "evidence": self._make_evidence(user),
            "threatFamilyName": random.choice(["Cobalt", "Mimikatz", "Emotet", "TrickBot", "Ryuk", ""]),
            "recommendedAction": random.choice([
                "Isolate the device and investigate.",
                "Run full antivirus scan.",
                "Reset user credentials immediately.",
                "Review process tree and collect forensic evidence.",
            ]),
        }
