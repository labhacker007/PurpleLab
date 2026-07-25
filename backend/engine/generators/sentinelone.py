"""SentinelOne Singularity — Threat Notification webhook payload format.

Real SentinelOne sends POST requests to registered webhook URLs when threats
are detected. Configured via: Management Console → Settings → Notifications
→ Create Notification → Webhook.

Official format reference:
https://usea1-partners.sentinelone.net/docs/en/api-reference.html#tag/Threats
https://usea1-partners.sentinelone.net/docs/en/webhook-notifications.html
"""
import random
import string
from backend.engine.generators.base import BaseGenerator


class SentinelOneGenerator(BaseGenerator):
    product_name = "SentinelOne Singularity"
    product_category = "edr"

    THREAT_NAMES = [
        "TrojanDropper.GenericKD",
        "Ransomware.ShadowCrypt",
        "Backdoor.CobaltStrike",
        "Trojan.Mimikatz",
        "Exploit.CVE-2023-38831",
        "Worm.LateralMover",
        "PUA.SystemTool",
        "Trojan.PSExec",
        "Ransomware.BlackCat",
        "Backdoor.QuasarRAT",
    ]

    INDICATOR_NAMES = [
        "ProcessInjection.RemoteThread",
        "CredentialAccess.LsassDump",
        "Persistence.ScheduledTask",
        "Execution.PowerShellEncoded",
        "LateralMovement.PsExec",
        "DefenseEvasion.LOLBinAbuse",
        "Discovery.NetworkScan",
        "Exfiltration.DnsBeaconing",
        "Impact.RansomwareEncryption",
        "CommandAndControl.C2Beaconing",
    ]

    INDICATOR_CATEGORIES = [
        "Lateral Movement", "Credential Access", "Persistence",
        "Execution", "Defense Evasion", "Discovery",
        "Exfiltration", "Command and Control", "Impact",
    ]

    CLASSIFICATION_SOURCES = ["Static", "Engine", "Cloud", "User"]

    MACHINE_TYPES = ["desktop", "laptop", "server", "k8s_node", "virtual_machine"]

    AGENT_VERSIONS = ["23.1.2.9", "23.3.1.294", "23.4.0.354", "24.1.0.100"]

    MITIGATION_STATUSES = [
        ("active", "Virus Quarantine"),
        ("mitigated", "Threat Quarantined"),
        ("blocked", "Threat Blocked"),
        ("suspicious", "Suspicious Activity Detected"),
        ("not_mitigated", "Manual Remediation Required"),
    ]

    ENGINES = [
        ["reputation"],
        ["reputation", "static"],
        ["pre_execution_suspicious"],
        ["behavioral"],
        ["reputation", "pre_execution_suspicious", "behavioral"],
        ["static", "behavioral"],
    ]

    FILE_PATHS = [
        "C:\\Users\\{user}\\AppData\\Roaming\\{filename}",
        "C:\\Windows\\Temp\\{filename}",
        "C:\\ProgramData\\{filename}",
        "C:\\Users\\{user}\\Downloads\\{filename}",
        "C:\\Windows\\System32\\{filename}",
        "C:\\Users\\{user}\\AppData\\Local\\Temp\\{filename}",
    ]

    FILENAMES = [
        "svchost32.exe", "update.exe", "setup.exe", "winlogon32.exe",
        "chrome_update.exe", "RuntimeBroker.exe", "systemd.exe",
        "powershell_ise.exe", "msiexec64.exe", "dllhost32.exe",
    ]

    def _make_agent_id(self) -> str:
        return "".join(random.choices(string.hexdigits[:16].lower(), k=18))

    def _make_storyline_id(self) -> str:
        return "".join(random.choices(string.hexdigits[:16].lower(), k=16))

    def generate(self) -> dict:
        severity = self._pick_severity()
        technique_id, technique_name = self._pick_technique()
        host = self._pick_host()
        user = self._pick_user()
        src_ip = self._pick_ip()
        filename = random.choice(self.FILENAMES)
        file_path = random.choice(self.FILE_PATHS).format(user=user, filename=filename)
        sha256 = "".join(random.choices("0123456789abcdef", k=64))
        threat_name = random.choice(self.THREAT_NAMES)
        mitigation_status, mitigation_desc = random.choice(self.MITIGATION_STATUSES)
        agent_id = self._make_agent_id()

        # Map our severity to SentinelOne rank (1-10) and confidence level
        rank_map = {"critical": random.randint(8, 10), "high": random.randint(6, 8),
                    "medium": random.randint(4, 6), "low": random.randint(1, 4)}
        confidence_map = {"critical": "malicious", "high": "malicious",
                          "medium": "suspicious", "low": "suspicious"}

        # SentinelOne webhook payload — matches official format exactly
        return {
            "name": "Joti-PurpleLab-Simulation",
            "data": {
                "id": self._uuid(),
                "agentComputerName": host,
                "agentDomain": "corp.example.com",
                "agentExternalIp": src_ip,
                "agentId": agent_id,
                "agentInfected": severity in ("critical", "high"),
                "agentIp": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "agentIsActive": True,
                "agentMachineType": random.choice(self.MACHINE_TYPES),
                "agentNetworkStatus": "connected",
                "agentOs": random.choice(["windows", "linux", "macos"]),
                "agentVersion": random.choice(self.AGENT_VERSIONS),
                "classification": random.choice(["Malware", "Exploit", "PUA", "Ransomware", "Trojan"]),
                "classificationSource": random.choice(self.CLASSIFICATION_SOURCES),
                "cloudFiles_id": None,
                "confidenceLevel": confidence_map[severity],
                "createdAt": self._now_iso(),
                "description": self._pick_title(severity),
                "engines": random.choice(self.ENGINES),
                "filePath": file_path,
                "fileSize": random.randint(4096, 4194304),
                "id": self._uuid(),
                "imageFilePath": file_path,
                "indicatorCategory": random.choice(self.INDICATOR_CATEGORIES),
                "indicatorDescription": f"MITRE ATT&CK {technique_id}: {technique_name}",
                "indicatorName": random.choice(self.INDICATOR_NAMES),
                "mitigationStatus": mitigation_status,
                "mitigationStatusDescription": mitigation_desc,
                "publisherName": "",
                "rank": rank_map[severity],
                "sha256": sha256,
                "siteId": "".join(random.choices(string.digits, k=18)),
                "siteName": "Default",
                "storyline": self._make_storyline_id(),
                "threatName": threat_name,
                "updatedAt": self._now_iso(),
                "username": user,
                "whiteningOptions": [],
                "mitreTechnique": technique_name,
                "mitreTechniqueId": technique_id,
                "mitreAttackTactics": [technique_name.split()[0] if " " in technique_name else "Execution"],
                "sourceIp": src_ip,
                "destinationIp": None,
            },
        }
