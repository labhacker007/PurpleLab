"""CrowdStrike Falcon — Detection API response format.

Real CrowdStrike sends detections via Falcon Streaming API or SIEM connector.
Format: https://falcon.crowdstrike.com/documentation/page/d3c4fc5e/streaming-api
"""
import random
from backend.generators.base import BaseGenerator


class CrowdStrikeGenerator(BaseGenerator):
    product_name = "CrowdStrike Falcon"
    product_category = "edr"

    DETECTION_NAMES = [
        "ProcessRollup2 - Suspicious PowerShell",
        "SuspiciousActivity - Credential Access",
        "MalwareDetection - Ransomware Behavior",
        "NetworkConnect - C2 Communication",
        "DNSRequest - Suspicious Domain",
        "FileWrite - Dropper Activity",
        "ProcessInjection - Remote Thread",
        "RegistryOperationType - Persistence",
        "UserLogon - Brute Force",
        "SuspiciousActivity - Lateral Movement",
    ]

    SEVERITY_MAP = {
        "critical": {"severity": 5, "severity_name": "Critical"},
        "high":     {"severity": 4, "severity_name": "High"},
        "medium":   {"severity": 3, "severity_name": "Medium"},
        "low":      {"severity": 2, "severity_name": "Low"},
    }

    TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
               "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
               "Collection", "Command and Control", "Exfiltration", "Impact"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        sev = self.SEVERITY_MAP[severity]
        technique_id, technique_name = self._pick_technique()
        host = self._pick_host()

        return {
            "metadata": {
                "customerIDString": self._uuid()[:12],
                "offset": random.randint(100000, 999999),
                "eventType": "DetectionSummaryEvent",
                "eventCreationTime": self._now_iso(),
                "version": "1.0",
            },
            "event": {
                "DetectId": f"ldt:{self._uuid()[:12]}:{random.randint(100000000, 999999999)}",
                "DetectName": random.choice(self.DETECTION_NAMES),
                "DetectDescription": self._pick_title(severity),
                "Severity": sev["severity"],
                "SeverityName": sev["severity_name"],
                "Confidence": random.randint(60, 99),
                "MachineDomain": "corp.example.com",
                "ComputerName": host,
                "UserName": self._pick_user(),
                "FalconHostLink": f"https://falcon.crowdstrike.com/activity/detections/detail/{self._uuid()}",
                "Tactic": random.choice(self.TACTICS),
                "Technique": technique_name,
                "TechniqueId": technique_id,
                "IOCType": random.choice(["hash_md5", "domain", "ipv4"]),
                "IOCValue": random.choice([self._pick_hash(), self._pick_domain(), self._pick_ip()]),
                "FileName": random.choice(["powershell.exe", "cmd.exe", "rundll32.exe", "svchost.exe", "mimikatz.exe"]),
                "FilePath": f"\\Device\\HarddiskVolume3\\Windows\\System32\\",
                "CommandLine": random.choice([
                    "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0A",
                    "cmd.exe /c whoami /all",
                    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
                    "schtasks /create /tn persist /tr c:\\temp\\beacon.exe /sc onlogon",
                ]),
                "SHA256String": f"{''.join(random.choices('0123456789abcdef', k=64))}",
                "MD5String": self._pick_hash(),
                "ParentImageFileName": "explorer.exe",
                "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
                "PatternDispositionValue": random.choice([0, 16, 2048]),
                "PatternDispositionDescription": random.choice(["Detection", "Prevention", "Blocking"]),
                "GrandparentImageFileName": "userinit.exe",
                "LocalIP": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "ExternalIP": self._pick_ip(),
                "Timestamp": self._now_iso(),
            },
        }
