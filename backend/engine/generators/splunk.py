"""Splunk SIEM — Webhook Alert Action payload format.

Real Splunk sends POST to webhook URL when a saved search triggers.
Format: https://docs.splunk.com/Documentation/Splunk/latest/Alert/Webhooks
"""
import random
from backend.engine.generators.base import BaseGenerator


class SplunkGenerator(BaseGenerator):
    product_name = "Splunk Enterprise"
    product_category = "siem"

    # Real Splunk saved search names (detection rules)
    SEARCH_NAMES = [
        "Detect Excessive Failed Logins",
        "Windows - Credential Dumping via LSASS",
        "Detect PowerShell Empire",
        "Network - C2 Beaconing Detected",
        "Endpoint - Ransomware File Modification",
        "Windows - Lateral Movement via WMI",
        "Network - DNS Tunneling Detected",
        "Windows - Scheduled Task Created via CMD",
        "Endpoint - Suspicious Process Injection",
        "Windows - Service Created via sc.exe",
        "Network - Data Exfiltration over DNS",
        "Endpoint - Mimikatz Usage Detected",
        "Windows - Registry Run Key Modified",
        "Network - TOR Exit Node Communication",
        "Endpoint - Rundll32 Suspicious Execution",
    ]

    URGENCY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}

    INDEXES = ["main", "wineventlog", "sysmon", "firewall", "proxy", "dns"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        technique_id, technique_name = self._pick_technique()
        src_ip = self._pick_ip()
        dest_host = self._pick_host()
        user = self._pick_user()

        # This matches the EXACT format Splunk sends to webhook endpoints
        return {
            "sid": f"scheduler__{self._uuid()}",
            "search_name": random.choice(self.SEARCH_NAMES),
            "app": "SplunkEnterpriseSecuritySuite",
            "owner": "admin",
            "results_link": f"https://splunk.internal:8089/services/search/jobs/{self._uuid()}/results",
            "result": {
                "_time": self._now_iso(),
                "host": dest_host,
                "source": f"WinEventLog:Security",
                "sourcetype": "WinEventLog:Security",
                "index": random.choice(self.INDEXES),
                "src_ip": src_ip,
                "dest": dest_host,
                "user": user,
                "action": random.choice(["allowed", "blocked", "unknown"]),
                "signature": f"{technique_id}: {technique_name}",
                "mitre_technique_id": technique_id,
                "severity": severity,
            },
            "urgency": self.URGENCY_MAP[severity],
            "trigger_time": self._now_iso(),
            "message": self._pick_title(severity),
        }
