"""Elastic SIEM — Kibana alert webhook payload format."""
import random
from backend.generators.base import BaseGenerator


class ElasticGenerator(BaseGenerator):
    product_name = "Elastic SIEM"
    product_category = "siem"

    RULE_NAMES = [
        "Suspicious PowerShell Execution",
        "Potential Credential Access via LSASS",
        "Unusual Network Connection",
        "DNS Activity to Suspicious Domain",
        "Potential Lateral Movement via RDP",
        "Ransomware File Modification Detected",
        "Suspicious Scheduled Task Creation",
        "Process Injection Detected",
    ]

    RULE_TYPES = ["query", "eql", "threshold", "machine_learning"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        technique_id, technique_name = self._pick_technique()
        host = self._pick_host()
        user = self._pick_user()
        src_ip = self._pick_ip()

        return {
            "rule": {
                "name": random.choice(self.RULE_NAMES),
                "description": self._pick_title(severity),
                "severity": severity,
                "type": random.choice(self.RULE_TYPES),
                "tags": [f"attack.{technique_id.lower()}", "elastic_rule"],
            },
            "kibana.alert.severity": severity,
            "signal": {
                "rule": {"type": random.choice(self.RULE_TYPES)},
                "original_time": self._now_iso(),
            },
            "host": {"name": host, "os": {"platform": "windows", "version": "10.0.19044"}},
            "source": {"ip": src_ip, "port": random.randint(1024, 65535)},
            "destination": {"ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", "port": random.choice([80, 443, 445, 3389, 5985])},
            "process": {
                "name": random.choice(["powershell.exe", "cmd.exe", "rundll32.exe", "wscript.exe"]),
                "args": ["-enc", "SQBFAFgA"],
                "pid": random.randint(1000, 50000),
            },
            "user": {"name": user, "domain": "CORP"},
            "event": {"action": "execution", "category": ["process"], "kind": "signal"},
            "@timestamp": self._now_iso(),
            "message": self._pick_title(severity),
        }
