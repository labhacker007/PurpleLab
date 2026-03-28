"""Base generator class for all security product simulators."""
from __future__ import annotations

import random
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Any

from pydantic import BaseModel, Field


# ── Shared IOC / TTP data pools ──────────────────────────────────────────────

MALICIOUS_IPS = [
    "185.220.101.34", "45.155.205.233", "91.219.236.174", "23.129.64.130",
    "104.244.76.13", "193.42.33.7", "5.188.86.114", "212.102.35.102",
    "185.56.83.82", "77.247.181.163", "195.176.3.23", "162.247.74.74",
    "198.98.56.149", "89.34.111.113", "103.75.201.4", "45.61.185.90",
]

MALICIOUS_DOMAINS = [
    "evil-c2.example.net", "phish-login.example.org", "malware-drop.example.com",
    "exfil-data.example.net", "cobalt-strike.example.org", "apt29-relay.example.com",
    "mimikatz-dl.example.net", "ransomware-pay.example.org",
]

MALICIOUS_HASHES = [
    "e99a18c428cb38d5f260853678922e03", "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592", "098f6bcd4621d373cade4e832627b4f6",
    "b0baee9d279d34fa1dfd71aadb908c3f", "7c6a180b36896a65c4c790f6c1b0456e",
]

MALICIOUS_URLS = [
    "https://evil-c2.example.net/beacon", "https://phish-login.example.org/office365",
    "https://malware-drop.example.com/payload.exe", "https://exfil-data.example.net/upload",
]

MITRE_TECHNIQUES = [
    ("T1059.001", "PowerShell"), ("T1566.001", "Spearphishing Attachment"),
    ("T1566.002", "Spearphishing Link"), ("T1078", "Valid Accounts"),
    ("T1021.001", "Remote Desktop Protocol"), ("T1053.005", "Scheduled Task"),
    ("T1027", "Obfuscated Files"), ("T1105", "Ingress Tool Transfer"),
    ("T1071.001", "Web Protocols C2"), ("T1486", "Data Encrypted for Impact"),
    ("T1547.001", "Registry Run Keys"), ("T1003.001", "LSASS Memory"),
    ("T1055", "Process Injection"), ("T1218.011", "Rundll32"),
    ("T1036.005", "Match Legitimate Name"), ("T1482", "Domain Trust Discovery"),
    ("T1087.002", "Domain Account Discovery"), ("T1046", "Network Service Scanning"),
    ("T1190", "Exploit Public-Facing Application"), ("T1133", "External Remote Services"),
]

HOSTNAMES = [
    "WKSTN-FIN-042", "SRV-DC-01", "WKSTN-HR-019", "SRV-FILE-03",
    "SRV-WEB-01", "WKSTN-ENG-107", "SRV-DB-02", "WKSTN-EXEC-003",
    "SRV-MAIL-01", "WKSTN-IT-055", "SRV-APP-04", "LAPTOP-REMOTE-22",
]

USERNAMES = [
    "jsmith", "admin", "svc_backup", "jane.doe", "root",
    "michael.chen", "sarah.wilson", "svc_sql", "bob.johnson",
    "alice.martinez", "david.kim", "svc_web", "emily.taylor",
]

THREAT_ACTORS = [
    "APT29 (Cozy Bear)", "APT28 (Fancy Bear)", "Lazarus Group",
    "FIN7", "Conti Group", "LockBit", "ALPHV/BlackCat",
    "Scattered Spider", "Volt Typhoon", "Sandworm",
]

ALERT_TITLES = {
    "critical": [
        "Ransomware encryption detected on {host}",
        "Credential dumping via LSASS on {host}",
        "Active C2 beacon to known APT infrastructure from {host}",
        "Golden ticket attack detected — domain admin compromised",
        "Mass data exfiltration (>500MB) to external IP {ip}",
    ],
    "high": [
        "Lateral movement via RDP from {host} to {target}",
        "Suspicious PowerShell execution on {host}",
        "Phishing email delivered to {user} — malicious attachment opened",
        "Privilege escalation attempt on {host} by {user}",
        "Cobalt Strike beacon detected on {host}",
    ],
    "medium": [
        "Unusual login time for {user} on {host}",
        "Port scan detected from {host} targeting internal subnet",
        "Scheduled task created by {user} on {host}",
        "DNS query to suspicious domain from {host}",
        "Failed login brute force (15+ attempts) for {user}",
    ],
    "low": [
        "Software installation by {user} on {host}",
        "USB device connected on {host}",
        "VPN login from new location for {user}",
        "Browser extension installed on {host}",
        "Informational: routine scan completed on {host}",
    ],
}


class GeneratorConfig(BaseModel):
    """Configuration for a simulator instance."""
    product_type: str                          # "splunk", "crowdstrike", etc.
    target_url: str                            # Where to send webhooks
    webhook_token: str = ""                    # Auth token for target
    events_per_minute: float = Field(2.0, ge=0.1, le=120)
    severity_weights: dict[str, float] = Field(
        default={"critical": 0.05, "high": 0.20, "medium": 0.50, "low": 0.25}
    )
    enabled: bool = True
    custom_config: dict[str, Any] = Field(default_factory=dict)


class BaseGenerator(ABC):
    """Abstract base for all security product simulators."""

    product_name: str = "generic"
    product_category: str = "siem"  # siem, edr, itdr, email, itsm, vuln, cloud

    def __init__(self, config: GeneratorConfig):
        self.config = config

    def _pick_severity(self) -> str:
        w = self.config.severity_weights
        choices = list(w.keys())
        weights = [w[c] for c in choices]
        return random.choices(choices, weights=weights, k=1)[0]

    def _pick_ip(self) -> str:
        return random.choice(MALICIOUS_IPS)

    def _pick_domain(self) -> str:
        return random.choice(MALICIOUS_DOMAINS)

    def _pick_hash(self) -> str:
        return random.choice(MALICIOUS_HASHES)

    def _pick_host(self) -> str:
        return random.choice(HOSTNAMES)

    def _pick_user(self) -> str:
        return random.choice(USERNAMES)

    def _pick_technique(self) -> tuple[str, str]:
        return random.choice(MITRE_TECHNIQUES)

    def _pick_title(self, severity: str) -> str:
        templates = ALERT_TITLES.get(severity, ALERT_TITLES["medium"])
        template = random.choice(templates)
        return template.format(
            host=self._pick_host(), ip=self._pick_ip(),
            user=self._pick_user(), target=self._pick_host(),
        )

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _uuid(self) -> str:
        return str(uuid.uuid4())

    @abstractmethod
    def generate(self) -> dict:
        """Generate a single event in the vendor's exact payload format."""
        ...

    def generate_batch(self, count: int = 5) -> list[dict]:
        """Generate multiple events."""
        return [self.generate() for _ in range(count)]
