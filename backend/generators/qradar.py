"""IBM QRadar — Offense notification webhook payload format.

Real QRadar sends offense data via custom actions or SIEM forwarding rules.
Format: https://www.ibm.com/docs/en/qradar-common?topic=api-offenses
"""
import random
from backend.generators.base import BaseGenerator


class QRadarGenerator(BaseGenerator):
    product_name = "IBM QRadar"
    product_category = "siem"

    OFFENSE_NAMES = [
        "Multiple Login Failures from Same Source",
        "Potential Data Exfiltration Detected",
        "Suspicious DNS Activity",
        "Exploit Attempt Against Web Server",
        "Anomalous Outbound Traffic Volume",
        "Botnet Communication Detected",
        "Brute Force Attack in Progress",
        "Unauthorized Port Scan",
        "Privilege Escalation Attempt",
        "Malware Callback Activity",
        "Insider Threat - Unusual Data Access",
        "Lateral Movement Detected",
    ]

    OFFENSE_TYPES = [
        "Source IP", "Destination IP", "Username", "Source MAC",
        "Hostname", "Source Port", "Destination Port",
    ]

    CATEGORIES = [
        "Authentication", "Access", "Exploit", "Malware",
        "Reconnaissance", "Suspicious Activity", "Denial of Service",
        "Policy Violation", "CRE", "Botnet", "Exfiltration",
    ]

    LOG_SOURCES = [
        "Palo Alto Firewall", "Windows Security Event Log", "Cisco ASA",
        "Snort IDS", "Apache Web Server", "IBM Endpoint Manager",
        "Blue Coat Proxy", "Juniper SRX", "Linux Audit", "F5 BIG-IP",
    ]

    NETWORKS = [
        "DMZ", "Internal-Servers", "Workstations", "Guest-Wifi",
        "Management", "PCI-Zone", "Production", "Development",
    ]

    RULES = [
        "BB:CategoryDefinition: Reconnaissance",
        "BB:BehaviorDefinition: Brute Force",
        "BB:BehaviorDefinition: Anomalous Traffic",
        "CRE: Multiple Offenses from Single Source",
        "CRE: High Severity Event Correlation",
    ]

    def _calc_magnitude(self, severity: str) -> int:
        base = {"critical": 8, "high": 6, "medium": 4, "low": 2}[severity]
        return min(10, max(1, base + random.randint(-1, 2)))

    def generate(self) -> dict:
        severity = self._pick_severity()
        ip = self._pick_ip()
        host = self._pick_host()
        user = self._pick_user()
        technique_id, technique_name = self._pick_technique()
        offense_id = random.randint(10000, 99999)
        magnitude = self._calc_magnitude(severity)
        credibility = min(10, max(1, random.randint(3, 10)))
        relevance = min(10, max(1, random.randint(2, 10)))
        sev_score = min(10, max(1, random.randint(2, 10)))
        event_count = {"critical": 500, "high": 150, "medium": 40, "low": 8}[severity]
        event_count += random.randint(-5, event_count)

        return {
            "id": offense_id,
            "offense_name": random.choice(self.OFFENSE_NAMES),
            "offense_type": random.choice(self.OFFENSE_TYPES),
            "description": f"{self._pick_title(severity)} [MITRE: {technique_id} {technique_name}]",
            "magnitude": magnitude,
            "severity": sev_score,
            "credibility": credibility,
            "relevance": relevance,
            "status": random.choice(["OPEN", "OPEN", "OPEN", "HIDDEN", "CLOSED"]),
            "offense_source": ip,
            "source_network": random.choice(self.NETWORKS),
            "destination_networks": [random.choice(self.NETWORKS)],
            "source_count": random.randint(1, 20),
            "local_destination_count": random.randint(1, 10),
            "remote_destination_count": random.randint(0, 5),
            "event_count": max(1, event_count),
            "flow_count": random.randint(0, event_count // 2),
            "categories": random.sample(self.CATEGORIES, k=random.randint(1, 3)),
            "log_sources": [
                {"name": ls, "id": random.randint(100, 999)}
                for ls in random.sample(self.LOG_SOURCES, k=random.randint(1, 3))
            ],
            "rules": [
                {"name": rule, "id": random.randint(1000, 9999)}
                for rule in random.sample(self.RULES, k=random.randint(1, 2))
            ],
            "assigned_to": random.choice([user, "admin", None]),
            "start_time": self._now_iso(),
            "last_updated_time": self._now_iso(),
            "close_time": None,
            "domain_id": 0,
            "follow_up": random.choice([True, False]),
            "username_count": random.randint(1, 5),
        }
