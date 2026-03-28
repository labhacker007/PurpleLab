"""ServiceNow — Incident REST API / webhook payload format.

Real ServiceNow sends incident data via Outbound REST or Business Rule webhook.
Format: https://docs.servicenow.com/bundle/tokyo-it-service-management/page/product/incident-management/reference/r_IncidentTableAPI.html
"""
import random
from backend.engine.generators.base import BaseGenerator


class ServiceNowGenerator(BaseGenerator):
    product_name = "ServiceNow ITSM"
    product_category = "itsm"

    SHORT_DESCRIPTIONS = [
        "Malware detected on endpoint {host}",
        "Phishing email reported by {user}",
        "Unauthorized access attempt on {host}",
        "VPN connectivity issue for {user}",
        "Suspicious login from foreign IP {ip}",
        "Ransomware alert triggered on {host}",
        "DLP policy violation by {user}",
        "Firewall rule change request",
        "Certificate expiry warning for {host}",
        "Account lockout for {user} after failed attempts",
        "Endpoint compliance check failure on {host}",
        "Security patch deployment failure on {host}",
    ]

    CATEGORIES = [
        ("Security", "Malware"),
        ("Security", "Phishing"),
        ("Security", "Unauthorized Access"),
        ("Security", "Data Loss"),
        ("Network", "Firewall"),
        ("Software", "Antivirus"),
        ("Hardware", "Endpoint"),
    ]

    STATES = {
        1: "New", 2: "In Progress", 3: "On Hold",
        6: "Resolved", 7: "Closed",
    }

    ASSIGNMENT_GROUPS = [
        "SOC Tier 1", "SOC Tier 2", "Network Security", "Endpoint Security",
        "Identity & Access Management", "Incident Response", "IT Service Desk",
    ]

    URGENCY_MAP = {"critical": 1, "high": 1, "medium": 2, "low": 3}
    IMPACT_MAP = {"critical": 1, "high": 1, "medium": 2, "low": 3}

    PRIORITY_MATRIX = {
        (1, 1): "1 - Critical", (1, 2): "2 - High", (1, 3): "2 - High",
        (2, 1): "2 - High", (2, 2): "3 - Moderate", (2, 3): "3 - Moderate",
        (3, 1): "2 - High", (3, 2): "3 - Moderate", (3, 3): "4 - Low",
    }

    def generate(self) -> dict:
        severity = self._pick_severity()
        host = self._pick_host()
        user = self._pick_user()
        ip = self._pick_ip()
        category, subcategory = random.choice(self.CATEGORIES)
        urgency = self.URGENCY_MAP[severity]
        impact = self.IMPACT_MAP[severity]
        state_code = random.choice([1, 1, 1, 2, 2, 6])
        assigned_to = f"{random.choice(['alex', 'morgan', 'jordan', 'casey', 'riley'])}.{random.choice(['smith', 'jones', 'patel', 'chen', 'garcia'])}"

        short_desc = random.choice(self.SHORT_DESCRIPTIONS).format(
            host=host, user=user, ip=ip,
        )

        return {
            "sys_id": self._uuid().replace("-", ""),
            "number": f"INC{random.randint(1000000, 9999999):07d}",
            "short_description": short_desc,
            "description": f"{short_desc}\n\nSource IP: {ip}\nAffected Host: {host}\nReported by: {user}",
            "state": str(state_code),
            "state_display": self.STATES[state_code],
            "urgency": str(urgency),
            "impact": str(impact),
            "priority": self.PRIORITY_MATRIX[(urgency, impact)],
            "category": category,
            "subcategory": subcategory,
            "assignment_group": random.choice(self.ASSIGNMENT_GROUPS),
            "assigned_to": assigned_to,
            "caller_id": user,
            "opened_at": self._now_iso(),
            "opened_by": user,
            "sys_created_on": self._now_iso(),
            "sys_updated_on": self._now_iso(),
            "contact_type": random.choice(["Email", "Phone", "Self-service", "Monitoring"]),
            "close_code": "Solved (Permanently)" if state_code >= 6 else "",
            "close_notes": f"Remediated {subcategory.lower()} incident." if state_code >= 6 else "",
            "work_notes": f"[Automated] Alert correlated with {ip} activity on {host}.",
            "cmdb_ci": host,
            "business_service": random.choice(["Email Service", "Active Directory", "Web Portal", "VPN Gateway"]),
            "correlation_id": self._uuid()[:16],
        }
