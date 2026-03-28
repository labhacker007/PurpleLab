"""Pre-built attack scenarios for one-click simulation setup.

Each scenario is a pre-configured session with specific products,
severity distributions, and attack narratives.
"""

SCENARIOS = [
    {
        "id": "ransomware_incident",
        "name": "Ransomware Incident (Full Kill Chain)",
        "description": "Simulates a complete ransomware attack: phishing email → credential harvest → lateral movement → encryption",
        "products": ["proofpoint", "crowdstrike", "okta", "splunk"],
        "severity_weights": {"critical": 0.15, "high": 0.35, "medium": 0.35, "low": 0.15},
        "events_per_minute": 5,
    },
    {
        "id": "apt_campaign",
        "name": "APT Campaign (Low & Slow)",
        "description": "Nation-state actor: rare high-confidence alerts mixed with normal noise. Tests FP suppression.",
        "products": ["crowdstrike", "sentinel", "okta", "elastic"],
        "severity_weights": {"critical": 0.02, "high": 0.08, "medium": 0.30, "low": 0.60},
        "events_per_minute": 1,
    },
    {
        "id": "insider_threat",
        "name": "Insider Threat (Identity Focused)",
        "description": "Compromised employee account: unusual logins, privilege escalation, data access patterns",
        "products": ["okta", "entra_id", "splunk", "servicenow"],
        "severity_weights": {"critical": 0.05, "high": 0.25, "medium": 0.50, "low": 0.20},
        "events_per_minute": 3,
    },
    {
        "id": "cloud_breach",
        "name": "Cloud Infrastructure Breach",
        "description": "AWS GuardDuty findings: port scanning, crypto mining, data exfiltration",
        "products": ["guardduty", "crowdstrike", "splunk"],
        "severity_weights": {"critical": 0.10, "high": 0.30, "medium": 0.40, "low": 0.20},
        "events_per_minute": 2,
    },
    {
        "id": "soc_daily_ops",
        "name": "SOC Daily Operations (Realistic Mix)",
        "description": "Normal day: 80% low/medium noise, 15% real threats, 5% critical. Tests triage efficiency.",
        "products": ["splunk", "crowdstrike", "okta", "proofpoint", "sentinel"],
        "severity_weights": {"critical": 0.03, "high": 0.12, "medium": 0.35, "low": 0.50},
        "events_per_minute": 8,
    },
    {
        "id": "alert_flood",
        "name": "Alert Flood (Stress Test)",
        "description": "High-volume alert storm. Tests cognitive load autonomy adjustment and rate limiting.",
        "products": ["splunk", "crowdstrike", "elastic", "sentinel"],
        "severity_weights": {"critical": 0.01, "high": 0.09, "medium": 0.40, "low": 0.50},
        "events_per_minute": 30,
    },
]
