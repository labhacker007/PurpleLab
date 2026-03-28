"""Microsoft Sentinel — Alert webhook payload format.

Real Sentinel sends alerts via Logic App / Automation Rule webhook action.
Format: https://learn.microsoft.com/en-us/azure/sentinel/automate-responses-with-playbooks
"""
import random
from backend.generators.base import BaseGenerator


class SentinelGenerator(BaseGenerator):
    product_name = "Microsoft Sentinel"
    product_category = "siem"

    ALERT_TYPES = [
        "Fusion", "MLBehaviorAnalytics", "MicrosoftSecurityIncidentCreation",
        "Scheduled", "NRT", "ThreatIntelligence",
    ]

    DISPLAY_NAMES = [
        "Suspicious sign-in from Tor exit node",
        "Potential credential dumping activity",
        "Anomalous RDP login detected",
        "Malware C2 beaconing pattern",
        "Mass file deletion on SharePoint",
        "Brute force attack against Azure AD",
        "Suspicious PowerShell command execution",
        "Data exfiltration to external storage",
        "Rare process execution on {host}",
        "Impossible travel activity detected for {user}",
    ]

    SEVERITY_MAP = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    TACTICS = [
        "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation",
        "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
        "Collection", "Exfiltration", "CommandAndControl", "Impact",
    ]

    REMEDIATION_STEPS = [
        "1. Isolate affected host from the network.\n2. Reset user credentials.\n3. Run full AV scan.",
        "1. Block source IP at firewall.\n2. Review sign-in logs.\n3. Enable MFA for affected account.",
        "1. Disable compromised account.\n2. Revoke active sessions.\n3. Investigate lateral movement.",
        "1. Quarantine endpoint.\n2. Collect forensic image.\n3. Escalate to Tier 2.",
    ]

    def generate(self) -> dict:
        severity = self._pick_severity()
        host = self._pick_host()
        user = self._pick_user()
        ip = self._pick_ip()
        technique_id, technique_name = self._pick_technique()
        alert_id = self._uuid()

        display_name = random.choice(self.DISPLAY_NAMES).format(host=host, user=user)

        return {
            "SchemaVersion": "2.0",
            "AlertId": alert_id,
            "AlertDisplayName": display_name,
            "AlertType": random.choice(self.ALERT_TYPES),
            "AlertSeverity": self.SEVERITY_MAP[severity],
            "ConfidenceLevel": random.choice(["Low", "Medium", "High"]),
            "ConfidenceScore": round(random.uniform(0.4, 0.99), 2),
            "Description": f"{display_name}. Technique: {technique_id} ({technique_name}).",
            "StartTimeUtc": self._now_iso(),
            "EndTimeUtc": self._now_iso(),
            "Status": "New",
            "Tactics": random.sample(self.TACTICS, k=random.randint(1, 3)),
            "Techniques": [technique_id],
            "ProviderName": "Azure Sentinel",
            "ProductName": "Azure Sentinel",
            "CompromisedEntity": random.choice([host, user]),
            "RemediationSteps": random.choice(self.REMEDIATION_STEPS),
            "ExtendedProperties": {
                "SourceIP": ip,
                "DestinationHost": host,
                "AccountName": user,
                "ProcessName": random.choice(["powershell.exe", "cmd.exe", "rundll32.exe", "svchost.exe"]),
                "MitreTechniqueId": technique_id,
                "MitreTechniqueName": technique_name,
            },
            "Entities": [
                {"Type": "ip", "Address": ip},
                {"Type": "host", "HostName": host, "DnsDomain": "corp.example.com"},
                {"Type": "account", "Name": user, "UPNSuffix": "corp.example.com"},
            ],
            "ResourceId": f"/subscriptions/{self._uuid()}/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-ws",
            "WorkspaceId": self._uuid(),
        }
