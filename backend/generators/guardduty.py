"""AWS GuardDuty — Finding format."""
import random
from backend.generators.base import BaseGenerator


class GuardDutyGenerator(BaseGenerator):
    product_name = "AWS GuardDuty"
    product_category = "cloud"

    FINDING_TYPES = {
        "critical": [
            "Trojan:EC2/DNSDataExfiltration",
            "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
        ],
        "high": [
            "Recon:EC2/PortProbeUnprotectedPort",
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "Persistence:IAMUser/AnomalousBehavior",
            "Impact:EC2/WinRMBruteForce",
        ],
        "medium": [
            "Recon:EC2/Portscan",
            "UnauthorizedAccess:EC2/SSHBruteForce",
            "Discovery:S3/MaliciousIPCaller",
            "Behavior:EC2/NetworkPortUnusual",
        ],
        "low": [
            "Recon:IAMUser/UserPermissions",
            "Policy:IAMUser/RootCredentialUsage",
            "UnauthorizedAccess:EC2/TorClient",
        ],
    }

    REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
    INSTANCE_TYPES = ["t3.micro", "m5.large", "c5.xlarge", "r5.2xlarge"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        sev_score = {"critical": 8.5, "high": 7.0, "medium": 5.0, "low": 2.0}[severity]
        finding_type = random.choice(self.FINDING_TYPES[severity])
        instance_id = f"i-{''.join(random.choices('0123456789abcdef', k=17))}"

        return {
            "schemaVersion": "2.0",
            "accountId": f"{''.join(random.choices('0123456789', k=12))}",
            "region": random.choice(self.REGIONS),
            "id": self._uuid(),
            "type": finding_type,
            "severity": round(sev_score + random.uniform(-0.5, 0.5), 1),
            "title": self._pick_title(severity),
            "description": f"GuardDuty finding: {finding_type} detected on {instance_id}",
            "createdAt": self._now_iso(),
            "updatedAt": self._now_iso(),
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": instance_id,
                    "instanceType": random.choice(self.INSTANCE_TYPES),
                    "platform": random.choice(["Linux", "Windows"]),
                    "networkInterfaces": [{
                        "privateIpAddress": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                        "publicIp": self._pick_ip(),
                        "subnetId": f"subnet-{''.join(random.choices('0123456789abcdef', k=8))}",
                        "vpcId": f"vpc-{''.join(random.choices('0123456789abcdef', k=8))}",
                    }],
                    "tags": [{"key": "Name", "value": self._pick_host()}],
                },
            },
            "service": {
                "serviceName": "guardduty",
                "action": {
                    "actionType": "NETWORK_CONNECTION",
                    "networkConnectionAction": {
                        "connectionDirection": random.choice(["INBOUND", "OUTBOUND"]),
                        "remoteIpDetails": {
                            "ipAddressV4": self._pick_ip(),
                            "organization": {"asn": str(random.randint(10000, 99999)), "asnOrg": "SuspiciousISP"},
                            "country": {"countryName": random.choice(["Russia", "China", "North Korea", "Iran"])},
                            "city": {"cityName": random.choice(["Moscow", "Beijing", "Pyongyang", "Tehran"])},
                        },
                        "remotePortDetails": {"port": random.choice([80, 443, 4444, 8080, 9001])},
                        "localPortDetails": {"port": random.choice([22, 80, 443, 3389])},
                    },
                },
                "count": random.randint(1, 50),
                "eventFirstSeen": self._now_iso(),
                "eventLastSeen": self._now_iso(),
            },
        }
