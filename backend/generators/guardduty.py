"""AWS GuardDuty — Finding notification format.

Real GuardDuty publishes findings to EventBridge / SNS or via GetFindings API.
Format: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html
"""
import random
from backend.generators.base import BaseGenerator


FINDING_TYPES = {
    "critical": [
        "Trojan:EC2/DNSDataExfiltration",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        "Impact:EC2/WinRMBruteForce",
    ],
    "high": [
        "Backdoor:EC2/C&CActivity.B!DNS",
        "Recon:EC2/PortProbeUnprotectedPort",
        "UnauthorizedAccess:EC2/RDPBruteForce",
        "Trojan:EC2/BlackholeTraffic",
    ],
    "medium": [
        "Recon:EC2/Portscan",
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "Discovery:S3/MaliciousIPCaller",
        "Persistence:IAMUser/AnomalousBehavior",
    ],
    "low": [
        "Recon:IAMUser/TorIPCaller",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "Policy:IAMUser/RootCredentialUsage",
        "Behavior:EC2/TrafficVolumeUnusual",
    ],
}

SEVERITY_RANGES = {
    "critical": (7.0, 8.9),
    "high": (5.0, 6.9),
    "medium": (3.0, 4.9),
    "low": (1.0, 2.9),
}


class GuardDutyGenerator(BaseGenerator):
    product_name = "AWS GuardDuty"
    product_category = "cloud"

    REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"]

    INSTANCE_TYPES = ["t3.micro", "t3.medium", "m5.large", "c5.xlarge", "r5.2xlarge"]

    ACTION_TYPES = [
        "NETWORK_CONNECTION", "PORT_PROBE", "DNS_REQUEST", "AWS_API_CALL",
    ]

    ISP_NAMES = ["DigitalOcean", "OVH SAS", "Hetzner", "Choopa", "M247", "Amazon.com"]
    ORG_NAMES = ["TOR Exit Node", "VPN Provider", "Hosting Company", "Anonymous Proxy"]

    VPC_IDS = [f"vpc-{''.join(random.choices('0123456789abcdef', k=8))}" for _ in range(5)]
    SUBNET_IDS = [f"subnet-{''.join(random.choices('0123456789abcdef', k=8))}" for _ in range(5)]
    SG_IDS = [f"sg-{''.join(random.choices('0123456789abcdef', k=8))}" for _ in range(5)]

    def generate(self) -> dict:
        severity = self._pick_severity()
        finding_type = random.choice(FINDING_TYPES[severity])
        sev_lo, sev_hi = SEVERITY_RANGES[severity]
        sev_score = round(random.uniform(sev_lo, sev_hi), 1)
        ip = self._pick_ip()
        region = random.choice(self.REGIONS)
        account_id = "".join(random.choices("0123456789", k=12))
        instance_id = f"i-{''.join(random.choices('0123456789abcdef', k=17))}"

        is_ec2 = "EC2" in finding_type
        resource_type = "Instance" if is_ec2 else "AccessKey"
        action_type = random.choice(self.ACTION_TYPES)

        title = finding_type.replace(":", " - ").replace("/", ": ")

        resource = {"resourceType": resource_type}
        if is_ec2:
            resource["instanceDetails"] = {
                "instanceId": instance_id,
                "instanceType": random.choice(self.INSTANCE_TYPES),
                "launchTime": self._now_iso(),
                "platform": random.choice(["Linux", "Linux", "Windows"]),
                "networkInterfaces": [
                    {
                        "privateIpAddress": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                        "publicIp": self._pick_ip(),
                        "vpcId": random.choice(self.VPC_IDS),
                        "subnetId": random.choice(self.SUBNET_IDS),
                        "securityGroups": [{"groupId": random.choice(self.SG_IDS), "groupName": "default"}],
                    }
                ],
                "tags": [
                    {"key": "Name", "value": self._pick_host()},
                    {"key": "Environment", "value": random.choice(["production", "staging", "development"])},
                ],
                "imageId": f"ami-{''.join(random.choices('0123456789abcdef', k=8))}",
                "availabilityZone": f"{region}{''.join(random.choices('abc', k=1))}",
            }
        else:
            resource["accessKeyDetails"] = {
                "accessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
                "principalId": f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
                "userName": self._pick_user(),
                "userType": random.choice(["IAMUser", "AssumedRole", "Root"]),
            }

        action = {"actionType": action_type}
        if action_type == "NETWORK_CONNECTION":
            action["networkConnectionAction"] = {
                "connectionDirection": random.choice(["INBOUND", "OUTBOUND"]),
                "localPortDetails": {"port": random.choice([22, 80, 443, 3389, 8080]), "portName": "HTTP"},
                "remoteIpDetails": {
                    "ipAddressV4": ip,
                    "organization": {
                        "asn": str(random.randint(1000, 65000)),
                        "asnOrg": random.choice(self.ISP_NAMES),
                        "isp": random.choice(self.ISP_NAMES),
                        "org": random.choice(self.ORG_NAMES),
                    },
                    "country": {"countryName": random.choice(["Russia", "China", "North Korea", "Iran", "Brazil"])},
                    "city": {"cityName": random.choice(["Moscow", "Beijing", "Pyongyang", "Tehran", "Sao Paulo"])},
                },
                "remotePortDetails": {"port": random.randint(1024, 65535), "portName": "Unknown"},
                "protocol": random.choice(["TCP", "UDP"]),
                "blocked": random.choice([True, False]),
            }
        elif action_type == "DNS_REQUEST":
            action["dnsRequestAction"] = {
                "domain": self._pick_domain(),
                "protocol": "UDP",
                "blocked": random.choice([True, False]),
            }

        return {
            "schemaVersion": "2.0",
            "accountId": account_id,
            "region": region,
            "partition": "aws",
            "id": self._uuid(),
            "arn": f"arn:aws:guardduty:{region}:{account_id}:detector/{self._uuid()[:12]}/finding/{self._uuid()}",
            "type": finding_type,
            "severity": sev_score,
            "title": title,
            "description": f"GuardDuty finding: {title}. Remote IP: {ip}.",
            "resource": resource,
            "service": {
                "serviceName": "guardduty",
                "detectorId": self._uuid()[:12],
                "action": action,
                "resourceRole": random.choice(["TARGET", "ACTOR"]),
                "additionalInfo": {
                    "threatListName": random.choice(["ProofPoint", "TorNode", "CustomThreatList", ""]),
                },
                "eventFirstSeen": self._now_iso(),
                "eventLastSeen": self._now_iso(),
                "count": random.randint(1, 500),
            },
            "createdAt": self._now_iso(),
            "updatedAt": self._now_iso(),
        }
