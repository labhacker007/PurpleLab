"""Cloud Security Posture Management (CSPM) event generator.

Produces cloud misconfiguration and compliance findings: public buckets,
overprivileged IAM, unencrypted storage, security group violations.
"""
import random
import uuid
from datetime import datetime, timezone, timedelta
from backend.engine.generators.base import BaseGenerator


CLOUD_PROVIDERS = ["AWS", "GCP", "Azure", "OCI"]
RESOURCE_TYPES = ["S3Bucket", "IAMRole", "SecurityGroup", "RDSInstance",
                  "StorageAccount", "VirtualMachine", "KMSKey", "ECRRepository",
                  "AzureKeyVault", "GCSBucket", "BigQueryDataset", "GCPIAMBinding"]

RULES = {
    "critical": [
        ("S3-001", "S3 bucket allows public read access", "T1530"),
        ("IAM-007", "IAM role with administrator access attached to EC2", "T1078.004"),
        ("SG-001", "Security group allows unrestricted inbound SSH from 0.0.0.0/0", "T1133"),
        ("RDS-003", "RDS instance publicly accessible with no encryption", "T1530"),
    ],
    "high": [
        ("IAM-012", "IAM password policy does not require MFA", "T1078"),
        ("S3-008", "S3 bucket versioning disabled", "T1490"),
        ("SG-005", "Security group allows unrestricted inbound RDP", "T1021.001"),
        ("KMS-001", "KMS key rotation disabled", "T1552"),
    ],
    "medium": [
        ("LOG-002", "CloudTrail logging disabled for management events", "T1562.008"),
        ("FLOW-001", "VPC Flow Logs not enabled", "T1040"),
        ("IAM-021", "Access keys not rotated in 90+ days", "T1552.004"),
        ("S3-012", "S3 bucket server-side encryption not enabled", "T1530"),
    ],
    "low": [
        ("TAG-001", "Resource missing required cost allocation tags", None),
        ("IAM-033", "Root account access keys exist", "T1078"),
        ("LOG-007", "Access logging disabled for S3 bucket", "T1562"),
    ],
}
COMPLIANCE_FRAMEWORKS = [
    ["CIS", "SOC2"], ["CIS", "PCI"], ["NIST", "SOC2"], ["CIS", "HIPAA"],
    ["SOC2"], ["PCI", "HIPAA", "NIST"], ["CIS"],
]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
           "ap-southeast-1", "eastus", "westeurope", "us-central1"]


class CSPMGenerator(BaseGenerator):
    product_name = "CSPM"
    product_category = "cspm"

    def generate(self) -> dict:
        severity = random.choice(["critical", "high", "medium", "low"])
        rule_id, rule_title, technique = random.choice(RULES[severity])
        provider = random.choice(CLOUD_PROVIDERS)
        resource_type = random.choice(RESOURCE_TYPES)
        now = datetime.now(timezone.utc)
        first_detected = (now - timedelta(days=random.randint(0, 60))).isoformat()
        account = f"{random.randint(100000000000, 999999999999)}" if provider == "AWS" else f"sub-{uuid.uuid4().hex[:8]}"

        return {
            "finding_id": f"cspm-{uuid.uuid4().hex[:8]}",
            "cloud_provider": provider,
            "account_id": account,
            "region": random.choice(REGIONS),
            "resource_id": _resource_id(provider, resource_type, account),
            "resource_type": resource_type,
            "rule_id": rule_id,
            "rule_title": rule_title,
            "severity": severity,
            "status": random.choice(["open", "open", "open", "in_progress", "suppressed"]),
            "compliance_frameworks": random.choice(COMPLIANCE_FRAMEWORKS),
            "mitre_technique": technique,
            "first_detected": first_detected,
            "last_evaluated": now.isoformat(),
            "remediation_guidance": _remediation(rule_id),
        }


def _resource_id(provider: str, resource_type: str, account: str) -> str:
    name = f"resource-{random.randint(100, 999)}"
    if provider == "AWS":
        region = random.choice(["us-east-1", "us-west-2", "eu-west-1"])
        if resource_type == "S3Bucket":
            return f"arn:aws:s3:::{name}-bucket"
        if resource_type == "IAMRole":
            return f"arn:aws:iam::{account}:role/{name}"
        if resource_type == "SecurityGroup":
            return f"arn:aws:ec2:{region}:{account}:security-group/sg-{random.randint(10000000, 99999999):x}"
        return f"arn:aws::{region}:{account}:{resource_type.lower()}/{name}"
    if provider == "Azure":
        return f"/subscriptions/{account}/resourceGroups/rg-{name}/{resource_type}/{name}"
    if provider == "GCP":
        return f"projects/my-project/{resource_type.lower()}/{name}"
    return f"{provider.lower()}://{account}/{resource_type}/{name}"


def _remediation(rule_id: str) -> str:
    recs = {
        "S3-001": "Remove public bucket ACL/policy and enable S3 Block Public Access settings",
        "IAM-007": "Replace AdministratorAccess with a least-privilege IAM policy",
        "SG-001": "Restrict SSH to specific CIDR ranges or use AWS Systems Manager Session Manager",
        "RDS-003": "Disable public accessibility and enable encryption at rest",
        "IAM-012": "Enable MFA on all IAM users. Enforce via IAM policy condition.",
        "S3-008": "Enable versioning on S3 bucket for ransomware/accidental deletion protection",
        "SG-005": "Restrict RDP inbound to corporate VPN range only",
        "KMS-001": "Enable automatic key rotation in KMS key settings",
        "LOG-002": "Enable CloudTrail for all regions with management event logging",
        "FLOW-001": "Enable VPC Flow Logs to S3 or CloudWatch Logs",
        "IAM-021": "Rotate or delete unused access keys older than 90 days",
        "S3-012": "Enable AES-256 or SSE-KMS server-side encryption on all S3 buckets",
        "TAG-001": "Add required cost allocation tags per tagging policy",
        "IAM-033": "Delete root account access keys immediately; use IAM users instead",
        "LOG-007": "Enable S3 server access logging to a separate audit bucket",
    }
    return recs.get(rule_id, "Review finding and remediate per security policy")
