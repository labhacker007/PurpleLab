"""AWS CloudTrail JSON log source generator.

Generates realistic AWS CloudTrail API call events for detection
engineering and purple team exercises. Covers both benign API usage
patterns and common cloud attack techniques (privilege escalation,
credential theft, detection evasion, backdoor access, data exfil,
and reconnaissance).
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


# ── Static data pools ────────────────────────────────────────────────────────

_ACCOUNT_IDS = [
    "123456789012", "210987654321", "445566778899", "998877665544",
]

_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "us-east-2"]

_IAM_USERS = [
    "alice", "bob.chen", "sarah.ops", "michael.dev", "carol.admin",
    "svc-deploy", "svc-backup", "svc-monitor", "terraform-ci", "jenkins-bot",
]

_ROLE_NAMES = [
    "DevRole", "OpsRole", "ReadOnlyRole", "EC2InstanceRole",
    "LambdaExecutionRole", "CrossAccountRole", "AdminRole",
]

_USER_AGENTS = [
    "aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0",
    "aws-cli/2.14.3 Python/3.10.12 Windows/10",
    "Boto3/1.34.0 Python/3.11.0 Linux/5.15.0",
    "aws-sdk-go/1.51.6 (go1.21; linux; amd64)",
    "aws-sdk-java/2.22.0 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/17",
    "Terraform/1.7.0",
    "console.amazonaws.com",
    "signin.amazonaws.com",
    "elasticloadbalancing.amazonaws.com",
]

_EXTERNAL_IPS = [
    f"203.0.113.{x}" for x in range(10, 50)
] + [
    f"198.51.100.{x}" for x in range(1, 30)
]

_INTERNAL_IPS = [
    f"10.0.{b}.{d}"
    for b in range(0, 4)
    for d in [5, 10, 20, 50, 100, 200]
]

_S3_BUCKETS = [
    "corp-data-2024", "prod-assets", "dev-artifacts", "logs-archive",
    "backup-store-2024", "terraform-state", "ci-artifacts", "data-lake-raw",
]

_SECRET_NAMES = [
    "prod/database/password", "prod/api/stripe-key", "dev/rds/credentials",
    "prod/oauth/client-secret", "infra/ssh/deploy-key", "prod/smtp/credentials",
]

_INSTANCE_IDS = [
    f"i-0{random.randint(10**14, 10**15 - 1):015x}"[:19]
    for _ in range(12)
]

# Pre-generate stable instance IDs at module load time
_STABLE_INSTANCE_IDS = [
    "i-0a1b2c3d4e5f67890", "i-0b2c3d4e5f6789012", "i-0c3d4e5f678901234",
    "i-0d4e5f67890123456", "i-0e5f6789012345678", "i-0f678901234567890",
]

_BENIGN_EVENT_NAMES = [
    ("ConsoleLogin",                  "signin.amazonaws.com",      True),
    ("GetObject",                     "s3.amazonaws.com",          True),
    ("PutObject",                     "s3.amazonaws.com",          False),
    ("CreateInstance",                "ec2.amazonaws.com",         False),
    ("DescribeInstances",             "ec2.amazonaws.com",         True),
    ("ListBuckets",                   "s3.amazonaws.com",          True),
    ("GetCallerIdentity",             "sts.amazonaws.com",         True),
    ("CreateSecurityGroup",           "ec2.amazonaws.com",         False),
    ("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com",         False),
    ("RunInstances",                  "ec2.amazonaws.com",         False),
    ("TerminateInstances",            "ec2.amazonaws.com",         False),
]


# ── Technique-to-generator mapping ───────────────────────────────────────────

_TECHNIQUE_MAP: dict[str, str] = {
    "T1078.004": "_gen_privilege_escalation",
    "T1552.005": "_gen_credential_theft",
    "T1562.008": "_gen_detection_evasion",
    "T1098":     "_gen_backdoor_access",
    "T1530":     "_gen_data_exfil",
    "T1526":     "_gen_recon",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(offset_seconds: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp, optionally shifted."""
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _uid() -> str:
    return str(uuid.uuid4())


def _account() -> str:
    return random.choice(_ACCOUNT_IDS)


def _iam_user_identity(account_id: str, username: str | None = None) -> dict[str, Any]:
    user = username or random.choice(_IAM_USERS)
    return {
        "type": "IAMUser",
        "principalId": f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}",
        "arn": f"arn:aws:iam::{account_id}:user/{user}",
        "accountId": account_id,
        "userName": user,
    }


def _assumed_role_identity(account_id: str) -> dict[str, Any]:
    role = random.choice(_ROLE_NAMES)
    session = f"session-{random.randint(100000, 999999)}"
    return {
        "type": "AssumedRole",
        "principalId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}:{session}",
        "arn": f"arn:aws:sts::{account_id}:assumed-role/{role}/{session}",
        "accountId": account_id,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}",
                "arn": f"arn:aws:iam::{account_id}:role/{role}",
                "accountId": account_id,
                "userName": role,
            }
        },
    }


def _root_identity(account_id: str) -> dict[str, Any]:
    return {
        "type": "Root",
        "principalId": account_id,
        "arn": f"arn:aws:iam::{account_id}:root",
        "accountId": account_id,
    }


def _base_event(
    event_name: str,
    event_source: str,
    read_only: bool,
    account_id: str,
    region: str,
    event_category: str = "Management",
) -> dict[str, Any]:
    """Build the CloudTrail event envelope."""
    return {
        "eventVersion": "1.08",
        "eventTime": _ts(random.randint(0, 7200)),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": random.choice(_EXTERNAL_IPS + _INTERNAL_IPS),
        "userAgent": random.choice(_USER_AGENTS),
        "requestParameters": None,
        "responseElements": None,
        "requestID": _uid(),
        "eventID": _uid(),
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": account_id,
        "eventCategory": event_category,
    }


# ── Main class ────────────────────────────────────────────────────────────────

class CloudTrailLogSource(AbstractLogSource):
    source_type = "cloudtrail"
    description = "AWS CloudTrail API call events"

    def __init__(self, seed: int | None = None) -> None:
        if seed is not None:
            random.seed(seed)
        self._account_id = random.choice(_ACCOUNT_IDS)
        self._region = random.choice(_REGIONS)

    # ── Benign event generators ───────────────────────────────────────────────

    def _gen_benign(self) -> dict[str, Any]:
        """Generate a random benign CloudTrail event."""
        event_name, event_source, read_only = random.choice(_BENIGN_EVENT_NAMES)
        identity_fn = random.choice([
            lambda: _iam_user_identity(self._account_id),
            lambda: _assumed_role_identity(self._account_id),
        ])
        ev = _base_event(event_name, event_source, read_only, self._account_id, self._region)
        ev["userIdentity"] = identity_fn()

        # Add plausible requestParameters for common events
        if event_name == "GetObject":
            ev["requestParameters"] = {
                "bucketName": random.choice(_S3_BUCKETS),
                "key": f"data/{random.randint(2020, 2024)}/{random.randint(1, 12):02d}/report.csv",
            }
        elif event_name == "PutObject":
            ev["requestParameters"] = {
                "bucketName": random.choice(_S3_BUCKETS),
                "key": f"uploads/{_uid()[:8]}.json",
            }
        elif event_name == "DescribeInstances":
            ev["requestParameters"] = {
                "filterSet": {},
                "instancesSet": {"items": [{"instanceId": random.choice(_STABLE_INSTANCE_IDS)}]},
            }
        elif event_name == "RunInstances":
            ev["requestParameters"] = {
                "instanceType": random.choice(["t3.micro", "t3.small", "m5.large"]),
                "imageId": f"ami-0{random.randint(10**14, 10**15 - 1):015x}"[:19],
                "minCount": 1,
                "maxCount": 1,
            }

        ev["malicious_indicator"] = False
        return ev

    # ── Attack event generators ───────────────────────────────────────────────

    def _gen_privilege_escalation(self) -> dict[str, Any]:
        """T1078.004 — Valid Cloud Accounts: attach AdministratorAccess policy."""
        target_user = random.choice(_IAM_USERS)
        ev = _base_event(
            "AttachUserPolicy", "iam.amazonaws.com", False,
            self._account_id, self._region,
        )
        ev["userIdentity"] = _assumed_role_identity(self._account_id)
        ev["requestParameters"] = {
            "userName": target_user,
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        }
        ev["responseElements"] = None
        ev["technique_id"] = "T1078.004"
        ev["malicious_indicator"] = True
        return ev

    def _gen_credential_theft(self) -> dict[str, Any]:
        """T1552.005 — Cloud Instance Metadata API / Secrets Manager access."""
        secret = random.choice(_SECRET_NAMES)
        ev = _base_event(
            "GetSecretValue", "secretsmanager.amazonaws.com", True,
            self._account_id, self._region,
        )
        ev["userIdentity"] = _iam_user_identity(self._account_id)
        ev["requestParameters"] = {"secretId": secret}
        ev["responseElements"] = {
            "ARN": f"arn:aws:secretsmanager:{self._region}:{self._account_id}:secret:{secret}-AbCdEf",
            "name": secret,
            "versionId": _uid(),
        }
        ev["technique_id"] = "T1552.005"
        ev["malicious_indicator"] = True
        return ev

    def _gen_detection_evasion(self) -> dict[str, Any]:
        """T1562.008 — Impair Defenses: Disable or Delete CloudTrail."""
        action = random.choice(["StopLogging", "DeleteTrail"])
        trail_name = f"arn:aws:cloudtrail:{self._region}:{self._account_id}:trail/management-events"
        ev = _base_event(
            action, "cloudtrail.amazonaws.com", False,
            self._account_id, self._region,
        )
        ev["userIdentity"] = random.choice([
            _iam_user_identity(self._account_id),
            _root_identity(self._account_id),
        ])
        ev["requestParameters"] = {"name": trail_name}
        ev["responseElements"] = None
        ev["technique_id"] = "T1562.008"
        ev["malicious_indicator"] = True
        return ev

    def _gen_backdoor_access(self) -> dict[str, Any]:
        """T1098 — Account Manipulation: create access key for backdoor service account."""
        ev = _base_event(
            "CreateAccessKey", "iam.amazonaws.com", False,
            self._account_id, self._region,
        )
        ev["userIdentity"] = _assumed_role_identity(self._account_id)
        ev["requestParameters"] = {"userName": "backdoor_svc"}
        ev["responseElements"] = {
            "accessKey": {
                "accessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "status": "Active",
                "userName": "backdoor_svc",
                "createDate": _ts(0),
            }
        }
        ev["technique_id"] = "T1098"
        ev["malicious_indicator"] = True
        return ev

    def _gen_data_exfil(self) -> dict[str, Any]:
        """T1530 — Data from Cloud Storage Object: make bucket public."""
        bucket = random.choice(_S3_BUCKETS)
        ev = _base_event(
            "PutBucketAcl", "s3.amazonaws.com", False,
            self._account_id, self._region,
        )
        ev["userIdentity"] = _iam_user_identity(self._account_id)
        ev["requestParameters"] = {
            "bucketName": bucket,
            "AccessControlPolicy": {
                "AccessControlList": {
                    "Grant": [
                        {
                            "Grantee": {
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                                "xsi:type": "Group",
                            },
                            "Permission": "READ",
                        }
                    ]
                },
                "Owner": {
                    "ID": "".join(random.choices("0123456789abcdef", k=64)),
                },
            },
        }
        ev["responseElements"] = None
        ev["technique_id"] = "T1530"
        ev["malicious_indicator"] = True
        return ev

    def _gen_recon(self) -> dict[str, Any]:
        """T1526 — Cloud Service Discovery: high-volume enumeration calls."""
        recon_events = [
            ("DescribeInstances",  "ec2.amazonaws.com",  True),
            ("ListBuckets",        "s3.amazonaws.com",   True),
            ("GetCallerIdentity",  "sts.amazonaws.com",  True),
            ("ListUsers",          "iam.amazonaws.com",  True),
            ("DescribeVpcs",       "ec2.amazonaws.com",  True),
            ("ListRoles",          "iam.amazonaws.com",  True),
            ("DescribeSecurityGroups", "ec2.amazonaws.com", True),
        ]
        event_name, event_source, read_only = random.choice(recon_events)
        ev = _base_event(
            event_name, event_source, read_only,
            self._account_id, self._region,
        )
        ev["userIdentity"] = _iam_user_identity(self._account_id)
        ev["requestParameters"] = {}
        ev["responseElements"] = None
        ev["technique_id"] = "T1526"
        ev["malicious_indicator"] = True
        return ev

    # ── AbstractLogSource interface ───────────────────────────────────────────

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        """Generate a single CloudTrail event.

        Args:
            malicious: If True, generate an event containing attack indicators.
            technique_id: Optional MITRE technique to simulate (e.g. "T1078.004").

        Returns:
            A dict representing the CloudTrail event in its native JSON format.
        """
        if not malicious:
            return self._gen_benign()

        # Resolve to a specific generator
        if technique_id and technique_id in _TECHNIQUE_MAP:
            method_name = _TECHNIQUE_MAP[technique_id]
        else:
            method_name = random.choice(list(_TECHNIQUE_MAP.values()))

        return getattr(self, method_name)()

    def generate_batch(
        self,
        count: int = 10,
        malicious_ratio: float = 0.1,
        technique_id: str = "",
    ) -> list[dict[str, Any]]:
        """Generate a batch of CloudTrail events with a mix of benign and malicious.

        Args:
            count: Total number of events to generate.
            malicious_ratio: Fraction of events that should be malicious (0.0-1.0).
            technique_id: Optional MITRE technique for all malicious events.

        Returns:
            Shuffled list of event dicts.
        """
        n_malicious = max(0, min(count, round(count * malicious_ratio)))
        events: list[dict[str, Any]] = []

        for _ in range(n_malicious):
            events.append(self.generate(malicious=True, technique_id=technique_id))

        for _ in range(count - n_malicious):
            events.append(self.generate(malicious=False))

        random.shuffle(events)
        return events

    def get_schema(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "fields": {
                "eventVersion": "string",
                "userIdentity": "object",
                "eventTime": "ISO8601 string",
                "eventSource": "string",
                "eventName": "string",
                "awsRegion": "string",
                "sourceIPAddress": "string",
                "userAgent": "string",
                "requestParameters": "object|null",
                "responseElements": "object|null",
                "requestID": "uuid string",
                "eventID": "uuid string",
                "readOnly": "bool",
                "eventType": "string",
                "managementEvent": "bool",
                "recipientAccountId": "string",
                "eventCategory": "string",
                "malicious_indicator": "bool",
                "technique_id": "string (malicious events only)",
            },
        }
