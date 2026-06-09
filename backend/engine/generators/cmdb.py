"""CMDB (Configuration Management Database) event generator.

Produces CI lifecycle and drift events: asset changes, decommissions, configuration drift.
"""
import random
import uuid
from datetime import datetime, timezone, timedelta
from backend.engine.generators.base import BaseGenerator


CI_CLASSES = ["Server", "Workstation", "NetworkDevice", "Application",
              "Database", "Container", "LoadBalancer", "StorageArray"]
ENVIRONMENTS = ["prod", "staging", "dev", "dr", "qa"]
CHANGE_TYPES = ["created", "updated", "deleted", "drift_detected", "decommissioned"]
OS_VERSIONS = ["Ubuntu 22.04 LTS", "RHEL 9.3", "Windows Server 2022",
               "Debian 12", "Amazon Linux 2023", "macOS 14 Sonoma"]
TEAMS = ["platform-eng", "security-ops", "netops", "dba-team", "devops", "identity-eng"]
CHANGED_BY = ["ansible-automation", "terraform-runner", "jira-automation",
              "patch-manager", "admin-user@corp.com", "devops-pipeline"]


class CMDBGenerator(BaseGenerator):
    product_name = "CMDB"
    product_category = "cmdb"

    def generate(self) -> dict:
        now = datetime.now(timezone.utc)
        ci_class = random.choice(CI_CLASSES)
        env = random.choice(ENVIRONMENTS)
        change_type = random.choice(CHANGE_TYPES)
        patch_date = (now - timedelta(days=random.randint(0, 120))).strftime("%Y-%m-%d")
        n_ips = random.randint(1, 3)

        return {
            "ci_id": f"ci-{random.randint(1000, 99999)}",
            "ci_class": ci_class,
            "ci_name": f"{env}-{ci_class.lower().replace(' ', '-')}-{random.randint(1, 50):02d}",
            "owner": random.choice(TEAMS),
            "environment": env,
            "status": _status(change_type),
            "ip_addresses": [f"10.{random.randint(0,9)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(n_ips)],
            "os_version": random.choice(OS_VERSIONS) if ci_class in ("Server", "Workstation") else None,
            "patch_level": patch_date,
            "last_scanned": (now - timedelta(hours=random.randint(0, 48))).isoformat(),
            "change_type": change_type,
            "changed_at": now.isoformat(),
            "changed_by": random.choice(CHANGED_BY),
            "change_ticket": f"CHG{random.randint(10000, 99999)}" if change_type != "drift_detected" else None,
            "drift_field": random.choice(["kernel_version", "open_ports", "running_services", "cron_jobs", "sudoers"]) if change_type == "drift_detected" else None,
        }


def _status(change_type: str) -> str:
    if change_type in ("deleted", "decommissioned"):
        return "decommissioned"
    if change_type == "drift_detected":
        return random.choice(["active", "maintenance"])
    return "active"
