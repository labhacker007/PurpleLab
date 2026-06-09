"""Product / Service Registry event generator.

Produces internal service lifecycle events: registration, updates, deprecation,
decommissioning, and drift for the microservice catalog.
"""
import random
from datetime import datetime, timezone, timedelta
from backend.engine.generators.base import BaseGenerator


TEAMS = ["platform-eng", "payments-eng", "identity-eng", "data-eng", "security-ops",
         "observability", "ml-platform", "growth-eng", "api-gateway", "auth-team"]
LANGUAGES = ["Go", "Python", "TypeScript", "Java", "Rust", "Node.js", "Kotlin", "Ruby"]
DEPLOY_TARGETS = ["k8s", "ecs", "lambda", "vm", "on-prem", "cloud-run", "azure-functions"]
EVENT_TYPES = ["registered", "updated", "deprecated", "decommissioned", "security_review_due",
               "dependency_vuln_detected", "api_version_retired"]
DATA_CLASSES = ["public", "internal", "confidential", "restricted"]
TIERS = ["tier-1", "tier-2", "tier-3"]

SERVICE_NAMES = [
    ("auth-svc", "Authentication Service"),
    ("payment-svc", "Payment Service"),
    ("notification-svc", "Notification Service"),
    ("user-profile-svc", "User Profile Service"),
    ("search-svc", "Search Service"),
    ("analytics-pipeline", "Analytics Pipeline"),
    ("fraud-detection", "Fraud Detection"),
    ("inventory-svc", "Inventory Service"),
    ("order-mgmt", "Order Management"),
    ("api-gateway", "API Gateway"),
    ("identity-provider", "Identity Provider"),
    ("report-generator", "Report Generator"),
    ("data-exporter", "Data Export Service"),
    ("webhook-router", "Webhook Router"),
    ("session-store", "Session Store"),
]


class ProductRegistryGenerator(BaseGenerator):
    product_name = "Product Registry"
    product_category = "product_registry"

    def generate(self) -> dict:
        now = datetime.now(timezone.utc)
        service_id, service_name = random.choice(SERVICE_NAMES)
        event_type = random.choice(EVENT_TYPES)
        tier = random.choice(TIERS)
        pii = random.random() < 0.3
        external = random.random() < 0.4
        n_deps = random.randint(0, 6)
        last_review = (now - timedelta(days=random.randint(30, 400))).isoformat()

        result = {
            "service_id": service_id,
            "service_name": service_name,
            "team": random.choice(TEAMS),
            "tier": tier,
            "data_classification": random.choice(DATA_CLASSES),
            "pii_handler": pii,
            "external_facing": external,
            "language": random.choice(LANGUAGES),
            "deploy_target": random.choice(DEPLOY_TARGETS),
            "slo_availability": round(random.choice([0.999, 0.9999, 0.99999, 0.99, 0.995]), 5),
            "dependencies": [random.choice(SERVICE_NAMES)[0] for _ in range(n_deps)],
            "last_security_review": last_review,
            "event_type": event_type,
            "changed_at": now.isoformat(),
        }

        if event_type == "dependency_vuln_detected":
            result["vuln_cve"] = f"CVE-{random.randint(2020,2026)}-{random.randint(1000,99999)}"
            result["vuln_severity"] = random.choice(["critical", "high", "medium"])
            result["affected_dependency"] = random.choice(SERVICE_NAMES)[0]

        if event_type == "security_review_due":
            result["review_overdue_days"] = random.randint(1, 180)

        if event_type == "api_version_retired":
            result["retired_version"] = f"v{random.randint(1, 5)}"
            result["replacement_version"] = f"v{random.randint(2, 6)}"

        return result
