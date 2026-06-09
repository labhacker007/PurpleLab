"""Attack Surface Management (ASM) event generator.

Produces external attack surface findings: exposed services, expired certs,
subdomain takeovers, leaked credentials, and open ports.
"""
import random
import uuid
from datetime import datetime, timezone, timedelta
from backend.engine.generators.base import BaseGenerator


ASSET_TYPES = ["domain", "ip", "certificate", "url", "service"]
FINDING_TYPES = {
    "critical": ["subdomain_takeover", "leaked_credential", "exposed_admin_panel"],
    "high": ["expired_cert", "exposed_service", "open_rdp", "open_database_port"],
    "medium": ["http_security_headers_missing", "open_port", "tls_weak_cipher"],
    "low": ["info_disclosure", "outdated_software_version", "missing_dnssec"],
}
SERVICES = ["OpenSSH", "Apache HTTPD", "nginx", "Microsoft RDP", "MySQL", "PostgreSQL",
            "Redis", "Elasticsearch", "Kubernetes API", "Jenkins", "Grafana"]
PORTS = [22, 80, 443, 3306, 5432, 6379, 9200, 8080, 8443, 3389, 27017]
TAGS = ["prod", "staging", "dev", "legacy", "api", "admin", "public", "partner"]


class ASMGenerator(BaseGenerator):
    product_name = "Attack Surface Management"
    product_category = "asm"

    _DOMAINS = [f"subdomain{i}.example.com" for i in range(1, 20)]
    _IPS = [f"203.0.113.{i}" for i in range(10, 50)]

    def generate(self) -> dict:
        severity = random.choice(["critical", "high", "medium", "low"])
        finding_type = random.choice(FINDING_TYPES[severity])
        asset_type = random.choice(ASSET_TYPES)
        now = datetime.now(timezone.utc)
        first_seen = now - timedelta(days=random.randint(1, 90))
        port = random.choice(PORTS) if "port" in finding_type or "service" in finding_type else None
        service = random.choice(SERVICES) if port else None

        return {
            "asset_id": f"asm-{uuid.uuid4().hex[:8]}",
            "asset_type": asset_type,
            "asset_value": random.choice(self._DOMAINS) if asset_type == "domain" else random.choice(self._IPS),
            "severity": severity,
            "finding_type": finding_type,
            "port": port,
            "service": f"{service} {random.choice(['7.x', '8.x', '9.x', '14.x'])}" if service else None,
            "first_seen": first_seen.isoformat(),
            "last_seen": now.isoformat(),
            "tags": random.sample(TAGS, k=random.randint(1, 3)),
            "remediation": _remediation(finding_type),
            "scan_source": random.choice(["shodan", "censys", "internal_scanner", "bitsight"]),
        }


def _remediation(finding_type: str) -> str:
    recs = {
        "expired_cert": "Renew TLS certificate immediately and automate renewal via ACME/Let's Encrypt",
        "exposed_service": "Restrict access to VPN/internal network via security group/firewall rule",
        "subdomain_takeover": "Claim or delete the dangling DNS CNAME record immediately",
        "leaked_credential": "Rotate credentials, scan git history, enable secret scanning",
        "open_rdp": "Disable RDP or restrict to VPN. Enable NLA and MFA.",
        "open_database_port": "Remove public database exposure. Use VPC peering or private endpoint.",
        "tls_weak_cipher": "Disable SSLv3/TLS 1.0/1.1. Configure strong cipher suites only.",
        "http_security_headers_missing": "Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options headers",
        "open_port": "Review firewall rules. Close unnecessary ports.",
        "info_disclosure": "Remove server version banners and error stack traces from responses",
        "outdated_software_version": "Apply available security patches and updates",
        "missing_dnssec": "Enable DNSSEC for the domain at your DNS registrar",
        "exposed_admin_panel": "Restrict admin interface to internal IPs only",
    }
    return recs.get(finding_type, "Review and remediate according to security policy")
